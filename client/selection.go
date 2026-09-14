package main

import (
	"context"
	"log"
	"sort"
	"sync"
	"time"
)

const (
	probeInterval = 30 * time.Second
	probeTimeout  = 5 * time.Second
	scoreMaxAge   = 2 * time.Minute
)

type nodeScore struct {
	value       float64
	updated     time.Time
	failures    int
	recoveries  int
	unavailable bool
}

func (n *nodeScore) fresh(now time.Time) bool {
	return !n.updated.IsZero() && now.Sub(n.updated) <= scoreMaxAge
}

func (n *nodeScore) usable(now time.Time) bool {
	return n.fresh(now) && !n.unavailable && n.failures == 0
}

// Observe uses the start time to reject an older probe finishing after a newer
// foreground failure. Successful traffic does not bias scores by request volume.
func (n *nodeScore) observe(start time.Time, elapsed time.Duration, failed bool) {
	if start.Before(n.updated) {
		return
	}
	cost := float64(elapsed) / float64(time.Millisecond)
	if failed {
		cost = float64(probeTimeout / time.Millisecond)
	}
	if !n.fresh(start) {
		n.value = cost
		n.failures, n.recoveries = 0, 0
	} else {
		n.value = 0.75*n.value + 0.25*cost
	}
	n.updated = start
	if failed {
		n.recoveries = 0
		n.failures = min(n.failures+1, 2)
		if n.failures == 2 {
			n.unavailable = true
		}
	} else {
		n.failures = 0
		n.recoveries = min(n.recoveries+1, 2)
		if n.recoveries == 2 {
			n.unavailable = false
		}
	}
}

// Serializes selection with foreground failover. The generation prevents an old
// dial from undoing a newer selection, including switches away and back again.
type upstreamSelector struct {
	mu         sync.Mutex
	client     *client
	nodes      []nodeScore
	generation uint64
	candidate  int
	wins       int
}

func newUpstreamSelector(c *client) *upstreamSelector {
	return &upstreamSelector{client: c, nodes: make([]nodeScore, len(c.upstreams)), candidate: -1}
}

func (s *upstreamSelector) selectLocked(index int, reason string) {
	previous := int(s.client.stableIndex.Load())
	if previous != index {
		if s.client.pool != nil {
			s.client.pool.selectUpstream(index)
		} else {
			s.client.stableIndex.Store(uint32(index))
		}
		s.generation++
		log.Printf("Selected upstream %s (%s, score=%.1fms)", s.client.upstreams[index].label, reason, s.nodes[index].value)
	}
	s.candidate, s.wins = -1, 0
}

func (s *upstreamSelector) plan() ([]int, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := int(s.client.stableIndex.Load())
	order := make([]int, 0, len(s.nodes))
	for i := range s.nodes {
		if i != current {
			order = append(order, i)
		}
	}
	now := time.Now()
	rank := func(n nodeScore) int {
		if n.usable(now) {
			return 0
		}
		if !n.fresh(now) {
			return 1
		}
		return 2
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := s.nodes[order[i]], s.nodes[order[j]]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return a.fresh(now) && b.fresh(now) && a.value < b.value
	})
	// Even unknown or unavailable nodes remain a last resort for live traffic.
	return append([]int{current}, order...), s.generation
}

func (s *upstreamSelector) failed(index int, start time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[index].observe(start, probeTimeout, true)
}

func (s *upstreamSelector) connected(index int, generation uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation == s.generation && index != int(s.client.stableIndex.Load()) {
		s.selectLocked(index, "failover")
	}
}

func (s *upstreamSelector) consider(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := int(s.client.stableIndex.Load())
	best := current
	for i, node := range s.nodes {
		if node.usable(now) && (!s.nodes[best].usable(now) || node.value < s.nodes[best].value) {
			best = i
		}
	}
	if best == current || !s.nodes[best].usable(now) {
		s.candidate, s.wins = -1, 0
		return
	}
	if s.nodes[current].unavailable || !s.nodes[current].fresh(now) {
		s.selectLocked(best, "unavailable or expired current node")
		return
	}
	if s.nodes[best].value > 0.8*s.nodes[current].value {
		s.candidate, s.wins = -1, 0
		return
	}
	if s.candidate != best {
		s.candidate, s.wins = best, 0
	}
	s.wins++
	if s.wins >= 2 {
		s.selectLocked(best, "lower score for two rounds")
	}
}

func (s *upstreamSelector) run(ctx context.Context) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		for i, endpoint := range s.client.upstreams {
			if ctx.Err() != nil {
				return
			}
			// Probes always complete SOCKS authentication, including no-auth
			// for certificate-only upstreams. Traffic keeps legacy passthrough.
			endpoint.negotiate = true
			probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			start := time.Now()
			conn, err := dialUpstream(probeCtx, endpoint)
			elapsed := time.Since(start)
			cancel()
			if conn != nil {
				closeIdle(conn)
			}
			if ctx.Err() != nil {
				return
			}
			s.mu.Lock()
			s.nodes[i].observe(start, elapsed, err != nil)
			score := s.nodes[i].value
			s.mu.Unlock()
			log.Printf("Upstream probe %s: score=%.1fms, success=%t", endpoint.label, score, err == nil)
			if i+1 < len(s.nodes) {
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
		s.consider(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

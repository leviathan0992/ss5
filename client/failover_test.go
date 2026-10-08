package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func testSelector(count int) *upstreamSelector {
	c := &client{upstreams: make([]upstreamEndpoint, count)}
	return newUpstreamSelector(c)
}

func assertPlan(t *testing.T, s *upstreamSelector, want []int) uint64 {
	t.Helper()
	got, generation := s.plan()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan = %v, want %v", got, want)
	}
	return generation
}

func TestFailoverKeepsActiveWhileBackupsAreHealthy(t *testing.T) {
	s := testSelector(3)
	now := time.Now()
	for round := 0; round < 4; round++ {
		start := now.Add(time.Duration(round) * time.Millisecond)
		s.nodes[0].observe(start, false)
		s.nodes[1].observe(start, false)
		s.nodes[2].observe(start, false)
		assertPlan(t, s, []int{0, 1, 2})
	}
}

func TestFailoverSticksAfterRecoveryAndRejectsStaleDial(t *testing.T) {
	s := testSelector(3)
	generation := assertPlan(t, s, []int{0, 1, 2})
	s.failed(0, time.Now())
	s.connected(1, generation)
	assertPlan(t, s, []int{1, 2, 0})
	// An older concurrent dial must not undo the new selection.
	s.connected(0, generation)
	assertPlan(t, s, []int{1, 2, 0})
	for i := 0; i < 2; i++ {
		s.nodes[0].observe(time.Now(), false)
	}
	assertPlan(t, s, []int{1, 0, 2})
	// Only a new foreground fallback can change the sticky selection again.
	_, currentGeneration := s.plan()
	s.failed(1, time.Now())
	s.connected(2, currentGeneration)
	if s.client.stableIndex.Load() != 2 {
		t.Fatal("second failover did not select successful backup")
	}
}

func TestFailoverProbesDoNotReplaceUnavailableOrStaleActive(t *testing.T) {
	s := testSelector(3)
	now := time.Now()
	s.nodes[1].observe(now, false)
	s.nodes[0].observe(now, true)
	s.nodes[0].observe(now.Add(time.Millisecond), true)
	assertPlan(t, s, []int{0, 1, 2})
	s.nodes[0].updated = now.Add(-3 * time.Minute)
	assertPlan(t, s, []int{0, 1, 2})
}

func TestFailoverBackupsPreferHealthThenConfigurationOrder(t *testing.T) {
	s := testSelector(5)
	now := time.Now()
	s.nodes[1].observe(now, true)
	s.nodes[4].observe(now, false)
	s.nodes[3].observe(now, false)
	assertPlan(t, s, []int{0, 3, 4, 2, 1})
}

// Drop the first N TCP connections before the TLS server sees them.
type failingListener struct {
	net.Listener
	failures int32
	calls    atomic.Int32
}

func (l *failingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.calls.Add(1) <= l.failures {
			conn.Close()
			continue
		}
		return conn, nil
	}
}
func TestAcquireRetriesBeforeChangingExit(t *testing.T) {
	for _, failures := range []int32{2, 3} {
		t.Run(fmt.Sprint(failures), func(t *testing.T) {
			primary := httptest.NewUnstartedServer(http.NotFoundHandler())
			listener := &failingListener{Listener: primary.Listener, failures: failures}
			primary.Listener = listener
			primary.StartTLS()
			defer primary.Close()
			backup := httptest.NewTLSServer(http.NotFoundHandler())
			defer backup.Close()
			c := &client{upstreams: []upstreamEndpoint{
				{addrStr: primary.Listener.Addr().String(), tlsConfig: &tls.Config{InsecureSkipVerify: true}},
				{addrStr: backup.Listener.Addr().String(), tlsConfig: &tls.Config{InsecureSkipVerify: true}},
			}}
			c.selector = newUpstreamSelector(c)
			conn, _, err := c.acquireServer(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if got := listener.calls.Load(); got != 3 {
				t.Fatalf("primary attempts=%d, want 3", got)
			}
			want := uint32(0)
			if failures == 3 {
				want = 1
			}
			if got := c.stableIndex.Load(); got != want {
				t.Fatalf("active=%d, want %d", got, want)
			}
		})
	}
}

func TestPreconnectTargetFollowsRecentDemand(t *testing.T) {
	var stable atomic.Uint32
	p := newPreconnectPool(context.Background(), 16, &stable, nil)
	defer p.cancel()
	now := time.Now()
	p.demandStart = now

	if got := p.targetLocked(now); got != 1 {
		t.Fatalf("idle target=%d, want 1", got)
	}
	for i := 0; i < 5; i++ {
		p.recordDemandLocked(now)
	}
	if got := p.targetLocked(now); got != 5 {
		t.Fatalf("target=%d, want 5", got)
	}
	// The previous window still counts after one rotation.
	if got := p.targetLocked(now.Add(p.ttl)); got != 5 {
		t.Fatalf("target after one window=%d, want 5", got)
	}
	if got := p.targetLocked(now.Add(2 * p.ttl)); got != 1 {
		t.Fatalf("target after two quiet windows=%d, want 1", got)
	}
	for i := 0; i < 40; i++ {
		p.recordDemandLocked(now.Add(2 * p.ttl))
	}
	if got := p.targetLocked(now.Add(2 * p.ttl)); got != 16 {
		t.Fatalf("burst target=%d, want size 16", got)
	}
}

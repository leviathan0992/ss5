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

func TestFailoverKeepsActiveDespiteFasterBackups(t *testing.T) {
	s := testSelector(3)
	now := time.Now()
	for round := 0; round < 4; round++ {
		start := now.Add(time.Duration(round) * time.Millisecond)
		s.nodes[0].observe(start, time.Second, false)
		s.nodes[1].observe(start, time.Millisecond, false)
		s.nodes[2].observe(start, time.Microsecond, false)
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
		s.nodes[0].observe(time.Now(), time.Microsecond, false)
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
	s.nodes[1].observe(now, time.Millisecond, false)
	s.nodes[0].observe(now, 0, true)
	s.nodes[0].observe(now.Add(time.Millisecond), 0, true)
	assertPlan(t, s, []int{0, 1, 2})
	s.nodes[0].updated = now.Add(-3 * time.Minute)
	assertPlan(t, s, []int{0, 1, 2})
}

func TestFailoverBackupsPreferHealthThenConfigurationOrder(t *testing.T) {
	s := testSelector(5)
	now := time.Now()
	s.nodes[1].observe(now, 0, true)
	s.nodes[3].observe(now, time.Second, false)
	s.nodes[4].observe(now, time.Millisecond, false)
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

package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type idleConnection struct {
	conn    net.Conn
	expires time.Time
}

// Only authenticated connections that have never received a SOCKS request enter
// this pool. Active tunnels belong to their caller and are never returned.
type preconnectPool struct {
	mu         sync.Mutex
	items      []idleConnection
	size       int
	stable     *atomic.Uint32
	generation uint64
	lastUse    time.Time
	nextDial   time.Time
	backoff    time.Duration
	closed     bool
	dialCancel context.CancelFunc
	dial       func(context.Context, int) (net.Conn, error)
	ctx        context.Context
	cancel     context.CancelFunc
	wake       chan struct{}
	done       chan struct{}
	ttl        time.Duration
	idle       time.Duration
}

func newPreconnectPool(parent context.Context, size int, stable *atomic.Uint32, dial func(context.Context, int) (net.Conn, error)) *preconnectPool {
	ctx, cancel := context.WithCancel(parent)
	return &preconnectPool{
		size:    size,
		stable:  stable,
		dial:    dial,
		ctx:     ctx,
		cancel:  cancel,
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
		ttl:     10 * time.Second,
		idle:    10 * time.Second,
		lastUse: time.Now(),
		backoff: time.Second,
	}
}

// Unused TLS connections have no application data to flush. Closing the raw
// socket also avoids waiting for a TLS close-notify on an unreachable peer.
func closeIdle(conn net.Conn) {
	if tc, ok := conn.(*tls.Conn); ok {
		_ = tc.NetConn().Close()
	} else {
		_ = conn.Close()
	}
}

func (p *preconnectPool) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *preconnectPool) take(index int) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.lastUse = time.Now()
	p.signal()
	if int(p.stable.Load()) != index {
		return nil
	}
	for len(p.items) > 0 {
		item := p.items[0]
		p.items[0] = idleConnection{}
		p.items = p.items[1:]
		if !time.Now().Before(item.expires) {
			closeIdle(item.conn)
			continue
		}
		return item.conn
	}
	return nil
}

// Selection changes drain only unused connections; active tunnels stay open.
// Generation checks discard a background dial finishing after a switch.
func (p *preconnectPool) selectUpstream(index int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || int(p.stable.Load()) == index {
		return
	}
	p.stable.Store(uint32(index))
	p.generation++
	if p.dialCancel != nil {
		p.dialCancel()
	}
	for _, item := range p.items {
		closeIdle(item.conn)
	}
	p.items = nil
	p.nextDial = time.Time{}
	p.backoff = time.Second
	p.signal()
}

func (p *preconnectPool) run() {
	defer close(p.done)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		p.mu.Lock()
		now := time.Now()
		kept := p.items[:0]
		for _, item := range p.items {
			if now.Before(item.expires) {
				kept = append(kept, item)
			} else {
				closeIdle(item.conn)
			}
		}
		clear(p.items[len(kept):])
		p.items = kept
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			return
		}
		if len(p.items) >= p.size || now.Sub(p.lastUse) >= p.idle || now.Before(p.nextDial) {
			p.mu.Unlock()
			select {
			case <-p.ctx.Done():
				return
			case <-p.wake:
			case <-ticker.C:
			}
			continue
		}
		index, generation := int(p.stable.Load()), p.generation
		dialCtx, cancel := context.WithCancel(p.ctx)
		p.dialCancel = cancel
		born := time.Now()
		p.mu.Unlock()

		conn, err := p.dial(dialCtx, index)
		cancel()
		p.mu.Lock()
		p.dialCancel = nil
		if p.closed || generation != p.generation || p.ctx.Err() != nil {
			if conn != nil {
				closeIdle(conn)
			}
			p.mu.Unlock()
			continue
		}
		if err != nil || time.Since(born) >= p.ttl {
			if conn != nil {
				closeIdle(conn)
			}
			p.nextDial = time.Now().Add(p.backoff)
			p.backoff = min(2*p.backoff, 30*time.Second)
			p.mu.Unlock()
			if err != nil {
				log.Printf("Preconnection to upstream %d failed: %v", index, err)
			}
			continue
		}
		p.backoff = time.Second
		p.nextDial = time.Time{}
		if time.Since(p.lastUse) < p.idle {
			p.items = append(p.items, idleConnection{conn: conn, expires: born.Add(p.ttl)})
		} else {
			closeIdle(conn)
		}
		p.mu.Unlock()
	}
}

func (p *preconnectPool) close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	for _, item := range p.items {
		closeIdle(item.conn)
	}
	p.items = nil
	p.mu.Unlock()
	<-p.done
}

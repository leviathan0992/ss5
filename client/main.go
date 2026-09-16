package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	util "github.com/leviathan0992/ss5"
)

// Accepts local SOCKS5 traffic and tunnels it to one of the configured
// upstream servers over mutual TLS.
type client struct {
	*util.Service
	upstreams   []upstreamEndpoint
	stableIndex atomic.Uint32
	negotiate   bool
	pool        *preconnectPool
	selector    *upstreamSelector
	ctx         context.Context
	cancel      context.CancelFunc
}

// Keeps the original endpoint so DNS is resolved again on each dial.
type upstreamEndpoint struct {
	auth      *util.Credentials
	negotiate bool
	addrStr   string
	tlsConfig *tls.Config
	label     string
}

type Config struct {
	ServerAuth map[string]util.Credentials `json:"server_auth,omitempty"`
	ServerAddr []string                    `json:"server_addr"`
	ClientPEM  string                      `json:"client_pem"`
	ClientKey  string                      `json:"client_key"`
	ServerPEM  string                      `json:"server_pem"` /* Server CA cert for verifying the server identity. */
	ListenAddr string                      `json:"listen_addr"`
}

// Reuses one dialer across all upstream dial attempts. net.Dialer is safe for
// concurrent use, so a single instance avoids one heap allocation per dial.
var serverDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

// Constructs a client from the given configuration parameters.
// Returns nil and logs an error if any parameter is invalid.
func NewClient(listen string, srvAddrs []string, clientPEM string, clientKEY string, serverPEM string, authMap map[string]util.Credentials) *client {
	clientPEM = filepath.Clean(clientPEM)
	clientKEY = filepath.Clean(clientKEY)
	serverPEM = filepath.Clean(serverPEM)

	listenAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		log.Printf("Failed to resolve listen address %s: %v", listen, err)
		return nil
	}

	// Load client certificate for mTLS authentication.
	cert, err := tls.LoadX509KeyPair(clientPEM, clientKEY)
	if err != nil {
		log.Printf("The client failed to load the certificate and key pair: %v", err)
		return nil
	}

	// Load the server's CA certificate to verify the server's identity.
	serverCertBytes, err := os.ReadFile(serverPEM)
	if err != nil {
		log.Printf("Failed to read server PEM %s: %v", serverPEM, err)
		return nil
	}
	serverCertPool := x509.NewCertPool()
	if !serverCertPool.AppendCertsFromPEM(serverCertBytes) {
		log.Println("Failed to parse server PEM certificate")
		return nil
	}

	// Build a base TLS config that is cloned once per upstream endpoint at
	// construction time, avoiding a Clone() on every dial attempt.
	baseTLS := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		RootCAs:            serverCertPool,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
	}

	for endpoint, auth := range authMap {
		found := false
		for _, configured := range srvAddrs {
			if endpoint == configured {
				found = true
				break
			}
		}
		if !found {
			log.Printf("Authentication configured for unknown upstream %s", endpoint)
			return nil
		}
		if err := auth.Validate(); err != nil {
			log.Printf("Invalid upstream authentication for %s: %v", endpoint, err)
			return nil
		}
	}
	var upstreams []upstreamEndpoint
	for _, srvAddr := range srvAddrs {
		host, portText, err := net.SplitHostPort(srvAddr)
		port, portErr := strconv.Atoi(portText)
		if err != nil || host == "" || portErr != nil || port < 1 || port > 65535 {
			log.Printf("Invalid server address %q", srvAddr)
			return nil
		}
		cfg := baseTLS.Clone()
		cfg.ServerName = host
		var auth *util.Credentials
		if value, ok := authMap[srvAddr]; ok {
			auth = &value
		}
		upstreams = append(upstreams, upstreamEndpoint{
			auth:      auth,
			negotiate: len(authMap) > 0,
			addrStr:   srvAddr,
			tlsConfig: cfg,
			label:     srvAddr,
		})
	}

	if len(upstreams) == 0 {
		log.Println("No valid server addresses provided")
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &client{
		Service: &util.Service{
			ListenAddr: listenAddr,
		},
		ctx:       ctx,
		cancel:    cancel,
		upstreams: upstreams,
		negotiate: len(authMap) > 0,
	}
	c.selector = newUpstreamSelector(c)
	return c
}

// Accepts incoming TCP connections and dispatches each to handleConn.
// Returns when a shutdown signal is received.
func (c *client) Listen() error {
	defer c.cancel()
	for _, srv := range c.upstreams {
		log.Printf("The configured server address is %s.", srv.label)
	}

	stableIdx := int(c.stableIndex.Load())
	if stableIdx >= len(c.upstreams) {
		stableIdx = 0
		c.stableIndex.Store(0)
	}
	stable := c.upstreams[stableIdx]
	log.Printf("Using the default server address: %s.", stable.label)

	listener, err := net.ListenTCP("tcp", c.ListenAddr)
	if err != nil {
		log.Printf("Failed to start the client listening on %s: %v", c.ListenAddr.String(), err)
		return err
	}
	log.Printf("The client successfully started listening on %s.", c.ListenAddr.String())
	defer listener.Close()
	if c.pool != nil {
		go c.pool.run()
		defer c.pool.close()
		log.Printf("Preconnection pool enabled: size=%d, TTL=10s, refill stops after 10s idle", c.pool.size)
	}

	if len(c.upstreams) > 1 {
		probeCtx, stopProbes := context.WithCancel(c.ctx)
		probeDone := make(chan struct{})
		go func() {
			defer close(probeDone)
			c.selector.run(probeCtx)
		}()
		defer func() { stopProbes(); <-probeDone }()
	}

	stop, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	return util.Serve(stop, listener, 1024, func(ctx context.Context, conn net.Conn) {
		c.handleConn(ctx, conn.(*net.TCPConn))
	})
}

// Handles a single incoming SOCKS5 connection from a local user.
func (c *client) handleConn(ctx context.Context, userConn *net.TCPConn) {
	defer userConn.Close()

	util.ConfigureTCPConn(userConn)
	c.connectServer(ctx, userConn)
}

// Dials the upstream server and bidirectionally relays data
// between userConn and the server connection.
func (c *client) connectServer(ctx context.Context, userConn *net.TCPConn) {
	if c.negotiate {
		_ = userConn.SetDeadline(time.Now().Add(30 * time.Second))
		if err := util.NegotiateServer(userConn, nil); err != nil {
			log.Printf("Invalid local SOCKS5 greeting: %v", err)
			return
		}
		_ = userConn.SetDeadline(time.Time{})
	}

	var srvConn net.Conn
	var err error
	if c.pool != nil {
		srvConn, err = c.connectPrepared(ctx, userConn)
	} else {
		srvConn, _, err = c.acquireServer(ctx, false)
	}
	if err != nil {
		log.Printf("Failed to get server connection: %v", err)
		return
	}

	if err := util.RelayClient(userConn, srvConn); err != nil {
		log.Printf("Connection relay ended: %v", err)
	}
}

// Tries the selected upstream first, then alternatives ordered by health and
// score. Unknown and unavailable nodes remain eligible as a last resort.
func (c *client) acquireServer(parent context.Context, allowPool bool) (net.Conn, bool, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	order, generation := c.selector.plan()
	stableIdx := order[0]
	if allowPool && c.pool != nil {
		if conn := c.pool.take(stableIdx); conn != nil {
			log.Printf("Using preconnected server %s", c.upstreams[stableIdx].label)
			return conn, true, nil
		}
	}
	var err error
	for position, index := range order {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		var conn net.Conn
		start := time.Now()
		// Reserve a share of the remaining budget for every untried node.
		// dialUpstream still caps a single attempt at ten seconds.
		deadline, _ := ctx.Deadline()
		budget := time.Until(deadline) / time.Duration(len(order)-position)
		attempt, stopAttempt := context.WithTimeout(ctx, budget)
		conn, err = dialUpstream(attempt, c.upstreams[index])
		stopAttempt()
		if err == nil {
			c.selector.connected(index, generation)
			log.Printf("Connected to server %s", c.upstreams[index].label)
			return conn, false, nil
		}
		if ctx.Err() == nil {
			c.selector.failed(index, start)
		}
		log.Printf("Failed to connect to server %s: %v", c.upstreams[index].label, err)
	}
	return nil, false, fmt.Errorf("all %d upstream(s) failed; last error: %w", len(c.upstreams), err)
}

// Opens a TLS connection to a single upstream endpoint.
// Each attempt has one deadline covering TCP, TLS and authentication.
func dialUpstream(ctx context.Context, upstream upstreamEndpoint) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: serverDialer, Config: upstream.tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", upstream.addrStr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { util.CloseConnection(conn) })
	defer stop()
	if upstream.negotiate {
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		if err := util.NegotiateClient(conn, upstream.auth); err != nil {
			util.CloseConnection(conn)
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
	}
	if !stop() || ctx.Err() != nil {
		util.CloseConnection(conn)
		return nil, ctx.Err()
	}
	return conn, nil
}

// Retry a failed unused connection only before application data is forwarded.
// A valid SOCKS failure reply is returned unchanged, never retried.
func (c *client) connectPrepared(ctx context.Context, userConn net.Conn) (net.Conn, error) {
	_ = userConn.SetDeadline(time.Now().Add(30 * time.Second))
	request, err := readSOCKSFrame(userConn)
	if err != nil {
		return nil, err
	}
	if request[1] != util.CmdConnect && request[1] != util.CmdUDPAssociate {
		util.SendSOCKS5Reply(userConn, 7)
		return nil, fmt.Errorf("unsupported SOCKS5 command")
	}
	conn, pooled, err := c.acquireServer(ctx, true)
	if err != nil {
		util.SendSOCKS5Reply(userConn, 1)
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		current := conn
		stop := context.AfterFunc(ctx, func() { util.CloseConnection(current) })
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		err = util.WriteAll(conn, request)
		var reply []byte
		if err == nil {
			reply, err = readSOCKSFrame(conn)
		}
		stop()
		if ctx.Err() != nil {
			util.CloseConnection(conn)
			return nil, ctx.Err()
		}
		if err == nil {
			_ = userConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err = util.WriteAll(userConn, reply); err != nil {
				util.CloseConnection(conn)
				return nil, err
			}
			if reply[1] != 0 {
				util.CloseConnection(conn)
				return nil, fmt.Errorf("upstream SOCKS5 request rejected: %d", reply[1])
			}
			_ = conn.SetDeadline(time.Time{})
			_ = userConn.SetDeadline(time.Time{})
			return conn, nil
		}
		util.CloseConnection(conn)
		if !pooled || attempt != 0 {
			util.SendSOCKS5Reply(userConn, 1)
			return nil, err
		}
		// Do not take another possibly stale pooled connection for the retry.
		conn, _, err = c.acquireServer(ctx, false)
		if err != nil {
			util.SendSOCKS5Reply(userConn, 1)
			return nil, err
		}
	}
}

// Read exactly one SOCKS request/reply, leaving any application bytes unread.
func readSOCKSFrame(r io.Reader) ([]byte, error) {
	frame := make([]byte, 4, 262)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	if frame[0] != util.SocksVersion || frame[2] != 0 {
		return nil, fmt.Errorf("invalid SOCKS5 header")
	}
	n := 0
	switch frame[3] {
	case util.AtypIPv4:
		n = net.IPv4len
	case util.AtypIPv6:
		n = net.IPv6len
	case util.AtypDomain:
		frame = append(frame, 0)
		if _, err := io.ReadFull(r, frame[4:5]); err != nil {
			return nil, err
		}
		n = int(frame[4])
		if n == 0 {
			return nil, fmt.Errorf("empty SOCKS5 domain")
		}
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 address type")
	}
	pos := len(frame)
	frame = frame[:pos+n+2]
	_, err := io.ReadFull(r, frame[pos:])
	return frame, err
}

func (c *client) enablePreconnect() {
	// Keep opaque SOCKS authentication passthrough for legacy configurations.
	if !c.negotiate {
		return
	}
	const poolSize = 16
	c.pool = newPreconnectPool(c.ctx, poolSize, &c.stableIndex, func(ctx context.Context, index int) (net.Conn, error) {
		return dialUpstream(ctx, c.upstreams[index])
	})
}

type idleConnection struct {
	conn    net.Conn
	expires time.Time
}

// Only authenticated connections that have never received a SOCKS request enter
// this pool. Active tunnels belong to their caller and are never returned.
type preconnectPool struct {
	// mu protects idle connections, refill policy and dial generation.
	// Active tunnels have been handed to callers and are not tracked here.
	mu         sync.Mutex
	items      []idleConnection
	size       int
	stable     *atomic.Uint32
	generation uint64
	lastUse    time.Time
	nextDial   time.Time
	backoff    time.Duration
	closed     bool
	dialCtx    context.Context
	dialCancel context.CancelFunc
	dial       func(context.Context, int) (net.Conn, error)
	ctx        context.Context
	cancel     context.CancelFunc
	wake       chan struct{}
	done       chan struct{}
	ttl        time.Duration
	idle       time.Duration
}

type preconnectResult struct {
	conn       net.Conn
	err        error
	born       time.Time
	generation uint64
	index      int
}

func newPreconnectPool(parent context.Context, size int, stable *atomic.Uint32, dial func(context.Context, int) (net.Conn, error)) *preconnectPool {
	ctx, cancel := context.WithCancel(parent)
	dialCtx, dialCancel := context.WithCancel(ctx)
	return &preconnectPool{
		size:       size,
		stable:     stable,
		dial:       dial,
		ctx:        ctx,
		cancel:     cancel,
		dialCtx:    dialCtx,
		dialCancel: dialCancel,
		wake:       make(chan struct{}, 1),
		done:       make(chan struct{}),
		ttl:        10 * time.Second,
		idle:       10 * time.Second,
		lastUse:    time.Now(),
		backoff:    time.Second,
	}
}

func (p *preconnectPool) take(index int) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	now := time.Now()
	if now.Sub(p.lastUse) >= p.idle {
		// An idle-era cancellation must not delay a new request with backoff.
		p.resetDialsLocked()
	}
	p.lastUse = now
	p.signal()
	if int(p.stable.Load()) != index {
		return nil
	}
	for len(p.items) > 0 {
		item := p.items[0]
		p.items[0] = idleConnection{}
		p.items = p.items[1:]
		if !time.Now().Before(item.expires) {
			util.CloseConnection(item.conn)
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
	p.resetDialsLocked()
	for _, item := range p.items {
		util.CloseConnection(item.conn)
	}
	p.items = nil
	p.signal()
}

func (p *preconnectPool) run() {
	defer close(p.done)
	const maxConcurrentDials = 4
	results := make(chan preconnectResult, maxConcurrentDials)
	pending := 0
	// close cancels all dials before waiting for done. Drain every result so
	// neither a completed socket nor a sender outlives the pool.
	defer func() {
		for pending > 0 {
			result := <-results
			pending--
			if result.conn != nil {
				util.CloseConnection(result.conn)
			}
		}
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		p.mu.Lock()
		now := time.Now()
		p.pruneExpiredLocked(now)
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			return
		}
		for pending < maxConcurrentDials && len(p.items)+pending < p.size &&
			now.Sub(p.lastUse) < p.idle && !now.Before(p.nextDial) {
			result := preconnectResult{born: now, generation: p.generation, index: int(p.stable.Load())}
			// An unused pool must not keep handshakes alive past its idle window.
			dialCtx, cancel := context.WithTimeout(p.dialCtx, min(p.ttl, p.idle-now.Sub(p.lastUse)))
			pending++
			go func(result preconnectResult, ctx context.Context, cancel context.CancelFunc) {
				result.conn, result.err = p.dial(ctx, result.index)
				cancel()
				results <- result
			}(result, dialCtx, cancel)
		}
		p.mu.Unlock()
		select {
		case <-p.ctx.Done():
			return
		case result := <-results:
			pending--
			p.acceptResult(result)
		case <-p.wake:
		case <-ticker.C:
		}
	}
}

// pruneExpiredLocked releases expired idle connections. The caller holds mu.
func (p *preconnectPool) pruneExpiredLocked(now time.Time) {
	kept := p.items[:0]
	for _, item := range p.items {
		if now.Before(item.expires) {
			kept = append(kept, item)
		} else {
			util.CloseConnection(item.conn)
		}
	}
	clear(p.items[len(kept):])
	p.items = kept
}

func (p *preconnectPool) acceptResult(result preconnectResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.closed || p.ctx.Err() != nil || result.generation != p.generation || now.Sub(p.lastUse) >= p.idle {
		if result.conn != nil {
			util.CloseConnection(result.conn)
		}
		return
	}
	if result.err != nil || !now.Before(result.born.Add(p.ttl)) {
		if result.conn != nil {
			util.CloseConnection(result.conn)
		}
		// Concurrent failures share one backoff window instead of multiplying it.
		if !now.Before(p.nextDial) {
			p.nextDial = now.Add(p.backoff)
			p.backoff = min(2*p.backoff, 30*time.Second)
		}
		if result.err != nil {
			log.Printf("Preconnection to upstream %d failed: %v", result.index, result.err)
		}
		return
	}
	p.backoff = time.Second
	p.nextDial = time.Time{}
	p.items = append(p.items, idleConnection{conn: result.conn, expires: result.born.Add(p.ttl)})
}

// The caller holds mu. Late results are discarded even if a dial completed
// just before its context was cancelled.
func (p *preconnectPool) resetDialsLocked() {
	p.generation++
	p.dialCancel()
	p.dialCtx, p.dialCancel = context.WithCancel(p.ctx)
	p.nextDial = time.Time{}
	p.backoff = time.Second
}

func (p *preconnectPool) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *preconnectPool) close() {
	p.mu.Lock()
	p.closed = true
	p.cancel()
	for _, item := range p.items {
		util.CloseConnection(item.conn)
	}
	p.items = nil
	p.mu.Unlock()
	<-p.done
}

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

func (s *upstreamSelector) run(ctx context.Context) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		for i, endpoint := range s.client.upstreams {
			if ctx.Err() != nil {
				return
			}
			stage := "socks-method"
			if endpoint.negotiate {
				stage = "socks-auth"
			}
			start := time.Now()
			err := probeUpstream(ctx, endpoint)
			elapsed := time.Since(start)
			if ctx.Err() != nil {
				return
			}
			s.mu.Lock()
			s.nodes[i].observe(start, elapsed, err != nil)
			score := s.nodes[i].value
			s.mu.Unlock()
			log.Printf("Upstream probe %s: stage=%s, score=%.1fms, success=%t", endpoint.label, stage, score, err == nil)
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

// A probe owns a separate connection and never consumes a caller's handshake.
// Legacy credentials belong to the caller, but a method-selection reply still
// confirms that the server accepted mTLS and is speaking SOCKS5.
func probeUpstream(parent context.Context, endpoint upstreamEndpoint) error {
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()
	conn, err := dialUpstream(ctx, endpoint)
	if err != nil {
		return err
	}
	defer util.CloseConnection(conn)
	if endpoint.negotiate {
		return nil
	}
	stop := context.AfterFunc(ctx, func() { util.CloseConnection(conn) })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if err := util.WriteAll(conn, []byte{util.SocksVersion, 2, 0, 2}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != util.SocksVersion || (reply[1] != 0 && reply[1] != 2) {
		return fmt.Errorf("upstream rejected supported SOCKS5 methods: %x", reply)
	}
	return ctx.Err()
}

func main() {
	var confPath string
	flag.StringVar(&confPath, "c", ".ss5-client.json", "The client configuration file.")
	flag.Parse()

	confPath = filepath.Clean(confPath)
	bytes, err := os.ReadFile(confPath)
	if err != nil {
		log.Fatalf("The client failed to read the configuration file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("The client failed to parse the configuration file %s: %v", confPath, err)
	}

	if config.ListenAddr == "" {
		log.Fatalf("Configuration field listen_addr is required")
	}
	if len(config.ServerAddr) == 0 {
		log.Fatalf("Configuration field server_addr is required and must be non-empty")
	}
	if config.ClientPEM == "" {
		log.Fatalf("Configuration field client_pem is required")
	}
	if config.ClientKey == "" {
		log.Fatalf("Configuration field client_key is required")
	}
	if config.ServerPEM == "" {
		log.Fatalf("Configuration field server_pem is required")
	}

	c := NewClient(config.ListenAddr, config.ServerAddr, config.ClientPEM, config.ClientKey, config.ServerPEM, config.ServerAuth)
	if c == nil {
		log.Fatalf("Failed to create client")
	}

	c.enablePreconnect()

	if err := c.Listen(); err != nil {
		log.Fatalf("Client exited with error: %v", err)
	}
}

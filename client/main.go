package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	util "github.com/leviathan0992/ss5"
)

/* Holds the address and pre-built TLS config for one upstream server.
 * The TLS config is pre-cloned with the correct ServerName so dialing avoids
 * cloning it on every connection attempt. addrStr is the pre-computed string form
 * of addr so dialing never allocates it on the hot path. */
type upstreamEndpoint struct {
	auth      *util.Credentials
	negotiate bool
	addr      *net.TCPAddr
	addrStr   string /* pre-computed addr.String(); avoids allocation per dial */
	tlsConfig *tls.Config
	label     string
}

/* Accepts local SOCKS5 traffic and tunnels it to one of the configured
 * upstream servers over mutual TLS. */
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

/* Reuses one dialer across all upstream dial attempts. net.Dialer is safe for
 * concurrent use, so a single instance avoids one heap allocation per dial. */
var serverDialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

/* Opens a TLS connection to a single upstream endpoint.
 * Each attempt has one deadline covering TCP, TLS and authentication. */
func dialUpstream(ctx context.Context, upstream upstreamEndpoint) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: serverDialer, Config: upstream.tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", upstream.addrStr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { closeIdle(conn) })
	defer stop()
	if upstream.negotiate {
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
		if err := util.NegotiateClient(conn, upstream.auth); err != nil {
			closeIdle(conn)
			return nil, err
		}
		_ = conn.SetDeadline(time.Time{})
	}
	if !stop() || ctx.Err() != nil {
		closeIdle(conn)
		return nil, ctx.Err()
	}
	return conn, nil
}

/* Constructs a client from the given configuration parameters.
 * Returns nil and logs an error if any parameter is invalid. */
func NewClient(listen string, srvAddrs []string, clientPEM string, clientKEY string, serverPEM string, authMap map[string]util.Credentials) *client {
	clientPEM = filepath.Clean(clientPEM)
	clientKEY = filepath.Clean(clientKEY)
	serverPEM = filepath.Clean(serverPEM)

	listenAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		log.Printf("Failed to resolve listen address %s: %v", listen, err)
		return nil
	}

	/* Load client certificate for mTLS authentication. */
	cert, err := tls.LoadX509KeyPair(clientPEM, clientKEY)
	if err != nil {
		log.Printf("The client failed to load the certificate and key pair: %v", err)
		return nil
	}

	/* Load the server's CA certificate to verify the server's identity. */
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

	/* Build a base TLS config that is cloned once per upstream endpoint at
	 * construction time, avoiding a Clone() on every dial attempt. */
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
		addr, err := net.ResolveTCPAddr("tcp", srvAddr)
		if err != nil {
			log.Printf("Failed to resolve server address %s: %v", srvAddr, err)
			continue
		}
		host, _, splitErr := net.SplitHostPort(srvAddr)
		if splitErr != nil {
			log.Printf("Failed to parse server address %s: %v", srvAddr, splitErr)
			continue
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
			addr:      addr,
			addrStr:   addr.String(),
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

/* Tries the selected upstream first, then alternatives ordered by health and
 * score. Unknown and unavailable nodes remain eligible as a last resort. */
func (c *client) acquireServer(allowPool bool) (net.Conn, bool, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
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
	for _, index := range order {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		var conn net.Conn
		start := time.Now()
		conn, err = dialUpstream(ctx, c.upstreams[index])
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

func (c *client) enablePreconnect() {
	// Keep opaque SOCKS authentication passthrough for legacy configurations.
	if !c.negotiate {
		return
	}
	const poolSize = 4
	c.pool = newPreconnectPool(c.ctx, poolSize, &c.stableIndex, func(ctx context.Context, index int) (net.Conn, error) {
		return dialUpstream(ctx, c.upstreams[index])
	})
}

/* Accepts incoming TCP connections and dispatches each to handleConn.
 * Returns when a shutdown signal is received. */
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

	/* Setup graceful shutdown using atomic flag to avoid race condition. */
	var closing atomic.Bool
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		signal.Stop(sigChan)
		log.Println("Received shutdown signal, closing...")
		closing.Store(true)
		_ = listener.Close()
	}()

	const maxConnections = 1024
	sem := make(chan struct{}, maxConnections)

	for {
		userConn, err := listener.AcceptTCP()
		if err != nil {
			/* Check if we're shutting down. */
			if closing.Load() {
				return nil
			}
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		_ = userConn.SetKeepAlive(true)
		_ = userConn.SetKeepAlivePeriod(30 * time.Second)
		/* SetLinger(0) discards unacknowledged data on close for a fast reset. */
		_ = userConn.SetLinger(0)
		_ = userConn.SetNoDelay(true)
		_ = userConn.SetReadBuffer(128 * 1024)
		_ = userConn.SetWriteBuffer(128 * 1024)

		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				c.handleConn(userConn)
			}()
		default:
			log.Println("Connection limit reached, dropping connection")
			_ = userConn.Close()
		}
	}
}

/* Dials the upstream server and bidirectionally relays data
 * between userConn and the server connection. */
func (c *client) connectServer(userConn *net.TCPConn) {
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
		srvConn, err = c.connectPrepared(userConn)
	} else {
		srvConn, _, err = c.acquireServer(false)
	}
	if err != nil {
		log.Printf("Failed to get server connection: %v", err)
		return
	}

	/* SOCKS5 connections are stateful; once used a connection cannot be reused. */
	var srvCloseOnce sync.Once
	closeSrv := func() { srvCloseOnce.Do(func() { _ = srvConn.Close() }) }
	defer closeSrv()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		/* TLS -> TCP: Splice offers no benefit for TLS. */
		if err := c.TransferToTCP(srvConn, userConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}

		/* Signal the user that we are done sending. Also close the server
		 * connection: TLS has no half-close, so this is the only way to
		 * unblock the other goroutine if it is stalled mid-write to srvConn. */
		if cwErr := userConn.CloseWrite(); cwErr != nil {
			log.Printf("CloseWrite to user failed: %v", cwErr)
		}
		closeSrv()
	}()

	go func() {
		defer wg.Done()

		/* TCP -> TLS. */
		if err := c.TransferToTLS(userConn, srvConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}

		/* Unblock the TLS->TCP goroutine which is reading from srvConn. */
		closeSrv()
	}()

	wg.Wait()
}

/* Handles a single incoming SOCKS5 connection from a local user. */
func (c *client) handleConn(userConn *net.TCPConn) {
	defer userConn.Close()

	c.connectServer(userConn)
}

type Config struct {
	ServerAuth map[string]util.Credentials `json:"server_auth,omitempty"`
	ServerAddr []string                    `json:"server_addr"`
	ClientPEM  string                      `json:"client_pem"`
	ClientKey  string                      `json:"client_key"`
	ServerPEM  string                      `json:"server_pem"` /* Server CA cert for verifying the server identity. */
	ListenAddr string                      `json:"listen_addr"`
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

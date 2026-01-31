package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	util "github.com/leviathan0992/ss5"
)

/*
 * Pre-warmed connection pool configuration.
 *
 * This pool pre-creates TLS connections to reduce latency for incoming requests.
 * Note: SOCKS5 connections are stateful (one connection = one target), so connections
 * cannot be reused after handling a request. The pool's value is purely in pre-warming
 * TLS handshakes to save ~100-200ms per request.
 */
const (
	poolSize    = 16               /* Maximum number of pre-warmed connections */
	poolMinIdle = 4                /* Minimum connections to keep pre-warmed */
	idleTimeout = 60 * time.Second /* Discard pre-warmed connections older than this */
)

type pooledConn struct {
	conn      net.Conn
	createdAt time.Time
}

type connPool struct {
	mu       sync.Mutex
	conns    []*pooledConn
	dialFunc func() (net.Conn, error)
	closed   bool
	warmWg   sync.WaitGroup /* Tracks warm-up goroutines for graceful shutdown. */
}

func newConnPool(dialFunc func() (net.Conn, error)) *connPool {
	p := &connPool{
		conns:    make([]*pooledConn, 0, poolSize),
		dialFunc: dialFunc,
	}

	go p.maintain()
	go p.warmUp()

	return p
}

/* Pre-create connections to reduce TLS handshake latency for initial requests. */
func (p *connPool) warmUp() {
	for i := 0; i < poolMinIdle; i++ {
		p.warmWg.Add(1)
		go func() {
			defer p.warmWg.Done()
			p.addConnection()
		}()
	}
}

/* Add a single pre-warmed connection to the pool. */
func (p *connPool) addConnection() {
	conn, err := p.dialFunc()
	if err != nil {
		log.Printf("Failed to pre-warm connection: %v", err)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.closed && len(p.conns) < poolSize {
		p.conns = append(p.conns, &pooledConn{
			conn:      conn,
			createdAt: time.Now(),
		})
	} else {
		conn.Close()
	}
}

/* Periodically clean up stale connections and replenish the pool. */
func (p *connPool) maintain() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}

		/* Remove stale connections, keeping at least poolMinIdle. */
		now := time.Now()
		valid := make([]*pooledConn, 0, len(p.conns))
		for _, pc := range p.conns {
			if now.Sub(pc.createdAt) > idleTimeout && len(valid) >= poolMinIdle {
				pc.conn.Close()
			} else {
				valid = append(valid, pc)
			}
		}
		p.conns = valid
		deficit := poolMinIdle - len(p.conns)
		p.mu.Unlock()

		/* Replenish the pool if below minimum. */
		for i := 0; i < deficit; i++ {
			p.warmWg.Add(1)
			go func() {
				defer p.warmWg.Done()
				p.addConnection()
			}()
		}
	}
}

/* Get a pre-warmed connection from the pool, or create a new one if pool is empty. */
func (p *connPool) get() (net.Conn, error) {
	p.mu.Lock()

	/* Find a fresh connection while holding the lock. */
	for len(p.conns) > 0 {
		/* Pop from the end (LIFO - most recently added). */
		pc := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]

		/* Check if the connection is still fresh. */
		if time.Since(pc.createdAt) < idleTimeout {
			p.mu.Unlock()
			return pc.conn, nil
		}

		/* Connection is stale, close it and try next one. */
		pc.conn.Close()
	}

	/* Pool is empty, release lock before creating new connection. */
	p.mu.Unlock()

	/* Create a new connection outside the lock to avoid blocking other goroutines. */
	return p.dialFunc()
}

/* Close all connections and shut down the pool. */
func (p *connPool) close() {
	/* Wait for any in-progress warm-up connections to complete. */
	p.warmWg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	for _, pc := range p.conns {
		pc.conn.Close()
	}
	p.conns = nil
}

type client struct {
	*util.Service
	clientTLSConfig *tls.Config
	pool            *connPool
}

func NewClient(listen string, srvAdders []string, clientPEM string, clientKEY string) *client {
	listenAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		log.Printf("Failed to resolve listen address %s: %v", listen, err)
		return nil
	}

	var proxyAdders []*net.TCPAddr
	for _, srvAddr := range srvAdders {
		addr, err := net.ResolveTCPAddr("tcp", srvAddr)
		if err != nil {
			log.Printf("Failed to resolve server address %s: %v", srvAddr, err)
			continue
		}
		proxyAdders = append(proxyAdders, addr)
	}

	if len(proxyAdders) == 0 {
		log.Println("No valid server addresses provided")
		return nil
	}

	/* Load client certificate for mTLS authentication. */
	cert, err := tls.LoadX509KeyPair(clientPEM, clientKEY)
	if err != nil {
		log.Println("The client failed to load the certificate and key pair.")
		return nil
	}

	/*
	 * TLS configuration for connecting to the server.
	 * InsecureSkipVerify is used because we use self-signed certificates.
	 * Security is ensured by mTLS (server verifies client certificate).
	 */
	TLSconfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
	}

	c := &client{
		Service: &util.Service{
			ListenAddr:   listenAddr,
			ServerAdders: proxyAdders,
		},
		clientTLSConfig: TLSconfig,
	}

	/* Set the initial stable server. */
	c.SetStableServer(proxyAdders[0])

	/* Initialize the connection pool. */
	c.pool = newConnPool(func() (net.Conn, error) {
		return c.DialSrv(c.clientTLSConfig)
	})

	return c
}

func (c *client) Listen() error {
	for _, srv := range c.ServerAdders {
		log.Printf("The configured server address is %s:%d.", srv.IP, srv.Port)
	}

	stable := c.GetStableServer()
	log.Printf("Using the default server address: %s:%d.", stable.IP, stable.Port)

	listener, err := net.ListenTCP("tcp", c.ListenAddr)
	if err != nil {
		log.Printf("Failed to start the client listening on %s.", c.ListenAddr.String())
		return err
	}
	log.Printf("The client successfully started listening on %s.", c.ListenAddr.String())

	/* Setup graceful shutdown using atomic flag to avoid race condition. */
	var closing atomic.Bool
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, closing...")
		closing.Store(true)
		listener.Close()
		c.pool.close()
	}()

	for {
		userConn, err := listener.AcceptTCP()
		if err != nil {
			/* Check if we're shutting down. */
			if closing.Load() {
				return nil
			}
			log.Println(err)
			continue
		}

		_ = userConn.SetKeepAlive(true)
		_ = userConn.SetKeepAlivePeriod(30 * time.Second)

		/* Discard any unsent or unacknowledged data. */
		_ = userConn.SetLinger(0)
		_ = userConn.SetNoDelay(true)
		_ = userConn.SetReadBuffer(128 * 1024)
		_ = userConn.SetWriteBuffer(128 * 1024)

		go c.handleConn(userConn)
	}
}

func (c *client) connectServer(userConn *net.TCPConn) {
	srvConn, err := c.pool.get()
	if err != nil {
		log.Printf("Failed to get server connection: %v", err)
		return
	}

	/* SOCKS5 connections are stateful. Once used, we cannot reuse it for another request. */
	defer srvConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		/* TLS -> TCP: Standard transfer (Splice offers no benefit for TLS). */
		if err := c.TransferToTCP(srvConn, userConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}

		_ = userConn.CloseWrite()
	}()

	go func() {
		defer wg.Done()

		/* TCP -> TLS: Standard transfer. */
		if err := c.TransferToTLS(userConn, srvConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}
	}()

	wg.Wait()
}

func (c *client) handleConn(userConn *net.TCPConn) {
	defer userConn.Close()

	c.connectServer(userConn)
}

type Config struct {
	ServerAddr []string `json:"server_addr"`
	ClientPEM  string   `json:"client_pem"`
	ClientKey  string   `json:"client_key"`
	ListenAddr string   `json:"listen_addr"`
}

func main() {
	var confPath string
	flag.StringVar(&confPath, "c", ".ss5-client.json", "The client configuration file.")
	flag.Parse()

	bytes, err := os.ReadFile(confPath)
	if err != nil {
		log.Fatalf("The client failed to read the configuration file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("The client failed to parse the configuration file %s: %v", confPath, err)
	}

	c := NewClient(config.ListenAddr, config.ServerAddr, config.ClientPEM, config.ClientKey)
	if c == nil {
		log.Fatalf("Failed to create client")
	}

	_ = c.Listen()
}

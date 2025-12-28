package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"sync"
	"time"

	util "github.com/leviathan0992/ss5"
)

/* Connection pool configuration */
const (
	poolSize    = 16               /* Maximum number of idle connections in the pool */
	poolMinIdle = 4                /* Minimum idle connections to maintain */
	idleTimeout = 60 * time.Second /* Close idle connections after this duration */
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
}

func newConnPool(dialFunc func() (net.Conn, error)) *connPool {
	p := &connPool{
		conns:    make([]*pooledConn, 0, poolSize),
		dialFunc: dialFunc,
	}

	/* Start the pool maintenance goroutine. */
	go p.maintain()

	/* Pre-warm the pool with some connections. */
	go p.warmUp()

	return p
}

/* Pre-create some connections to reduce latency for initial requests. */
func (p *connPool) warmUp() {
	for i := 0; i < poolMinIdle; i++ {
		conn, err := p.dialFunc()
		if err != nil {
			log.Printf("Failed to pre-warm connection: %v", err)
			continue
		}

		p.mu.Lock()
		if !p.closed && len(p.conns) < poolSize {
			p.conns = append(p.conns, &pooledConn{
				conn:      conn,
				createdAt: time.Now(),
			})
		} else {
			conn.Close()
		}

		p.mu.Unlock()
	}
}

/* Periodically clean up stale connections and ensure minimum idle connections. */
func (p *connPool) maintain() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()

			return
		}

		now := time.Now()
		/* Remove stale connections. Keep at least poolMinIdle. */
		newConns := make([]*pooledConn, 0, len(p.conns))
		for _, pc := range p.conns {
			if now.Sub(pc.createdAt) > idleTimeout && len(newConns) >= poolMinIdle {
				pc.conn.Close()
			} else {
				newConns = append(newConns, pc)
			}
		}
		p.conns = newConns
		currentLen := len(p.conns)
		p.mu.Unlock()

		/* Replenish the pool if below minimum. */
		if currentLen < poolMinIdle {
			for i := currentLen; i < poolMinIdle; i++ {
				conn, err := p.dialFunc()
				if err != nil {
					continue
				}
				p.mu.Lock()
				if !p.closed && len(p.conns) < poolSize {
					p.conns = append(p.conns, &pooledConn{
						conn:      conn,
						createdAt: time.Now(),
					})
				} else {
					conn.Close()
				}

				p.mu.Unlock()
			}
		}
	}
}

/* Retrieve a connection from the pool or create a new one. */
func (p *connPool) get() (net.Conn, error) {
	p.mu.Lock()

	/* Try to get an existing connection. */
	for len(p.conns) > 0 {
		/* Pop from the end (LIFO). */
		pc := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		p.mu.Unlock()

		/* Check if the connection is still valid. */
		if time.Since(pc.createdAt) < idleTimeout {
			/* Quick health check to detect closed connection. */
			pc.conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
			buf := make([]byte, 1)
			_, err := pc.conn.Read(buf)
			pc.conn.SetReadDeadline(time.Time{})

			/* EOF or connection reset means the connection is dead. */
			if err != nil && err.Error() != "i/o timeout" && !isTimeoutError(err) {
				pc.conn.Close()
				p.mu.Lock()

				continue
			}

			return pc.conn, nil
		}

		pc.conn.Close()
		p.mu.Lock()
	}

	p.mu.Unlock()

	/* No valid connection in pool. Create a new one. */
	return p.dialFunc()
}

/* Return a connection to the pool if it is still usable. */
func (p *connPool) put(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed || len(p.conns) >= poolSize {
		conn.Close()
		return
	}

	p.conns = append(p.conns, &pooledConn{
		conn:      conn,
		createdAt: time.Now(),
	})
}

/* Close all connections in the pool. */
func (p *connPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	for _, pc := range p.conns {
		pc.conn.Close()
	}
	p.conns = nil
}

func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
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

	/* Try to read and parse the public/private key pairs from the file. */
	cert, err := tls.LoadX509KeyPair(clientPEM, clientKEY)
	if err != nil {
		log.Println("The client failed to read and parses the public/private key pairs from the file.")

		return nil
	}

	certBytes, err := os.ReadFile(clientPEM)
	if err != nil {
		log.Println("The client failed to read the client's PEM file.")

		return nil
	}

	clientCertPool := x509.NewCertPool()

	/* Try to attempt to parse the PEM encoded certificates. */
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		log.Println("The client failed to parse the PEM-encoded certificates.")

		return nil
	}

	TLSconfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		RootCAs:            clientCertPool,
		InsecureSkipVerify: false, /* Enable certificate verification to prevent MITM attacks. */
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
	}

	c := &client{
		Service: &util.Service{
			ListenAddr:   listenAddr,
			ServerAdders: proxyAdders,
			StableServer: proxyAdders[0],
		},
		clientTLSConfig: TLSconfig,
	}

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

	log.Printf("Using the default server address: %s:%d.", c.Service.StableServer.IP, c.Service.StableServer.Port)

	listener, err := net.ListenTCP("tcp", c.ListenAddr)
	if err != nil {
		log.Printf("Failed to start the client listening on %s.", c.ListenAddr.String())

		return err
	} else {
		log.Printf("The client successfully started listening on %s.", c.ListenAddr.String())
	}

	defer listener.Close()

	for {
		userConn, err := listener.AcceptTCP()
		if err != nil {
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

		/* TLS -> TCP: Use splice-optimized transfer. */
		if err := c.SpliceTransferToTCP(srvConn, userConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}

		_ = userConn.CloseWrite()
	}()

	go func() {
		defer wg.Done()

		/* TCP -> TLS: Use splice-optimized transfer. */
		if err := c.SpliceTransferToTLS(userConn, srvConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}
	}()

	wg.Wait()
}

func (c *client) handleConn(userConn *net.TCPConn) {
	defer userConn.Close()

	c.connectServer(userConn)
}

func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".ss5-client.json", "The client configuration file.")
	flag.Parse()

	bytes, err := os.ReadFile(conf)
	if err != nil {
		log.Fatalf("The client failed to read the configuration file.")
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("The client failed to parse the configuration file: %s .", conf)
	}

	var srvAdders []string
	srvAddr, ok := config["server_addr"].([]interface{})
	if !ok {
		log.Fatalf("Invalid server_addr in configuration file")
	}

	for _, ip := range srvAddr {
		if ipStr, ok := ip.(string); ok {
			srvAdders = append(srvAdders, ipStr)
		}
	}

	clientPEM, ok := config["client_pem"].(string)
	if !ok {
		log.Fatalf("Invalid client_pem in configuration file")
	}

	clientKEY, ok := config["client_key"].(string)
	if !ok {
		log.Fatalf("Invalid client_key in configuration file")
	}

	listenAddr, ok := config["listen_addr"].(string)
	if !ok {
		log.Fatalf("Invalid listen_addr in configuration file")
	}

	c := NewClient(listenAddr, srvAdders, clientPEM, clientKEY)
	if c == nil {
		log.Fatalf("Failed to create client")
	}

	_ = c.Listen()
}

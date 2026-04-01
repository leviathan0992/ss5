package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
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

type upstreamEndpoint struct {
	addr       *net.TCPAddr
	serverName string
	label      string
}

type client struct {
	*util.Service
	clientTLSConfig *tls.Config
	upstreams       []upstreamEndpoint
	stableIndex     atomic.Uint32
}

func NewClient(listen string, srvAddrs []string, clientPEM string, clientKEY string, serverPEM string) *client {
	listenAddr, err := net.ResolveTCPAddr("tcp", listen)
	if err != nil {
		log.Printf("Failed to resolve listen address %s: %v", listen, err)
		return nil
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
		upstreams = append(upstreams, upstreamEndpoint{
			addr:       addr,
			serverName: host,
			label:      srvAddr,
		})
	}

	if len(upstreams) == 0 {
		log.Println("No valid server addresses provided")
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

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		RootCAs:            serverCertPool,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
	}

	return &client{
		Service: &util.Service{
			ListenAddr: listenAddr,
		},
		clientTLSConfig: tlsConfig,
		upstreams:       upstreams,
	}
}

func (c *client) dialServer() (net.Conn, error) {
	dial := func(upstream upstreamEndpoint) (net.Conn, error) {
		tlsConf := c.clientTLSConfig.Clone()
		tlsConf.ServerName = upstream.serverName
		d := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return tls.DialWithDialer(d, "tcp", upstream.addr.String(), tlsConf)
	}

	stableIdx := int(c.stableIndex.Load())
	if stableIdx >= len(c.upstreams) {
		stableIdx = 0
	}
	stable := c.upstreams[stableIdx]
	srvConn, err := dial(stable)
	if err == nil {
		log.Printf("Connected to server %s", stable.label)
		return srvConn, nil
	}

	log.Printf("Failed to connect to server %s: %s", stable.label, err)
	for i, srv := range c.upstreams {
		if i == stableIdx {
			continue
		}
		log.Printf("Trying alternate server: %s", srv.label)
		srvConn, err = dial(srv)
		if err == nil {
			c.stableIndex.Store(uint32(i))
			return srvConn, nil
		}
	}

	return nil, fmt.Errorf("all %d upstream(s) failed; last error: %w", len(c.upstreams), err)
}

func (c *client) Listen() error {
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
	srvConn, err := c.dialServer()
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

		/* Signal the user that we are done sending, then unblock
		 * the other goroutine which is reading from the server. */
		_ = userConn.CloseWrite()
		srvConn.Close()
	}()

	go func() {
		defer wg.Done()

		/* TCP -> TLS: Standard transfer. */
		if err := c.TransferToTLS(userConn, srvConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}

		/* Unblock the other goroutine which is reading from srvConn. */
		_ = userConn.CloseRead()
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
	ServerPEM  string   `json:"server_pem"` /* Server CA cert for TLS verification. */
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

	c := NewClient(config.ListenAddr, config.ServerAddr, config.ClientPEM, config.ClientKey, config.ServerPEM)
	if c == nil {
		log.Fatalf("Failed to create client")
	}

	_ = c.Listen()
}

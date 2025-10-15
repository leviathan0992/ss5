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

type client struct {
	*util.Service
	clientTLSConfig *tls.Config
}

func NewClient(listen string, srvAdders []string, clientPEM string, clientKEY string) *client {
	listenAddr, _ := net.ResolveTCPAddr("tcp", listen)

	var proxyAdders []*net.TCPAddr
	for _, srvAddr := range srvAdders {
		addr, _ := net.ResolveTCPAddr("tcp", srvAddr)
		proxyAdders = append(proxyAdders, addr)
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
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
	}

	return &client{
		&util.Service{
			ListenAddr:   listenAddr,
			ServerAdders: proxyAdders,
			StableServer: proxyAdders[0],
		},
		TLSconfig,
	}
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

var (
	srvPool    = make(chan net.Conn, 32)
	poolClosed bool
	poolMutex  sync.Mutex
)

func init() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			poolMutex.Lock()
			if poolClosed {
				poolMutex.Unlock()
				return
			}
			poolMutex.Unlock()

			for len(srvPool) > 8 {
				select {
				case conn := <-srvPool:
					_ = conn.Close()
				default:
					return
				}
			}
		}
	}()
}

func (c *client) getConn() (net.Conn, error) {
	select {
	case conn := <-srvPool:
		return conn, nil
	default:
		return c.DialSrv(c.clientTLSConfig)
	}
}



func (c *client) connectServer(userConn *net.TCPConn) {
	srvConn, err := c.getConn()
	if err != nil {
		log.Printf("Failed to get server connection: %v", err)
		return
	}

	defer srvConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		if err := c.TransferToTCP(srvConn, userConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}

		_ = userConn.CloseWrite()
	}()

	go func() {
		defer wg.Done()

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
	srvAddr, _ := config["server_addr"].([]interface{})

	for _, ip := range srvAddr {
		srvAdders = append(srvAdders, ip.(string))
	}

	clientPEM := config["client_pem"].(string)
	clientKEY := config["client_key"].(string)

	c := NewClient(config["listen_addr"].(string), srvAdders, clientPEM, clientKEY)

	_ = c.Listen()
}

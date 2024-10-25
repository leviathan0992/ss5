package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"time"

	util "github.com/Mesaukee/ss5"
)

type client struct {
	*util.Service
	conf *tls.Config
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

	config := &tls.Config{
		RootCAs:            clientCertPool,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	return &client{
		&util.Service{
			ListenAddr:   listenAddr,
			ServerAdders: proxyAdders,
			StableServer: proxyAdders[0],
		},
		config,
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

		/* Discard any unsent or unacknowledged data. */
		_ = userConn.SetLinger(0)

		go c.handleConn(userConn)
	}
}

var srvPool = make(chan net.Conn, 32)

func init() {
	go func() {
		for range time.Tick(5 * time.Second) {
			/* Discard the idle connection. */
			p := <-srvPool
			_ = p.Close()
		}
	}()
}

func (c *client) newSrvConn() (net.Conn, error) {
	if len(srvPool) < 32 {
		go func() {
			for i := len(srvPool); i < 32; i++ {
				proxy, err := c.DialSrv(c.conf)

				if err != nil {
					log.Println("The client failed to connect to the target server.")
					return
				}

				srvPool <- proxy
			}
		}()
	}

	select {
	case pc := <-srvPool:
		return pc, nil
	default:
		return c.DialSrv(c.conf)
	}
}

func (c *client) connectServer(userConn *net.TCPConn) {
	proxy, err := c.newSrvConn()

	if err != nil {
		log.Println(err)

		proxy, err = c.newSrvConn()
		if err != nil {
			log.Println(err)

			return
		}

		return
	}

	defer proxy.Close()

	go func() {
		/* Using TCP connection between server and client. */
		errTransfer := c.TransferToTCP(proxy, userConn)

		if errTransfer != nil {
			_ = userConn.Close()
			_ = proxy.Close()
		}
	}()

	/* Using TLS connection directly between client and server. */
	_ = c.TransferToTLS(userConn, proxy)
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

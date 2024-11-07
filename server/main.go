package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"sync"

	util "github.com/leviathan0992/ss5"
)

type server struct {
	*util.Service
	serverPEM string
	serverKEY string
	clientPEM string
}

func NewServer(listenAddr string, serverPEM string, serverKEY string, clientPEM string) *server {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", listenAddr)

	return &server{
		&util.Service{
			ListenAddr: tcpAddr,
		},
		serverPEM,
		serverKEY,
		clientPEM,
	}
}

func (s *server) ListenTLS() error {
	log.Printf("The server's listening address is %s.", s.ListenAddr.String())

	/* Try to read and parse public/private key pairs from the file. */
	cert, err := tls.LoadX509KeyPair(s.serverPEM, s.serverKEY)
	if err != nil {
		log.Println("The server failed to read and parses public/private key pairs from the file.")

		return err
	}

	certBytes, err := os.ReadFile(s.clientPEM)
	if err != nil {
		log.Println("The server failed to read the client's PEM file.")

		return err
	}

	clientCertPool := x509.NewCertPool()
	/* Try to attempt to parse the PEM encoded certificates. */
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		return errors.New("The server failed to parse the PEM-encoded certificates.")
	}

	serverTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS10,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}

	listener, err := tls.Listen("tcp", s.ListenAddr.String(), serverTLSConfig)
	if err != nil {
		log.Printf("Failed to start the server listening on %s.", s.ListenAddr.String())

		return err
	} else {
		log.Printf("The server successfully started listening on %s.", s.ListenAddr.String())
	}

	defer listener.Close()

	for {
		cliConn, err := listener.Accept()
		if err != nil {
			continue
		}

		go s.handleTLSConn(cliConn)
	}
}

func (s *server) handleTLSConn(cliConn net.Conn) {
	defer cliConn.Close()

	/* Parsing the SOCKS5 over TLS connection. */
	dstAddr, err := s.ParseSOCKS5FromTLS(cliConn)
	if err != nil {
		log.Printf("The server failed to parse the SOCKS5 protocol: %s.", err.Error())

		return
	}

	/* Attempting to connect to the destination address. */
	dstConn, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		log.Printf("The server failed to connect to the destination address %s.", dstAddr.String())

		return
	}
	defer dstConn.Close()
	log.Printf("The server connects to the destination address %s successful.", dstAddr.String())

	_ = dstConn.SetKeepAlive(true)

	/* Discard any unsent or unacknowledged data. */
	_ = dstConn.SetLinger(0)

	/* Disable Nagle algorithm to reduce latency. */
	_ = dstConn.SetNoDelay(true)

	/* Connection to the destination address successful, responding to the client. */
	errWrite := s.TLSWrite(cliConn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if errWrite != nil {
		log.Println("The server successfully connected to the destination address, but failed to respond to the client.")

		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()

		if err := s.TransferToTCP(cliConn, dstConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}

		_ = dstConn.CloseWrite()
	}()

	go func() {
		defer wg.Done()

		if err := s.TransferToTLS(dstConn, cliConn); err != nil {
			log.Printf("The connection closed: %v", err)
		}
	}()

	wg.Wait()
}

func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".ss5-server.json", "The server configuration file.")
	flag.Parse()

	bytes, err := os.ReadFile(conf)
	if err != nil {
		log.Fatalf("The server failed to read the configuration file.")
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("The server failed to parse the configuration file: %s .", conf)
	}

	serverPEM := config["server_pem"].(string)
	serverKEY := config["server_key"].(string)
	clientPEM := config["client_pem"].(string)

	s := NewServer(config["listen_addr"].(string), serverPEM, serverKEY, clientPEM)

	s.ListenTLS()
}

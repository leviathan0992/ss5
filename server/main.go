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

	util "github.com/Mesaukee/ss5"
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
	log.Printf("The server's listening address is %s", s.ListenAddr.String())

	/* Try to read and parses a public/private key pair from a pair of files. */
	cert, err := tls.LoadX509KeyPair(s.serverPEM, s.serverKEY)
	if err != nil {
		log.Println("Failed to read and parses public/private key pair from a pair of files")

		return err
	}

	certBytes, err := os.ReadFile(s.clientPEM)
	if err != nil {
		log.Println("Failed to read the client's PEM file")

		return err
	}

	clientCertPool := x509.NewCertPool()
	/* Try to attempt to parse a series of PEM encoded certificates. */
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		return errors.New("failed to parse a series of PEM encoded certificates")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}

	listener, err := tls.Listen("tcp", s.ListenAddr.String(), config)
	if err != nil {
		log.Printf("Failed to start server listening on %s", s.ListenAddr.String())

		return err
	} else {
		log.Printf("The server successfully started listening on %s", s.ListenAddr.String())
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
	/* Parsing SOCKS5 over TLS connection. */
	dstAddr, err := s.ParseSOCKS5FromTLS(cliConn)
	if err != nil {
		_ = cliConn.Close()

		log.Printf("Failed to parse SOCKS5 protocol: %s.", err.Error())

		return
	}

	/* Attempting to connect to the target address. */
	dstConn, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		_ = cliConn.Close()
		log.Printf("Failed to connect to the destination address %s.", dstAddr.String())

		return
	} else {
		log.Printf("Connection to the destination address %s successful.", dstAddr.String())
	}

	_ = dstConn.SetLinger(0)

	/* Connection to the target address successful, responding to the client. */
	errWrite := s.TLSWrite(cliConn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if errWrite != nil {
		_ = cliConn.Close()
		_ = dstConn.Close()

		log.Println("Server successfully connected to the target address, but failed to respond to the client")

		return
	}

	/* Using TCP connection between server and target address. */
	go func() {
		errTransfer := s.TransferToTCP(cliConn, dstConn)
		if errTransfer != nil {
			_ = cliConn.Close()
			_ = dstConn.Close()
		}
	}()

	/* Using TLS connection directly between client and server. */
	_ = s.TransferToTLS(dstConn, cliConn)
}

func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".ss5-server.json", "The server configuration file")
	flag.Parse()

	bytes, err := os.ReadFile(conf)
	if err != nil {
		log.Fatalf("Failed to read file [%s]", conf)
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("Failed to parse configuration file [%s]", conf)
	}

	serverPEM := config["server_pem"].(string)
	serverKEY := config["server_key"].(string)
	clientPEM := config["client_pem"].(string)

	s := NewServer(config["listen_addr"].(string), serverPEM, serverKEY, clientPEM)

	s.ListenTLS()
}

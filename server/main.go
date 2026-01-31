package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	util "github.com/leviathan0992/ss5"
)

type server struct {
	*util.Service
	serverPEM string
	serverKEY string
	clientPEM string
}

/* Encodes a SOCKS5 UDP reply header and payload into buf for dst. */
func buildUDPResponse(dst *net.UDPAddr, payload []byte, buf []byte) (int, bool) {
	/* Ensuring the buffer can hold the fixed 3-byte reserved header. */
	if len(buf) < 3 {
		return 0, false
	}

	/* RSV (2 bytes) and FRAG (1 byte) must be zeroed for SOCKS5 UDP replies. */
	buf[0], buf[1], buf[2] = 0x00, 0x00, 0x00

	offset := 3

	if ip4 := dst.IP.To4(); ip4 != nil {
		/* Verifying the buffer can hold the IPv4 address, port, and payload. */
		if len(buf) < offset+1+len(ip4)+2+len(payload) {
			return 0, false
		}

		buf[offset] = util.AtypIPv4 /* IPv4 address type. */
		offset++
		copy(buf[offset:], ip4)
		offset += len(ip4)

	} else {
		ip6 := dst.IP.To16()
		if ip6 == nil {
			return 0, false
		}

		/* Verifying the buffer can hold the IPv6 address, port, and payload. */
		if len(buf) < offset+1+len(ip6)+2+len(payload) {
			return 0, false
		}

		buf[offset] = util.AtypIPv6 /* IPv6 address type. */
		offset++
		copy(buf[offset:], ip6)
		offset += len(ip6)
	}

	/* Appending the destination port in network byte order. */
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(dst.Port))
	offset += 2

	/* Copying the payload after the SOCKS5 UDP header. */
	copy(buf[offset:], payload)
	offset += len(payload)

	return offset, true
}

func NewServer(listenAddr string, serverPEM string, serverKEY string, clientPEM string) *server {
	tcpAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		log.Printf("Failed to resolve listen address %s: %v", listenAddr, err)
		return nil
	}

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
		MinVersion:             tls.VersionTLS12,
		Certificates:           []tls.Certificate{cert},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientCertPool,
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(128),
	}

	listener, err := tls.Listen("tcp", s.ListenAddr.String(), serverTLSConfig)
	if err != nil {
		log.Printf("Failed to start the server listening on %s.", s.ListenAddr.String())
		return err
	}
	log.Printf("The server successfully started listening on %s.", s.ListenAddr.String())

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
		cliConn, err := listener.Accept()
		if err != nil {
			/* Check if we're shutting down. */
			if closing.Load() {
				return nil
			}
			continue
		}

		go s.handleTLSConn(cliConn)
	}
}

func (s *server) handleTLSConn(cliConn net.Conn) {
	defer cliConn.Close()

	/* Parsing the SOCKS5 over TLS connection. */
	addr, cmd, err := s.ParseSOCKS5FromTLS(cliConn)
	if err != nil {
		log.Printf("The server failed to parse the SOCKS5 protocol: %s.", err.Error())

		return
	}

	switch cmd {
	case util.CmdConnect:
		/* The CONNECT command. */
		dstAddr := addr.(*net.TCPAddr)

		/* Attempting to connect to the destination address. */
		dstConn, err := net.DialTCP("tcp", nil, dstAddr)
		if err != nil {
			log.Printf("The server failed to connect to the destination address %s.", dstAddr.String())

			return
		}
		defer dstConn.Close()
		log.Printf("The server connects to the destination address %s successful.", dstAddr.String())

		_ = dstConn.SetKeepAlive(true)
		_ = dstConn.SetKeepAlivePeriod(30 * time.Second)
		_ = dstConn.SetLinger(0)
		_ = dstConn.SetNoDelay(true)
		_ = dstConn.SetReadBuffer(128 * 1024)
		_ = dstConn.SetWriteBuffer(128 * 1024)

		/* Connection to the destination address successful, responding to the client. */
		var resp []byte
		if ip4 := dstAddr.IP.To4(); ip4 != nil {
			/* IPv4. */
			resp = []byte{util.SocksVersion, 0x00, 0x00, util.AtypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		} else {
			/* IPv6. */
			resp = []byte{util.SocksVersion, 0x00, 0x00, util.AtypIPv6}
			resp = append(resp, make([]byte, 16)...)
			resp = append(resp, 0x00, 0x00)
		}

		errWrite := s.TLSWrite(cliConn, resp)
		if errWrite != nil {
			log.Println("The server successfully connected to the destination address, but failed to respond to the client.")

			return
		}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()

			/* TLS -> TCP: Standard transfer (Splice offers no benefit for TLS). */
			if err := s.TransferToTCP(cliConn, dstConn); err != nil {
				log.Printf("The connection closed: %v", err)
			}

			_ = dstConn.CloseWrite()
		}()

		go func() {
			defer wg.Done()

			/* TCP -> TLS: Standard transfer. */
			if err := s.TransferToTLS(dstConn, cliConn); err != nil {
				log.Printf("The connection closed: %v", err)
			}
		}()

		wg.Wait()

		return

	case util.CmdUDPAssociate:
		/* The UDP ASSOCIATE command. */
		s.handleUDPAssociate(cliConn)

		return
	}
}

func (s *server) handleUDPAssociate(cliConn net.Conn) {
	/* Start listening for UDP connections. */
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Println("The server failed to listen on UDP.")
		return
	}
	defer udpConn.Close()

	/* Preparing the response address for the client. */
	udpAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip := udpAddr.IP.To4()
	addressType := byte(util.AtypIPv4) /* IPv4. */
	if ip == nil {
		ip = udpAddr.IP
		addressType = util.AtypIPv6 /* IPv6. */
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(udpAddr.Port))

	resp := []byte{util.SocksVersion, 0x00, 0x00, addressType}
	resp = append(resp, ip...)
	resp = append(resp, port...)

	errWrite := s.TLSWrite(cliConn, resp)
	if errWrite != nil {
		log.Println("The server failed to respond to the client after the UDP associate.")
		return
	}

	/*
	 * RFC 1928: The UDP association terminates when the TCP connection that
	 * the UDP ASSOCIATE request arrived on terminates.
	 * Monitor the TCP control connection and close UDP when it drops.
	 */
	go func() {
		buf := make([]byte, 1)
		/* Set deadline to prevent goroutine leak if connection never closes. */
		_ = cliConn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		/* This Read will return error when TCP connection closes or deadline exceeded. */
		_, _ = cliConn.Read(buf)
		udpConn.Close()
	}()

	/* Use a semaphore to limit concurrent UDP handlers. */
	const maxConcurrentUDP = 64
	sem := make(chan struct{}, maxConcurrentUDP)
	var wg sync.WaitGroup

	for {
		buf := util.GetUDPBuffer()

		/* Forwarding UDP packets. */
		n, srcAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			util.PutUDPBuffer(buf)
			/* Wait for all ongoing handlers to finish before returning. */
			wg.Wait()
			return
		}

		/* The minimal packet length: 3 bytes RSV/FRAG, 1 byte ATYP, 4 bytes IPv4, 2 bytes port. */
		if n < (3 + 1 + 4 + 2) {
			util.PutUDPBuffer(buf)
			continue
		}

		if buf[2] != 0x00 {
			/* Fragmentation is unsupported. */
			util.PutUDPBuffer(buf)
			continue
		}

		/* Handle UDP packet concurrently. */
		sem <- struct{}{}
		wg.Add(1)
		go func(buf []byte, n int, srcAddr *net.UDPAddr) {
			defer func() {
				<-sem
				wg.Done()
			}()
			defer util.PutUDPBuffer(buf)
			s.handleUDPPacket(udpConn, buf, n, srcAddr)
		}(buf, n, srcAddr)
	}
}

/* handleUDPPacket processes a single UDP packet. */
func (s *server) handleUDPPacket(udpConn *net.UDPConn, buf []byte, n int, srcAddr *net.UDPAddr) {
	addressType := buf[3]
	var dstAddr *net.UDPAddr
	var headerLen int

	if addressType == util.AtypIPv4 { /* IPv4. */
		if n < 10 {
			return
		}

		ip := make(net.IP, net.IPv4len)
		copy(ip, buf[4:4+net.IPv4len])
		port := int(binary.BigEndian.Uint16(buf[8:10]))

		dstAddr = &net.UDPAddr{IP: ip, Port: port}
		headerLen = 10
	} else if addressType == util.AtypDomain { /* The domain name. */
		hostLen := int(buf[4])
		if 5+hostLen+2 > n {
			return
		}

		host := string(buf[5 : 5+hostLen])
		port := int(binary.BigEndian.Uint16(buf[5+hostLen : 5+hostLen+2]))

		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil || addr == nil || addr.IP == nil {
			return
		}

		dstAddr = addr
		headerLen = 5 + hostLen + 2
	} else if addressType == util.AtypIPv6 { /* IPv6. */
		if n < 22 {
			return
		}

		ip := make(net.IP, net.IPv6len)
		copy(ip, buf[4:4+net.IPv6len])
		port := int(binary.BigEndian.Uint16(buf[20:22]))

		dstAddr = &net.UDPAddr{IP: ip, Port: port}
		headerLen = 22
	} else { /* Unknown address type. */
		return
	}

	payload := buf[headerLen:n]

	if dstAddr == nil {
		return
	}

	dstConn, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		return
	}
	defer dstConn.Close()

	if _, err := dstConn.Write(payload); err != nil {
		return
	}

	_ = dstConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	respBuf := util.GetUDPBuffer()
	defer util.PutUDPBuffer(respBuf)

	nRead, err := dstConn.Read(respBuf)
	if err != nil {
		return
	}

	packetBuf := util.GetUDPBuffer()
	defer util.PutUDPBuffer(packetBuf)

	total, ok := buildUDPResponse(dstAddr, respBuf[:nRead], packetBuf)
	if !ok {
		return
	}

	_, _ = udpConn.WriteToUDP(packetBuf[:total], srcAddr)
}

type Config struct {
	ServerPEM  string `json:"server_pem"`
	ServerKey  string `json:"server_key"`
	ClientPEM  string `json:"client_pem"`
	ListenAddr string `json:"listen_addr"`
}

func main() {
	var confPath string
	flag.StringVar(&confPath, "c", ".ss5-server.json", "The server configuration file.")
	flag.Parse()

	bytes, err := os.ReadFile(confPath)
	if err != nil {
		log.Fatalf("The server failed to read the configuration file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("The server failed to parse the configuration file %s: %v", confPath, err)
	}

	s := NewServer(config.ListenAddr, config.ServerPEM, config.ServerKey, config.ClientPEM)
	if s == nil {
		log.Fatalf("Failed to create server")
	}

	s.ListenTLS()
}

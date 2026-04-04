package main

import (
	"context"
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	util "github.com/leviathan0992/ss5"
)

type server struct {
	*util.Service
	publicIP  net.IP
	serverPEM string
	serverKEY string
	clientPEM string
}

type udpAssociation struct {
	clientConn *net.UDPConn
	clientAddr *net.UDPAddr

	mu     sync.Mutex
	closed bool
	relays map[string]*udpRelay
	wg     sync.WaitGroup
}

type udpRelay struct {
	assoc     *udpAssociation
	key       string
	target    *net.UDPAddr
	conn      *net.UDPConn
	closeOnce sync.Once
}

const udpAssociationIdleTimeout = 5 * time.Minute

/* Encodes a SOCKS5 UDP reply header and payload into buf for dst. */
func buildUDPResponse(dst *net.UDPAddr, payload []byte, buf []byte) (int, bool) {
	if dst == nil || dst.IP == nil {
		return 0, false
	}
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

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	clone := &net.UDPAddr{Port: addr.Port, Zone: addr.Zone}
	if addr.IP != nil {
		clone.IP = append(net.IP(nil), addr.IP...)
	}
	return clone
}

func udpWildcardAddrFor(ip net.IP) *net.UDPAddr {
	if ip != nil && ip.To4() == nil && ip.To16() != nil {
		return &net.UDPAddr{IP: append(net.IP(nil), net.IPv6zero...), Port: 0}
	}
	return &net.UDPAddr{IP: append(net.IP(nil), net.IPv4zero...), Port: 0}
}

func udpPublicAddrFor(localIP net.IP, port int) *net.UDPAddr {
	addr := &net.UDPAddr{Port: port}
	if localIP != nil {
		addr.IP = append(net.IP(nil), localIP...)
	}
	return addr
}

func newUDPAssociation(clientConn *net.UDPConn, clientAddr *net.UDPAddr) *udpAssociation {
	if clientConn == nil || clientAddr == nil {
		return nil
	}
	return &udpAssociation{
		clientConn: clientConn,
		clientAddr: cloneUDPAddr(clientAddr),
		relays:     make(map[string]*udpRelay),
	}
}

func (a *udpAssociation) relayFor(dst *net.UDPAddr) (*udpRelay, error) {
	if a == nil {
		return nil, errors.New("nil udp association")
	}
	if dst == nil {
		return nil, errors.New("nil relay target address")
	}
	key := dst.String()

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, errors.New("udp association closed")
	}
	if relay, ok := a.relays[key]; ok {
		a.mu.Unlock()
		return relay, nil
	}
	a.mu.Unlock()

	/* Dial outside the lock: for UDP this is a non-blocking syscall, but we
	 * still avoid holding a mutex during any I/O operation. */
	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return nil, err
	}

	relay := &udpRelay{
		assoc:  a,
		key:    key,
		target: cloneUDPAddr(dst),
		conn:   conn,
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		conn.Close()
		return nil, errors.New("udp association closed")
	}
	if existing, ok := a.relays[key]; ok {
		/* Another goroutine raced and created a relay for this target first. */
		a.mu.Unlock()
		conn.Close()
		return existing, nil
	}
	a.relays[key] = relay
	a.wg.Add(1)
	a.mu.Unlock()

	go relay.readLoop()
	return relay, nil
}

func (a *udpAssociation) removeRelay(key string, relay *udpRelay) {
	if a == nil {
		return
	}
	a.mu.Lock()
	if current, ok := a.relays[key]; ok && current == relay {
		delete(a.relays, key)
	}
	a.mu.Unlock()
}

func (a *udpAssociation) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.closed = true
	relays := make([]*udpRelay, 0, len(a.relays))
	for _, relay := range a.relays {
		relays = append(relays, relay)
	}
	a.relays = make(map[string]*udpRelay)
	a.mu.Unlock()

	for _, relay := range relays {
		relay.close()
	}
	a.wg.Wait()
}

func (r *udpRelay) close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		if r.conn != nil {
			_ = r.conn.Close()
		}
	})
}

func (r *udpRelay) readLoop() {
	if r.assoc == nil {
		return
	}
	defer r.assoc.wg.Done()
	respBuf := util.GetUDPBuffer()
	defer util.PutUDPBuffer(respBuf)
	packetBuf := util.GetUDPBuffer()
	defer util.PutUDPBuffer(packetBuf)

	for {
		_ = r.conn.SetReadDeadline(time.Now().Add(udpAssociationIdleTimeout))
		nRead, err := r.conn.Read(respBuf)
		if err != nil {
			r.assoc.removeRelay(r.key, r)
			r.close()
			return
		}

		total, ok := buildUDPResponse(r.target, respBuf[:nRead], packetBuf)
		if !ok {
			continue
		}

		if _, err := r.assoc.clientConn.WriteToUDP(packetBuf[:total], r.assoc.clientAddr); err != nil {
			r.assoc.removeRelay(r.key, r)
			r.close()
			return
		}
	}
}

func resolvePublicIP(publicAddr string) (net.IP, error) {
	value := strings.TrimSpace(publicAddr)
	if value == "" {
		return nil, nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.TrimSpace(host)
	}
	if value == "" {
		return nil, nil
	}
	if ip := net.ParseIP(value); ip != nil {
		return append(net.IP(nil), ip...), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, value)
	if err != nil {
		return nil, err
	}
	for _, ipAddr := range resolved {
		if ipAddr.IP != nil {
			return append(net.IP(nil), ipAddr.IP...), nil
		}
	}
	return nil, errors.New("no ip address found")
}

func NewServer(listenAddr string, publicAddr string, serverPEM string, serverKEY string, clientPEM string) *server {
	tcpAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		log.Printf("Failed to resolve listen address %s: %v", listenAddr, err)
		return nil
	}
	publicIP, err := resolvePublicIP(publicAddr)
	if err != nil {
		log.Printf("Failed to resolve public address %s: %v", publicAddr, err)
		return nil
	}

	return &server{
		Service: &util.Service{
			ListenAddr: tcpAddr,
		},
		publicIP:  publicIP,
		serverPEM: serverPEM,
		serverKEY: serverKEY,
		clientPEM: clientPEM,
	}
}

func (s *server) ListenTLS() error {
	log.Printf("The server's listening address is %s.", s.ListenAddr.String())
	if s.publicIP != nil {
		log.Printf("The server's public UDP address is %s.", s.publicIP.String())
	}

	/* Load TLS certificate and private key. */
	cert, err := tls.LoadX509KeyPair(s.serverPEM, s.serverKEY)
	if err != nil {
		log.Printf("The server failed to load the TLS key pair: %v", err)
		return err
	}

	certBytes, err := os.ReadFile(s.clientPEM)
	if err != nil {
		log.Printf("The server failed to read the client's PEM file: %v", err)
		return err
	}

	clientCertPool := x509.NewCertPool()
	/* Attempt to parse the PEM encoded certificates. */
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		return errors.New("failed to parse PEM-encoded client certificates")
	}

	serverTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}

	listener, err := tls.Listen("tcp", s.ListenAddr.String(), serverTLSConfig)
	if err != nil {
		log.Printf("Failed to start the server listening on %s: %v", s.ListenAddr.String(), err)
		return err
	}
	log.Printf("The server successfully started listening on %s.", s.ListenAddr.String())

	/* Setup graceful shutdown using atomic flag to avoid race condition. */
	var closing atomic.Bool
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		signal.Stop(sigChan)
		log.Println("Received shutdown signal, closing...")
		closing.Store(true)
		listener.Close()
	}()

	const maxConnections = 4096
	connSem := make(chan struct{}, maxConnections)

	for {
		cliConn, err := listener.Accept()
		if err != nil {
			/* Check if we're shutting down. */
			if closing.Load() {
				return nil
			}
			log.Printf("Failed to accept TLS connection: %v", err)
			continue
		}

		select {
		case connSem <- struct{}{}:
			go func() {
				defer func() { <-connSem }()
				s.handleTLSConn(cliConn)
			}()
		default:
			log.Println("Connection limit reached, dropping connection")
			cliConn.Close()
		}
	}
}

/* Maps a dial error to the appropriate SOCKS5 reply code per RFC 1928. */
func dialErrToSOCKS5Code(err error) byte {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return 0x05 /* connection refused */
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EADDRNOTAVAIL) {
		return 0x03 /* network unreachable */
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EHOSTDOWN) || errors.Is(err, syscall.ETIMEDOUT) {
		return 0x04 /* host unreachable */
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return 0x04 /* host unreachable (timeout) */
	}
	return 0x01 /* general SOCKS server failure */
}

func (s *server) handleTLSConn(cliConn net.Conn) {
	defer cliConn.Close()

	/* Parsing the SOCKS5 over TLS connection. */
	_ = cliConn.SetDeadline(time.Now().Add(30 * time.Second))
	addr, cmd, err := s.ParseSOCKS5FromTLS(cliConn)
	if err != nil {
		log.Printf("The server failed to parse the SOCKS5 protocol: %v", err)
		return
	}
	_ = cliConn.SetDeadline(time.Time{})

	switch cmd {
	case util.CmdConnect:
		/* The CONNECT command. */
		targetAddr := addr.String()

		/* Attempting to connect to the destination address with a 30s timeout. */
		d := &net.Dialer{Timeout: 30 * time.Second}
		dstConn, err := d.Dial("tcp", targetAddr)
		if err != nil {
			log.Printf("The server failed to connect to the destination address %s: %v", targetAddr, err)
			util.SendSOCKS5Reply(cliConn, dialErrToSOCKS5Code(err))
			return
		}
		tcpDst, ok := dstConn.(*net.TCPConn)
		if !ok {
			dstConn.Close()
			util.SendSOCKS5Reply(cliConn, 0x01) /* 0x01 = general SOCKS server failure */
			return
		}
		defer tcpDst.Close()
		log.Printf("The server connected to the destination address %s successfully.", targetAddr)

		_ = tcpDst.SetKeepAlive(true)
		_ = tcpDst.SetKeepAlivePeriod(30 * time.Second)
		_ = tcpDst.SetLinger(0)
		_ = tcpDst.SetNoDelay(true)
		_ = tcpDst.SetReadBuffer(128 * 1024)
		_ = tcpDst.SetWriteBuffer(128 * 1024)

		/* Connection to the destination address successful, responding to the client. */
		boundAddr, ok := tcpDst.LocalAddr().(*net.TCPAddr)
		if !ok {
			util.SendSOCKS5Reply(cliConn, 0x01)
			return
		}
		var resp []byte
		if ip4 := boundAddr.IP.To4(); ip4 != nil {
			/* IPv4. */
			resp = []byte{util.SocksVersion, 0x00, 0x00, util.AtypIPv4}
			resp = append(resp, ip4...)
		} else {
			/* IPv6. */
			ip6 := boundAddr.IP.To16()
			if ip6 == nil {
				util.SendSOCKS5Reply(cliConn, 0x01)
				return
			}
			resp = []byte{util.SocksVersion, 0x00, 0x00, util.AtypIPv6}
			resp = append(resp, ip6...)
		}
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], uint16(boundAddr.Port))
		resp = append(resp, port[:]...)

		errWrite := util.WriteAll(cliConn, resp)
		if errWrite != nil {
			log.Printf("The server connected to the destination, but failed to respond to the client: %v", errWrite)
			return
		}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()

			/* TLS -> TCP: Standard transfer (Splice offers no benefit for TLS). */
			if err := s.TransferToTCP(cliConn, tcpDst); err != nil {
				log.Printf("The connection closed: %v", err)
			}

			/* Signal the destination that we are done sending while keeping
			 * the read side open so the peer can finish replying. */
			if cwErr := tcpDst.CloseWrite(); cwErr != nil {
				log.Printf("CloseWrite to destination failed: %v", cwErr)
			}
		}()

		go func() {
			defer wg.Done()

			/* TCP -> TLS: Standard transfer. */
			if err := s.TransferToTLS(tcpDst, cliConn); err != nil {
				log.Printf("The connection closed: %v", err)
			}

			/* Unblock the other goroutine which is reading from cliConn.
			 * Use SetReadDeadline instead of Close to avoid double-close with
			 * the deferred cliConn.Close() in handleTLSConn. */
			_ = cliConn.SetReadDeadline(time.Now())
		}()

		wg.Wait()

	case util.CmdUDPAssociate:
		/* The UDP ASSOCIATE command. */
		s.handleUDPAssociate(cliConn)

	default:
		log.Printf("Unexpected SOCKS5 command after parse: 0x%02x", cmd)
		util.SendSOCKS5Reply(cliConn, 0x07)
	}
}

func (s *server) handleUDPAssociate(cliConn net.Conn) {
	/* Validate the TCP control connection's remote address before committing
	 * to any response so we can send a proper error reply if the check fails. */
	tcpRemote, ok := cliConn.RemoteAddr().(*net.TCPAddr)
	if !ok || tcpRemote.IP == nil {
		log.Println("The server failed to determine the UDP association client address.")
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}

	/*
	 * Use the actual local address of the TCP control connection so the UDP
	 * association uses the same interface the client reached unless a public
	 * address override is configured.
	 */
	publicIP := s.publicIP
	if publicIP == nil {
		publicIP = s.ListenAddr.IP
		if localTCP, ok := cliConn.LocalAddr().(*net.TCPAddr); ok &&
			localTCP.IP != nil &&
			!localTCP.IP.IsUnspecified() {
			publicIP = localTCP.IP
		}
	}
	if publicIP == nil || publicIP.IsUnspecified() {
		log.Println("The server failed to determine the public UDP address.")
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}

	/*
	 * Bind UDP on the wildcard address for the same IP family.
	 * This avoids coupling the relay to a private/local interface address in NAT
	 * or cloud environments while still keeping the family consistent.
	 */
	udpConn, err := net.ListenUDP("udp", udpWildcardAddrFor(publicIP))
	if err != nil {
		log.Printf("The server failed to listen on UDP: %v", err)
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	var udpCloseOnce sync.Once
	closeUDP := func() { udpCloseOnce.Do(func() { udpConn.Close() }) }
	defer closeUDP()

	/* Preparing the public response address for the client. */
	udpAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		log.Println("The server failed to get the UDP local address.")
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	publicAddr := udpPublicAddrFor(publicIP, udpAddr.Port)
	if publicAddr.IP == nil {
		log.Println("The server failed to determine a valid public IP for UDP response.")
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	ip := publicAddr.IP.To4()
	addressType := byte(util.AtypIPv4) /* IPv4. */
	if ip == nil {
		ip = publicAddr.IP.To16()
		addressType = util.AtypIPv6 /* IPv6. */
	}
	if ip == nil {
		log.Println("The server failed to normalize public IP for UDP response.")
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}

	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(publicAddr.Port))

	resp := []byte{util.SocksVersion, 0x00, 0x00, addressType}
	resp = append(resp, ip...)
	resp = append(resp, port[:]...)

	errWrite := util.WriteAll(cliConn, resp)
	if errWrite != nil {
		log.Printf("The server failed to respond to the client after the UDP associate: %v", errWrite)
		return
	}

	/*
	 * RFC 1928: The UDP association terminates when the TCP connection that
	 * the UDP ASSOCIATE request arrived on terminates.
	 * Monitor the TCP control connection and close UDP when it drops.
	 */
	go func() {
		var buf [1]byte
		_, _ = cliConn.Read(buf[:])
		closeUDP()
	}()

	/* Use a semaphore to limit concurrent UDP handlers. */
	const maxConcurrentUDP = 64
	sem := make(chan struct{}, maxConcurrentUDP)
	var wg sync.WaitGroup
	var allowedSrc *net.UDPAddr
	var assoc *udpAssociation
	defer func() {
		if assoc != nil {
			assoc.Close()
		}
	}()

	/*
	 * Reset the idle deadline before every read so that associations with
	 * infrequent traffic are not torn down prematurely, while associations
	 * that are truly idle (e.g. client crashed, network partition) are
	 * reclaimed within udpAssociationIdleTimeout. When the deadline fires
	 * and ReadFromUDP returns an error, handleUDPAssociate returns, which
	 * triggers defer cliConn.Close() in handleTLSConn and thereby
	 * unblocks the TCP-monitor goroutine — no separate deadline is needed
	 * there.
	 */
	for {
		buf := util.GetUDPBuffer()

		_ = udpConn.SetReadDeadline(time.Now().Add(udpAssociationIdleTimeout))

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

		if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
			/* SOCKS5 UDP requires zero RSV/FRAG; fragmentation is unsupported. */
			util.PutUDPBuffer(buf)
			continue
		}

		/*
		 * Tie the UDP association to the TCP control connection's client IP.
		 * After the first accepted UDP datagram, pin the full UDP source tuple.
		 */
		if srcAddr == nil || srcAddr.IP == nil {
			util.PutUDPBuffer(buf)
			continue
		}
		if !srcAddr.IP.Equal(tcpRemote.IP) {
			util.PutUDPBuffer(buf)
			continue
		}
		if allowedSrc == nil {
			allowedSrc = cloneUDPAddr(srcAddr)
			assoc = newUDPAssociation(udpConn, allowedSrc)
			if assoc == nil {
				util.PutUDPBuffer(buf)
				continue
			}
		} else if !srcAddr.IP.Equal(allowedSrc.IP) || srcAddr.Port != allowedSrc.Port || srcAddr.Zone != allowedSrc.Zone {
			util.PutUDPBuffer(buf)
			continue
		}

		/* Handle UDP packet concurrently; drop packet if all slots are busy. */
		select {
		case sem <- struct{}{}:
		default:
			util.PutUDPBuffer(buf)
			continue
		}
		wg.Add(1)
		go func(buf []byte, n int) {
			defer func() {
				<-sem
				wg.Done()
			}()
			defer util.PutUDPBuffer(buf)
			s.handleUDPPacket(assoc, buf, n)
		}(buf, n)
	}
}

/* handleUDPPacket processes a single UDP packet. */
func (s *server) handleUDPPacket(assoc *udpAssociation, buf []byte, n int) {
	if assoc == nil {
		return
	}
	/* The caller validated n >= 10, RSV/FRAG == 0, and source IP authorization.
	 * Per-type length checks below are defensive for non-IPv4 address types. */
	addressType := buf[3]
	var dstAddr *net.UDPAddr
	var headerLen int

	switch addressType {
	case util.AtypIPv4:
		if n < 10 {
			return
		}
		ip := make(net.IP, net.IPv4len)
		copy(ip, buf[4:4+net.IPv4len])
		dstAddr = &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(buf[8:10]))}
		headerLen = 10

	case util.AtypDomain:
		if n < 5 {
			return
		}
		hostLen := int(buf[4])
		if hostLen == 0 || 5+hostLen+2 > n {
			return
		}
		host := string(buf[5 : 5+hostLen])
		port := int(binary.BigEndian.Uint16(buf[5+hostLen : 5+hostLen+2]))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ipAddrs) == 0 {
			log.Printf("UDP relay DNS lookup failed for %q: %v", host, err)
			return
		}
		ip := make(net.IP, len(ipAddrs[0].IP))
		copy(ip, ipAddrs[0].IP)
		dstAddr = &net.UDPAddr{IP: ip, Port: port}
		headerLen = 5 + hostLen + 2

	case util.AtypIPv6:
		if n < 22 {
			return
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, buf[4:4+net.IPv6len])
		dstAddr = &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(buf[20:22]))}
		headerLen = 22

	default:
		return
	}

	payload := buf[headerLen:n]
	relay, err := assoc.relayFor(dstAddr)
	if err != nil {
		log.Printf("UDP relay setup failed for %s: %v", dstAddr, err)
		return
	}
	if err := relay.conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		log.Printf("UDP relay set deadline failed for %s: %v", dstAddr, err)
		assoc.removeRelay(relay.key, relay)
		relay.close()
		return
	}
	if _, err := relay.conn.Write(payload); err != nil {
		log.Printf("UDP relay write failed for %s: %v", dstAddr, err)
		assoc.removeRelay(relay.key, relay)
		relay.close()
		return
	}
}

type Config struct {
	ServerPEM  string `json:"server_pem"`
	ServerKey  string `json:"server_key"`
	ClientPEM  string `json:"client_pem"`
	ListenAddr string `json:"listen_addr"`
	PublicAddr string `json:"public_addr"`
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

	s := NewServer(config.ListenAddr, config.PublicAddr, config.ServerPEM, config.ServerKey, config.ClientPEM)
	if s == nil {
		log.Fatalf("Failed to create server")
	}

	if err := s.ListenTLS(); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}

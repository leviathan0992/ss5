// Ss5-server serves SOCKS5 TCP and UDP traffic over mutually authenticated TLS.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/leviathan0992/ss5"
)

// server holds the TLS listener settings and shared UDP resolver cache.
type server struct {
	*ss5.Service
	publicIP  net.IP
	serverPEM string
	serverKey string
	clientPEM string
	udpDNS    *dnsCache
}

// Config holds the server settings read from the JSON configuration file.
type Config struct {
	// Username and Password enable SOCKS5 authentication when either is set.
	// Both must then contain 1 to 255 bytes.
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	ServerPEM  string `json:"server_pem"`  // Server certificate file.
	ServerKey  string `json:"server_key"`  // Server private key file.
	ClientPEM  string `json:"client_pem"`  // Trusted client CA file.
	ListenAddr string `json:"listen_addr"` // TLS listen address.
	PublicAddr string `json:"public_addr"` // Optional address advertised for UDP relays.
}

// tcpDialer is shared by concurrent SOCKS5 CONNECT requests.
var tcpDialer = &net.Dialer{Timeout: 30 * time.Second}

// NewServer configures listener addresses and TLS credential paths.
func NewServer(listenAddr, publicAddr, serverPEM, serverKey, clientPEM string) (*server, error) {
	serverPEM = filepath.Clean(serverPEM)
	serverKey = filepath.Clean(serverKey)
	clientPEM = filepath.Clean(clientPEM)

	tcpAddr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen address %q: %w", listenAddr, err)
	}

	publicIP, err := resolvePublicIP(publicAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve public address %q: %w", publicAddr, err)
	}

	return &server{
		Service: &ss5.Service{
			ListenAddr: tcpAddr,
		},
		publicIP:  publicIP,
		serverPEM: serverPEM,
		serverKey: serverKey,
		clientPEM: clientPEM,
		udpDNS:    newDNSCache(),
	}, nil
}

// resolvePublicIP parses or resolves publicAddr to an IP address.
// An empty address returns nil, nil.
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
	return nil, errors.New("no IP address found")
}

// ListenTLS loads TLS credentials and serves connections until a shutdown signal
// is received. Clients must present a certificate trusted by the configured CA.
func (s *server) ListenTLS() error {
	log.Printf("The server's listening address is %s.", s.ListenAddr.String())
	if s.publicIP != nil {
		log.Printf("The server's public UDP address is %s.", s.publicIP.String())
	}

	cert, err := tls.LoadX509KeyPair(s.serverPEM, s.serverKey)
	if err != nil {
		return fmt.Errorf("load server certificate and key: %w", err)
	}

	certBytes, err := os.ReadFile(s.clientPEM)
	if err != nil {
		return fmt.Errorf("read client CA %q: %w", s.clientPEM, err)
	}
	clientCertPool := x509.NewCertPool()
	if !clientCertPool.AppendCertsFromPEM(certBytes) {
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
		return fmt.Errorf("listen on %s: %w", s.ListenAddr, err)
	}
	log.Printf("The server successfully started listening on %s.", s.ListenAddr.String())

	stop, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	return ss5.Serve(stop, listener, 4096, s.handleTLSConn)
}

// handleTLSConn authenticates a client and dispatches its SOCKS5 request.
func (s *server) handleTLSConn(ctx context.Context, clientConn net.Conn) {
	_ = clientConn.SetDeadline(time.Now().Add(30 * time.Second))
	addr, cmd, err := s.ParseSOCKS5FromTLS(clientConn)
	if err != nil {
		log.Printf("The server failed to parse the SOCKS5 protocol: %v", err)
		return
	}
	_ = clientConn.SetDeadline(time.Time{})

	switch cmd {
	case ss5.CmdConnect:
		s.handleTCPConnect(ctx, clientConn, addr)
	case ss5.CmdUDPAssociate:
		s.handleUDPAssociate(ctx, clientConn)
	default:
		log.Printf("Unexpected SOCKS5 command after parse: 0x%02x", cmd)
		ss5.SendSOCKS5Reply(clientConn, 0x07)
	}
}

// handleTCPConnect owns the target socket and relays it after a successful reply.
func (s *server) handleTCPConnect(ctx context.Context, clientConn net.Conn, addr net.Addr) {
	targetAddr := addr.String()
	dstConn, err := tcpDialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		log.Printf("The server failed to connect to the destination address %s: %v", targetAddr, err)
		ss5.SendSOCKS5Reply(clientConn, dialErrToSOCKS5Code(err))
		return
	}
	tcpDst, ok := dstConn.(*net.TCPConn)
	if !ok {
		_ = dstConn.Close()
		ss5.SendSOCKS5Reply(clientConn, 0x01) // 0x01 = general SOCKS server failure
		return
	}
	defer tcpDst.Close()
	ss5.ConfigureTCPConn(tcpDst)

	// Build and send the SOCKS5 success reply with the outgoing bound address.
	boundAddr, ok := tcpDst.LocalAddr().(*net.TCPAddr)
	if !ok {
		ss5.SendSOCKS5Reply(clientConn, 0x01)
		return
	}

	var resp []byte
	if ip4 := boundAddr.IP.To4(); ip4 != nil {
		// IPv4 response: VER + REP + RSV + ATYP (4) + IP (4) + PORT (2) = 10 bytes.
		resp = make([]byte, 0, 10)
		resp = append(resp, ss5.SocksVersion, 0x00, 0x00, ss5.AtypIPv4)
		resp = append(resp, ip4...)
	} else {
		ip6 := boundAddr.IP.To16()
		if ip6 == nil {
			ss5.SendSOCKS5Reply(clientConn, 0x01)
			return
		}
		// IPv6 response: VER + REP + RSV + ATYP (4) + IP (16) + PORT (2) = 22 bytes.
		resp = make([]byte, 0, 22)
		resp = append(resp, ss5.SocksVersion, 0x00, 0x00, ss5.AtypIPv6)
		resp = append(resp, ip6...)
	}

	var port [2]byte
	if !putPort(port[:], boundAddr.Port) {
		log.Printf("The server got an invalid local TCP port %d for destination %s.", boundAddr.Port, targetAddr)
		ss5.SendSOCKS5Reply(clientConn, 0x01)
		return
	}
	resp = append(resp, port[:]...)

	if err := ss5.WriteAll(clientConn, resp); err != nil {
		log.Printf("The server connected to the destination, but failed to respond to the client: %v", err)
		return
	}

	if err := ss5.Relay(clientConn, tcpDst); err != nil {
		log.Printf("Connection relay ended: %v", err)
	}
}

// dialErrToSOCKS5Code maps a dial error to an RFC 1928 reply code.
func dialErrToSOCKS5Code(err error) byte {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
		return 0x05 // connection refused
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EADDRNOTAVAIL) {
		return 0x03 // network unreachable
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EHOSTDOWN) || errors.Is(err, syscall.ETIMEDOUT) {
		return 0x04 // host unreachable
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return 0x04 // host unreachable (timeout)
	}
	return 0x01 // general SOCKS server failure
}

const (
	udpAssociationIdleTimeout = 5 * time.Minute
	maxUDPAssociations        = 128
	maxRelaysPerAssociation   = 128
	maxUDPRelays              = 1024
)

var (
	udpAssociationSlots = make(chan struct{}, maxUDPAssociations)
	udpRelaySlots       = make(chan struct{}, maxUDPRelays)
	errUDPRelayLimit    = errors.New("UDP relay capacity reached")
)

// udpAssociation owns the relays for one SOCKS5 UDP ASSOCIATE session.
type udpAssociation struct {
	clientConn *net.UDPConn
	clientAddr *net.UDPAddr
	ctx        context.Context
	cancel     context.CancelFunc
	activity   idleClock

	// mu protects closed, relays and pending. wg covers reserved dials and
	// running relays so Close can wait for both kinds of work.
	mu      sync.RWMutex
	closed  bool
	relays  map[udpAddrKey]*udpRelay
	pending int
	wg      sync.WaitGroup
}

// udpRelay forwards datagrams between an association and one remote target.
type udpRelay struct {
	assoc          *udpAssociation
	key            udpAddrKey
	target         *net.UDPAddr
	responseHeader []byte
	conn           *net.UDPConn
	closeOnce      sync.Once
	activity       idleClock

	// Last write-deadline refresh in Unix nanoseconds. Atomic access allows
	// forwarding workers to share a relay without a data race.
	lastWriteDeadline atomic.Int64
}

// udpPacketJob is one client UDP datagram queued for worker processing.
type udpPacketJob struct {
	assoc *udpAssociation
	buf   *[]byte // Ownership passes to the worker only after successful enqueue.
	n     int
	ip    netip.Addr // Cached domain result; invalid for IP targets and DNS misses.
}

// handleUDPAssociate binds and advertises a UDP relay, then forwards datagrams
// until the TCP control connection closes or the association expires.
func (s *server) handleUDPAssociate(ctx context.Context, clientConn net.Conn) {
	select {
	case udpAssociationSlots <- struct{}{}:
		defer func() { <-udpAssociationSlots }()
	default:
		ss5.SendSOCKS5Reply(clientConn, 0x01)
		return
	}

	// Validate the TCP control connection's remote address before committing
	// to any response so we can send a proper error reply if the check fails.
	tcpRemote, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok || tcpRemote.IP == nil {
		log.Println("The server failed to determine the UDP association client address.")
		ss5.SendSOCKS5Reply(clientConn, 0x01)
		return
	}
	controlIP, ok := netip.AddrFromSlice(tcpRemote.IP)
	if !ok {
		ss5.SendSOCKS5Reply(clientConn, 0x01)
		return
	}
	controlIP = controlIP.Unmap()

	// Use the actual local address of the TCP control connection so the UDP
	// association uses the same interface the client reached unless a public
	// address override is configured.
	publicIP := s.publicIP
	if publicIP == nil {
		publicIP = s.ListenAddr.IP
		if localTCP, ok := clientConn.LocalAddr().(*net.TCPAddr); ok &&
			localTCP.IP != nil &&
			!localTCP.IP.IsUnspecified() {
			publicIP = localTCP.IP
		}
	}
	if publicIP == nil || publicIP.IsUnspecified() {
		log.Println("The server failed to determine the public UDP address.")
		ss5.SendSOCKS5Reply(clientConn, 0x01)
		return
	}

	// Bind UDP on the wildcard address for the same IP family.
	// This avoids coupling the relay to a private/local interface address in NAT
	// or cloud environments while still keeping the family consistent.
	udpConn, err := net.ListenUDP("udp", udpWildcardAddrFor(publicIP))
	if err != nil {
		log.Printf("The server failed to listen on UDP: %v", err)
		ss5.SendSOCKS5Reply(clientConn, 0x01)
		return
	}

	var udpCloseOnce sync.Once
	closeUDP := func() {
		udpCloseOnce.Do(func() {
			_ = udpConn.Close()
		})
	}
	defer closeUDP()
	stopClosing := context.AfterFunc(ctx, closeUDP)
	defer stopClosing()

	resp, err := udpAssociateReply(udpConn, publicIP)
	if err != nil {
		log.Print(err)
		ss5.SendSOCKS5Reply(clientConn, 0x01)
		return
	}
	if err := ss5.WriteAll(clientConn, resp); err != nil {
		log.Printf("The server failed to respond to the client after the UDP associate: %v", err)
		return
	}

	// RFC 1928 §6: the UDP association terminates when the TCP control
	// connection closes. Monitor it and close UDP when it drops.
	go func() {
		var buf [1]byte
		_, _ = clientConn.Read(buf[:])
		closeUDP()
	}()

	s.receiveUDPPackets(ctx, udpConn, controlIP)
}

// udpAssociateReply describes the bound relay using the advertised public IP.
func udpAssociateReply(udpConn *net.UDPConn, publicIP net.IP) ([]byte, error) {
	udpAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("failed to get UDP local address")
	}
	publicAddr := udpPublicAddrFor(publicIP, udpAddr.Port)
	if publicAddr.IP == nil {
		return nil, errors.New("no valid public IP for UDP response")
	}
	if publicAddr.Port == 0 {
		return nil, errors.New("cannot advertise UDP relay on port 0")
	}

	ip := publicAddr.IP.To4()
	addressType := ss5.AtypIPv4
	if ip == nil {
		ip = publicAddr.IP.To16()
		addressType = ss5.AtypIPv6
	}
	if ip == nil {
		return nil, errors.New("failed to normalize public IP for UDP response")
	}

	var port [2]byte
	if !putPort(port[:], publicAddr.Port) {
		return nil, fmt.Errorf("invalid public UDP port %d", publicAddr.Port)
	}

	// Pre-allocate: VER + REP + RSV + ATYP (4) + IP + PORT (2).
	resp := make([]byte, 0, 4+len(ip)+2)
	resp = append(resp, ss5.SocksVersion, 0x00, 0x00, addressType)
	resp = append(resp, ip...)
	resp = append(resp, port[:]...)

	return resp, nil
}

// receiveUDPPackets owns the queues, association, timer and workers. It returns
// after closing target sockets and waiting for every borrowed buffer to return.
func (s *server) receiveUDPPackets(ctx context.Context, udpConn *net.UDPConn, controlIP netip.Addr) {
	const (
		forwardQueueWait = 100 * time.Microsecond
		maxConcurrentUDP = 4
		maxConcurrentDNS = 4
	)

	// Keep DNS waits away from IP and cached-domain traffic without reducing
	// the concurrency available to independent target sockets.
	jobs := make(chan udpPacketJob, 16)
	var forwardTimer *time.Timer
	dnsJobs := make(chan udpPacketJob, 16)
	var workerWG sync.WaitGroup
	for i := 0; i < maxConcurrentUDP; i++ {
		workerWG.Add(1)
		go s.udpPacketWorker(jobs, &workerWG)
	}
	for i := 0; i < maxConcurrentDNS; i++ {
		workerWG.Add(1)
		go s.udpPacketWorker(dnsJobs, &workerWG)
	}

	var allowedSrc netip.AddrPort
	var assoc *udpAssociation
	defer func() {
		if forwardTimer != nil {
			forwardTimer.Stop()
		}
		close(jobs)
		close(dnsJobs)
		if assoc != nil {
			assoc.Close()
		}
		workerWG.Wait()
	}()

	// Only accepted client packets and target replies count as activity.
	// Renew the read deadline on timeout, not for every datagram.
	_ = udpConn.SetReadDeadline(time.Now().Add(udpAssociationIdleTimeout))

	for {
		buffer := ss5.BorrowUDPBuffer()
		buf := *buffer

		n, srcAddr, err := udpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			ss5.ReturnUDPBuffer(buffer)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() && assoc != nil {
				if remaining := assoc.activity.remaining(); remaining > 0 {
					_ = udpConn.SetReadDeadline(time.Now().Add(remaining))
					continue
				}
			}
			return
		}

		if !validUDPPacket(buf[:n]) {
			ss5.ReturnUDPBuffer(buffer)
			continue
		}

		// Tie the UDP association to the TCP control connection's client IP.
		// After the first accepted UDP datagram, pin the full UDP source tuple.
		if !srcAddr.IsValid() {
			ss5.ReturnUDPBuffer(buffer)
			continue
		}
		if srcAddr.Addr().Unmap().WithZone("") != controlIP {
			ss5.ReturnUDPBuffer(buffer)
			continue
		}

		if !allowedSrc.IsValid() {
			allowedSrc = srcAddr
			assoc = newUDPAssociation(ctx, udpConn, net.UDPAddrFromAddrPort(srcAddr))
			if assoc == nil {
				ss5.ReturnUDPBuffer(buffer)
				continue
			}
		} else if srcAddr != allowedSrc {
			ss5.ReturnUDPBuffer(buffer)
			continue
		}

		assoc.activity.touch()

		job := udpPacketJob{assoc: assoc, buf: buffer, n: n}
		queue := jobs
		if buf[3] == ss5.AtypDomain {
			host := string(buf[5 : 5+int(buf[4])])
			if ip, cached := s.udpDNS.get(host, time.Now()); cached {
				job.ip = ip
			} else {
				queue = dnsJobs
			}
		}

		select {
		case queue <- job:
			continue
		default:
		}

		if queue == jobs {
			// Absorb short scheduling stalls without letting a blocked target
			// hold up the receive loop indefinitely. DNS never waits here.
			if forwardTimer == nil {
				forwardTimer = time.NewTimer(forwardQueueWait)
			} else {
				forwardTimer.Reset(forwardQueueWait)
			}
			select {
			case queue <- job:
				if !forwardTimer.Stop() {
					<-forwardTimer.C
				}
				continue
			case <-forwardTimer.C:
			}
		}

		ss5.ReturnUDPBuffer(buffer)
	}
}

// udpPacketWorker processes queued packets and returns each borrowed buffer.
func (s *server) udpPacketWorker(jobs <-chan udpPacketJob, workerWG *sync.WaitGroup) {
	defer workerWG.Done()
	for job := range jobs {
		if job.assoc.ctx.Err() == nil {
			s.handleUDPPacket(job.assoc, *job.buf, job.n, job.ip)
		}
		ss5.ReturnUDPBuffer(job.buf)
	}
}

// validUDPPacket reports whether packet has a complete, unfragmented SOCKS5 UDP
// header. Callers must validate it before pinning the source or refreshing activity.
func validUDPPacket(packet []byte) bool {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return false
	}

	var header int
	switch packet[3] {
	case ss5.AtypIPv4:
		header = 10
	case ss5.AtypIPv6:
		header = 22
	case ss5.AtypDomain:
		if len(packet) < 5 || packet[4] == 0 {
			return false
		}
		header = 7 + int(packet[4])
	default:
		return false
	}
	return len(packet) >= header
}

// handleUDPPacket resolves the target and forwards one validated UDP datagram.
// IP targets reuse existing relays without constructing a net.UDPAddr.
func (s *server) handleUDPPacket(assoc *udpAssociation, buf []byte, n int, resolvedIP netip.Addr) {
	if assoc == nil {
		return
	}

	// The caller validated the complete header, RSV/FRAG == 0, and source IP.
	// A complete frame may carry a zero-length UDP payload.
	addressType := buf[3]

	var key udpAddrKey
	var headerLen int

	switch addressType {
	case ss5.AtypIPv4:
		if n < 10 {
			return
		}
		key = ipv4KeyFromBytes(buf[4:8], binary.BigEndian.Uint16(buf[8:10]))
		headerLen = 10

	case ss5.AtypDomain:
		if n < 5 {
			return
		}
		hostLen := int(buf[4])
		if hostLen == 0 || 5+hostLen+2 > n {
			return
		}

		port := int(binary.BigEndian.Uint16(buf[5+hostLen : 5+hostLen+2]))

		ip := resolvedIP
		if !ip.IsValid() {
			host := string(buf[5 : 5+hostLen])
			var err error
			ip, err = s.resolveUDPHost(assoc.ctx, host)
			if err != nil {
				log.Printf("UDP relay DNS lookup failed for %q: %v", host, err)
				return
			}
		}

		var ok bool
		key, ok = makeUDPAddrKey(ip, port)
		if !ok {
			log.Printf("UDP relay DNS lookup produced invalid address %v", ip)
			return
		}

		headerLen = 5 + hostLen + 2
		payload := buf[headerLen:n]
		if relay := assoc.lookupRelay(key); relay != nil {
			s.writeUDPPayload(assoc, relay, payload)
			return
		}

		dstAddr := &net.UDPAddr{IP: ip.AsSlice(), Port: port}
		s.forwardUDPPayload(assoc, key, dstAddr, payload)
		return

	case ss5.AtypIPv6:
		if n < 22 {
			return
		}
		key = ipv6KeyFromBytes(buf[4:20], binary.BigEndian.Uint16(buf[20:22]))
		headerLen = 22

	default:
		return
	}

	payload := buf[headerLen:n]
	relay := assoc.lookupRelay(key)
	if relay == nil {
		// Copy the address before retaining it beyond the borrowed packet buffer.
		var dstAddr *net.UDPAddr
		switch addressType {
		case ss5.AtypIPv4:
			ip := make(net.IP, net.IPv4len)
			copy(ip, buf[4:8])
			dstAddr = &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(buf[8:10]))}
		case ss5.AtypIPv6:
			ip := make(net.IP, net.IPv6len)
			copy(ip, buf[4:20])
			dstAddr = &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(buf[20:22]))}
		}
		s.forwardUDPPayload(assoc, key, dstAddr, payload)
		return
	}

	s.writeUDPPayload(assoc, relay, payload)
}

// forwardUDPPayload obtains or creates a relay for dst and sends payload.
func (s *server) forwardUDPPayload(assoc *udpAssociation, key udpAddrKey, dst *net.UDPAddr, payload []byte) {
	relay, err := assoc.relayForKey(key, dst)
	if err != nil {
		if !errors.Is(err, errUDPRelayLimit) {
			log.Printf("UDP relay setup failed for %s: %v", dst, err)
		}
		return
	}

	s.writeUDPPayload(assoc, relay, payload)
}

// writeUDPPayload sends payload and periodically refreshes the write deadline.
// Concurrent workers may refresh it together; each refresh is safe to repeat.
func (s *server) writeUDPPayload(assoc *udpAssociation, relay *udpRelay, payload []byte) {
	const (
		writeDeadlineRefresh  = int64(10 * time.Second)
		writeDeadlineDuration = 30 * time.Second
	)

	now := time.Now()
	if now.UnixNano()-relay.lastWriteDeadline.Load() > writeDeadlineRefresh {
		if err := relay.conn.SetWriteDeadline(now.Add(writeDeadlineDuration)); err != nil {
			log.Printf("UDP relay set write deadline failed for %s: %v", relay.target, err)
			assoc.removeRelay(relay.key, relay)
			relay.close()
			return
		}
		relay.lastWriteDeadline.Store(now.UnixNano())
	}

	if _, err := relay.conn.Write(payload); err != nil {
		log.Printf("UDP relay write failed for %s: %v", relay.target, err)
		assoc.removeRelay(relay.key, relay)
		relay.close()
		return
	}
	relay.activity.touch()
}

// newUDPAssociation creates an association bound to clientConn and clientAddr.
// It returns nil if the connection or address is nil.
func newUDPAssociation(parent context.Context, clientConn *net.UDPConn, clientAddr *net.UDPAddr) *udpAssociation {
	if clientConn == nil || clientAddr == nil {
		return nil
	}

	ctx, cancel := context.WithCancel(parent)
	return &udpAssociation{
		clientConn: clientConn,
		clientAddr: cloneUDPAddr(clientAddr),
		ctx:        ctx,
		cancel:     cancel,
		activity:   idleClock{start: time.Now()},
		relays:     make(map[udpAddrKey]*udpRelay),
	}
}

// lookupRelay returns the relay for key under a read lock, or nil if none exists.
func (a *udpAssociation) lookupRelay(key udpAddrKey) *udpRelay {
	a.mu.RLock()
	relay := a.relays[key]
	a.mu.RUnlock()
	return relay
}

// relayForKey returns an existing relay or dials dst within the relay quotas.
// Concurrent calls may dial the same target; only one relay is retained.
func (a *udpAssociation) relayForKey(key udpAddrKey, dst *net.UDPAddr) (*udpRelay, error) {
	if a == nil {
		return nil, errors.New("nil UDP association")
	}
	if dst == nil {
		return nil, errors.New("nil relay target address")
	}

	// Reserve both quotas before opening a socket. Pending dials count toward
	// the association limit and keep Close waiting until they release resources.
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, errors.New("UDP association closed")
	}
	if relay := a.relays[key]; relay != nil {
		a.mu.Unlock()
		return relay, nil
	}

	if len(a.relays)+a.pending >= maxRelaysPerAssociation {
		a.mu.Unlock()
		return nil, errUDPRelayLimit
	}
	select {
	case udpRelaySlots <- struct{}{}:
	default:
		a.mu.Unlock()
		return nil, errUDPRelayLimit
	}
	a.pending++
	a.wg.Add(1)
	a.mu.Unlock()

	started := false
	defer func() {
		a.mu.Lock()
		a.pending--
		a.mu.Unlock()
		if !started {
			<-udpRelaySlots
			a.wg.Done()
		}
	}()

	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return nil, err
	}

	header, ok := buildUDPResponseHeader(dst)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("invalid UDP relay target address")
	}
	relay := &udpRelay{
		assoc:          a,
		key:            key,
		target:         cloneUDPAddr(dst),
		responseHeader: header,
		conn:           conn,
		activity:       idleClock{start: time.Now()},
	}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = conn.Close()
		return nil, errors.New("UDP association closed")
	}
	if existing := a.relays[key]; existing != nil {
		a.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	a.relays[key] = relay
	started = true
	a.mu.Unlock()

	go relay.readLoop()
	return relay, nil
}

// removeRelay removes relay only if it is still the current entry for key.
func (a *udpAssociation) removeRelay(key udpAddrKey, relay *udpRelay) {
	if a == nil {
		return
	}

	a.mu.Lock()
	if current, ok := a.relays[key]; ok && current == relay {
		delete(a.relays, key)
	}
	a.mu.Unlock()
}

// Close cancels DNS waits, closes relays and waits for pending dials and relays.
func (a *udpAssociation) Close() {
	if a == nil {
		return
	}

	a.cancel()
	a.mu.Lock()
	a.closed = true
	relays := make([]*udpRelay, 0, len(a.relays))
	for _, relay := range a.relays {
		relays = append(relays, relay)
	}
	a.relays = nil
	a.mu.Unlock()

	for _, relay := range relays {
		relay.close()
	}
	a.wg.Wait()
}

// readLoop forwards target replies until the relay closes or expires.
func (r *udpRelay) readLoop() {
	if r.assoc == nil {
		return
	}
	defer r.assoc.wg.Done()
	defer func() { <-udpRelaySlots }()

	buffer := ss5.BorrowUDPBuffer()
	defer ss5.ReturnUDPBuffer(buffer)
	packetBuf := *buffer

	headerLen := len(r.responseHeader)
	if headerLen == 0 || headerLen >= len(packetBuf) {
		log.Printf("UDP relay: invalid response header length %d for %s", headerLen, r.target)
		r.assoc.removeRelay(r.key, r)
		r.close()
		return
	}
	copy(packetBuf[:headerLen], r.responseHeader)

	const (
		writeDeadline        = 30 * time.Second
		writeDeadlineRefresh = 10 * time.Second
	)
	now := time.Now()
	_ = r.conn.SetReadDeadline(now.Add(udpAssociationIdleTimeout))
	_ = r.assoc.clientConn.SetWriteDeadline(now.Add(writeDeadline))
	lastWriteDeadline := now

	for {
		nRead, err := r.conn.Read(packetBuf[headerLen:])
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				if remaining := r.activity.remaining(); remaining > 0 {
					_ = r.conn.SetReadDeadline(time.Now().Add(remaining))
					continue
				}
			} else if !errors.Is(err, net.ErrClosed) {
				log.Printf("UDP relay read error for %s: %v", r.target, err)
			}
			r.assoc.removeRelay(r.key, r)
			r.close()
			return
		}

		r.activity.touch()
		now = time.Now()
		total := headerLen + nRead

		// Refresh the write deadline periodically so a slow client does not
		// stall the relay goroutine indefinitely.
		if now.Sub(lastWriteDeadline) > writeDeadlineRefresh {
			_ = r.assoc.clientConn.SetWriteDeadline(now.Add(writeDeadline))
			lastWriteDeadline = now
		}
		if _, err := r.assoc.clientConn.WriteToUDPAddrPort(packetBuf[:total], r.assoc.clientAddr.AddrPort()); err != nil {
			log.Printf("UDP relay: failed to forward response to client %s: %v", r.assoc.clientAddr, err)
			r.assoc.removeRelay(r.key, r)
			r.close()
			return
		}
		r.assoc.activity.touch()
	}
}

// close closes the relay socket exactly once.
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

// idleClock tracks activity using monotonic time so wall-clock changes do not
// affect expiration. It is safe for concurrent use after start is initialized.
type idleClock struct {
	start time.Time
	last  atomic.Int64
}

func (c *idleClock) touch() {
	now := time.Since(c.start).Nanoseconds()
	for previous := c.last.Load(); now > previous; previous = c.last.Load() {
		if c.last.CompareAndSwap(previous, now) {
			return
		}
	}
}

func (c *idleClock) remaining() time.Duration {
	return udpAssociationIdleTimeout - (time.Since(c.start) - time.Duration(c.last.Load()))
}

const (
	udpDNSCacheTTL        = 1 * time.Minute
	udpDNSCacheMaxEntries = 4096
)

type dnsCacheEntry struct {
	ip        netip.Addr
	expiresAt time.Time
}

type dnsLookupCall struct {
	// Closing done publishes ip and err to waiters.
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int // Protected by dnsCache.mu.
	ip      netip.Addr
	err     error
}

// dnsCache shares UDP domain lookups and caches successful results for a fixed TTL.
// It is safe for concurrent use after initialization with newDNSCache.
type dnsCache struct {
	mu       sync.RWMutex
	entries  map[string]dnsCacheEntry
	inflight map[string]*dnsLookupCall
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		entries:  make(map[string]dnsCacheEntry),
		inflight: make(map[string]*dnsLookupCall),
	}
}

// resolveUDPHost returns a cached IP or joins a shared lookup for host.
func (s *server) resolveUDPHost(parent context.Context, host string) (netip.Addr, error) {
	if err := parent.Err(); err != nil {
		return netip.Addr{}, err
	}

	now := time.Now()
	if ip, ok := s.udpDNS.get(host, now); ok {
		return ip, nil
	}

	s.udpDNS.mu.Lock()
	if entry, ok := s.udpDNS.entries[host]; ok && entry.expiresAt.After(now) {
		ip := entry.ip
		s.udpDNS.mu.Unlock()
		return ip, nil
	}

	call := s.udpDNS.inflight[host]
	if call == nil {
		// A lookup belongs to all its waiters, not to the first association.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		call = &dnsLookupCall{done: make(chan struct{}), cancel: cancel}
		s.udpDNS.inflight[host] = call
		go s.lookupUDPHost(ctx, host, call)
	}
	call.waiters++
	s.udpDNS.mu.Unlock()

	defer func() {
		s.udpDNS.mu.Lock()
		call.waiters--
		if call.waiters == 0 {
			call.cancel()
			// A later caller must not join a lookup that has been canceled.
			if s.udpDNS.inflight[host] == call {
				delete(s.udpDNS.inflight, host)
			}
		}
		s.udpDNS.mu.Unlock()
	}()

	select {
	case <-parent.Done():
		return netip.Addr{}, parent.Err()
	case <-call.done:
		return call.ip, call.err
	}
}

// lookupUDPHost resolves host for all waiters and publishes the result.
// The query stops after five seconds or when its last waiter leaves.
func (s *server) lookupUDPHost(ctx context.Context, host string, call *dnsLookupCall) {
	defer call.cancel()

	ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	var resolvedIP netip.Addr
	if err == nil {
		for _, ipAddr := range ipAddrs {
			if ip, ok := netip.AddrFromSlice(ipAddr.IP); ok {
				resolvedIP = ip.Unmap()
				break
			}
		}
		if !resolvedIP.IsValid() {
			err = errors.New("no IP address found")
		}
	}

	if err == nil {
		s.udpDNS.put(host, resolvedIP, time.Now())
	}

	s.udpDNS.mu.Lock()
	if s.udpDNS.inflight[host] == call {
		delete(s.udpDNS.inflight, host)
	}
	call.ip, call.err = resolvedIP, err
	close(call.done)
	s.udpDNS.mu.Unlock()
}

// get returns an unexpired cached address by value, or false on a miss.
func (c *dnsCache) get(host string, now time.Time) (netip.Addr, bool) {
	if c == nil || host == "" {
		return netip.Addr{}, false
	}

	c.mu.RLock()
	entry, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok {
		return netip.Addr{}, false
	}
	if !entry.expiresAt.After(now) {
		c.mu.Lock()
		if current, ok := c.entries[host]; ok && !current.expiresAt.After(now) {
			delete(c.entries, host)
		}
		c.mu.Unlock()
		return netip.Addr{}, false
	}
	return entry.ip, true
}

// put caches ip, evicting entries only when a new host needs space.
func (c *dnsCache) put(host string, ip netip.Addr, now time.Time) {
	if c == nil || host == "" || !ip.IsValid() {
		return
	}

	entry := dnsCacheEntry{
		ip:        ip.Unmap(),
		expiresAt: now.Add(udpDNSCacheTTL),
	}

	c.mu.Lock()
	_, exists := c.entries[host]
	if !exists && len(c.entries) >= udpDNSCacheMaxEntries {
		for key, existing := range c.entries {
			if !existing.expiresAt.After(now) {
				delete(c.entries, key)
			}
		}

		if len(c.entries) >= udpDNSCacheMaxEntries {
			for key := range c.entries {
				delete(c.entries, key)
				break
			}
		}
	}
	c.entries[host] = entry
	c.mu.Unlock()
}

const maxPortNumber = 65535

// udpAddrKey is a relay map key containing a 16-byte IP and a big-endian port.
// IPv4 addresses use the IPv4-mapped IPv6 form. Zones are omitted because SOCKS5
// address fields cannot represent IPv6 scope zones.
type udpAddrKey [18]byte

// makeUDPAddrKey encodes ip and port as a relay key.
// It returns false if the address or port is invalid.
func makeUDPAddrKey(ip netip.Addr, port int) (udpAddrKey, bool) {
	var key udpAddrKey
	if !ip.IsValid() || port < 0 || port > maxPortNumber {
		return key, false
	}

	ip16 := ip.As16()
	copy(key[:16], ip16[:])
	binary.BigEndian.PutUint16(key[16:], uint16(port))
	return key, true
}

// ipv4KeyFromBytes encodes the first four bytes of ip4 and port as a relay key.
// The address uses the IPv4-mapped IPv6 form, matching net.IP.To16.
func ipv4KeyFromBytes(ip4 []byte, port uint16) udpAddrKey {
	var k udpAddrKey
	// IPv4-mapped IPv6 prefix: 10 zero bytes, then 0xff 0xff, then the 4 IPv4 bytes.
	k[10] = 0xff
	k[11] = 0xff
	copy(k[12:16], ip4[:4])
	binary.BigEndian.PutUint16(k[16:], port)
	return k
}

// ipv6KeyFromBytes encodes the first 16 bytes of ip6 and port as a relay key.
func ipv6KeyFromBytes(ip6 []byte, port uint16) udpAddrKey {
	var k udpAddrKey
	copy(k[:16], ip6[:16])
	binary.BigEndian.PutUint16(k[16:], port)
	return k
}

// buildUDPResponseHeader returns a SOCKS5 UDP header for dst, or false if invalid.
// Relays reuse the header and read payloads directly into the space after it.
func buildUDPResponseHeader(dst *net.UDPAddr) ([]byte, bool) {
	if dst == nil || dst.IP == nil {
		return nil, false
	}
	if dst.Port < 0 || dst.Port > maxPortNumber {
		return nil, false
	}

	if ip4 := dst.IP.To4(); ip4 != nil {
		header := make([]byte, 0, 3+1+len(ip4)+2)
		header = append(header, 0x00, 0x00, 0x00, ss5.AtypIPv4)
		header = append(header, ip4...)

		var port [2]byte
		if !putPort(port[:], dst.Port) {
			return nil, false
		}
		header = append(header, port[:]...)
		return header, true
	}

	ip6 := dst.IP.To16()
	if ip6 == nil {
		return nil, false
	}

	header := make([]byte, 0, 3+1+len(ip6)+2)
	header = append(header, 0x00, 0x00, 0x00, ss5.AtypIPv6)
	header = append(header, ip6...)

	var port [2]byte
	if !putPort(port[:], dst.Port) {
		return nil, false
	}
	header = append(header, port[:]...)
	return header, true
}

// putPort writes port to dst in network byte order.
// It reports whether port is valid and dst has at least two bytes.
func putPort(dst []byte, port int) bool {
	if len(dst) < 2 || port < 0 || port > maxPortNumber {
		return false
	}
	binary.BigEndian.PutUint16(dst[:2], uint16(port))
	return true
}

// cloneUDPAddr returns a deep copy of addr, or nil if addr is nil.
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

// udpWildcardAddrFor returns a wildcard bind address in the same family as ip.
// Nil and invalid addresses default to IPv4.
func udpWildcardAddrFor(ip net.IP) *net.UDPAddr {
	if ip != nil && ip.To4() == nil && ip.To16() != nil {
		return &net.UDPAddr{IP: append(net.IP(nil), net.IPv6zero...)}
	}
	return &net.UDPAddr{IP: append(net.IP(nil), net.IPv4zero...)}
}

// udpPublicAddrFor copies localIP and pairs it with the bound UDP port.
func udpPublicAddrFor(localIP net.IP, port int) *net.UDPAddr {
	addr := &net.UDPAddr{Port: port}
	if localIP != nil {
		addr.IP = append(net.IP(nil), localIP...)
	}
	return addr
}

func main() {
	var confPath string
	flag.StringVar(&confPath, "c", ".ss5-server.json", "The server configuration file.")
	flag.Parse()

	confPath = filepath.Clean(confPath)
	data, err := os.ReadFile(confPath)
	if err != nil {
		log.Fatalf("The server failed to read the configuration file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		log.Fatalf("The server failed to parse the configuration file %s: %v", confPath, err)
	}

	if config.ListenAddr == "" {
		log.Fatalf("Configuration field listen_addr is required")
	}
	if config.ServerPEM == "" {
		log.Fatalf("Configuration field server_pem is required")
	}
	if config.ServerKey == "" {
		log.Fatalf("Configuration field server_key is required")
	}
	if config.ClientPEM == "" {
		log.Fatalf("Configuration field client_pem is required")
	}

	var auth *ss5.Credentials
	if config.Username != "" || config.Password != "" {
		auth = &ss5.Credentials{Username: config.Username, Password: config.Password}
		if err := auth.Validate(); err != nil {
			log.Fatal(err)
		}
	}

	s, err := NewServer(config.ListenAddr, config.PublicAddr, config.ServerPEM, config.ServerKey, config.ClientPEM)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	s.Auth = auth
	if err := s.ListenTLS(); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}

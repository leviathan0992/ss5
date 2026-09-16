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

	util "github.com/leviathan0992/ss5"
)

// Holds the configuration and state for the SOCKS5-over-TLS server.
type server struct {
	*util.Service
	publicIP  net.IP
	serverPEM string
	serverKEY string
	clientPEM string
	udpDNS    *dnsCache
}

type Config struct {
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	ServerPEM  string `json:"server_pem"`
	ServerKey  string `json:"server_key"`
	ClientPEM  string `json:"client_pem"`
	ListenAddr string `json:"listen_addr"`
	PublicAddr string `json:"public_addr"`
}

// Reuses one dialer across all CONNECT requests. net.Dialer is safe for
// concurrent use, so a single instance avoids one heap allocation per request.
var tcpDialer = &net.Dialer{Timeout: 30 * time.Second}

// Constructs a server from the given configuration parameters.
// Returns nil and logs an error if any parameter is invalid.
func NewServer(listenAddr string, publicAddr string, serverPEM string, serverKEY string, clientPEM string) *server {
	serverPEM = filepath.Clean(serverPEM)
	serverKEY = filepath.Clean(serverKEY)
	clientPEM = filepath.Clean(clientPEM)

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
		udpDNS:    newDNSCache(),
	}
}

// Parses or resolves publicAddr to an IP address.
// Returns nil, nil if publicAddr is empty.
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

// Loads TLS credentials, starts accepting connections, and dispatches
// each to handleTLSConn. Returns when a shutdown signal is received.
func (s *server) ListenTLS() error {
	log.Printf("The server's listening address is %s.", s.ListenAddr.String())
	if s.publicIP != nil {
		log.Printf("The server's public UDP address is %s.", s.publicIP.String())
	}

	// Load TLS certificate and private key.
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
	// Attempt to parse the PEM encoded certificates.
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

	stop, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	return util.Serve(stop, listener, 4096, s.handleTLSConn)
}

// Handles a single TLS client connection: parses the SOCKS5
// handshake and dispatches to CONNECT or UDP ASSOCIATE handling.
func (s *server) handleTLSConn(ctx context.Context, cliConn net.Conn) {
	defer cliConn.Close()

	_ = cliConn.SetDeadline(time.Now().Add(30 * time.Second))
	addr, cmd, err := s.ParseSOCKS5FromTLS(cliConn)
	if err != nil {
		log.Printf("The server failed to parse the SOCKS5 protocol: %v", err)
		return
	}
	_ = cliConn.SetDeadline(time.Time{})

	switch cmd {
	case util.CmdConnect:
		s.handleTCPConnect(ctx, cliConn, addr)

	case util.CmdUDPAssociate:
		s.handleUDPAssociate(ctx, cliConn)

	default:
		log.Printf("Unexpected SOCKS5 command after parse: 0x%02x", cmd)
		util.SendSOCKS5Reply(cliConn, 0x07)
	}
}

// handleTCPConnect owns the target socket and relays it after a successful reply.
func (s *server) handleTCPConnect(ctx context.Context, cliConn net.Conn, addr net.Addr) {
	targetAddr := addr.String()

	// Attempt to connect to the destination address with a 30 s timeout.
	dstConn, err := tcpDialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		log.Printf("The server failed to connect to the destination address %s: %v", targetAddr, err)
		util.SendSOCKS5Reply(cliConn, dialErrToSOCKS5Code(err))
		return
	}
	tcpDst, ok := dstConn.(*net.TCPConn)
	if !ok {
		_ = dstConn.Close()
		util.SendSOCKS5Reply(cliConn, 0x01) /* 0x01 = general SOCKS server failure */
		return
	}
	defer tcpDst.Close()
	log.Printf("The server connected to the destination address %s successfully.", targetAddr)

	util.ConfigureTCPConn(tcpDst)

	// Build and send the SOCKS5 success reply with the outgoing bound address.
	boundAddr, ok := tcpDst.LocalAddr().(*net.TCPAddr)
	if !ok {
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	var resp []byte
	if ip4 := boundAddr.IP.To4(); ip4 != nil {
		// IPv4 response: VER + REP + RSV + ATYP (4) + IP (4) + PORT (2) = 10 bytes.
		resp = make([]byte, 0, 10)
		resp = append(resp, util.SocksVersion, 0x00, 0x00, util.AtypIPv4)
		resp = append(resp, ip4...)
	} else {
		ip6 := boundAddr.IP.To16()
		if ip6 == nil {
			util.SendSOCKS5Reply(cliConn, 0x01)
			return
		}
		// IPv6 response: VER + REP + RSV + ATYP (4) + IP (16) + PORT (2) = 22 bytes.
		resp = make([]byte, 0, 22)
		resp = append(resp, util.SocksVersion, 0x00, 0x00, util.AtypIPv6)
		resp = append(resp, ip6...)
	}
	var port [2]byte
	if !putPort(port[:], boundAddr.Port) {
		log.Printf("The server got an invalid local TCP port %d for destination %s.", boundAddr.Port, targetAddr)
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	resp = append(resp, port[:]...)

	if err := util.WriteAll(cliConn, resp); err != nil {
		log.Printf("The server connected to the destination, but failed to respond to the client: %v", err)
		return
	}

	if err := util.Relay(cliConn, tcpDst); err != nil {
		log.Printf("Connection relay ended: %v", err)
	}
}

// Maps a dial error to the appropriate SOCKS5 reply code per RFC 1928.
func dialErrToSOCKS5Code(err error) byte {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) {
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

const (
	udpAssociationIdleTimeout = 5 * time.Minute
	maxUDPAssociations        = 128
	maxRelaysPerAssociation   = 128
	maxUDPRelays              = 1024
)

var (
	udpAssociationSlots = make(chan struct{}, maxUDPAssociations)
	udpRelaySlots       = make(chan struct{}, maxUDPRelays)
	errUDPRelayLimit    = errors.New("udp relay capacity reached")
)

// Tracks the UDP relay state for a single SOCKS5 UDP ASSOCIATE session.
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

// Represents a single UDP relay connection to one remote target.
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
	ip    net.IP // Cached domain result; nil for IP targets and DNS misses.
}

// Handles a SOCKS5 UDP ASSOCIATE command: binds a UDP socket,
// advertises the relay address to the client, and forwards datagrams until the
// TCP control connection closes or the idle timeout fires.
func (s *server) handleUDPAssociate(ctx context.Context, cliConn net.Conn) {
	select {
	case udpAssociationSlots <- struct{}{}:
		defer func() { <-udpAssociationSlots }()
	default:
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}

	// Validate the TCP control connection's remote address before committing
	// to any response so we can send a proper error reply if the check fails.
	tcpRemote, ok := cliConn.RemoteAddr().(*net.TCPAddr)
	if !ok || tcpRemote.IP == nil {
		log.Println("The server failed to determine the UDP association client address.")
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	controlIP, ok := netip.AddrFromSlice(tcpRemote.IP)
	if !ok {
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	controlIP = controlIP.Unmap()

	// Use the actual local address of the TCP control connection so the UDP
	// association uses the same interface the client reached unless a public
	// address override is configured.
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

	// Bind UDP on the wildcard address for the same IP family.
	// This avoids coupling the relay to a private/local interface address in NAT
	// or cloud environments while still keeping the family consistent.
	udpConn, err := net.ListenUDP("udp", udpWildcardAddrFor(publicIP))
	if err != nil {
		log.Printf("The server failed to listen on UDP: %v", err)
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	var udpCloseOnce sync.Once
	closeUDP := func() { udpCloseOnce.Do(func() { _ = udpConn.Close() }) }
	defer closeUDP()
	stopClosing := context.AfterFunc(ctx, closeUDP)
	defer stopClosing()

	resp, err := udpAssociateReply(udpConn, publicIP)
	if err != nil {
		log.Print(err)
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}

	if err := util.WriteAll(cliConn, resp); err != nil {
		log.Printf("The server failed to respond to the client after the UDP associate: %v", err)
		return
	}

	// RFC 1928 §6: the UDP association terminates when the TCP control
	// connection closes. Monitor it and close UDP when it drops.
	go func() {
		var buf [1]byte
		_, _ = cliConn.Read(buf[:])
		closeUDP()
	}()

	s.receiveUDPPackets(ctx, udpConn, controlIP)
}

// udpAssociateReply describes the bound relay using the advertised public IP.
func udpAssociateReply(udpConn *net.UDPConn, publicIP net.IP) ([]byte, error) {
	udpAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("The server failed to get the UDP local address.")
	}
	publicAddr := udpPublicAddrFor(publicIP, udpAddr.Port)
	if publicAddr.IP == nil {
		return nil, errors.New("The server failed to determine a valid public IP for UDP response.")
	}
	if publicAddr.Port == 0 {
		return nil, errors.New("The server bound UDP on port 0; cannot advertise a valid relay address.")
	}
	ip := publicAddr.IP.To4()
	addressType := util.AtypIPv4 /* IPv4. */
	if ip == nil {
		ip = publicAddr.IP.To16()
		addressType = util.AtypIPv6 /* IPv6. */
	}
	if ip == nil {
		return nil, errors.New("The server failed to normalize public IP for UDP response.")
	}

	var port [2]byte
	if !putPort(port[:], publicAddr.Port) {
		return nil, fmt.Errorf("The server got an invalid public UDP port %d.", publicAddr.Port)
	}

	// Pre-allocate: VER + REP + RSV + ATYP (4) + IP + PORT (2).
	resp := make([]byte, 0, 4+len(ip)+2)
	resp = append(resp, util.SocksVersion, 0x00, 0x00, addressType)
	resp = append(resp, ip...)
	resp = append(resp, port[:]...)

	return resp, nil
}

// receiveUDPPackets owns the queues, association, timer and workers. It returns
// after closing target sockets and waiting for every borrowed buffer to return.
func (s *server) receiveUDPPackets(ctx context.Context, udpConn *net.UDPConn, controlIP netip.Addr) {
	// Keep DNS waits away from IP and cached-domain traffic without reducing
	// the concurrency available to independent target sockets.
	jobs := make(chan udpPacketJob, 16)
	const forwardQueueWait = 100 * time.Microsecond
	var forwardTimer *time.Timer
	dnsJobs := make(chan udpPacketJob, 16)
	var workerWg sync.WaitGroup
	const maxConcurrentUDP = 4
	for i := 0; i < maxConcurrentUDP; i++ {
		workerWg.Add(1)
		go s.udpPacketWorker(jobs, &workerWg)
	}
	const maxConcurrentDNS = 4
	for i := 0; i < maxConcurrentDNS; i++ {
		workerWg.Add(1)
		go s.udpPacketWorker(dnsJobs, &workerWg)
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
		workerWg.Wait()
	}()

	// Only accepted client packets and target replies count as activity.
	// Renew the read deadline on timeout, not for every datagram.
	_ = udpConn.SetReadDeadline(time.Now().Add(udpAssociationIdleTimeout))

	for {
		buffer := util.BorrowUDPBuffer()
		buf := *buffer

		n, srcAddr, err := udpConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			util.ReturnUDPBuffer(buffer)
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
			util.ReturnUDPBuffer(buffer)
			continue
		}

		// Tie the UDP association to the TCP control connection's client IP.
		// After the first accepted UDP datagram, pin the full UDP source tuple.
		if !srcAddr.IsValid() {
			util.ReturnUDPBuffer(buffer)
			continue
		}
		if srcAddr.Addr().Unmap().WithZone("") != controlIP {
			util.ReturnUDPBuffer(buffer)
			continue
		}
		if !allowedSrc.IsValid() {
			allowedSrc = srcAddr
			assoc = newUDPAssociation(ctx, udpConn, net.UDPAddrFromAddrPort(srcAddr))
			if assoc == nil {
				util.ReturnUDPBuffer(buffer)
				continue
			}
		} else if srcAddr != allowedSrc {
			util.ReturnUDPBuffer(buffer)
			continue
		}

		assoc.activity.touch()

		job := udpPacketJob{assoc: assoc, buf: buffer, n: n}
		queue := jobs
		if buf[3] == util.AtypDomain {
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
		util.ReturnUDPBuffer(buffer)
	}
}

// Reuses a fixed goroutine to process queued UDP packets, avoiding
// per-datagram goroutine creation on the hot path.
func (s *server) udpPacketWorker(jobs <-chan udpPacketJob, workerWg *sync.WaitGroup) {
	defer workerWg.Done()
	for job := range jobs {
		if job.assoc.ctx.Err() == nil {
			s.handleUDPPacket(job.assoc, *job.buf, job.n, job.ip)
		}
		util.ReturnUDPBuffer(job.buf)
	}
}

// Validate the complete frame before pinning its source or refreshing activity.
func validUDPPacket(packet []byte) bool {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return false
	}
	var header int
	switch packet[3] {
	case util.AtypIPv4:
		header = 10
	case util.AtypIPv6:
		header = 22
	case util.AtypDomain:
		if len(packet) < 5 || packet[4] == 0 {
			return false
		}
		header = 7 + int(packet[4])
	default:
		return false
	}
	return len(packet) >= header
}

// Processes a single client UDP datagram: parses the SOCKS5 UDP header,
// resolves the destination, and forwards the payload via the relay socket.
//
// Hot-path design (IPv4/IPv6 with existing relay):
// 1. Build udpAddrKey directly from raw buffer bytes — zero heap allocations.
// 2. Call lookupRelay(key) under a read lock — no net.UDPAddr constructed.
// 3. Throttle SetWriteDeadline via atomic timestamp — at most one syscall per
// writeDeadlineRefresh interval instead of one per datagram.
//
// Cold path (new relay or domain target): allocates net.UDPAddr and dials.
func (s *server) handleUDPPacket(assoc *udpAssociation, buf []byte, n int, resolvedIP net.IP) {
	if assoc == nil {
		return
	}
	// The caller validated the complete header, RSV/FRAG == 0, and source IP.
	// A complete frame may carry a zero-length UDP payload.
	addressType := buf[3]

	// key is built from raw bytes without allocating a net.UDPAddr so that the
	// frequent case (relay already exists) is entirely allocation-free.
	var key udpAddrKey
	var headerLen int

	switch addressType {
	case util.AtypIPv4:
		if n < 10 {
			return
		}
		key = ipv4KeyFromBytes(buf[4:8], binary.BigEndian.Uint16(buf[8:10]))
		headerLen = 10

	case util.AtypDomain:
		// Domain targets use a small TTL cache to avoid resolving on every packet.
		if n < 5 {
			return
		}
		hostLen := int(buf[4])
		if hostLen == 0 || 5+hostLen+2 > n {
			return
		}
		host := string(buf[5 : 5+hostLen])
		port := int(binary.BigEndian.Uint16(buf[5+hostLen : 5+hostLen+2]))

		ip := resolvedIP
		if ip == nil {
			var err error
			ip, err = s.resolveUDPHost(assoc.ctx, host)
			if err != nil {
				log.Printf("UDP relay DNS lookup failed for %q: %v", host, err)
				return
			}
		}
		dstAddr := &net.UDPAddr{IP: ip, Port: port}
		var ok bool
		key, ok = makeUDPAddrKey(dstAddr)
		if !ok {
			log.Printf("UDP relay DNS lookup produced invalid target %v", dstAddr)
			return
		}
		headerLen = 5 + hostLen + 2
		payload := buf[headerLen:n]
		s.forwardUDPPayload(assoc, key, dstAddr, payload)
		return

	case util.AtypIPv6:
		if n < 22 {
			return
		}
		key = ipv6KeyFromBytes(buf[4:20], binary.BigEndian.Uint16(buf[20:22]))
		headerLen = 22

	default:
		return
	}

	payload := buf[headerLen:n]

	// Fast path: look up relay by key — no net.UDPAddr allocation.
	relay := assoc.lookupRelay(key)
	if relay == nil {
		// Slow path: relay does not yet exist; construct dst and dial.
		var dstAddr *net.UDPAddr
		switch addressType {
		case util.AtypIPv4:
			ip := make(net.IP, net.IPv4len)
			copy(ip, buf[4:8])
			dstAddr = &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(buf[8:10]))}
		case util.AtypIPv6:
			ip := make(net.IP, net.IPv6len)
			copy(ip, buf[4:20])
			dstAddr = &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(buf[20:22]))}
		}
		s.forwardUDPPayload(assoc, key, dstAddr, payload)
		return
	}

	s.writeUDPPayload(assoc, relay, payload)
}

// Obtains or creates the relay for (key, dst) and sends payload.
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

// Sends payload through relay, throttling SetWriteDeadline to at most once per
// writeDeadlineRefresh to avoid updating the deadline on every datagram.
func (s *server) writeUDPPayload(assoc *udpAssociation, relay *udpRelay, payload []byte) {
	const writeDeadlineRefresh = int64(10 * time.Second)
	const writeDeadlineDuration = 30 * time.Second

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

// Creates a udpAssociation for the given client UDP socket and address.
// Returns nil if either argument is nil.
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

// lookupRelay returns the existing relay for key under a read lock, or nil if none exists.
// This is the zero-allocation fast path: the caller already built key from raw buffer
// bytes, so no net.UDPAddr is allocated until a new relay actually needs to be dialled.
func (a *udpAssociation) lookupRelay(key udpAddrKey) *udpRelay {
	a.mu.RLock()
	relay := a.relays[key]
	a.mu.RUnlock()
	return relay
}

// Returns the existing relay for the pre-computed key or creates a new one by dialling dst.
// Safe for concurrent use; uses double-checked locking to minimise lock contention.
// The caller supplies the key to avoid recomputing it on every datagram.
func (a *udpAssociation) relayForKey(key udpAddrKey, dst *net.UDPAddr) (*udpRelay, error) {
	if a == nil {
		return nil, errors.New("nil udp association")
	}
	if dst == nil {
		return nil, errors.New("nil relay target address")
	}

	// Reserve both quotas before opening a socket. Pending dials count toward
	// the association limit and keep Close waiting until they release resources.
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, errors.New("udp association closed")
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
		return nil, errors.New("invalid udp relay target address")
	}
	relay := &udpRelay{
		assoc: a, key: key, target: cloneUDPAddr(dst),
		responseHeader: header, conn: conn,
		activity: idleClock{start: time.Now()},
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = conn.Close()
		return nil, errors.New("udp association closed")
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

// Removes relay from the association's map only if it is still the current entry.
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

// Closes all relay connections and waits for their goroutines to finish.
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
	a.relays = make(map[udpAddrKey]*udpRelay)
	a.mu.Unlock()

	for _, relay := range relays {
		relay.close()
	}
	a.wg.Wait()
}

// Reads datagrams from the remote target and forwards them back to the client.
func (r *udpRelay) readLoop() {
	if r.assoc == nil {
		return
	}
	defer r.assoc.wg.Done()
	defer func() { <-udpRelaySlots }()
	buffer := util.BorrowUDPBuffer()
	defer util.ReturnUDPBuffer(buffer)
	packetBuf := *buffer
	headerLen := len(r.responseHeader)
	if headerLen == 0 || headerLen >= len(packetBuf) {
		log.Printf("UDP relay: invalid response header length %d for %s", headerLen, r.target)
		r.assoc.removeRelay(r.key, r)
		r.close()
		return
	}
	copy(packetBuf[:headerLen], r.responseHeader)

	const writeDeadline = 30 * time.Second
	const writeDeadlineRefresh = 10 * time.Second
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

// Closes the relay's UDP connection exactly once.
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

// Relative monotonic time avoids wall-clock adjustments affecting expiration.
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
	ip        net.IP
	expiresAt time.Time
}

type dnsLookupCall struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int // Protected by dnsCache.mu.
	ip      net.IP
	err     error
}

// dnsCache caches UDP domain resolutions so repeated ATYP=DOMAIN packets do not
// synchronously hit the resolver on every datagram.
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

// Resolves a UDP target hostname with a small in-memory TTL cache tuned for
// the UDP relay hot path.
func (s *server) resolveUDPHost(parent context.Context, host string) (net.IP, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	if ip, ok := s.udpDNS.get(host, now); ok {
		return ip, nil
	}

	s.udpDNS.mu.Lock()
	if entry, ok := s.udpDNS.entries[host]; ok && entry.expiresAt.After(now) {
		ip := cloneIP(entry.ip)
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
			// A later caller must not join a lookup that has been cancelled.
			if s.udpDNS.inflight[host] == call {
				delete(s.udpDNS.inflight, host)
			}
		}
		s.udpDNS.mu.Unlock()
	}()
	select {
	case <-parent.Done():
		return nil, parent.Err()
	case <-call.done:
		return cloneIP(call.ip), call.err
	}
}

// Resolves once for all waiters. The query stops after five seconds or when
// its last waiter leaves; one association closing cannot cancel another's work.
func (s *server) lookupUDPHost(ctx context.Context, host string, call *dnsLookupCall) {
	defer call.cancel()
	ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	var resolvedIP net.IP
	if err == nil {
		for _, ipAddr := range ipAddrs {
			if ipAddr.IP != nil {
				resolvedIP = cloneIP(ipAddr.IP)
				break
			}
		}
		if resolvedIP == nil {
			err = errors.New("no ip address found")
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

func (c *dnsCache) get(host string, now time.Time) (net.IP, bool) {
	if c == nil || host == "" {
		return nil, false
	}
	c.mu.RLock()
	entry, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.After(now) {
		c.mu.Lock()
		if current, ok := c.entries[host]; ok && !current.expiresAt.After(now) {
			delete(c.entries, host)
		}
		c.mu.Unlock()
		return nil, false
	}
	return cloneIP(entry.ip), true
}

func (c *dnsCache) put(host string, ip net.IP, now time.Time) {
	if c == nil || host == "" || ip == nil {
		return
	}
	entry := dnsCacheEntry{
		ip:        cloneIP(ip),
		expiresAt: now.Add(udpDNSCacheTTL),
	}
	c.mu.Lock()
	if len(c.entries) >= udpDNSCacheMaxEntries {
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

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

const maxPortNumber = 65535

// udpAddrKey is a compact, hashable representation of a UDP address used as
// the relay map key. A fixed-size array avoids the heap allocation that
// net.UDPAddr.String() would incur on every lookup in the hot relay path.
// Bytes 0-15 hold the IPv4-in-IPv6 form of the IP (via To16()); bytes 16-17
// hold the port in big-endian. Zone is omitted: link-local scoped addresses
// are not expected in a SOCKS5 proxy relay.
type udpAddrKey [18]byte

// Converts a *net.UDPAddr to its compact key without any heap allocation.
// Returns false if addr is nil, has no IP, or has an invalid port.
func makeUDPAddrKey(addr *net.UDPAddr) (udpAddrKey, bool) {
	var k udpAddrKey
	if addr == nil || addr.IP == nil || addr.Port < 0 || addr.Port > maxPortNumber {
		return k, false
	}
	if ip16 := addr.IP.To16(); ip16 != nil {
		copy(k[:16], ip16)
	}
	binary.BigEndian.PutUint16(k[16:], uint16(addr.Port))
	return k, true
}

// Builds a udpAddrKey directly from a raw 4-byte IPv4 slice and port, matching
// the IPv4-mapped IPv6 encoding that net.IP.To16() produces. Avoids allocating
// a net.IP or net.UDPAddr in the hot UDP relay path.
func ipv4KeyFromBytes(ip4 []byte, port uint16) udpAddrKey {
	var k udpAddrKey
	// IPv4-mapped IPv6 prefix: 10 zero bytes, then 0xff 0xff, then the 4 IPv4 bytes.
	k[10] = 0xff
	k[11] = 0xff
	copy(k[12:16], ip4[:4])
	binary.BigEndian.PutUint16(k[16:], port)
	return k
}

// Builds a udpAddrKey directly from a raw 16-byte IPv6 slice and port,
// avoiding allocation in the hot UDP relay path.
func ipv6KeyFromBytes(ip6 []byte, port uint16) udpAddrKey {
	var k udpAddrKey
	copy(k[:16], ip6[:16])
	binary.BigEndian.PutUint16(k[16:], port)
	return k
}

// Builds the fixed SOCKS5 UDP response header for dst.
// The payload is written separately after this header on the hot path so
// relay responses avoid an extra payload copy.
func buildUDPResponseHeader(dst *net.UDPAddr) ([]byte, bool) {
	if dst == nil || dst.IP == nil {
		return nil, false
	}
	if dst.Port < 0 || dst.Port > maxPortNumber {
		return nil, false
	}

	if ip4 := dst.IP.To4(); ip4 != nil {
		header := make([]byte, 0, 3+1+len(ip4)+2)
		header = append(header, 0x00, 0x00, 0x00, util.AtypIPv4)
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
	header = append(header, 0x00, 0x00, 0x00, util.AtypIPv6)
	header = append(header, ip6...)
	var port [2]byte
	if !putPort(port[:], dst.Port) {
		return nil, false
	}
	header = append(header, port[:]...)
	return header, true
}

// Encodes port into dst in network byte order.
// Returns false if port is outside the valid TCP/UDP port range or dst is too small.
func putPort(dst []byte, port int) bool {
	if len(dst) < 2 || port < 0 || port > maxPortNumber {
		return false
	}
	binary.BigEndian.PutUint16(dst[:2], uint16(port))
	return true
}

// Returns a deep copy of addr, or nil if addr is nil.
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

// Returns a wildcard UDP bind address for the same IP family as ip.
func udpWildcardAddrFor(ip net.IP) *net.UDPAddr {
	if ip != nil && ip.To4() == nil && ip.To16() != nil {
		return &net.UDPAddr{IP: append(net.IP(nil), net.IPv6zero...)}
	}
	return &net.UDPAddr{IP: append(net.IP(nil), net.IPv4zero...)}
}

// Builds the public UDP address to advertise to clients,
// pairing the given IP with the OS-assigned port.
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
	bytes, err := os.ReadFile(confPath)
	if err != nil {
		log.Fatalf("The server failed to read the configuration file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(bytes, &config); err != nil {
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

	var auth *util.Credentials
	if config.Username != "" || config.Password != "" {
		auth = &util.Credentials{Username: config.Username, Password: config.Password}
		if err := auth.Validate(); err != nil {
			log.Fatal(err)
		}
	}

	s := NewServer(config.ListenAddr, config.PublicAddr, config.ServerPEM, config.ServerKey, config.ClientPEM)
	if s == nil {
		log.Fatalf("Failed to create server")
	}

	s.Auth = auth
	if err := s.ListenTLS(); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}

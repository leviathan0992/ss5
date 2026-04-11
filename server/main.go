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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	util "github.com/leviathan0992/ss5"
)

/* Holds the configuration and state for the SOCKS5-over-TLS server. */
type server struct {
	*util.Service
	publicIP  net.IP
	serverPEM string
	serverKEY string
	clientPEM string
	udpDNS    *dnsCache
}

const maxPortNumber = 65535
const udpDNSCacheTTL = 1 * time.Minute
const udpDNSCacheMaxEntries = 4096

type dnsCacheEntry struct {
	ip        net.IP
	expiresAt time.Time
}

type dnsLookupCall struct {
	done chan struct{}
	ip   net.IP
	err  error
}

/* dnsCache caches UDP domain resolutions so repeated ATYP=DOMAIN packets do not
 * synchronously hit the resolver on every datagram. */
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

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
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

/* Resolves a UDP target hostname with a small in-memory TTL cache tuned for
 * the UDP relay hot path. */
func (s *server) resolveUDPHost(host string) (net.IP, error) {
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
	if call, ok := s.udpDNS.inflight[host]; ok {
		s.udpDNS.mu.Unlock()
		<-call.done
		if call.err != nil {
			return nil, call.err
		}
		return cloneIP(call.ip), nil
	}
	call := &dnsLookupCall{done: make(chan struct{})}
	s.udpDNS.inflight[host] = call
	s.udpDNS.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	cancel()
	if err != nil {
		s.udpDNS.mu.Lock()
		delete(s.udpDNS.inflight, host)
		call.err = err
		close(call.done)
		s.udpDNS.mu.Unlock()
		return nil, err
	}

	var resolvedIP net.IP
	for _, ipAddr := range ipAddrs {
		if ipAddr.IP != nil {
			resolvedIP = cloneIP(ipAddr.IP)
			break
		}
	}
	if resolvedIP == nil {
		err = errors.New("no ip address found")
		s.udpDNS.mu.Lock()
		delete(s.udpDNS.inflight, host)
		call.err = err
		close(call.done)
		s.udpDNS.mu.Unlock()
		return nil, err
	}

	s.udpDNS.put(host, resolvedIP, now)
	s.udpDNS.mu.Lock()
	delete(s.udpDNS.inflight, host)
	call.ip = cloneIP(resolvedIP)
	close(call.done)
	s.udpDNS.mu.Unlock()
	return resolvedIP, nil
}

/* udpAddrKey is a compact, hashable representation of a UDP address used as
 * the relay map key. A fixed-size array avoids the heap allocation that
 * net.UDPAddr.String() would incur on every lookup in the hot relay path.
 * Bytes 0-15 hold the IPv4-in-IPv6 form of the IP (via To16()); bytes 16-17
 * hold the port in big-endian. Zone is omitted: link-local scoped addresses
 * are not expected in a SOCKS5 proxy relay. */
type udpAddrKey [18]byte

/* Converts a *net.UDPAddr to its compact key without any heap allocation.
 * Returns false if addr is nil, has no IP, or has an invalid port. */
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

/* Builds a udpAddrKey directly from a raw 4-byte IPv4 slice and port, matching
 * the IPv4-mapped IPv6 encoding that net.IP.To16() produces. Avoids allocating
 * a net.IP or net.UDPAddr in the hot UDP relay path. */
func ipv4KeyFromBytes(ip4 []byte, port uint16) udpAddrKey {
	var k udpAddrKey
	/* IPv4-mapped IPv6 prefix: 10 zero bytes, then 0xff 0xff, then the 4 IPv4 bytes. */
	k[10] = 0xff
	k[11] = 0xff
	copy(k[12:16], ip4[:4])
	binary.BigEndian.PutUint16(k[16:], port)
	return k
}

/* Builds a udpAddrKey directly from a raw 16-byte IPv6 slice and port,
 * avoiding allocation in the hot UDP relay path. */
func ipv6KeyFromBytes(ip6 []byte, port uint16) udpAddrKey {
	var k udpAddrKey
	copy(k[:16], ip6[:16])
	binary.BigEndian.PutUint16(k[16:], port)
	return k
}

/* Tracks the UDP relay state for a single SOCKS5 UDP ASSOCIATE session. */
type udpAssociation struct {
	clientConn *net.UDPConn
	clientAddr *net.UDPAddr

	/* mu protects closed and relays. Use RLock for read-only relay lookups so
	 * concurrent high-traffic sessions don't serialize on a single write lock. */
	mu     sync.RWMutex
	closed bool
	relays map[udpAddrKey]*udpRelay
	wg     sync.WaitGroup
}

/* Represents a single UDP relay connection to one remote target. */
type udpRelay struct {
	assoc          *udpAssociation
	key            udpAddrKey
	target         *net.UDPAddr
	responseHeader []byte
	conn           *net.UDPConn
	closeOnce      sync.Once
	/* lastWriteDeadline stores the last time SetWriteDeadline was issued as Unix
	 * nanoseconds. Accessed atomically to throttle setsockopt syscalls without
	 * a mutex: at most one call per writeDeadlineRefresh interval per relay. */
	lastWriteDeadline atomic.Int64
}

/* udpPacketJob is one client UDP datagram queued for worker processing. */
type udpPacketJob struct {
	assoc *udpAssociation
	buf   []byte
	n     int
}

const udpAssociationIdleTimeout = 5 * time.Minute

/* Encodes port into dst in network byte order.
 * Returns false if port is outside the valid TCP/UDP port range or dst is too small. */
func putPort(dst []byte, port int) bool {
	if len(dst) < 2 || port < 0 || port > maxPortNumber {
		return false
	}
	binary.BigEndian.PutUint16(dst[:2], uint16(port))
	return true
}

/* Reuses one dialer across all CONNECT requests. net.Dialer is safe for
 * concurrent use, so a single instance avoids one heap allocation per request. */
var tcpDialer = &net.Dialer{Timeout: 30 * time.Second}

/* Builds the fixed SOCKS5 UDP response header for dst.
 * The payload is written separately after this header on the hot path so
 * relay responses avoid an extra payload copy. */
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

/* Returns a deep copy of addr, or nil if addr is nil. */
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

/* Returns a wildcard UDP bind address for the same IP family as ip. */
func udpWildcardAddrFor(ip net.IP) *net.UDPAddr {
	if ip != nil && ip.To4() == nil && ip.To16() != nil {
		return &net.UDPAddr{IP: append(net.IP(nil), net.IPv6zero...)}
	}
	return &net.UDPAddr{IP: append(net.IP(nil), net.IPv4zero...)}
}

/* Builds the public UDP address to advertise to clients,
 * pairing the given IP with the OS-assigned port. */
func udpPublicAddrFor(localIP net.IP, port int) *net.UDPAddr {
	addr := &net.UDPAddr{Port: port}
	if localIP != nil {
		addr.IP = append(net.IP(nil), localIP...)
	}
	return addr
}

/* Creates a udpAssociation for the given client UDP socket and address.
 * Returns nil if either argument is nil. */
func newUDPAssociation(clientConn *net.UDPConn, clientAddr *net.UDPAddr) *udpAssociation {
	if clientConn == nil || clientAddr == nil {
		return nil
	}
	return &udpAssociation{
		clientConn: clientConn,
		clientAddr: cloneUDPAddr(clientAddr),
		relays:     make(map[udpAddrKey]*udpRelay),
	}
}

/* lookupRelay returns the existing relay for key under a read lock, or nil if none exists.
 * This is the zero-allocation fast path: the caller already built key from raw buffer
 * bytes, so no net.UDPAddr is allocated until a new relay actually needs to be dialled. */
func (a *udpAssociation) lookupRelay(key udpAddrKey) *udpRelay {
	a.mu.RLock()
	relay := a.relays[key]
	a.mu.RUnlock()
	return relay
}

/* Returns the existing relay for the pre-computed key or creates a new one by dialling dst.
 * Safe for concurrent use; uses double-checked locking to minimise lock contention.
 * Callers that already have the key should prefer this over relayFor to avoid
 * recomputing makeUDPAddrKey inside the method. */
func (a *udpAssociation) relayForKey(key udpAddrKey, dst *net.UDPAddr) (*udpRelay, error) {
	if a == nil {
		return nil, errors.New("nil udp association")
	}
	if dst == nil {
		return nil, errors.New("nil relay target address")
	}

	/* Fast path: take a read lock to check for an existing relay. */
	a.mu.RLock()
	if a.closed {
		a.mu.RUnlock()
		return nil, errors.New("udp association closed")
	}
	if relay, ok := a.relays[key]; ok {
		a.mu.RUnlock()
		return relay, nil
	}
	a.mu.RUnlock()

	/* Dial outside the lock: for UDP this is a non-blocking syscall, but we
	 * still avoid holding a mutex during any I/O operation. */
	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return nil, err
	}
	responseHeader, ok := buildUDPResponseHeader(dst)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("invalid udp relay target address")
	}

	relay := &udpRelay{
		assoc:          a,
		key:            key,
		target:         cloneUDPAddr(dst),
		responseHeader: responseHeader,
		conn:           conn,
	}

	/* Slow path: take the write lock to insert the new relay. */
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		_ = conn.Close()
		return nil, errors.New("udp association closed")
	}
	if existing, ok := a.relays[key]; ok {
		/* Another goroutine raced and created a relay for this target first. */
		a.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	a.relays[key] = relay
	a.wg.Add(1)
	a.mu.Unlock()

	go relay.readLoop()
	return relay, nil
}

/* Removes relay from the association's map only if it is still the current entry. */
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

/* Closes all relay connections and waits for their goroutines to finish. */
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
	a.relays = make(map[udpAddrKey]*udpRelay)
	a.mu.Unlock()

	for _, relay := range relays {
		relay.close()
	}
	a.wg.Wait()
}

/* Closes the relay's UDP connection exactly once. */
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

/* Reads datagrams from the remote target and forwards them back to the client. */
func (r *udpRelay) readLoop() {
	if r.assoc == nil {
		return
	}
	defer r.assoc.wg.Done()
	packetBuf := util.GetUDPBuffer()
	defer util.PutUDPBuffer(packetBuf)
	headerLen := len(r.responseHeader)
	if headerLen == 0 || headerLen >= len(packetBuf) {
		log.Printf("UDP relay: invalid response header length %d for %s", headerLen, r.target)
		r.assoc.removeRelay(r.key, r)
		r.close()
		return
	}
	copy(packetBuf[:headerLen], r.responseHeader)

	/* Refresh read/write deadlines at most once per minute instead of once per
	 * packet. Under high UDP traffic this eliminates O(PPS) setsockopt syscalls
	 * while keeping the effective idle timeout within [idleTimeout, idleTimeout+refresh]. */
	const readDeadlineRefresh = 1 * time.Minute
	const writeDeadline = 30 * time.Second
	const writeDeadlineRefresh = 10 * time.Second

	now := time.Now()
	_ = r.conn.SetReadDeadline(now.Add(udpAssociationIdleTimeout))
	_ = r.assoc.clientConn.SetWriteDeadline(now.Add(writeDeadline))
	lastReadDeadline := now
	lastWriteDeadline := now

	for {
		nRead, _, _, _, err := r.conn.ReadMsgUDP(packetBuf[headerLen:], nil)
		if err != nil {
			/* Timeout and closed-connection errors are expected during shutdown; log the rest. */
			var netErr net.Error
			if !errors.Is(err, net.ErrClosed) && !(errors.As(err, &netErr) && netErr.Timeout()) {
				log.Printf("UDP relay read error for %s: %v", r.target, err)
			}
			r.assoc.removeRelay(r.key, r)
			r.close()
			return
		}

		/* Refresh the read deadline periodically so the relay stays alive
		 * as long as traffic flows. */
		now = time.Now()
		if now.Sub(lastReadDeadline) > readDeadlineRefresh {
			_ = r.conn.SetReadDeadline(now.Add(udpAssociationIdleTimeout))
			lastReadDeadline = now
		}

		total := headerLen + nRead

		/* Refresh the write deadline periodically so a slow client does not
		 * stall the relay goroutine indefinitely. */
		if now.Sub(lastWriteDeadline) > writeDeadlineRefresh {
			_ = r.assoc.clientConn.SetWriteDeadline(now.Add(writeDeadline))
			lastWriteDeadline = now
		}
		if _, err := r.assoc.clientConn.WriteToUDP(packetBuf[:total], r.assoc.clientAddr); err != nil {
			log.Printf("UDP relay: failed to forward response to client %s: %v", r.assoc.clientAddr, err)
			r.assoc.removeRelay(r.key, r)
			r.close()
			return
		}
	}
}

/* Reuses a fixed goroutine to process queued UDP packets, avoiding
 * per-datagram goroutine creation on the hot path. */
func (s *server) udpPacketWorker(jobs <-chan udpPacketJob, workerWg *sync.WaitGroup) {
	defer workerWg.Done()
	for job := range jobs {
		s.handleUDPPacket(job.assoc, job.buf, job.n)
		util.PutUDPBuffer(job.buf)
	}
}

/* Parses or resolves publicAddr to an IP address.
 * Returns nil, nil if publicAddr is empty. */
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

/* Constructs a server from the given configuration parameters.
 * Returns nil and logs an error if any parameter is invalid. */
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

/* Loads TLS credentials, starts accepting connections, and dispatches
 * each to handleTLSConn. Returns when a shutdown signal is received. */
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
		_ = listener.Close()
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
			_ = cliConn.Close()
		}
	}
}

/* Maps a dial error to the appropriate SOCKS5 reply code per RFC 1928. */
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

/* Handles a single TLS client connection: parses the SOCKS5
 * handshake and dispatches to CONNECT or UDP ASSOCIATE handling. */
func (s *server) handleTLSConn(cliConn net.Conn) {
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
		targetAddr := addr.String()

		/* Attempt to connect to the destination address with a 30 s timeout. */
		dstConn, err := tcpDialer.Dial("tcp", targetAddr)
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

		_ = tcpDst.SetKeepAlive(true)
		_ = tcpDst.SetKeepAlivePeriod(30 * time.Second)
		/* SetLinger(0) discards unacknowledged data on close for a fast reset. */
		_ = tcpDst.SetLinger(0)
		_ = tcpDst.SetNoDelay(true)
		_ = tcpDst.SetReadBuffer(128 * 1024)
		_ = tcpDst.SetWriteBuffer(128 * 1024)

		/* Build and send the SOCKS5 success reply with the outgoing bound address. */
		boundAddr, ok := tcpDst.LocalAddr().(*net.TCPAddr)
		if !ok {
			util.SendSOCKS5Reply(cliConn, 0x01)
			return
		}
		var resp []byte
		if ip4 := boundAddr.IP.To4(); ip4 != nil {
			/* IPv4 response: VER + REP + RSV + ATYP (4) + IP (4) + PORT (2) = 10 bytes. */
			resp = make([]byte, 0, 10)
			resp = append(resp, util.SocksVersion, 0x00, 0x00, util.AtypIPv4)
			resp = append(resp, ip4...)
		} else {
			ip6 := boundAddr.IP.To16()
			if ip6 == nil {
				util.SendSOCKS5Reply(cliConn, 0x01)
				return
			}
			/* IPv6 response: VER + REP + RSV + ATYP (4) + IP (16) + PORT (2) = 22 bytes. */
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

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()

			/* TLS -> TCP: Splice offers no benefit for TLS. */
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

			/* TCP -> TLS. */
			if err := s.TransferToTLS(tcpDst, cliConn); err != nil {
				log.Printf("The connection closed: %v", err)
			}

			/* Unblock the TLS->TCP goroutine which is reading from cliConn.
			 * Use SetReadDeadline instead of Close to avoid double-close with
			 * the deferred cliConn.Close() in handleTLSConn. */
			_ = cliConn.SetReadDeadline(time.Now())
		}()

		wg.Wait()

	case util.CmdUDPAssociate:
		s.handleUDPAssociate(cliConn)

	default:
		log.Printf("Unexpected SOCKS5 command after parse: 0x%02x", cmd)
		util.SendSOCKS5Reply(cliConn, 0x07)
	}
}

/* Handles a SOCKS5 UDP ASSOCIATE command: binds a UDP socket,
 * advertises the relay address to the client, and forwards datagrams until the
 * TCP control connection closes or the idle timeout fires. */
func (s *server) handleUDPAssociate(cliConn net.Conn) {
	/* Validate the TCP control connection's remote address before committing
	 * to any response so we can send a proper error reply if the check fails. */
	tcpRemote, ok := cliConn.RemoteAddr().(*net.TCPAddr)
	if !ok || tcpRemote.IP == nil {
		log.Println("The server failed to determine the UDP association client address.")
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}

	/* Use the actual local address of the TCP control connection so the UDP
	 * association uses the same interface the client reached unless a public
	 * address override is configured. */
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

	/* Bind UDP on the wildcard address for the same IP family.
	 * This avoids coupling the relay to a private/local interface address in NAT
	 * or cloud environments while still keeping the family consistent. */
	udpConn, err := net.ListenUDP("udp", udpWildcardAddrFor(publicIP))
	if err != nil {
		log.Printf("The server failed to listen on UDP: %v", err)
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	var udpCloseOnce sync.Once
	closeUDP := func() { udpCloseOnce.Do(func() { _ = udpConn.Close() }) }
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
	if publicAddr.Port == 0 {
		log.Println("The server bound UDP on port 0; cannot advertise a valid relay address.")
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}
	ip := publicAddr.IP.To4()
	addressType := util.AtypIPv4 /* IPv4. */
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
	if !putPort(port[:], publicAddr.Port) {
		log.Printf("The server got an invalid public UDP port %d.", publicAddr.Port)
		util.SendSOCKS5Reply(cliConn, 0x01)
		return
	}

	/* Pre-allocate: VER + REP + RSV + ATYP (4) + IP + PORT (2). */
	resp := make([]byte, 0, 4+len(ip)+2)
	resp = append(resp, util.SocksVersion, 0x00, 0x00, addressType)
	resp = append(resp, ip...)
	resp = append(resp, port[:]...)

	if err := util.WriteAll(cliConn, resp); err != nil {
		log.Printf("The server failed to respond to the client after the UDP associate: %v", err)
		return
	}

	/* RFC 1928 §6: the UDP association terminates when the TCP control
	 * connection closes. Monitor it and close UDP when it drops. */
	go func() {
		var buf [1]byte
		_, _ = cliConn.Read(buf[:])
		closeUDP()
	}()

	/* Use a fixed worker pool and bounded queue to avoid one goroutine per
	 * datagram while still dropping packets under sustained overload. */
	const maxConcurrentUDP = 64
	jobs := make(chan udpPacketJob, maxConcurrentUDP)
	var workerWg sync.WaitGroup
	for i := 0; i < maxConcurrentUDP; i++ {
		workerWg.Add(1)
		go s.udpPacketWorker(jobs, &workerWg)
	}
	var allowedSrc *net.UDPAddr
	var assoc *udpAssociation
	defer func() {
		close(jobs)
		workerWg.Wait()
		if assoc != nil {
			assoc.Close()
		}
	}()

	/* The read deadline is refreshed at most once per minute rather than once per
	 * packet to avoid a setsockopt syscall on every datagram. The effective idle
	 * timeout stays within [idleTimeout, idleTimeout + deadlineRefresh]. When the
	 * deadline fires and ReadFromUDP returns an error, handleUDPAssociate returns,
	 * which triggers defer cliConn.Close() in handleTLSConn and thereby unblocks
	 * the TCP-monitor goroutine — no separate deadline is needed there. */
	const deadlineRefresh = 1 * time.Minute
	now := time.Now()
	_ = udpConn.SetReadDeadline(now.Add(udpAssociationIdleTimeout))
	lastDeadline := now

	for {
		buf := util.GetUDPBuffer()

		n, srcAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			util.PutUDPBuffer(buf)
			return
		}

		/* Refresh the deadline periodically so active associations are not
		 * torn down prematurely, but without a syscall on every datagram. */
		now = time.Now()
		if now.Sub(lastDeadline) > deadlineRefresh {
			_ = udpConn.SetReadDeadline(now.Add(udpAssociationIdleTimeout))
			lastDeadline = now
		}

		/* Minimal packet: 3 bytes RSV/FRAG + 1 byte ATYP + 4 bytes IPv4 + 2 bytes port. */
		if n < (3 + 1 + 4 + 2) {
			util.PutUDPBuffer(buf)
			continue
		}

		if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
			/* SOCKS5 UDP requires zero RSV/FRAG; fragmentation is not supported. */
			util.PutUDPBuffer(buf)
			continue
		}

		/* Tie the UDP association to the TCP control connection's client IP.
		 * After the first accepted UDP datagram, pin the full UDP source tuple. */
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

		/* Queue UDP packet for worker processing; drop packet if the queue is full. */
		select {
		case jobs <- udpPacketJob{assoc: assoc, buf: buf, n: n}:
		default:
			util.PutUDPBuffer(buf)
			continue
		}
	}
}

/* Processes a single client UDP datagram: parses the SOCKS5 UDP header,
 * resolves the destination, and forwards the payload via the relay socket.
 *
 * Hot-path design (IPv4/IPv6 with existing relay):
 *   1. Build udpAddrKey directly from raw buffer bytes — zero heap allocations.
 *   2. Call lookupRelay(key) under a read lock — no net.UDPAddr constructed.
 *   3. Throttle SetWriteDeadline via atomic timestamp — at most one syscall per
 *      writeDeadlineRefresh interval instead of one per datagram.
 *
 * Cold path (new relay or domain target): allocates net.UDPAddr and dials. */
func (s *server) handleUDPPacket(assoc *udpAssociation, buf []byte, n int) {
	if assoc == nil {
		return
	}
	/* The caller validated n >= 10, RSV/FRAG == 0, and source IP authorization.
	 * Per-type length checks below are defensive for non-IPv4 address types. */
	addressType := buf[3]

	/* key is built from raw bytes without allocating a net.UDPAddr so that the
	 * frequent case (relay already exists) is entirely allocation-free. */
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
		/* Domain targets use a small TTL cache to avoid resolving on every packet. */
		if n < 5 {
			return
		}
		hostLen := int(buf[4])
		if hostLen == 0 || 5+hostLen+2 > n {
			return
		}
		host := string(buf[5 : 5+hostLen])
		port := int(binary.BigEndian.Uint16(buf[5+hostLen : 5+hostLen+2]))

		ip, err := s.resolveUDPHost(host)
		if err != nil {
			log.Printf("UDP relay DNS lookup failed for %q: %v", host, err)
			return
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
		if len(payload) == 0 {
			return
		}
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
	if len(payload) == 0 {
		return
	}

	/* Fast path: look up relay by key — no net.UDPAddr allocation. */
	relay := assoc.lookupRelay(key)
	if relay == nil {
		/* Slow path: relay does not yet exist; construct dst and dial. */
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

/* Obtains or creates the relay for (key, dst) and sends payload. */
func (s *server) forwardUDPPayload(assoc *udpAssociation, key udpAddrKey, dst *net.UDPAddr, payload []byte) {
	relay, err := assoc.relayForKey(key, dst)
	if err != nil {
		log.Printf("UDP relay setup failed for %s: %v", dst, err)
		return
	}
	s.writeUDPPayload(assoc, relay, payload)
}

/* Sends payload through relay, throttling SetWriteDeadline to at most once per
 * writeDeadlineRefresh to avoid a syscall on every datagram. */
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

	s := NewServer(config.ListenAddr, config.PublicAddr, config.ServerPEM, config.ServerKey, config.ClientPEM)
	if s == nil {
		log.Fatalf("Failed to create server")
	}

	if err := s.ListenTLS(); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}

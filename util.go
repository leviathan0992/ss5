// Package ss5 provides the shared SOCKS5-over-TLS proxy primitives
// used by both the client and server binaries.
package ss5

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// SOCKS5 protocol constants per RFC 1928.
const (
	SocksVersion    byte = 0x05
	CmdConnect      byte = 0x01
	CmdUDPAssociate byte = 0x03
	AtypIPv4        byte = 0x01
	AtypDomain      byte = 0x03
	AtypIPv6        byte = 0x04
)

// Holds the shared configuration embedded by both the client and server.
type Service struct {
	ListenAddr *net.TCPAddr
	Auth       *Credentials
}

// Credentials are exchanged only inside the existing authenticated TLS channel.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c Credentials) Validate() error {
	if len(c.Username) < 1 || len(c.Username) > 255 || len(c.Password) < 1 || len(c.Password) > 255 {
		return errors.New("SOCKS5 username and password must each contain 1 to 255 bytes")
	}
	return nil
}

// NegotiateServer selects exactly the configured authentication method. It does
// not consume any bytes of the CONNECT or UDP ASSOCIATE request that follows.
func NegotiateServer(conn io.ReadWriter, auth *Credentials) error {
	method := byte(0)
	if auth != nil {
		if err := auth.Validate(); err != nil {
			return err
		}
		method = 2
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != SocksVersion || header[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}
	var methods [255]byte
	if _, err := io.ReadFull(conn, methods[:int(header[1])]); err != nil {
		return err
	}
	if bytes.IndexByte(methods[:int(header[1])], method) < 0 {
		if err := WriteAll(conn, []byte{SocksVersion, 255}); err != nil {
			return err
		}
		return errors.New("required SOCKS5 authentication method not offered")
	}
	if err := WriteAll(conn, []byte{SocksVersion, method}); err != nil {
		return err
	}
	if auth == nil {
		return nil
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 1 || header[1] == 0 {
		_ = WriteAll(conn, []byte{1, 1})
		return errors.New("invalid SOCKS5 authentication request")
	}
	var username, password [255]byte
	nu := int(header[1])
	if _, err := io.ReadFull(conn, username[:nu]); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return err
	}
	np := int(header[0])
	if np == 0 {
		_ = WriteAll(conn, []byte{1, 1})
		return errors.New("invalid SOCKS5 authentication request")
	}
	if _, err := io.ReadFull(conn, password[:np]); err != nil {
		return err
	}
	gotUser, wantUser := sha256.Sum256(username[:nu]), sha256.Sum256([]byte(auth.Username))
	gotPass, wantPass := sha256.Sum256(password[:np]), sha256.Sum256([]byte(auth.Password))
	ok := subtle.ConstantTimeCompare(gotUser[:], wantUser[:]) & subtle.ConstantTimeCompare(gotPass[:], wantPass[:])
	if ok != 1 {
		_ = WriteAll(conn, []byte{1, 1})
		return errors.New("SOCKS5 authentication failed")
	}
	return WriteAll(conn, []byte{1, 0})
}

// NegotiateClient never falls back to no-auth when credentials are configured.
func NegotiateClient(conn io.ReadWriter, auth *Credentials) error {
	method := byte(0)
	if auth != nil {
		if err := auth.Validate(); err != nil {
			return err
		}
		method = 2
	}
	if err := WriteAll(conn, []byte{SocksVersion, 1, method}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{SocksVersion, method} {
		return errors.New("upstream rejected required SOCKS5 authentication method")
	}
	if auth == nil {
		return nil
	}
	request := make([]byte, 0, 3+len(auth.Username)+len(auth.Password))
	request = append(request, 1, byte(len(auth.Username)))
	request = append(request, auth.Username...)
	request = append(request, byte(len(auth.Password)))
	request = append(request, auth.Password...)
	if err := WriteAll(conn, request); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{1, 0} {
		return errors.New("upstream SOCKS5 authentication failed")
	}
	return nil
}

// Stores one parsed SOCKS5 target address without forcing domain names to be
// resolved during protocol parsing.
type socksTargetAddr struct {
	atyp byte
	host string
	ip   net.IP
	port int
}

// Returns the internal SOCKS5 address flavor.
func (a *socksTargetAddr) Network() string {
	return "socks5"
}

// Formats the target as host:port or ip:port for dialing/logging.
func (a *socksTargetAddr) String() string {
	if a == nil {
		return ""
	}
	host := a.host
	if host == "" && a.ip != nil {
		host = a.ip.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(a.port))
}

// Reads and validates the SOCKS5 handshake from a TLS connection,
// returning the target address and the requested command (CmdConnect or CmdUDPAssociate).
func (s *Service) ParseSOCKS5FromTLS(cliConn net.Conn) (net.Addr, byte, error) {
	buf := socks5Pool.Get()
	defer socks5Pool.Put(buf)

	if err := NegotiateServer(cliConn, s.Auth); err != nil {
		return nil, 0, err
	}

	// Phase 2: Read the connection request header (VER, CMD, RSV, ATYP).
	if _, err := io.ReadFull(cliConn, buf[:4]); err != nil {
		return nil, 0x00, fmt.Errorf("failed to read SOCKS5 request header: %w", err)
	}

	if buf[0] != SocksVersion {
		SendSOCKS5Reply(cliConn, 0x01) /* 0x01 = general SOCKS server failure */
		return nil, 0x00, fmt.Errorf("unsupported SOCKS5 version in request: 0x%02x", buf[0])
	}
	// RSV must be 0x00 per RFC 1928.
	if buf[2] != 0x00 {
		SendSOCKS5Reply(cliConn, 0x01)
		return nil, 0x00, fmt.Errorf("SOCKS5 request has non-zero RSV field: 0x%02x", buf[2])
	}

	cmd := buf[1]
	// CMD: 0x01=CONNECT, 0x03=UDP ASSOCIATE.
	if cmd != CmdConnect && cmd != CmdUDPAssociate {
		SendSOCKS5Reply(cliConn, 0x07) /* 0x07 = command not supported */
		return nil, 0x00, fmt.Errorf("unsupported SOCKS5 command: 0x%02x", cmd)
	}

	target := &socksTargetAddr{}

	switch buf[3] {
	case AtypIPv4: /* IPv4: 4 bytes. */
		if _, err := io.ReadFull(cliConn, buf[:4+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read IPv4 address and port: %w", err)
		}
		// Copy IP and port immediately: buf is pooled and must not be referenced after return.
		ip4 := make(net.IP, net.IPv4len)
		copy(ip4, buf[:4])
		target.atyp = AtypIPv4
		target.ip = ip4
		target.port = int(binary.BigEndian.Uint16(buf[4:6]))

	case AtypDomain: /* Domain name. */
		if _, err := io.ReadFull(cliConn, buf[:1]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read domain length: %w", err)
		}
		domainLen := int(buf[0])
		if domainLen == 0 {
			SendSOCKS5Reply(cliConn, 0x01)
			return nil, 0x00, errors.New("SOCKS5 domain address has zero length")
		}

		// Read domain + 2 bytes port.
		if _, err := io.ReadFull(cliConn, buf[:domainLen+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read domain and port: %w", err)
		}

		target.atyp = AtypDomain
		target.host = string(buf[:domainLen])
		target.port = int(binary.BigEndian.Uint16(buf[domainLen : domainLen+2]))

	case AtypIPv6: /* IPv6: 16 bytes. */
		if _, err := io.ReadFull(cliConn, buf[:16+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read IPv6 address and port: %w", err)
		}
		// Copy IP and port immediately: buf is pooled and must not be referenced after return.
		ip6 := make(net.IP, net.IPv6len)
		copy(ip6, buf[:16])
		target.atyp = AtypIPv6
		target.ip = ip6
		target.port = int(binary.BigEndian.Uint16(buf[16:18]))

	default:
		SendSOCKS5Reply(cliConn, 0x08) /* 0x08 = address type not supported */
		return nil, 0x00, fmt.Errorf("unknown address type: 0x%02x", buf[3])
	}

	if target.host == "" && target.ip == nil {
		SendSOCKS5Reply(cliConn, 0x01)
		return nil, 0x00, errors.New("empty SOCKS5 target address")
	}

	return target, cmd, nil
}

// Sends a SOCKS5 reply with the given reply code.
func SendSOCKS5Reply(conn net.Conn, rep byte) {
	// Use a stack-allocated array to avoid a heap allocation on the error path.
	reply := [10]byte{SocksVersion, rep, 0x00, AtypIPv4}
	_ = WriteAll(conn, reply[:])
}

// Writes all bytes in buf to conn, looping until all bytes are written.
func WriteAll(conn io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if n > 0 {
			buf = buf[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// The buffer size used to relay TCP data.
const ConnectionBuffer = 64 * 1024

// The buffer size used to relay UDP payloads.
const UDPBuffer = 64 * 1024

// The buffer size used to parse SOCKS5 handshakes.
const Socks5Buffer = 8 * 1024

// Reuses fixed-size buffers without repeated allocations.
type bufferPool struct {
	pool sync.Pool
	size int
}

var (
	bytePool   = newBufferPool(ConnectionBuffer)
	udpPool    = newBufferPool(UDPBuffer)
	socks5Pool = newBufferPool(Socks5Buffer)
)

// Creates a pool of fixed-size byte slices. size must be positive.
func newBufferPool(size int) *bufferPool {
	if size <= 0 {
		panic("bufferPool: size must be positive")
	}
	return &bufferPool{
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
		size: size,
	}
}

// Pulls one buffer from the pool.
func (p *bufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

// Returns buf to the pool. Buffers of the wrong capacity are discarded.
// Only return buffers of the correct capacity to avoid memory bloat.
// Reslice to full capacity so the next Get returns the full buffer.
func (p *bufferPool) Put(buf []byte) {
	if cap(buf) == p.size {
		buf = buf[:cap(buf)]
		p.pool.Put(&buf)
	}
}

// Returns a buffer from the UDP pool sized for a maximum UDP datagram.
func GetUDPBuffer() []byte {
	return udpPool.Get()
}

// Returns a buffer obtained via GetUDPBuffer back to the pool.
func PutUDPBuffer(buf []byte) {
	udpPool.Put(buf)
}

// BorrowUDPBuffer retains the pooled slice header as well as its backing array.
// Transfer ownership with the pointer and return it exactly once after use.
// Unlike GetUDPBuffer/PutUDPBuffer, this avoids allocating a new header per packet.
func BorrowUDPBuffer() *[]byte {
	return udpPool.pool.Get().(*[]byte)
}

func ReturnUDPBuffer(buf *[]byte) {
	if buf != nil && cap(*buf) == UDPBuffer {
		*buf = (*buf)[:UDPBuffer]
		udpPool.pool.Put(buf)
	}
}

const relayIdleTimeout = 5 * time.Minute

const relayWriteTimeout = 30 * time.Second

// ConfigureTCPConn applies the TCP settings shared by accepted clients and targets.
// Socket options are best effort and do not abort connection setup on failure.
func ConfigureTCPConn(conn *net.TCPConn) {
	_ = conn.SetKeepAlive(true)
	_ = conn.SetKeepAlivePeriod(30 * time.Second)
	_ = conn.SetNoDelay(true)
	_ = conn.SetReadBuffer(128 * 1024)
	_ = conn.SetWriteBuffer(128 * 1024)
}

// CloseConnection interrupts blocked I/O without waiting for a TLS close alert.
// Normal EOF is propagated separately with CloseWrite.
func CloseConnection(conn net.Conn) {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		_ = tlsConn.NetConn().Close()
	} else {
		_ = conn.Close()
	}
}

// Relay preserves half-closes and treats activity in either direction as active
// use of the tunnel. A blocked write has its own, shorter deadline.
func Relay(a, b net.Conn) error {
	return relay(a, b, relayIdleTimeout)
}

// RelayClient leaves idle expiration to the server's protocol handler. UDP
// traffic does not pass through its TCP control connection, so TCP silence
// alone cannot determine whether the session is idle. After either direction
// ends, the remaining half of the stream must still make progress.
func RelayClient(a, b net.Conn) error {
	return relay(a, b, 0)
}

func relay(a, b net.Conn, idleTimeout time.Duration) error {
	var once sync.Once
	closeBoth := func() { once.Do(func() { CloseConnection(a); CloseConnection(b) }) }
	defer closeBoth()
	_ = a.SetDeadline(time.Time{})
	_ = b.SetDeadline(time.Time{})
	start := time.Now()
	var activity atomic.Int64
	touch := func() {
		now := time.Since(start).Nanoseconds()
		for previous := activity.Load(); now > previous; previous = activity.Load() {
			if activity.CompareAndSwap(previous, now) {
				return
			}
		}
	}
	results := make(chan error, 2)
	pump := func(src, dst net.Conn) {
		err := copyStream(src, dst, touch)
		if err == nil {
			if half, ok := dst.(interface{ CloseWrite() error }); ok {
				err = half.CloseWrite()
			}
		}
		if err != nil {
			closeBoth()
		}
		results <- err
	}
	go pump(a, b)
	go pump(b, a)
	var timer *time.Timer
	var idle <-chan time.Time
	if idleTimeout > 0 {
		timer = time.NewTimer(idleTimeout)
		idle = timer.C
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	var first error
	for completed := 0; completed < 2; {
		select {
		case err := <-results:
			completed++
			if timer == nil && completed == 1 {
				touch()
				idleTimeout = relayIdleTimeout
				timer = time.NewTimer(idleTimeout)
				idle = timer.C
			}
			if first == nil && err != nil && !errors.Is(err, net.ErrClosed) {
				first = err
			}
		case <-idle:
			remaining := idleTimeout - (time.Since(start) - time.Duration(activity.Load()))
			if remaining > 0 {
				timer.Reset(remaining)
			} else {
				first = context.DeadlineExceeded
				closeBoth()
			}
		}
	}
	return first
}

func copyStream(src, dst net.Conn, touch func()) error {
	buf := bytePool.Get()
	defer bytePool.Put(buf)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			touch()
			_ = dst.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
			if writeErr := WriteAll(dst, buf[:n]); writeErr != nil {
				return writeErr
			}
			touch()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

const shutdownGracePeriod = 10 * time.Second

const shutdownCleanupPeriod = 5 * time.Second

// Serve stops accepting on cancellation, drains existing sessions, then cancels
// their work and closes remaining sockets after the grace period.
func Serve(stop context.Context, listener net.Listener, limit int, handle func(context.Context, net.Conn)) error {
	work, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopClosing := context.AfterFunc(stop, func() { _ = listener.Close() })
	defer stopClosing()
	defer listener.Close()
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	var wg sync.WaitGroup
	var acceptErr error
	for {
		conn, err := listener.Accept()
		if err != nil {
			if stop.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			if temporary, ok := err.(net.Error); ok && temporary.Temporary() {
				log.Printf("Accept temporarily failed: %v", err)
				select {
				case <-stop.Done():
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			acceptErr = err
			break
		}
		mu.Lock()
		if stop.Err() != nil || len(active) >= limit {
			mu.Unlock()
			CloseConnection(conn)
			continue
		}
		active[conn] = struct{}{}
		wg.Add(1)
		mu.Unlock()
		go func(conn net.Conn) {
			defer wg.Done()
			defer func() {
				CloseConnection(conn)
				mu.Lock()
				delete(active, conn)
				mu.Unlock()
			}()
			handle(work, conn)
		}(conn)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	timer := time.NewTimer(shutdownGracePeriod)
	defer timer.Stop()
	select {
	case <-done:
		return acceptErr
	case <-timer.C:
	}
	cancel()
	mu.Lock()
	for conn := range active {
		CloseConnection(conn)
	}
	mu.Unlock()
	timer.Reset(shutdownCleanupPeriod)
	select {
	case <-done:
		return acceptErr
	case <-timer.C:
		return errors.New("connection cleanup exceeded shutdown deadline")
	}
}

// TransferToTCP copies a single direction with its own idle deadline.
// Deprecated: use Relay for bidirectional tunnels with shared activity.
func (s *Service) TransferToTCP(srcConn net.Conn, dstConn *net.TCPConn) error {
	return copyConn(srcConn, dstConn)
}

// TransferToTLS copies a single direction with its own idle deadline.
// Deprecated: use Relay for bidirectional tunnels with shared activity.
func (s *Service) TransferToTLS(tcpSrc *net.TCPConn, tlsDst net.Conn) error {
	return copyConn(tcpSrc, tlsDst)
}

// Copies data from src to dst while refreshing idle deadlines.
func copyConn(src, dst net.Conn) error {
	buf := bytePool.Get()
	defer bytePool.Put(buf)

	// Set initial deadline before the first read to guard against an immediate stall.
	const idleTimeout = 5 * time.Minute
	const deadlineInterval = 30 * time.Second
	now := time.Now()
	_ = src.SetReadDeadline(now.Add(idleTimeout))
	_ = dst.SetWriteDeadline(now.Add(idleTimeout))
	lastDeadlineUpdate := now

	for {
		// Refresh deadline less frequently to reduce syscall overhead.
		if time.Since(lastDeadlineUpdate) > deadlineInterval {
			now = time.Now()
			_ = src.SetReadDeadline(now.Add(idleTimeout))
			_ = dst.SetWriteDeadline(now.Add(idleTimeout))
			lastDeadlineUpdate = now
		}

		n, err := src.Read(buf)
		if n > 0 {
			if wErr := WriteAll(dst, buf[:n]); wErr != nil {
				return wErr
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			// Treat timeout as clean shutdown: idle timeout and deadline-based
			// signaling (e.g. SetReadDeadline(time.Now())) are expected events.
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil
			}
			return err
		}
	}
}

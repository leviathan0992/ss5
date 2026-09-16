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

// Service holds the listener address and optional SOCKS5 credentials shared by
// the client and server. A nil Auth disables SOCKS5 username/password authentication.
type Service struct {
	ListenAddr *net.TCPAddr
	Auth       *Credentials
}

// Credentials holds a SOCKS5 username and password for use over authenticated TLS.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Validate checks that the username and password each contain 1 to 255 bytes.
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

// socksTargetAddr holds a SOCKS5 target without resolving domain names.
type socksTargetAddr struct {
	host string
	ip   net.IP
	port int
}

// Network returns "socks5".
func (a *socksTargetAddr) Network() string {
	return "socks5"
}

// String returns the target in host:port form, or an empty string for a nil receiver.
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

// ParseSOCKS5FromTLS authenticates the client and reads one SOCKS5 request.
// It returns the target address and command without consuming application data.
func (s *Service) ParseSOCKS5FromTLS(clientConn net.Conn) (net.Addr, byte, error) {
	if err := NegotiateServer(clientConn, s.Auth); err != nil {
		return nil, 0, err
	}

	buffer := socks5Pool.Get()
	defer socks5Pool.Put(buffer)
	buf := *buffer

	// The request header contains VER, CMD, RSV and ATYP (RFC 1928).
	if _, err := io.ReadFull(clientConn, buf[:4]); err != nil {
		return nil, 0x00, fmt.Errorf("failed to read SOCKS5 request header: %w", err)
	}
	if buf[0] != SocksVersion {
		SendSOCKS5Reply(clientConn, 0x01) // 0x01 = general SOCKS server failure
		return nil, 0x00, fmt.Errorf("unsupported SOCKS5 version in request: 0x%02x", buf[0])
	}
	// RSV must be 0x00 per RFC 1928.
	if buf[2] != 0x00 {
		SendSOCKS5Reply(clientConn, 0x01)
		return nil, 0x00, fmt.Errorf("SOCKS5 request has non-zero RSV field: 0x%02x", buf[2])
	}

	cmd := buf[1]
	if cmd != CmdConnect && cmd != CmdUDPAssociate {
		SendSOCKS5Reply(clientConn, 0x07) // 0x07 = command not supported
		return nil, 0x00, fmt.Errorf("unsupported SOCKS5 command: 0x%02x", cmd)
	}

	target := &socksTargetAddr{}
	switch buf[3] {
	case AtypIPv4:
		if _, err := io.ReadFull(clientConn, buf[:4+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read IPv4 address and port: %w", err)
		}
		// Copy IP and port immediately: buf is pooled and must not be referenced after return.
		ip4 := make(net.IP, net.IPv4len)
		copy(ip4, buf[:4])
		target.ip = ip4
		target.port = int(binary.BigEndian.Uint16(buf[4:6]))

	case AtypDomain:
		if _, err := io.ReadFull(clientConn, buf[:1]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read domain length: %w", err)
		}
		domainLen := int(buf[0])
		if domainLen == 0 {
			SendSOCKS5Reply(clientConn, 0x01)
			return nil, 0x00, errors.New("SOCKS5 domain address has zero length")
		}

		if _, err := io.ReadFull(clientConn, buf[:domainLen+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read domain and port: %w", err)
		}
		target.host = string(buf[:domainLen])
		target.port = int(binary.BigEndian.Uint16(buf[domainLen : domainLen+2]))

	case AtypIPv6:
		if _, err := io.ReadFull(clientConn, buf[:16+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read IPv6 address and port: %w", err)
		}
		// Copy IP and port immediately: buf is pooled and must not be referenced after return.
		ip6 := make(net.IP, net.IPv6len)
		copy(ip6, buf[:16])
		target.ip = ip6
		target.port = int(binary.BigEndian.Uint16(buf[16:18]))

	default:
		SendSOCKS5Reply(clientConn, 0x08) // 0x08 = address type not supported
		return nil, 0x00, fmt.Errorf("unknown address type: 0x%02x", buf[3])
	}

	return target, cmd, nil
}

// SendSOCKS5Reply sends rep with an unspecified IPv4 bind address.
// It ignores write errors because callers use it before closing failed requests.
func SendSOCKS5Reply(conn net.Conn, rep byte) {
	reply := [10]byte{SocksVersion, rep, 0x00, AtypIPv4}
	_ = WriteAll(conn, reply[:])
}

// WriteAll writes all bytes in buf to conn or returns the first write error.
// It returns io.ErrShortWrite if a write returns no bytes and no error.
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

// ConnectionBuffer is the size in bytes of a TCP relay buffer.
const ConnectionBuffer = 64 * 1024

// UDPBuffer is the size in bytes of a UDP relay buffer.
const UDPBuffer = 64 * 1024

// Socks5Buffer is the size in bytes of a SOCKS5 parsing buffer.
// The parser reuses it for the header and for up to 255 domain bytes plus a port.
const Socks5Buffer = 255 + 2

// bufferPool reuses fixed-size byte slices and is safe for concurrent use.
type bufferPool struct {
	pool sync.Pool
	size int
}

var (
	bytePool   = newBufferPool(ConnectionBuffer)
	udpPool    = newBufferPool(UDPBuffer)
	socks5Pool = newBufferPool(Socks5Buffer)
)

// newBufferPool returns a pool of size-byte buffers. It panics if size is not positive.
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

// Get returns a pooled slice header and its fixed-size backing array.
// The caller must return the same pointer with Put after use.
func (p *bufferPool) Get() *[]byte {
	return p.pool.Get().(*[]byte)
}

// Put returns buf to the pool, restoring its length to the configured size.
// Nil pointers and buffers with a different capacity are discarded.
func (p *bufferPool) Put(buf *[]byte) {
	if buf != nil && cap(*buf) == p.size {
		*buf = (*buf)[:p.size]
		p.pool.Put(buf)
	}
}

// BorrowUDPBuffer returns a pooled slice header and its UDPBuffer-byte backing array.
// Ownership transfers with the pointer; return it exactly once with ReturnUDPBuffer.
func BorrowUDPBuffer() *[]byte {
	return udpPool.Get()
}

// ReturnUDPBuffer returns a buffer obtained from BorrowUDPBuffer to the pool.
// The caller must not use the buffer or its slice after returning it.
func ReturnUDPBuffer(buf *[]byte) {
	udpPool.Put(buf)
}

const (
	relayIdleTimeout  = 5 * time.Minute
	relayWriteTimeout = 30 * time.Second
)

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
	closeBoth := func() {
		once.Do(func() {
			CloseConnection(a)
			CloseConnection(b)
		})
	}
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
	buffer := bytePool.Get()
	defer bytePool.Put(buffer)
	buf := *buffer

	for {
		n, err := src.Read(buf)
		if n > 0 {
			touch()
			_ = dst.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
			if err := WriteAll(dst, buf[:n]); err != nil {
				return err
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

const (
	shutdownGracePeriod   = 10 * time.Second
	shutdownCleanupPeriod = 5 * time.Second
)

// Serve stops accepting on cancellation, drains existing sessions, then cancels
// their work and closes remaining sockets after the grace period.
// Serve owns the listener and closes each accepted connection when its handler returns.
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
	go func() {
		wg.Wait()
		close(done)
	}()
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

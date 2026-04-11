/* Package ss5 provides the shared SOCKS5-over-TLS proxy primitives
 * used by both the client and server binaries. */
package ss5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

/* The buffer size used to relay TCP data. */
const ConnectionBuffer = 64 * 1024

/* The buffer size used to relay UDP payloads. */
const UDPBuffer = 64 * 1024

/* The buffer size used to parse SOCKS5 handshakes. */
const Socks5Buffer = 8 * 1024

/* SOCKS5 protocol constants per RFC 1928. */
const (
	SocksVersion    byte = 0x05
	CmdConnect      byte = 0x01
	CmdUDPAssociate byte = 0x03
	AtypIPv4        byte = 0x01
	AtypDomain      byte = 0x03
	AtypIPv6        byte = 0x04
)

/* Reuses fixed-size buffers without repeated allocations. */
type bufferPool struct {
	pool sync.Pool
	size int
}

/* Creates a pool of fixed-size byte slices. size must be positive. */
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

/* Pulls one buffer from the pool. */
func (p *bufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

/* Returns buf to the pool. Buffers of the wrong capacity are discarded.
 * Only return buffers of the correct capacity to avoid memory bloat.
 * Reslice to full capacity so the next Get returns the full buffer. */
func (p *bufferPool) Put(buf []byte) {
	if cap(buf) == p.size {
		buf = buf[:cap(buf)]
		p.pool.Put(&buf)
	}
}

var (
	bytePool   = newBufferPool(ConnectionBuffer)
	udpPool    = newBufferPool(UDPBuffer)
	socks5Pool = newBufferPool(Socks5Buffer)
)

/* Holds the shared configuration embedded by both the client and server. */
type Service struct {
	ListenAddr *net.TCPAddr
}

/* Stores one parsed SOCKS5 target address without forcing domain names to be
 * resolved during protocol parsing. */
type socksTargetAddr struct {
	atyp byte
	host string
	ip   net.IP
	port int
}

/* Returns the internal SOCKS5 address flavor. */
func (a *socksTargetAddr) Network() string {
	return "socks5"
}

/* Formats the target as host:port or ip:port for dialing/logging. */
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

/* Writes all bytes in buf to conn, looping until all bytes are written. */
func WriteAll(conn net.Conn, buf []byte) error {
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

/* Sends a SOCKS5 reply with the given reply code. */
func SendSOCKS5Reply(conn net.Conn, rep byte) {
	/* Use a stack-allocated array to avoid a heap allocation on the error path. */
	reply := [10]byte{SocksVersion, rep, 0x00, AtypIPv4}
	_ = WriteAll(conn, reply[:])
}

/* Copies data from src to dst while refreshing idle deadlines. */
func copyConn(src, dst net.Conn) error {
	buf := bytePool.Get()
	defer bytePool.Put(buf)

	/* Set initial deadline before the first read to guard against an immediate stall. */
	const idleTimeout = 5 * time.Minute
	const deadlineInterval = 30 * time.Second
	now := time.Now()
	_ = src.SetReadDeadline(now.Add(idleTimeout))
	_ = dst.SetWriteDeadline(now.Add(idleTimeout))
	lastDeadlineUpdate := now

	for {
		/* Refresh deadline less frequently to reduce syscall overhead. */
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
			/* Treat timeout as clean shutdown: idle timeout and deadline-based
			 * signaling (e.g. SetReadDeadline(time.Now())) are expected events. */
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil
			}
			return err
		}
	}
}

/* Copies data from a TLS connection to a TCP connection. */
func (s *Service) TransferToTCP(srcConn net.Conn, dstConn *net.TCPConn) error {
	return copyConn(srcConn, dstConn)
}

/* Copies data from a TCP connection to a TLS connection. */
func (s *Service) TransferToTLS(tcpSrc *net.TCPConn, tlsDst net.Conn) error {
	return copyConn(tcpSrc, tlsDst)
}

/* Returns a buffer from the UDP pool sized for a maximum UDP datagram. */
func GetUDPBuffer() []byte {
	return udpPool.Get()
}

/* Returns a buffer obtained via GetUDPBuffer back to the pool. */
func PutUDPBuffer(buf []byte) {
	udpPool.Put(buf)
}

/* Reads and validates the SOCKS5 handshake from a TLS connection,
 * returning the target address and the requested command (CmdConnect or CmdUDPAssociate). */
func (s *Service) ParseSOCKS5FromTLS(cliConn net.Conn) (net.Addr, byte, error) {
	buf := socks5Pool.Get()
	defer socks5Pool.Put(buf)

	/* Phase 1: Read the client greeting (version + method list). */
	if _, err := io.ReadFull(cliConn, buf[:2]); err != nil {
		return nil, 0x00, fmt.Errorf("failed to read SOCKS5 greeting header: %w", err)
	}

	/* Verify SOCKS5 version (0x05). */
	if buf[0] != SocksVersion {
		return nil, 0x00, fmt.Errorf("unsupported SOCKS version in greeting: 0x%02x", buf[0])
	}

	nMethods := int(buf[1])
	if nMethods == 0 {
		return nil, 0x00, errors.New("SOCKS5 greeting has zero methods")
	}
	/* Read the methods list. */
	if _, err := io.ReadFull(cliConn, buf[:nMethods]); err != nil {
		return nil, 0x00, fmt.Errorf("failed to read SOCKS5 methods: %w", err)
	}

	if bytes.IndexByte(buf[:nMethods], 0x00) < 0 {
		if err := WriteAll(cliConn, []byte{SocksVersion, 0xFF}); err != nil {
			return nil, 0x00, fmt.Errorf("failed to reject unsupported SOCKS5 methods: %w", err)
		}
		return nil, 0x00, errors.New("client does not offer SOCKS5 no-authentication method")
	}

	/* Reply: SOCKS5, no authentication required. */
	if err := WriteAll(cliConn, []byte{SocksVersion, 0x00}); err != nil {
		return nil, 0x00, fmt.Errorf("failed to respond to SOCKS5 greeting: %w", err)
	}

	/* Phase 2: Read the connection request header (VER, CMD, RSV, ATYP). */
	if _, err := io.ReadFull(cliConn, buf[:4]); err != nil {
		return nil, 0x00, fmt.Errorf("failed to read SOCKS5 request header: %w", err)
	}

	if buf[0] != SocksVersion {
		SendSOCKS5Reply(cliConn, 0x01) /* 0x01 = general SOCKS server failure */
		return nil, 0x00, fmt.Errorf("unsupported SOCKS5 version in request: 0x%02x", buf[0])
	}
	/* RSV must be 0x00 per RFC 1928. */
	if buf[2] != 0x00 {
		SendSOCKS5Reply(cliConn, 0x01)
		return nil, 0x00, fmt.Errorf("SOCKS5 request has non-zero RSV field: 0x%02x", buf[2])
	}

	cmd := buf[1]
	/* CMD: 0x01=CONNECT, 0x03=UDP ASSOCIATE. */
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
		/* Copy IP and port immediately: buf is pooled and must not be referenced after return. */
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

		/* Read domain + 2 bytes port. */
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
		/* Copy IP and port immediately: buf is pooled and must not be referenced after return. */
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

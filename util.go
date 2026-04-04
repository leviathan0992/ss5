/* Provides the shared SOCKS5-over-TLS proxy primitives used by both binaries. */
package ss5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

/* Stores the buffer size used to relay TCP data. */
const ConnectionBuffer = 64 * 1024

/* Stores the buffer size used to relay UDP payloads. */
const UDPBuffer = 64 * 1024

/* Stores the buffer size used to parse SOCKS5 handshakes. */
const Socks5Buffer = 8 * 1024

/* Defines SOCKS5 protocol constants per RFC 1928. */
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

func newBufferPool(size int) *bufferPool {
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

func (p *bufferPool) Put(buf []byte) {
	/* Only return buffers of the correct capacity to avoid memory bloat.
	 * Reslice to full capacity so the next Get returns the full buffer. */
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
	reply := []byte{SocksVersion, rep, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
	_ = WriteAll(conn, reply)
}

/* Copies data from src to dst while refreshing idle deadlines. */
func copyConn(src, dst net.Conn) error {
	buf := bytePool.Get()
	defer bytePool.Put(buf)

	/* Set initial deadline before the first read to guard against an immediate stall. */
	const idleTimeout = 5 * time.Minute
	const deadlineInterval = 30 * time.Second
	_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
	_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
	lastDeadlineUpdate := time.Now()

	for {
		/* Refresh deadline less frequently to reduce syscall overhead. */
		if time.Since(lastDeadlineUpdate) > deadlineInterval {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			lastDeadlineUpdate = time.Now()
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

func (s *Service) TransferToTCP(srcConn net.Conn, dstConn *net.TCPConn) error {
	return copyConn(srcConn, dstConn)
}

func (s *Service) TransferToTLS(tcpSrc *net.TCPConn, tlsDst net.Conn) error {
	return copyConn(tcpSrc, tlsDst)
}

func GetUDPBuffer() []byte {
	return udpPool.Get()
}

func PutUDPBuffer(buf []byte) {
	udpPool.Put(buf)
}

func (s *Service) ParseSOCKS5FromTLS(cliConn net.Conn) (net.Addr, byte, error) {
	buf := socks5Pool.Get()
	defer socks5Pool.Put(buf)

	/* Phase 1: Read client greeting. */
	/* Read version and nMethods first (2 bytes). */
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

	hasNoAuth := false
	for _, method := range buf[:nMethods] {
		if method == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		if err := WriteAll(cliConn, []byte{SocksVersion, 0xFF}); err != nil {
			return nil, 0x00, fmt.Errorf("failed to reject unsupported SOCKS5 methods: %w", err)
		}
		return nil, 0x00, errors.New("client does not offer SOCKS5 no-authentication method")
	}

	/* Reply: SOCKS5, no authentication required. */
	if err := WriteAll(cliConn, []byte{SocksVersion, 0x00}); err != nil {
		return nil, 0x00, fmt.Errorf("failed to respond to SOCKS5 greeting: %w", err)
	}

	/* Phase 2: Read connection request. */
	/* Read header up to ATYP (4 bytes). */
	if _, err := io.ReadFull(cliConn, buf[:4]); err != nil {
		return nil, 0x00, fmt.Errorf("failed to read SOCKS5 request header: %w", err)
	}

	if buf[0] != SocksVersion {
		SendSOCKS5Reply(cliConn, 0x01) /* 0x01 = general SOCKS server failure */
		return nil, 0x00, fmt.Errorf("unsupported SOCKS5 version in request: 0x%02x", buf[0])
	}

	cmd := buf[1]
	/* CMD: 0x01=CONNECT, 0x03=UDP ASSOCIATE. */
	if cmd != CmdConnect && cmd != CmdUDPAssociate {
		SendSOCKS5Reply(cliConn, 0x07) /* 0x07 = command not supported */
		return nil, 0x00, fmt.Errorf("unsupported SOCKS5 command: 0x%02x", cmd)
	}

	var dstIP []byte
	var port int

	switch buf[3] {
	case AtypIPv4: /* IPv4: 4 bytes. */
		if _, err := io.ReadFull(cliConn, buf[:4+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read IPv4 address and port: %w", err)
		}
		/* Copy IP and port immediately: buf is pooled and must not be referenced after return. */
		ip4 := make(net.IP, net.IPv4len)
		copy(ip4, buf[:4])
		dstIP = ip4
		port = int(binary.BigEndian.Uint16(buf[4:6]))

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

		domain := string(buf[:domainLen])
		port = int(binary.BigEndian.Uint16(buf[domainLen : domainLen+2]))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		if err != nil || len(ipAddrs) == 0 {
			SendSOCKS5Reply(cliConn, 0x04) /* 0x04 = host unreachable */
			if err != nil {
				return nil, 0x00, fmt.Errorf("failed to resolve domain %q: %w", domain, err)
			}
			return nil, 0x00, fmt.Errorf("failed to resolve domain %q", domain)
		}

		resolvedIP := make(net.IP, len(ipAddrs[0].IP))
		copy(resolvedIP, ipAddrs[0].IP)
		dstIP = resolvedIP

	case AtypIPv6: /* IPv6: 16 bytes. */
		if _, err := io.ReadFull(cliConn, buf[:16+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read IPv6 address and port: %w", err)
		}
		/* Copy IP and port immediately: buf is pooled and must not be referenced after return. */
		ip6 := make(net.IP, net.IPv6len)
		copy(ip6, buf[:16])
		dstIP = ip6
		port = int(binary.BigEndian.Uint16(buf[16:18]))

	default:
		SendSOCKS5Reply(cliConn, 0x08) /* 0x08 = address type not supported */
		return nil, 0x00, fmt.Errorf("unknown address type: 0x%02x", buf[3])
	}

	var dstAddr net.Addr
	if cmd == CmdConnect {
		dstAddr = &net.TCPAddr{IP: dstIP, Port: port}
	} else {
		dstAddr = &net.UDPAddr{IP: dstIP, Port: port}
	}

	return dstAddr, cmd, nil
}

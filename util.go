package ss5

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

/* The buffer (64KB) is used after successful authentication between the connections. */
const ConnectionBuffer = 64 * 1024

/* The buffer (64KB) is used for relaying UDP payloads. */
const UDPBuffer = 64 * 1024

/* The buffer (8KB) is used for parsing SOCKS5. */
const Socks5Buffer = 8 * 1024

/* SOCKS5 Protocol Constants */
const (
	SocksVersion    = 0x05
	CmdConnect      = 0x01
	CmdUDPAssociate = 0x03
	AtypIPv4        = 0x01
	AtypDomain      = 0x03
	AtypIPv6        = 0x04
)

/* Strongly-typed buffer pool wrappers to eliminate type assertion overhead. */
type bufferPool struct {
	pool sync.Pool
	size int
}

func newBufferPool(size int) *bufferPool {
	return &bufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
		size: size,
	}
}

/* sync.Pool.Get never returns nil when New is set, so no nil check needed. */
func (p *bufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *bufferPool) Put(buf []byte) {
	/* Only return buffers of the correct size to avoid memory bloat. */
	if len(buf) == p.size {
		p.pool.Put(buf)
	}
}

var bytePool = newBufferPool(ConnectionBuffer)
var udpPool = newBufferPool(UDPBuffer)
var socks5Pool = newBufferPool(Socks5Buffer)

type Service struct {
	ListenAddr   *net.TCPAddr
	ServerAddrs  []*net.TCPAddr
	stableServer atomic.Pointer[net.TCPAddr]
}

/* GetStableServer returns the current stable server address (thread-safe). */
func (s *Service) GetStableServer() *net.TCPAddr {
	return s.stableServer.Load()
}

/* SetStableServer updates the stable server address (thread-safe). */
func (s *Service) SetStableServer(addr *net.TCPAddr) {
	s.stableServer.Store(addr)
}

func writeAll(conn net.Conn, buf []byte) error {
	for len(buf) > 0 {
		n, err := conn.Write(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

func (s *Service) TLSWrite(conn net.Conn, buf []byte) error {
	return writeAll(conn, buf)
}

/* SendSOCKS5Reply sends a SOCKS5 reply with the given reply code. */
func SendSOCKS5Reply(conn net.Conn, rep byte) {
	reply := []byte{SocksVersion, rep, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
	_ = writeAll(conn, reply)
}

func (s *Service) TransferToTCP(srcConn net.Conn, dstConn *net.TCPConn) error {
	buf := bytePool.Get()
	defer bytePool.Put(buf)

	/* Set initial deadline before the first read to guard against an immediate stall. */
	const idleTimeout = 5 * time.Minute
	const deadlineInterval = 30 * time.Second
	_ = srcConn.SetReadDeadline(time.Now().Add(idleTimeout))
	_ = dstConn.SetWriteDeadline(time.Now().Add(idleTimeout))
	lastDeadlineUpdate := time.Now()

	for {
		/* Refresh deadline less frequently to reduce syscall overhead. */
		if time.Since(lastDeadlineUpdate) > deadlineInterval {
			_ = srcConn.SetReadDeadline(time.Now().Add(idleTimeout))
			_ = dstConn.SetWriteDeadline(time.Now().Add(idleTimeout))
			lastDeadlineUpdate = time.Now()
		}

		n, err := srcConn.Read(buf)
		if n > 0 {
			if wErr := writeAll(dstConn, buf[:n]); wErr != nil {
				return wErr
			}
		}

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func (s *Service) TransferToTLS(dstConn *net.TCPConn, srcConn net.Conn) error {
	buf := bytePool.Get()
	defer bytePool.Put(buf)

	/* Set initial deadline before the first read to guard against an immediate stall. */
	const idleTimeout = 5 * time.Minute
	const deadlineInterval = 30 * time.Second
	_ = dstConn.SetReadDeadline(time.Now().Add(idleTimeout))
	_ = srcConn.SetWriteDeadline(time.Now().Add(idleTimeout))
	lastDeadlineUpdate := time.Now()

	for {
		if time.Since(lastDeadlineUpdate) > deadlineInterval {
			_ = dstConn.SetReadDeadline(time.Now().Add(idleTimeout))
			_ = srcConn.SetWriteDeadline(time.Now().Add(idleTimeout))
			lastDeadlineUpdate = time.Now()
		}

		n, err := dstConn.Read(buf)
		if n > 0 {
			if wErr := writeAll(srcConn, buf[:n]); wErr != nil {
				return wErr
			}
		}

		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
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
		return nil, 0x00, errors.New("currently only supporting the SOCKS5 protocol")
	}

	nMethods := int(buf[1])
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
		if err := s.TLSWrite(cliConn, []byte{SocksVersion, 0xFF}); err != nil {
			return nil, 0x00, fmt.Errorf("failed to reject unsupported SOCKS5 methods: %w", err)
		}
		return nil, 0x00, errors.New("client does not offer SOCKS5 no-authentication method")
	}

	/* Reply: SOCKS5, no authentication required. */
	if err := s.TLSWrite(cliConn, []byte{SocksVersion, 0x00}); err != nil {
		return nil, 0x00, fmt.Errorf("failed to respond to SOCKS5 greeting: %w", err)
	}

	/* Phase 2: Read connection request. */
	/* Read header up to ATYP (4 bytes). */
	if _, err := io.ReadFull(cliConn, buf[:4]); err != nil {
		return nil, 0x00, fmt.Errorf("failed to read SOCKS5 request header: %w", err)
	}

	cmd := buf[1]
	/* CMD: 0x01=CONNECT, 0x03=UDP ASSOCIATE. */
	if cmd != CmdConnect && cmd != CmdUDPAssociate {
		SendSOCKS5Reply(cliConn, 0x07) /* 0x07 = command not supported */
		return nil, 0x00, fmt.Errorf("unsupported SOCKS5 command: 0x%02x", cmd)
	}

	var dstIP []byte
	var portBytes []byte

	switch buf[3] {
	case AtypIPv4: /* IPv4: 4 bytes. */
		if _, err := io.ReadFull(cliConn, buf[:4+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read IPv4 address and port: %w", err)
		}
		/* Copy IP bytes: buf is a pooled slice returned after this function exits. */
		ip4 := make(net.IP, net.IPv4len)
		copy(ip4, buf[:4])
		dstIP = ip4
		portBytes = buf[4:6]

	case AtypDomain: /* Domain name. */
		if _, err := io.ReadFull(cliConn, buf[:1]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read domain length: %w", err)
		}
		domainLen := int(buf[0])

		/* Read domain + 2 bytes port. */
		if _, err := io.ReadFull(cliConn, buf[:domainLen+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read domain and port: %w", err)
		}

		domain := string(buf[:domainLen])
		portBytes = buf[domainLen : domainLen+2]

		/* Use context with timeout for DNS resolution. */
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resolver := net.Resolver{}
		ips, err := resolver.LookupIPAddr(ctx, domain)
		if err != nil {
			SendSOCKS5Reply(cliConn, 0x04) /* 0x04 = host unreachable */
			return nil, 0x00, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
		}
		if len(ips) == 0 {
			SendSOCKS5Reply(cliConn, 0x04) /* 0x04 = host unreachable */
			return nil, 0x00, fmt.Errorf("domain %s resolved to no IP addresses", domain)
		}
		dstIP = ips[0].IP

	case AtypIPv6: /* IPv6: 16 bytes. */
		if _, err := io.ReadFull(cliConn, buf[:16+2]); err != nil {
			return nil, 0x00, fmt.Errorf("failed to read IPv6 address and port: %w", err)
		}
		/* Copy IP bytes: buf is a pooled slice returned after this function exits. */
		ip6 := make(net.IP, net.IPv6len)
		copy(ip6, buf[:16])
		dstIP = ip6
		portBytes = buf[16:18]

	default:
		SendSOCKS5Reply(cliConn, 0x08) /* 0x08 = address type not supported */
		return nil, 0x00, fmt.Errorf("unknown address type: 0x%02x", buf[3])
	}

	var dstAddr net.Addr
	port := int(binary.BigEndian.Uint16(portBytes))

	if cmd == CmdConnect {
		dstAddr = &net.TCPAddr{IP: dstIP, Port: port}
	} else {
		dstAddr = &net.UDPAddr{IP: dstIP, Port: port}
	}

	return dstAddr, cmd, nil
}

func (s *Service) DialSrv(conf *tls.Config) (net.Conn, error) {
	dial := func(addr string) (net.Conn, error) {
		tlsConf := conf.Clone()
		if tlsConf.ServerName == "" {
			host, _, err := net.SplitHostPort(addr)
			if err == nil {
				tlsConf.ServerName = host
			}
		}
		d := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return tls.DialWithDialer(d, "tcp", addr, tlsConf)
	}

	/* Try the stable server first. */
	stable := s.GetStableServer()
	srvConn, err := dial(stable.String())
	if err != nil {
		log.Printf("Failed to connect to server %s: %s", stable.String(), err)

		/* Fallback: try other servers in order, skipping the already-failed stable. */
		for _, srv := range s.ServerAddrs {
			if srv.String() == stable.String() {
				continue
			}
			log.Printf("Trying alternate server: %s", srv.String())

			srvConn, err = dial(srv.String())
			if err == nil {
				s.SetStableServer(srv)
				return srvConn, nil
			}
		}

		return nil, errors.New("all server connection attempts failed")
	}

	log.Printf("Connected to server %s", stable.String())
	return srvConn, nil
}

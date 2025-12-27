package ss5

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

/* The buffer (64KB) is used after successful authentication between the connections. */
const ConnectionBuffer = 64 * 1024

/* The buffer (64KB) is used for relaying UDP payloads. */
const UDPBuffer = 64 * 1024

/* The buffer (8KB) is used for parsing SOCKS5. */
const Socks5Buffer = 8 * 1024

var bytePool = sync.Pool{
	New: func() interface{} {
		return make([]byte, ConnectionBuffer)
	},
}

var udpPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, UDPBuffer)
	},
}

var socks5Pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, Socks5Buffer)
	},
}

/* Pipe pool to avoid repeated allocation for splice operations. */
type pipePair struct {
	r *os.File
	w *os.File
}

var pipePool = sync.Pool{
	New: func() interface{} {
		r, w, err := os.Pipe()
		if err != nil {
			return nil
		}
		return &pipePair{r: r, w: w}
	},
}

func getPipe() *pipePair {
	p := pipePool.Get()
	if p == nil {
		r, w, err := os.Pipe()
		if err != nil {
			return nil
		}
		return &pipePair{r: r, w: w}
	}
	return p.(*pipePair)
}

func putPipe(p *pipePair) {
	if p != nil {
		pipePool.Put(p)
	}
}

type Service struct {
	ListenAddr   *net.TCPAddr
	ServerAdders []*net.TCPAddr
	StableServer *net.TCPAddr
}

func (s *Service) TLSWrite(conn net.Conn, buf []byte) error {
	_, err := conn.Write(buf)
	return err
}

func (s *Service) TransferToTCP(srcConn net.Conn, dstConn *net.TCPConn) error {
	buf := bytePool.Get().([]byte)
	defer bytePool.Put(buf)

	_ = srcConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	_ = dstConn.SetWriteDeadline(time.Now().Add(5 * time.Minute))

	_, err := io.CopyBuffer(dstConn, srcConn, buf)
	return err
}

func (s *Service) TransferToTLS(dstConn *net.TCPConn, srcConn net.Conn) error {
	buf := bytePool.Get().([]byte)
	defer bytePool.Put(buf)

	_ = dstConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	_ = srcConn.SetWriteDeadline(time.Now().Add(5 * time.Minute))

	_, err := io.CopyBuffer(srcConn, dstConn, buf)
	return err
}

func GetUDPBuffer() []byte {
	return udpPool.Get().([]byte)
}

func PutUDPBuffer(buf []byte) {
	udpPool.Put(buf)
}

func (s *Service) ParseSOCKS5FromTLS(cliConn net.Conn) (net.Addr, byte, error) {
	buf := socks5Pool.Get().([]byte)
	defer socks5Pool.Put(buf)

	/* Phase 1: Read client greeting. */
	nRead, errRead := cliConn.Read(buf)
	if errRead != nil {
		return nil, 0x00, errors.New("the service failed to read SOCKS5 during the initial handshake phase")
	}

	if nRead == 0 {
		return nil, 0x00, errors.New("the service failed to parse the SOCKS5 protocol")
	}

	/* Verify SOCKS5 version (0x05). */
	if buf[0] != 0x05 {
		return nil, 0x00, errors.New("currently only supporting the SOCKS5 protocol")
	}

	/* Reply: SOCKS5, no authentication required. */
	errWrite := s.TLSWrite(cliConn, []byte{0x05, 0x00})
	if errWrite != nil {
		return nil, 0x00, errors.New("the service failed to respond to the client during the SOCKS5 initial handshake phase")
	}

	/* Phase 2: Read connection request. */
	nRead, errRead = cliConn.Read(buf)
	if errRead != nil {
		return nil, 0x00, errors.New("the service failed to read SOCKS5 during the second handshake phase")
	}

	if nRead == 0 {
		return nil, 0x00, errors.New("the service failed to parse the SOCKS5 protocol")
	}

	/* Minimal header length: VER, CMD, RSV, ATYP. */
	if nRead < 4 {
		return nil, 0x00, errors.New("the service failed to parse the SOCKS5 protocol")
	}

	/* CMD: 0x01=CONNECT, 0x03=UDP ASSOCIATE. */
	if buf[1] != 0x01 && buf[1] != 0x03 {
		return nil, 0x00, errors.New("currently only supporting the CONNECT and UDP ASSOCIATE commands in SOCKS5")
	}

	var dstIP []byte
	switch buf[3] {
	case 0x01: /* IPv4: 4 bytes. */
		if nRead < (4 + net.IPv4len + 2) {
			return nil, 0x00, errors.New("the service failed to parse the SOCKS5 protocol")
		}
		dstIP = buf[4 : 4+net.IPv4len]

	case 0x03: /* Domain name: 1 byte length + domain. */
		domainLen := int(buf[4])
		if 5+domainLen+2 > nRead {
			/* Bugfix: avoid out-of-bounds when domain length is malformed. */
			return nil, 0x00, errors.New("the domain name length exceeds the buffer")
		}
		ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:5+domainLen]))
		if err != nil {
			return nil, 0x00, errors.New("the service failed to parse the domain name")
		}
		dstIP = ipAddr.IP

	case 0x04: /* IPv6: 16 bytes. */
		if nRead < (4 + net.IPv6len + 2) {
			return nil, 0x00, errors.New("the service failed to parse the SOCKS5 protocol")
		}
		dstIP = buf[4 : 4+net.IPv6len]

	default:
		return nil, 0x00, errors.New("the received address field is incorrect")
	}

	/* Port is always the last 2 bytes. */
	dstPort := buf[nRead-2 : nRead]

	if buf[1] == 0x01 {
		/* TCP CONNECT command. */
		return &net.TCPAddr{
			IP:   dstIP,
			Port: int(binary.BigEndian.Uint16(dstPort)),
		}, buf[1], nil
	} else if buf[1] == 0x03 {
		/* UDP ASSOCIATE command. */
		return &net.UDPAddr{
			IP:   dstIP,
			Port: int(binary.BigEndian.Uint16(dstPort)),
		}, buf[1], nil
	}

	return nil, 0x00, errors.New("failed to parse SOCKS5 request")
}

func (s *Service) DialSrv(conf *tls.Config) (net.Conn, error) {
	dial := func(addr string) (net.Conn, error) {
		d := &net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return tls.DialWithDialer(d, "tcp", addr, conf)
	}

	/* Try the stable server first. */
	srvConn, err := dial(s.StableServer.String())
	if err != nil {
		log.Printf("Failed to connect to server %s: %s", s.StableServer.String(), err)

		/* Fallback: try other servers in order. */
		for _, srv := range s.ServerAdders {
			log.Printf("Trying alternate server: %s", srv.String())

			srvConn, err = dial(srv.String())
			if err == nil {
				s.StableServer = srv
				return srvConn, nil
			}
		}

		return nil, errors.New("all server connection attempts failed")
	}

	log.Printf("Connected to server %s", s.StableServer.String())
	return srvConn, nil
}

/* Extracts the underlying file descriptor from a TCP connection for splice() operations. */
func getTCPFd(conn *net.TCPConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}

	var fd int
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return fd, nil
}

/*
 * Transfers data from TCP to TLS using splice (zero-copy on Linux).
 *
 * On Linux: TCP Socket → [splice] → Pipe → [read] → Buffer → [encrypt] → TLS
 * On other platforms: falls back to TransferToTLS (standard io.Copy).
 *
 * Note: TLS encryption requires userspace, so only the TCP read path is optimized.
 */
func (s *Service) SpliceTransferToTLS(tcpConn *net.TCPConn, tlsConn net.Conn) error {
	/* Check if splice is available on this platform. */
	if !spliceAvailable() {
		return s.TransferToTLS(tcpConn, tlsConn)
	}

	/* Get a pipe for the splice operation. */
	pipe := getPipe()
	if pipe == nil {
		return s.TransferToTLS(tcpConn, tlsConn)
	}
	defer putPipe(pipe)

	/* Extract raw file descriptor from TCP connection. */
	tcpFd, err := getTCPFd(tcpConn)
	if err != nil {
		return s.TransferToTLS(tcpConn, tlsConn)
	}

	buf := bytePool.Get().([]byte)
	defer bytePool.Put(buf)

	_ = tcpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	_ = tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Minute))

	pipeFdW := int(pipe.w.Fd())

	for {
		/*
		 * Step 1: Splice from TCP socket to pipe (zero-copy in kernel).
		 * Data moves: TCP socket buffer → Pipe buffer (no userspace copy).
		 */
		n, err := spliceSyscall(tcpFd, pipeFdW, ConnectionBuffer)
		if err != nil {
			/* EINTR/EAGAIN: retry. */
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}

			/* Real error, return it. */
			return err
		}

		if n == 0 {
			/* splice() returns 0 when EOF (socket closed). */
			return nil
		}

		if n < 0 {
			/* Should never happen, but be safe. */
			continue
		}

		/*
		 * Step 2: Read from pipe into userspace buffer.
		 * This copy is unavoidable - TLS encryption requires userspace access.
		 * Must read all n bytes to avoid data loss.
		 */
		totalRead := 0
		for totalRead < n {
			nRead, err := pipe.r.Read(buf[totalRead:n])
			if err != nil {
				return err
			}
			totalRead += nRead
		}

		/*
		 * Step 3: Write encrypted data to TLS connection.
		 * Go's TLS library handles encryption transparently.
		 */
		_, err = tlsConn.Write(buf[:n])
		if err != nil {
			return err
		}
	}
}

/*
 * Transfers data from TLS to TCP using splice (zero-copy on Linux).
 *
 * On Linux: TLS → [decrypt] → Buffer → [write] → Pipe → [splice] → TCP Socket
 * On other platforms: falls back to TransferToTCP (standard io.Copy).
 *
 * Note: TLS decryption requires userspace, so only the TCP write path is optimized.
 */
func (s *Service) SpliceTransferToTCP(tlsConn net.Conn, tcpConn *net.TCPConn) error {
	/* Check if splice is available on this platform. */
	if !spliceAvailable() {
		return s.TransferToTCP(tlsConn, tcpConn)
	}

	/* Get a pipe for the splice operation. */
	pipe := getPipe()
	if pipe == nil {
		return s.TransferToTCP(tlsConn, tcpConn)
	}
	defer putPipe(pipe)

	/* Extract raw file descriptor from TCP connection. */
	tcpFd, err := getTCPFd(tcpConn)
	if err != nil {
		return s.TransferToTCP(tlsConn, tcpConn)
	}

	buf := bytePool.Get().([]byte)
	defer bytePool.Put(buf)

	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	_ = tcpConn.SetWriteDeadline(time.Now().Add(5 * time.Minute))

	pipeFdR := int(pipe.r.Fd())

	for {
		/*
		 * Step 1: Read decrypted data from TLS connection.
		 * Go's TLS library handles decryption transparently.
		 */
		n, err := tlsConn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		if n == 0 {
			return nil
		}

		/*
		 * Step 2: Write to pipe.
		 * This copy is unavoidable - data comes from TLS decryption buffer.
		 * Must write all n bytes to avoid data loss.
		 */
		totalWritten := 0
		for totalWritten < n {
			nWritten, err := pipe.w.Write(buf[totalWritten:n])
			if err != nil {
				return err
			}
			totalWritten += nWritten
		}

		/*
		 * Step 3: Splice from pipe to TCP socket (zero-copy in kernel).
		 * Data moves: Pipe buffer → TCP socket buffer (no userspace copy).
		 */
		written := 0
		for written < n {
			spliced, err := spliceToPipe(pipeFdR, tcpFd, n-written)
			if err != nil {
				/* EINTR/EAGAIN: retry. */
				if err == syscall.EINTR || err == syscall.EAGAIN {
					continue
				}

				return err
			}

			if spliced == 0 {
				/*
				 * splice() returns 0 when pipe is empty or EOF.
				 * Since we just wrote data to the pipe, this shouldn't happen.
				 * But if it does, wait a bit and retry to avoid busy loop.
				 */
				time.Sleep(1 * time.Millisecond)
				continue
			}

			if spliced < 0 {
				/* Should never happen, but be safe. */
				continue
			}

			written += spliced
		}
	}
}

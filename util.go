package ss5

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"sync"
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
		bytes := make([]byte, ConnectionBuffer)

		return bytes
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

	nRead, errRead := cliConn.Read(buf)
	if errRead != nil {
		return nil, 0x00, errors.New("the service failed to read SOCKS5 during the initial handshake phase")
	}

	if nRead > 0 {
		if buf[0] != 0x05 {
			/* The version of the protocol. */
			return nil, 0x00, errors.New("currently only supporting the SOCKS5 protocol")
		} else {
			/* [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			errWrite := s.TLSWrite(cliConn, []byte{0x05, 0x00})
			if errWrite != nil {
				return nil, 0x00, errors.New("the service failed to respond to the client during the SOCKS5 initial handshake phase")
			}
		}
	}

	nRead, errRead = cliConn.Read(buf)
	if errRead != nil {
		return nil, 0x00, errors.New("the service failed to read SOCKS5 during the second handshake phase")
	}

	if nRead > 0 {
		if buf[1] != 0x01 && buf[1] != 0x03 {
			return nil, 0x00, errors.New("currently only supporting the CONNECT and UDP ASSOCIATE commands in SOCKS5")
		}

		var dstIP []byte
		switch buf[3] {
		/* Checking the address field. */
		case 0x01: /* The version-4 IP address. */
			dstIP = buf[4 : 4+net.IPv4len]

		case 0x03: /* The fully-qualified domain name. */
			domainLen := int(buf[4])
			if 5+domainLen+2 > nRead {
				return nil, 0x00, errors.New("the domain name length exceeds the buffer")
			}
			ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:5+domainLen]))
			if err != nil {
				return nil, 0x00, errors.New("the service failed to parse the domain name")
			}

			dstIP = ipAddr.IP
		case 0x04: /* The version-6 IP address. */
			dstIP = buf[4 : 4+net.IPv6len]
		default:
			return nil, 0x00, errors.New("the received address field is incorrect")
		}

		dstPort := buf[nRead-2 : nRead]

		if buf[1] == 0x01 {
			/* The TCP over SOCKS5. */
			dstAddr := &net.TCPAddr{
				IP:   dstIP,
				Port: int(binary.BigEndian.Uint16(dstPort)),
			}

			return dstAddr, buf[1], errRead
		} else if buf[1] == 0x03 {
			/* The UDP over SOCKS5. */
			dstAddr := &net.UDPAddr{
				IP:   dstIP,
				Port: int(binary.BigEndian.Uint16(dstPort)),
			}

			return dstAddr, buf[1], errRead
		}
	}

	return nil, 0x00, errors.New("the service failed to parse the SOCKS5 protocol")
}

func (s *Service) DialSrv(conf *tls.Config) (net.Conn, error) {
	dial := func(addr string) (net.Conn, error) {
		d := &net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		return tls.DialWithDialer(d, "tcp", addr, conf)
	}

	srvConn, err := dial(s.StableServer.String())
	if err != nil {
		log.Printf("The service failed to connect to the server %s failed: %s.", s.StableServer.String(), err)

		/* Attempting to connect to another server. */
		for _, srv := range s.ServerAdders {
			log.Printf("Try to connect to another server: %s.", srv.String())

			srvConn, err = dial(srv.String())
			if err == nil {
				s.StableServer = srv

				return srvConn, nil
			}
		}

		return nil, errors.New("all attempts to connect to servers have failed")
	}

	log.Printf("Connection to server %s successful.", s.StableServer.String())

	return srvConn, nil
}

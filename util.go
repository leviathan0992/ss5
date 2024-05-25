package util

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

const ConnectionBuffer = 1024 * 1024 * 2 /* Buffer used after successful authentication in the connection 2M */

const Socks5Buffer = 256 * 1024 /* Buffer used for parsing SOCKS5 - 256 KB. */

var bytePool = sync.Pool{
	New: func() interface{} {
		bytes := make([]byte, ConnectionBuffer)
		return bytes
	},
}

type Service struct {
	ListenAddr   *net.TCPAddr
	ServerAdders []*net.TCPAddr
	StableServer *net.TCPAddr
}

func (s *Service) TLSWrite(conn net.Conn, buf []byte) error {
	nWrite := 0
	nBuffer := len(buf)

	for nWrite < nBuffer {
		n, err := conn.Write(buf[nWrite:])
		if err != nil {
			return err
		}
		nWrite += n
	}
	return nil
}

func (s *Service) TransferToTCP(cliConn net.Conn, dstConn *net.TCPConn) error {
	buf := make([]byte, ConnectionBuffer)
	for {
		nRead, errRead := cliConn.Read(buf)

		if errRead != nil {
			return errRead
		}

		if nRead > 0 {
			_, errWrite := dstConn.Write(buf[0:nRead])

			if errWrite != nil {
				return errWrite
			}
		}
	}
}

func (s *Service) TransferToTLS(dstConn *net.TCPConn, srcConn net.Conn) error {
	buf := bytePool.Get().([]byte)

	for {
		nRead, errRead := dstConn.Read(buf)

		if errRead != nil {
			bytePool.Put(buf)
			return errRead
		}

		if nRead > 0 {
			errWrite := s.TLSWrite(srcConn, buf[0:nRead])

			if errWrite != nil {
				bytePool.Put(buf)
				return errWrite
			}
		}
	}
}

func (s *Service) ParseSOCKS5FromTLS(cliConn net.Conn) (*net.TCPAddr, error) {
	buf := make([]byte, Socks5Buffer)

	nRead, errRead := cliConn.Read(buf)
	if errRead != nil {
		return &net.TCPAddr{}, errors.New("failed to read SOCKS5 during the initial handshake phase")
	}

	if nRead > 0 {
		if buf[0] != 0x05 {
			/* The version of the protocol */
			return &net.TCPAddr{}, errors.New("currently only supporting SOCKS5 protocol")
		} else {
			/* [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			errWrite := s.TLSWrite(cliConn, []byte{0x05, 0x00})
			if errWrite != nil {
				return &net.TCPAddr{}, errors.New("failed to respond to the client during the SOCKS5 initial handshake phase")
			}
		}
	}

	nRead, errRead = cliConn.Read(buf)
	if errRead != nil {
		return &net.TCPAddr{}, errors.New("failed to read SOCKS5 during the second handshake phase")
	}

	if nRead > 0 {
		if buf[1] != 0x01 {
			return &net.TCPAddr{}, errors.New("currently only supporting the CONNECT command in SOCKS5")
		}

		var dstIP []byte
		switch buf[3] { /* Checking the address field. */
		case 0x01: /* The version-4 IP address. */
			dstIP = buf[4 : 4+net.IPv4len]
		case 0x03: /* The fully-qualified domain name. */
			ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:nRead-2]))
			if err != nil {
				return &net.TCPAddr{}, errors.New("failed to parse the domain name")
			}
			dstIP = ipAddr.IP
		case 0x04: /* The version-6 IP address. */
			dstIP = buf[4 : 4+net.IPv6len]
		default:
			return &net.TCPAddr{}, errors.New("the received address field is incorrect")
		}
		dstPort := buf[nRead-2 : nRead]

		if buf[1] == 0x01 {
			/* TCP over SOCKS5 */
			dstAddr := &net.TCPAddr{
				IP:   dstIP,
				Port: int(binary.BigEndian.Uint16(dstPort)),
			}
			return dstAddr, errRead
		}
	}

	return &net.TCPAddr{}, errors.New("failed to parse SOCKS5 protocol")
}

func (s *Service) DialSrv(conf *tls.Config) (net.Conn, error) {
	srvConn, err := tls.Dial("tcp", s.StableServer.String(), conf)
	if err != nil {
		log.Printf("Failed to connect to the server %s failed: %s", s.StableServer.String(), err)

		/* Attempting to connect to another server. */
		for _, srv := range s.ServerAdders {
			log.Printf("Attempting to connect to another server: %s", srv.String())

			srvConn, err := tls.Dial("tcp", srv.String(), conf)
			if err == nil {
				s.StableServer = srv

				return srvConn, nil
			}
		}
		return nil, errors.New(fmt.Sprintf("All attempts to connect to servers have failed."))
	}

	log.Printf("Connection to server %s successful.", s.StableServer.String())

	return srvConn, nil
}

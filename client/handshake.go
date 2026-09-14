package main

import (
	"fmt"
	"io"
	"net"
	"time"

	util "github.com/leviathan0992/ss5"
)

// Read exactly one SOCKS request/reply, leaving any application bytes unread.
func readSOCKSFrame(r io.Reader) ([]byte, error) {
	frame := make([]byte, 4, 262)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	if frame[0] != 5 || frame[2] != 0 {
		return nil, fmt.Errorf("invalid SOCKS5 header")
	}
	n := 0
	switch frame[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		frame = append(frame, 0)
		if _, err := io.ReadFull(r, frame[4:5]); err != nil {
			return nil, err
		}
		n = int(frame[4])
		if n == 0 {
			return nil, fmt.Errorf("empty SOCKS5 domain")
		}
	default:
		return nil, fmt.Errorf("unsupported SOCKS5 address type")
	}
	pos := len(frame)
	frame = frame[:pos+n+2]
	_, err := io.ReadFull(r, frame[pos:])
	return frame, err
}

// Retry a failed unused connection only before application data is forwarded.
// A valid SOCKS failure reply is returned unchanged, never retried.
func (c *client) connectPrepared(userConn net.Conn) (net.Conn, error) {
	_ = userConn.SetDeadline(time.Now().Add(30 * time.Second))
	request, err := readSOCKSFrame(userConn)
	if err != nil {
		return nil, err
	}
	if request[1] != util.CmdConnect && request[1] != util.CmdUDPAssociate {
		util.SendSOCKS5Reply(userConn, 7)
		return nil, fmt.Errorf("unsupported SOCKS5 command")
	}
	conn, pooled, err := c.acquireServer(true)
	if err != nil {
		util.SendSOCKS5Reply(userConn, 1)
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		err = util.WriteAll(conn, request)
		var reply []byte
		if err == nil {
			reply, err = readSOCKSFrame(conn)
		}
		if err == nil {
			_ = userConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err = util.WriteAll(userConn, reply); err != nil {
				closeIdle(conn)
				return nil, err
			}
			if reply[1] != 0 {
				closeIdle(conn)
				return nil, fmt.Errorf("upstream SOCKS5 request rejected: %d", reply[1])
			}
			_ = conn.SetDeadline(time.Time{})
			_ = userConn.SetDeadline(time.Time{})
			return conn, nil
		}
		closeIdle(conn)
		if !pooled || attempt != 0 {
			util.SendSOCKS5Reply(userConn, 1)
			return nil, err
		}
		// Do not take another possibly stale pooled connection for the retry.
		conn, _, err = c.acquireServer(false)
		if err != nil {
			util.SendSOCKS5Reply(userConn, 1)
			return nil, err
		}
	}
}

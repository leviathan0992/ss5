package ss5

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
)

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

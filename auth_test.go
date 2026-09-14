package ss5

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestAuthentication(t *testing.T) {
	valid := &Credentials{Username: "test-user", Password: "test-pass"}
	for _, tc := range []struct {
		name           string
		server, client *Credentials
		ok             bool
	}{
		{"legacy", nil, nil, true}, {"authenticated", valid, valid, true},
		{"missing", valid, nil, false}, {"wrong-password", valid, &Credentials{"test-user", "wrong"}, false},
		{"wrong-user", valid, &Credentials{"wrong", "test-pass"}, false},
		{"no-downgrade", nil, valid, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(2 * time.Second))
			b.SetDeadline(time.Now().Add(2 * time.Second))
			serverDone := make(chan error, 1)
			go func() { defer a.Close(); serverDone <- NegotiateServer(a, tc.server) }()
			err := NegotiateClient(b, tc.client)
			b.Close()
			serverErr := <-serverDone
			if (err == nil) != tc.ok || (serverErr == nil) != tc.ok {
				t.Fatalf("client=%v server=%v", err, serverErr)
			}
		})
	}
}

type wire struct {
	*bytes.Reader
	bytes.Buffer
}

func (w *wire) Read(p []byte) (int, error)  { return w.Reader.Read(p) }
func (w *wire) Write(p []byte) (int, error) { return w.Buffer.Write(p) }

func TestAuthenticationFraming(t *testing.T) {
	auth := &Credentials{"u", "p"}
	for _, tc := range []struct {
		name         string
		input, reply []byte
		ok           bool
	}{
		{"prefer-required", []byte{5, 2, 0, 2, 1, 1, 'u', 1, 'p', 5, 1, 0, 1}, []byte{5, 2, 1, 0}, true},
		{"bad-version", []byte{5, 1, 2, 2, 1}, []byte{5, 2, 1, 1}, false},
		{"empty-user", []byte{5, 1, 2, 1, 0}, []byte{5, 2, 1, 1}, false},
		{"empty-password", []byte{5, 1, 2, 1, 1, 'u', 0}, []byte{5, 2, 1, 1}, false},
		{"truncated", []byte{5, 1, 2, 1, 1, 'u', 1}, []byte{5, 2}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &wire{Reader: bytes.NewReader(tc.input)}
			err := NegotiateServer(w, auth)
			if (err == nil) != tc.ok || !bytes.Equal(w.Buffer.Bytes(), tc.reply) {
				t.Fatalf("err=%v reply=%x", err, w.Buffer.Bytes())
			}
			if tc.ok {
				rest, _ := io.ReadAll(w.Reader)
				if !bytes.Equal(rest, []byte{5, 1, 0, 1}) {
					t.Fatalf("consumed command: %x", rest)
				}
			}
		})
	}
}

func TestInvalidCredentials(t *testing.T) {
	for _, c := range []Credentials{{"", "p"}, {"u", ""}, {string(bytes.Repeat([]byte{'u'}, 256)), "p"}, {"u", string(bytes.Repeat([]byte{'p'}, 256))}} {
		if c.Validate() == nil {
			t.Fatal("invalid credentials accepted")
		}
	}
}

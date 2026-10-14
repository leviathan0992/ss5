package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func testSelector(count int) *upstreamSelector {
	c := &client{upstreams: make([]upstreamEndpoint, count)}
	return newUpstreamSelector(c)
}

func assertPlan(t *testing.T, s *upstreamSelector, want []int) uint64 {
	t.Helper()
	got, generation := s.plan()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan = %v, want %v", got, want)
	}
	return generation
}

func TestFailoverKeepsActiveWhileBackupsAreHealthy(t *testing.T) {
	s := testSelector(3)
	now := time.Now()
	for round := 0; round < 4; round++ {
		start := now.Add(time.Duration(round) * time.Millisecond)
		s.nodes[0].observe(start, false)
		s.nodes[1].observe(start, false)
		s.nodes[2].observe(start, false)
		assertPlan(t, s, []int{0, 1, 2})
	}
}

func TestFailoverSticksAfterRecoveryAndRejectsStaleDial(t *testing.T) {
	s := testSelector(3)
	generation := assertPlan(t, s, []int{0, 1, 2})
	s.failed(0, time.Now())
	s.connected(1, generation)
	assertPlan(t, s, []int{1, 2, 0})
	// An older concurrent dial must not undo the new selection.
	s.connected(0, generation)
	assertPlan(t, s, []int{1, 2, 0})
	for i := 0; i < 2; i++ {
		s.nodes[0].observe(time.Now(), false)
	}
	assertPlan(t, s, []int{1, 0, 2})
	// Only a new foreground fallback can change the sticky selection again.
	_, currentGeneration := s.plan()
	s.failed(1, time.Now())
	s.connected(2, currentGeneration)
	if s.client.stableIndex.Load() != 2 {
		t.Fatal("second failover did not select successful backup")
	}
}

func TestFailoverProbesDoNotReplaceUnavailableOrStaleActive(t *testing.T) {
	s := testSelector(3)
	now := time.Now()
	s.nodes[1].observe(now, false)
	s.nodes[0].observe(now, true)
	s.nodes[0].observe(now.Add(time.Millisecond), true)
	assertPlan(t, s, []int{0, 1, 2})
	s.nodes[0].updated = now.Add(-3 * time.Minute)
	assertPlan(t, s, []int{0, 1, 2})
}

func TestFailoverBackupsPreferHealthThenConfigurationOrder(t *testing.T) {
	s := testSelector(5)
	now := time.Now()
	s.nodes[1].observe(now, true)
	s.nodes[4].observe(now, false)
	s.nodes[3].observe(now, false)
	assertPlan(t, s, []int{0, 3, 4, 2, 1})
}

// Drop the first N TCP connections before the TLS server sees them.
type failingListener struct {
	net.Listener
	failures int32
	calls    atomic.Int32
}

func (l *failingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.calls.Add(1) <= l.failures {
			conn.Close()
			continue
		}
		return conn, nil
	}
}
func TestAcquireRetriesBeforeChangingExit(t *testing.T) {
	for _, failures := range []int32{2, 3} {
		t.Run(fmt.Sprint(failures), func(t *testing.T) {
			primary := httptest.NewUnstartedServer(http.NotFoundHandler())
			listener := &failingListener{Listener: primary.Listener, failures: failures}
			primary.Listener = listener
			primary.StartTLS()
			defer primary.Close()
			backup := httptest.NewTLSServer(http.NotFoundHandler())
			defer backup.Close()
			c := &client{upstreams: []upstreamEndpoint{
				{addrStr: primary.Listener.Addr().String(), tlsConfig: &tls.Config{InsecureSkipVerify: true}},
				{addrStr: backup.Listener.Addr().String(), tlsConfig: &tls.Config{InsecureSkipVerify: true}},
			}}
			c.selector = newUpstreamSelector(c)
			conn, _, err := c.acquireServer(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if got := listener.calls.Load(); got != 3 {
				t.Fatalf("primary attempts=%d, want 3", got)
			}
			want := uint32(0)
			if failures == 3 {
				want = 1
			}
			if got := c.stableIndex.Load(); got != want {
				t.Fatalf("active=%d, want %d", got, want)
			}
		})
	}
}

func TestPreconnectTargetFollowsRecentDemand(t *testing.T) {
	var stable atomic.Uint32
	p := newPreconnectPool(context.Background(), 16, &stable, nil)
	defer p.cancel()
	now := time.Now()
	p.demandStart = now

	if got := p.targetLocked(now); got != 1 {
		t.Fatalf("idle target=%d, want 1", got)
	}
	for i := 0; i < 5; i++ {
		p.recordDemandLocked(now)
	}
	if got := p.targetLocked(now); got != 5 {
		t.Fatalf("target=%d, want 5", got)
	}
	// The previous window still counts after one rotation.
	if got := p.targetLocked(now.Add(p.ttl)); got != 5 {
		t.Fatalf("target after one window=%d, want 5", got)
	}
	if got := p.targetLocked(now.Add(2 * p.ttl)); got != 1 {
		t.Fatalf("target after two quiet windows=%d, want 1", got)
	}
	for i := 0; i < 40; i++ {
		p.recordDemandLocked(now.Add(2 * p.ttl))
	}
	if got := p.targetLocked(now.Add(2 * p.ttl)); got != 16 {
		t.Fatalf("burst target=%d, want size 16", got)
	}
}

// testClientIdentity signs a client-only leaf with an independent trust root.
func testClientIdentity(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, ca
}

// The normal client constructor must reject an upstream limited to TLS 1.2.
func TestClientTLSMinimum(t *testing.T) {
	identity, ca := testClientIdentity(t)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)
	for _, tc := range []struct {
		name     string
		version  uint16
		accepted bool
	}{
		{"TLS12OnlyUpstreamRejected", tls.VersionTLS12, false},
		{"TLS13UpstreamAccepted", tls.VersionTLS13, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, identity.Certificate[0]) {
					http.Error(w, "unexpected client identity", http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			upstream.TLS = &tls.Config{MinVersion: tc.version, MaxVersion: tc.version, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
			upstream.StartTLS()
			defer upstream.Close()
			serverIdentity := upstream.TLS.Certificates[0]
			directory := t.TempDir()
			certPath, keyPath := filepath.Join(directory, "identity.pem"), filepath.Join(directory, "identity.key")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Certificate[0]}), 0600); err != nil {
				t.Fatal(err)
			}
			key, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
				t.Fatal(err)
			}
			serverCAPath := filepath.Join(directory, "server-ca.pem")
			if err := os.WriteFile(serverCAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverIdentity.Certificate[0]}), 0600); err != nil {
				t.Fatal(err)
			}
			client, err := NewClient("127.0.0.1:0", []string{upstream.Listener.Addr().String()}, certPath, keyPath, serverCAPath, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.cancel()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", upstream.Listener.Addr().String(), client.upstreams[0].tlsConfig)
			if conn != nil {
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.accepted {
				if err != nil {
					t.Fatal(err)
				}
				if got := conn.ConnectionState().Version; got != tls.VersionTLS13 {
					t.Fatalf("version=%x, want TLS 1.3", got)
				}
				// A TLS 1.3 client can finish locally before receiving a server
				// authentication alert. Require an authenticated response too.
				if _, err := fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					t.Fatalf("authenticated response status=%d", response.StatusCode)
				}
			} else if err == nil {
				t.Fatal("client accepted a TLS 1.2-only upstream")
			}
		})
	}
}

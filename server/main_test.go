package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leviathan0992/ss5"
)

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A preconnected client authenticates and then drops the raw TCP socket without
// a close_notify. The server must see a clean io.EOF so it can stay quiet.
func TestParseReportsEOFForUnusedPreconnection(t *testing.T) {
	cert := testCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	auth := &ss5.Credentials{Username: "user", Password: "pass"}
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		service := &ss5.Service{Auth: auth}
		_, _, err = service.ParseSOCKS5FromTLS(conn)
		result <- err
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := ss5.NegotiateClient(conn, auth); err != nil {
		t.Fatal(err)
	}
	ss5.CloseConnection(conn)

	if err := <-result; !errors.Is(err, io.EOF) {
		t.Fatalf("parse error = %v, want io.EOF", err)
	}
}

type udpHarness struct {
	t      *testing.T
	server *server
	target *net.UDPConn
	client *net.UDPConn
}

// startUDPHarness runs one association on loopback with a single target socket.
func startUDPHarness(t *testing.T, lookup func(context.Context, string) ([]net.IPAddr, error)) *udpHarness {
	t.Helper()
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp", nil, relay.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	s := &server{udpDNS: newDNSCache(), lookupIPAddr: lookup}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.receiveUDPPackets(ctx, relay, netip.MustParseAddr("127.0.0.1"))
	}()
	t.Cleanup(func() {
		cancel()
		_ = relay.Close()
		<-done
	})
	return &udpHarness{t: t, server: s, target: target, client: client}
}

func (h *udpHarness) targetPort() int {
	return h.target.LocalAddr().(*net.UDPAddr).Port
}

// sendIPv4 sends sequence number seq to the target by IP address.
func (h *udpHarness) sendIPv4(seq int) {
	packet := []byte{0, 0, 0, ss5.AtypIPv4, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(packet[8:10], uint16(h.targetPort()))
	binary.BigEndian.PutUint32(packet[10:], uint32(seq))
	if _, err := h.client.Write(packet); err != nil {
		h.t.Fatal(err)
	}
}

// sendDomain sends sequence number seq to the target by domain name.
func (h *udpHarness) sendDomain(host string, seq int) {
	packet := []byte{0, 0, 0, ss5.AtypDomain, byte(len(host))}
	packet = append(packet, host...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(h.targetPort()))
	packet = binary.BigEndian.AppendUint32(packet, uint32(seq))
	if _, err := h.client.Write(packet); err != nil {
		h.t.Fatal(err)
	}
}

// receiveInOrder reads until the target is quiet and fails on any datagram
// that arrives after a later one. It returns the number received.
func (h *udpHarness) receiveInOrder(last int) (int, int) {
	h.t.Helper()
	received := 0
	buf := make([]byte, 64)
	for {
		_ = h.target.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := h.target.Read(buf)
		if err != nil {
			return received, last
		}
		if n != 4 {
			h.t.Fatalf("payload length = %d, want 4", n)
		}
		seq := int(binary.BigEndian.Uint32(buf[:4]))
		if seq <= last {
			h.t.Fatalf("datagram %d arrived after %d", seq, last)
		}
		last = seq
		received++
	}
}

// Datagrams to one target must leave the relay in the order they arrived.
func TestUDPFlowPreservesOrder(t *testing.T) {
	h := startUDPHarness(t, nil)
	for i := 0; i < 500; i++ {
		h.sendIPv4(i)
		if i%50 == 0 {
			// Let the first datagram create the relay before the burst.
			time.Sleep(time.Millisecond)
		}
	}
	if received, _ := h.receiveInOrder(-1); received == 0 {
		t.Fatal("no datagrams were relayed")
	}
}

// A domain flow must stay in order while its first lookup is in flight and
// after the shared cache fills or expires.
func TestUDPDomainFlowPreservesOrderAcrossCacheChanges(t *testing.T) {
	const host = "flow.test"
	h := startUDPHarness(t, func(ctx context.Context, name string) ([]net.IPAddr, error) {
		time.Sleep(20 * time.Millisecond)
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	})

	seq, last, total := 0, -1, 0
	for round := 0; round < 2; round++ {
		if round == 1 {
			// Expire the shared entry while the flow is active.
			h.server.udpDNS.mu.Lock()
			h.server.udpDNS.entries[host] = dnsCacheEntry{ip: netip.MustParseAddr("127.0.0.1"), expiresAt: time.Now()}
			h.server.udpDNS.mu.Unlock()
		}
		// Keep sending across the moment the 20ms lookup completes, so later
		// datagrams race the ones queued behind the lookup.
		for stop := time.Now().Add(60 * time.Millisecond); time.Now().Before(stop); seq++ {
			h.sendDomain(host, seq)
			if seq%16 == 0 {
				time.Sleep(50 * time.Microsecond)
			}
		}
		var received int
		received, last = h.receiveInOrder(last)
		total += received
	}
	if total == 0 {
		t.Fatal("no datagrams were relayed")
	}
}

// After the first lookup, a domain flow keeps its relay even when the shared
// cache expires, so the target tuple does not change with DNS.
func TestUDPDomainFlowStaysPinnedAfterCacheExpiry(t *testing.T) {
	const host = "pinned.test"
	var lookups atomic.Int32
	h := startUDPHarness(t, func(ctx context.Context, name string) ([]net.IPAddr, error) {
		lookups.Add(1)
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	})

	h.sendDomain(host, 0)
	if received, _ := h.receiveInOrder(-1); received != 1 {
		t.Fatalf("received %d datagrams, want 1", received)
	}
	h.server.udpDNS.mu.Lock()
	clear(h.server.udpDNS.entries)
	h.server.udpDNS.mu.Unlock()

	for i := 1; i <= 5; i++ {
		h.sendDomain(host, i)
	}
	if received, _ := h.receiveInOrder(0); received != 5 {
		t.Fatalf("received %d datagrams, want 5", received)
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("lookups = %d, want 1", got)
	}
}

// A slow first lookup must not delay a pinned domain flow that hashes to the
// same worker.
func TestUDPSlowLookupDoesNotBlockPinnedDomainFlow(t *testing.T) {
	const active = "active.test"
	release := make(chan struct{})
	defer close(release)
	slowStarted := make(chan struct{}, 1)
	h := startUDPHarness(t, func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if name != active {
			slowStarted <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, nil
	})

	flowWorker := func(host string) uint32 {
		flow := binary.BigEndian.AppendUint16([]byte(host), uint16(h.targetPort()))
		return flowHash(flow) % 4
	}
	slow := ""
	for i := 0; slow == ""; i++ {
		if name := fmt.Sprintf("slow%d.test", i); flowWorker(name) == flowWorker(active) {
			slow = name
		}
	}

	h.sendDomain(active, 0)
	if received, _ := h.receiveInOrder(-1); received != 1 {
		t.Fatalf("received %d datagrams, want 1", received)
	}
	h.sendDomain(slow, 1000)
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow lookup did not start")
	}

	// While the slow lookup is stuck, the pinned flow must still get through in
	// order. Pacing keeps UDP loss under CPU contention out of the result.
	start := time.Now()
	for i := 1; i <= 20; i++ {
		h.sendDomain(active, i)
		time.Sleep(time.Millisecond)
	}
	buf := make([]byte, 64)
	last, received := 0, 0
	for {
		_ = h.target.SetReadDeadline(start.Add(300 * time.Millisecond))
		n, err := h.target.Read(buf)
		if err != nil {
			break
		}
		seq := int(binary.BigEndian.Uint32(buf[:n]))
		if seq <= last {
			t.Fatalf("datagram %d arrived after %d", seq, last)
		}
		last = seq
		received++
	}
	if received == 0 {
		t.Fatal("pinned flow blocked behind slow lookup")
	}
}

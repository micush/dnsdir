package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// newKeepDoTServer is a DoT server that keeps each connection open for many queries (closeAfter > 0: it closes a
// connection after that many answers, as a server ending an idle connection would).
func newKeepDoTServer(t *testing.T, f *fakeDNS, closeAfter int) (string, *atomic.Int64) {
	t.Helper()
	crt, key, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := tls.X509KeyPair(crt, key)
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	old := dotRootCAs
	dotRootCAs = pool
	t.Cleanup(func() { dotRootCAs = old })
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				for n := 0; closeAfter == 0 || n < closeAfter; n++ {
					var lb [2]byte
					if _, err := io.ReadFull(c, lb[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(lb[:]))
					io.ReadFull(c, q)
					if r := f.answer(q); r != nil {
						c.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...))
					}
				}
			}()
		}
	}()
	return "tls://" + l.Addr().String(), &accepted
}

// Queries to a DoT server go down one kept connection, not one each.
func TestDoTUpstreamReusesTheConnection(t *testing.T) {
	f := newFakeDNS(t)
	addr, accepted := newKeepDoTServer(t, f, 0)
	for i := 0; i < 5; i++ {
		q, _ := buildQuery(uint16(i+1), "a.example", "A")
		if _, _, err := exchange(context.Background(), addr, q, false, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if accepted.Load() != 1 {
		t.Fatalf("%d connections for 5 queries, want 1", accepted.Load())
	}
	if n := dotConns.count(dotKey(addr[len(dotScheme):], false)); n != 1 {
		t.Fatalf("%d idle connections kept, want 1", n)
	}
}

// A kept connection the server has closed costs a new one, not a failed query.
func TestDoTUpstreamRetriesAClosedConnection(t *testing.T) {
	f := newFakeDNS(t)
	addr, accepted := newKeepDoTServer(t, f, 2)
	for i := 0; i < 6; i++ {
		q, _ := buildQuery(uint16(i+1), "a.example", "A")
		if _, _, err := exchange(context.Background(), addr, q, false, time.Second); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	if a := accepted.Load(); a < 3 || a > 4 {
		t.Fatalf("%d connections for 6 queries at 2 a connection", a)
	}
}

// A connection made under other certificate rules is not reused.
func TestDoTUpstreamKeyFollowsTheRules(t *testing.T) {
	if dotKey("h:853", false) == dotKey("h:853", true) {
		t.Fatal("insecure and checked connections share a key")
	}
	old := dotRootCAs
	a := dotKey("h:853", false)
	dotRootCAs = x509.NewCertPool()
	defer func() { dotRootCAs = old }()
	if a == dotKey("h:853", false) {
		t.Fatal("other trusted authorities share a key")
	}
}

// Queries to a DoH server share one HTTP/2 connection.
func TestDoHUpstreamReusesTheConnection(t *testing.T) {
	f := newFakeDNS(t)
	addr, hits, h2 := newDoHServer(t, f, "/dns-query")
	var conns atomic.Int64
	// count the TCP connections the server accepts, by wrapping its listener through the client's dialer
	u := mustURL(t, addr)
	c := dohClientFor(u, false)
	c.tr.DialContext = func(ctx context.Context, network, a string) (net.Conn, error) {
		conns.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, a)
	}
	for i := 0; i < 5; i++ {
		q, _ := buildQuery(uint16(i+1), "a.example", "A")
		if _, _, err := exchange(context.Background(), addr, q, false, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if conns.Load() != 1 || hits.Load() != 5 || h2.Load() != 5 {
		t.Fatalf("connections %d, requests %d, HTTP/2 %d; want 1, 5, 5", conns.Load(), hits.Load(), h2.Load())
	}
	// the server drops its connections: the next query goes on a new one and still succeeds
	c.tr.CloseIdleConnections()
	q, _ := buildQuery(9, "a.example", "A")
	if _, _, err := exchange(context.Background(), addr, q, false, time.Second); err != nil {
		t.Fatal(err)
	}
}

// The DoT frontend answers the queries of one connection side by side: five slow ones take about as long as one.
func TestDoTFrontendAnswersAConnectionsQueriesTogether(t *testing.T) {
	up := newFakeDNS(t)
	up.delay.Store(int64(200 * time.Millisecond))
	cfg := testDNSCfg(up.addr)
	cfg.QueryTimeoutMS = 2000
	cfg.Cache = false
	p := NewPool(cfg)
	p.ProbeNow(context.Background())
	crt, key, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := tls.X509KeyPair(crt, key)
	old := dotCertificate
	dotCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
	t.Cleanup(func() { dotCertificate = old })
	port, dport := freeTCPPort(t), freeTCPPort(t)
	fe := NewDNSFrontend(mustAddr("127.0.0.1"), port, func() *Pool { return p })
	fe.dotPort = dport
	if err := fe.Start(); err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer fe.Stop()
	c, err := tls.Dial("tcp", "127.0.0.1:"+itoa(dport), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	for i := 0; i < 5; i++ { // all five written before any answer is read
		q, _ := buildQuery(uint16(100+i), "p"+itoa(i)+".example", "A")
		c.Write(append([]byte{byte(len(q) >> 8), byte(len(q))}, q...))
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	seen := map[uint16]bool{}
	for i := 0; i < 5; i++ {
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			t.Fatalf("answer %d: %v", i, err)
		}
		r := make([]byte, binary.BigEndian.Uint16(lb[:]))
		io.ReadFull(c, r)
		seen[binary.BigEndian.Uint16(r)] = true
	}
	if len(seen) != 5 {
		t.Fatalf("answers for %v", seen)
	}
	if el := time.Since(start); el > 700*time.Millisecond {
		t.Fatalf("five queries of 200 ms each took %v: they were answered one after another", el)
	}
}

// The DoH frontend speaks HTTP/2, so a client's queries share one connection.
func TestDoHFrontendSpeaksHTTP2(t *testing.T) {
	up := newFakeDNS(t)
	p := NewPool(testDNSCfg(up.addr))
	p.ProbeNow(context.Background())
	crt, key, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := tls.X509KeyPair(crt, key)
	old := dotCertificate
	dotCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
	t.Cleanup(func() { dotCertificate = old })
	port, hport := freeTCPPort(t), freeTCPPort(t)
	fe := NewDNSFrontend(mustAddr("127.0.0.1"), port, func() *Pool { return p })
	fe.dohPort = hport
	if err := fe.Start(); err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer fe.Stop()
	var conns atomic.Int64
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			conns.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, n, a)
		}}
	cl := &http.Client{Transport: tr}
	for i := 0; i < 3; i++ {
		q, _ := buildQuery(uint16(i+1), "a.example", "A")
		q[0], q[1] = 0, 0
		resp, err := cl.Post("https://127.0.0.1:"+itoa(hport)+dohPath, "application/dns-message", bytesReader(q))
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("HTTP/%d.%d, want HTTP/2", resp.ProtoMajor, resp.ProtoMinor)
		}
	}
	if conns.Load() != 1 {
		t.Fatalf("%d connections for 3 queries", conns.Load())
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// Plain DNS over TCP to an upstream keeps its connection too.
func TestTCPUpstreamReusesTheConnection(t *testing.T) {
	f := newFakeDNS(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				for {
					var lb [2]byte
					if _, err := io.ReadFull(c, lb[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(lb[:]))
					io.ReadFull(c, q)
					if r := f.answer(q); r != nil {
						c.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...))
					}
				}
			}()
		}
	}()
	for i := 0; i < 5; i++ {
		q, _ := buildQuery(uint16(i+1), "a.example", "A")
		if _, _, err := exchange(context.Background(), l.Addr().String(), q, true, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if accepted.Load() != 1 {
		t.Fatalf("%d connections for 5 queries over TCP, want 1", accepted.Load())
	}
}

// A panic in a query is still caught and counted when the peer's name is only made then.
func TestRecoverPanicFromCatches(t *testing.T) {
	before := panicCount.Load()
	func() {
		defer recoverPanicFrom("a test query from ", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53})
		panic("boom")
	}()
	if panicCount.Load() != before+1 {
		t.Fatal("the panic was not counted")
	}
}

// A frontend's ports are free as soon as stopListening returns, even with a client connected and queries running: a
// new frontend on the same address starts at once (a gateway restart used to lose this race now and then).
func TestFrontendPortsAreFreeWhenStopListeningReturns(t *testing.T) {
	up := newFakeDNS(t)
	p := NewPool(testDNSCfg(up.addr))
	p.ProbeNow(context.Background())
	crt, key, err := generateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := tls.X509KeyPair(crt, key)
	old := dotCertificate
	dotCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
	t.Cleanup(func() { dotCertificate = old })
	port, dport, hport := freeTCPPort(t), freeTCPPort(t), freeTCPPort(t)
	mk := func() *DNSFrontend {
		fe := NewDNSFrontend(mustAddr("127.0.0.1"), port, func() *Pool { return p })
		fe.dotPort, fe.dohPort = dport, hport
		return fe
	}
	fe := mk()
	if err := fe.Start(); err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	for i := 0; i < 30; i++ {
		// a client holds a TCP connection, and one sits in a DoT handshake
		c1, _ := net.Dial("tcp", "127.0.0.1:"+itoa(port))
		c2, _ := net.Dial("tcp", "127.0.0.1:"+itoa(dport))
		drain := fe.stopListening()
		fe = mk()
		if err := fe.Start(); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		fe.mu.Lock()
		dot, doh := fe.dot != nil, fe.doh != nil
		fe.mu.Unlock()
		if !dot || !doh {
			t.Fatalf("round %d: DoT %v, DoH %v after the restart", i, dot, doh)
		}
		if c1 != nil {
			c1.Close()
		}
		if c2 != nil {
			c2.Close()
		}
		go drain()
	}
	fe.Stop()
}

// A DoT or DoH port that is taken when the frontend starts is tried again until it is free.
func TestFrontendRetriesATakenDoTPort(t *testing.T) {
	old := dnsRetryEvery
	dnsRetryEvery = 50 * time.Millisecond
	t.Cleanup(func() { dnsRetryEvery = old })
	up := newFakeDNS(t)
	p := NewPool(testDNSCfg(up.addr))
	crt, key, _ := generateSelfSigned()
	cert, _ := tls.X509KeyPair(crt, key)
	oldc := dotCertificate
	dotCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }
	t.Cleanup(func() { dotCertificate = oldc })
	port, dport := freeTCPPort(t), freeTCPPort(t)
	busy, err := net.Listen("tcp4", "127.0.0.1:"+itoa(dport))
	if err != nil {
		t.Skip(err)
	}
	fe := NewDNSFrontend(mustAddr("127.0.0.1"), port, func() *Pool { return p })
	fe.dotPort = dport
	if err := fe.Start(); err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer fe.Stop()
	fe.mu.Lock()
	if fe.dot != nil {
		t.Fatal("DoT opened on a taken port")
	}
	fe.mu.Unlock()
	busy.Close()
	for i := 0; i < 40; i++ {
		time.Sleep(25 * time.Millisecond)
		fe.mu.Lock()
		ok := fe.dot != nil
		fe.mu.Unlock()
		if ok {
			return
		}
	}
	t.Fatal("DoT did not open once its port was free")
}

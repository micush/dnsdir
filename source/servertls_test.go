package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// certFor makes a certificate for host names only (no IP address in it), trusted by dotRootCAs for the test: what a
// public resolver's certificate looks like to a client that connects to it by address.
func certFor(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	old := dotRootCAs
	dotRootCAs = pool
	t.Cleanup(func() { dotRootCAs = old })
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// newNamedDoTServer is a DNS-over-TLS server on 127.0.0.1 whose certificate is for name only.
func newNamedDoTServer(t *testing.T, f *fakeDNS, name string) string {
	t.Helper()
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certFor(t, name)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
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
	return "tls://" + l.Addr().String()
}

// A server given by address whose certificate names only its host fails the normal check ("doesn't contain any IP
// SANs") and passes when it is checked against that name; another name fails.
func TestDoTCheckedAgainstAName(t *testing.T) {
	f := newFakeDNS(t)
	addr := newNamedDoTServer(t, f, "dns.test")
	q := func(tt upTLS) error {
		_, _, err := exchangeOpt(context.Background(), addr, mustQ(t), true, time.Second, tt)
		return err
	}
	if err := q(upTLS{}); err == nil || !strings.Contains(err.Error(), "IP SANs") {
		t.Fatalf("by address, checked: %v", err)
	}
	if err := q(upTLS{name: "dns.test"}); err != nil {
		t.Fatalf("checked against its name: %v", err)
	}
	if err := q(upTLS{name: "other.test"}); err == nil {
		t.Fatal("checked against another name, accepted")
	}
	if err := q(upTLS{insecure: true}); err != nil {
		t.Fatalf("not checked: %v", err)
	}
	// and through a pool, the name coming from the configuration
	cfg := testDNSCfg(addr)
	cfg.ServerTLS = map[string]ServerTLS{addr: {Name: "dns.test"}}
	p := NewPool(cfg)
	p.ProbeNow(context.Background())
	if r := rankedAddrs(p); len(r) != 1 {
		t.Fatalf("pool with the name: %v", r)
	}
	if st := p.Snapshot(); st[0].CertName != "dns.test" || st[0].CertUnchecked {
		t.Fatalf("snapshot: %+v", st[0])
	}
}

// DoH: checked against the name, and the request is for that host too.
func TestDoHCheckedAgainstAName(t *testing.T) {
	f := newFakeDNS(t)
	var host atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host.Store(r.Host)
		q, _ := io.ReadAll(r.Body)
		a := f.answer(q)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(a)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{certFor(t, "doh.test")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr, err := normalizeServer("https://" + strings.TrimPrefix(srv.URL, "https://") + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := exchangeOpt(context.Background(), addr, mustQ(t), true, time.Second, upTLS{}); err == nil {
		t.Fatal("by address, checked: accepted")
	}
	if _, _, err := exchangeOpt(context.Background(), addr, mustQ(t), true, time.Second, upTLS{name: "doh.test"}); err != nil {
		t.Fatalf("checked against its name: %v", err)
	}
	if h, _ := host.Load().(string); h != "doh.test" {
		t.Fatalf("Host %q", h)
	}
}

// One server not checked leaves the others checked: the point of the setting being per server.
func TestUncheckedIsPerServer(t *testing.T) {
	f1, f2 := newFakeDNS(t), newFakeDNS(t)
	a, b := newDoTServer(t, f1), newDoTServer(t, f2)
	dotRootCAs = x509.NewCertPool() // trusts neither
	cfg := testDNSCfg(a, b)
	cfg.ServerTLS = map[string]ServerTLS{a: {Insecure: true}}
	p := NewPool(cfg)
	p.ProbeNow(context.Background())
	if r := rankedAddrs(p); len(r) != 1 || r[0] != a {
		t.Fatalf("ranked %v, want only %s", r, a)
	}
	for _, s := range p.Snapshot() {
		if (s.Addr == a) != s.CertUnchecked {
			t.Fatalf("snapshot %s unchecked=%v", s.Addr, s.CertUnchecked)
		}
	}
	if u := cfg.uncheckedServers(); len(u) != 1 || u[0] != a {
		t.Fatalf("unchecked %v", u)
	}
}

func TestServerTLSValidation(t *testing.T) {
	d := defaultDNS()
	d.Servers = []string{"tls://86.54.11.1", "8.8.8.8", "https://dns.example/dns-query"}
	d.FallbackServers = []string{"tls://9.9.9.9"}
	d.Queries = []DNSQuery{{Name: "example.com", Type: "A"}}
	d.ServerTLS = map[string]ServerTLS{
		"tls://86.54.11.1":      {Name: " Protective.JoinDNS4.eu. "},
		"tls://9.9.9.9:853":     {Insecure: true},
		"8.8.8.8":               {Insecure: true}, // not tls: dropped
		"tls://1.2.3.4":         {Insecure: true}, // not a server of the pool: dropped
		"https://dns.example/x": {Insecure: true}, // another path, so another server: dropped
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	want := map[string]ServerTLS{"tls://86.54.11.1:853": {Name: "protective.joindns4.eu"}, "tls://9.9.9.9:853": {Insecure: true}}
	if len(d.ServerTLS) != len(want) {
		t.Fatalf("got %v", d.ServerTLS)
	}
	for k, v := range want {
		if d.ServerTLS[k] != v {
			t.Fatalf("%s: %+v, want %+v (all %v)", k, d.ServerTLS[k], v, d.ServerTLS)
		}
	}
	for name, bad := range map[string]ServerTLS{"an address": {Name: "86.54.11.1"}, "not a name": {Name: "a b"}, "both": {Name: "x.example", Insecure: true}} {
		d.ServerTLS = map[string]ServerTLS{"tls://86.54.11.1:853": bad}
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d.ServerTLS = map[string]ServerTLS{"tls://86.54.11.1:853": {}}
	if err := d.Validate(); err != nil || d.ServerTLS != nil {
		t.Fatalf("an empty entry: %v %v", err, d.ServerTLS)
	}
}

// The old pool-wide switch becomes a setting on each tls:// and https:// server, so nothing that answered stops
// answering; a server that already had a setting keeps it, and the switch is not written again.
func TestTLSInsecureMigratesPerServer(t *testing.T) {
	dc := newDaemonConfig()
	own := defaultDNS()
	own.Servers = []string{"tls://86.54.11.1:853", "8.8.8.8:53", "https://dns.example:443/dns-query"}
	own.FallbackServers = []string{"tls://9.9.9.9:853"}
	own.Queries = []DNSQuery{{Name: "example.com", Type: "A"}}
	own.ServerTLS = map[string]ServerTLS{"https://dns.example:443/dns-query": {Name: "doh.example"}}
	dc.Groups[0].DNS = &own
	dc.DNS.TLSInsecure = true // on the Settings page: the gateway's pool followed it
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	g := dc.Groups[0].DNS
	want := map[string]ServerTLS{"tls://86.54.11.1:853": {Insecure: true}, "tls://9.9.9.9:853": {Insecure: true}, "https://dns.example:443/dns-query": {Name: "doh.example"}}
	if len(g.ServerTLS) != 3 {
		t.Fatalf("got %v", g.ServerTLS)
	}
	for k, v := range want {
		if g.ServerTLS[k] != v {
			t.Fatalf("%s: %+v (all %v)", k, g.ServerTLS[k], g.ServerTLS)
		}
	}
	if dc.DNS.TLSInsecure || g.TLSInsecure {
		t.Fatal("the switch is still on")
	}
	b, _ := json.Marshal(dc)
	if strings.Contains(string(b), "tls_insecure") {
		t.Fatal("tls_insecure is written again")
	}
	// a gateway's own pool with the switch on, the shared block off: only that pool
	dc2 := newDaemonConfig()
	own2 := own
	own2.ServerTLS = nil
	own2.TLSInsecure = true
	dc2.Groups[0].DNS = &own2
	if got := migrateTLSInsecure(dc2); len(got) != 1 || len(own2.ServerTLS) != 3 {
		t.Fatalf("own pool: %v %v", got, own2.ServerTLS)
	}
	// nothing on: nothing changes
	dc3 := newDaemonConfig()
	if got := migrateTLSInsecure(dc3); len(got) != 0 || dc3.DNS.ServerTLS != nil {
		t.Fatalf("off: %v", got)
	}
}

// --canvas-set server|fallback ... --cert check|none|NAME, and the setting is gone with the server.
func TestCanvasCertEdits(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups[0].DNS = nil
	gid := dc.Groups[0].GroupID
	do := func(e canvasEdit) string {
		t.Helper()
		e.Group = gid
		msg, err := applyCanvasEdit(dc, e)
		if err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
		if err := dc.Validate(); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
		return msg
	}
	do(canvasEdit{Action: "add", Kind: "server", Server: "tls://86.54.11.1", Name: "example.com", Cert: "protective.joindns4.eu"})
	d := dc.Groups[0].DNS
	if d.ServerTLS["tls://86.54.11.1:853"].Name != "protective.joindns4.eu" {
		t.Fatalf("add: %v", d.ServerTLS)
	}
	if msg := do(canvasEdit{Action: "set", Kind: "server", Server: "tls://86.54.11.1", Cert: "none"}); !strings.Contains(msg, "NOT checked") || !d.ServerTLS["tls://86.54.11.1:853"].Insecure {
		t.Fatalf("set none: %s %v", msg, d.ServerTLS)
	}
	do(canvasEdit{Action: "set", Kind: "server", Server: "tls://86.54.11.1", Cert: "check"})
	if d.ServerTLS != nil {
		t.Fatalf("set check: %v", d.ServerTLS)
	}
	do(canvasEdit{Action: "add", Kind: "fallback", Server: "tls://9.9.9.9"})
	do(canvasEdit{Action: "set", Kind: "fallback", Server: "tls://9.9.9.9", Cert: "none"})
	if !d.ServerTLS["tls://9.9.9.9:853"].Insecure {
		t.Fatalf("fallback: %v", d.ServerTLS)
	}
	do(canvasEdit{Action: "del", Kind: "fallback", Server: "tls://9.9.9.9"})
	if d.ServerTLS != nil {
		t.Fatalf("deleted with its server: %v", d.ServerTLS)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "server", Group: gid, Server: "8.8.8.8", Cert: "none"}); err == nil {
		t.Fatal("a plain server got a certificate setting")
	}
}

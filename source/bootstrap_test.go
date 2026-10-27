package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// bootAnswer makes a response to q with the given A/AAAA addresses (and a CNAME in front, as a recursive server sends).
func bootAnswer(q []byte, rcode int, ttl uint32, ips ...string) []byte {
	r := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(r[2:], 0x8180|uint16(rcode))
	n := 0
	// a CNAME first: the name points at itself (a pointer to the question name), only to be skipped
	r = append(r, 0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 12)
	n++
	for _, s := range ips {
		ip := net.ParseIP(s)
		typ, data := uint16(1), []byte(ip.To4())
		if ip.To4() == nil {
			typ, data = 28, []byte(ip.To16())
		}
		r = append(r, 0xC0, 12, byte(typ>>8), byte(typ), 0, 1)
		r = binary.BigEndian.AppendUint32(r, ttl)
		r = binary.BigEndian.AppendUint16(r, uint16(len(data)))
		r = append(r, data...)
		n++
	}
	binary.BigEndian.PutUint16(r[6:], uint16(n))
	return r
}

func qtypeOf(q []byte) uint16 {
	end, _ := questionEnd(q)
	return binary.BigEndian.Uint16(q[end-4:])
}

func TestAnswerIPs(t *testing.T) {
	q, _ := buildQuery(1, "dns.example.com", "A")
	ips, ttl, err := answerIPs(bootAnswer(q, 0, 120, "192.0.2.1", "192.0.2.2"), "A")
	if err != nil || strings.Join(ips, ",") != "192.0.2.1,192.0.2.2" || ttl != 120*time.Second {
		t.Fatalf("%v %v %v", ips, ttl, err)
	}
	q6, _ := buildQuery(1, "dns.example.com", "AAAA")
	if ips, _, err := answerIPs(bootAnswer(q6, 0, 60, "2001:db8::1"), "AAAA"); err != nil || len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("%v %v", ips, err)
	}
	if _, _, err := answerIPs(bootAnswer(q, 2, 60), "A"); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Fatalf("%v", err)
	}
	if _, _, err := answerIPs(bootAnswer(q, 3, 60), "A"); err == nil || !strings.Contains(err.Error(), "no such name") {
		t.Fatalf("%v", err)
	}
}

func TestUpstreamHost(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1:53": "192.0.2.1", "[2001:db8::1]:53": "2001:db8::1", "tls://dns.example.com:853": "dns.example.com",
		"tls://1.1.1.1:853": "1.1.1.1", "https://dns.example.com:443/dns-query": "dns.example.com", "https://9.9.9.9/dns-query": "9.9.9.9",
		"resolver.example.net:53": "resolver.example.net",
	} {
		if got := upstreamHost(in); got != want {
			t.Errorf("%s: %q", in, got)
		}
	}
}

// bootRig is a resolver with a pool of servers, all up, and a fake network.
func bootRig(t *testing.T, servers ...string) (*bootResolver, *Pool, map[string]func(q []byte) ([]byte, error)) {
	t.Helper()
	b := newBootResolver()
	p := NewPool(DNSConfig{Servers: servers})
	for i, s := range p.servers {
		s.healthy, s.ewma = true, float64(10*(i+1))
	}
	b.register(p)
	net := map[string]func(q []byte) ([]byte, error){}
	b.exchange = func(ctx context.Context, addr string, q []byte) ([]byte, error) {
		if f := net[addr]; f != nil {
			return f(q)
		}
		return nil, errors.New("unreachable")
	}
	b.hostLook = func(context.Context, string) ([]string, error) {
		return nil, errors.New("host resolver must not be asked")
	}
	return b, p, net
}

// A name is asked of the servers given by address, fastest first; never of a server given by name, never of the host.
func TestBootstrapAsksServersGivenByAddress(t *testing.T) {
	b, p, net := bootRig(t, "192.0.2.53:53", "tls://dns.example.com:853", "198.51.100.53:53", "https://doh.example.com:443/dns-query")
	if got := strings.Join(b.sources("dns.example.com"), " "); got != "192.0.2.53:53 198.51.100.53:53" {
		t.Fatalf("sources %q", got)
	}
	var asked atomic.Int32
	net["192.0.2.53:53"] = func(q []byte) ([]byte, error) { asked.Add(1); return nil, errors.New("timeout") }
	net["198.51.100.53:53"] = func(q []byte) ([]byte, error) {
		asked.Add(1)
		if qtypeOf(q) == 28 {
			return bootAnswer(q, 0, 300, "2001:db8::853"), nil
		}
		return bootAnswer(q, 0, 300, "203.0.113.8"), nil
	}
	ips, via, err := b.lookup(context.Background(), "dns.example.com")
	if err != nil || strings.Join(ips, ",") != "203.0.113.8,2001:db8::853" || via != "198.51.100.53" {
		t.Fatalf("%v %q %v", ips, via, err)
	}
	// cached: not asked again
	n := asked.Load()
	if _, _, err := b.lookup(context.Background(), "DNS.example.com."); err != nil || asked.Load() != n {
		t.Fatal("asked again while the answer is fresh")
	}
	// the Monitor page sees it
	if ips, via := b.resolvedVia("tls://dns.example.com:853"); len(ips) != 2 || via != "198.51.100.53" {
		t.Fatalf("%v %q", ips, via)
	}
	_ = p
}

// The last good answer stays in use when no server can give a new one.
func TestBootstrapKeepsTheLastGoodAnswer(t *testing.T) {
	b, _, net := bootRig(t, "192.0.2.53:53", "tls://dns.example.com:853")
	clock := time.Now()
	b.now = func() time.Time { return clock }
	net["192.0.2.53:53"] = func(q []byte) ([]byte, error) { return bootAnswer(q, 0, 60, "203.0.113.8"), nil }
	if _, _, err := b.lookup(context.Background(), "dns.example.com"); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Minute) // expired
	net["192.0.2.53:53"] = func(q []byte) ([]byte, error) { return bootAnswer(q, 2, 60), nil }
	ips, _, err := b.lookup(context.Background(), "dns.example.com")
	if err != nil || len(ips) != 1 || ips[0] != "203.0.113.8" {
		t.Fatalf("%v %v", ips, err)
	}
	// a name never resolved: the error says why
	if _, _, err := b.lookup(context.Background(), "other.example.com"); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Fatalf("%v", err)
	}
}

// With no server given by address up, the bootstrap servers are asked; with none of those, the host's resolver.
func TestBootstrapServersThenHostResolver(t *testing.T) {
	b, p, net := bootRig(t, "tls://dns.example.com:853")
	b.setExtra([]string{"192.0.2.99:53"})
	net["192.0.2.99:53"] = func(q []byte) ([]byte, error) { return bootAnswer(q, 0, 60, "203.0.113.9"), nil }
	if ips, via, err := b.lookup(context.Background(), "dns.example.com"); err != nil || ips[0] != "203.0.113.9" || via != "192.0.2.99" {
		t.Fatalf("%v %q %v", ips, via, err)
	}
	b2 := newBootResolver()
	b2.register(p)
	b2.hostLook = func(context.Context, string) ([]string, error) { return []string{"2001:db8::1", "203.0.113.10"}, nil }
	ips, via, err := b2.lookup(context.Background(), "dns.example.com")
	if err != nil || strings.Join(ips, ",") != "203.0.113.10,2001:db8::1" || via != bootHostNote {
		t.Fatalf("%v %q %v", ips, via, err)
	}
	// a server that is down is not asked
	b3, p3, net3 := bootRig(t, "192.0.2.53:53", "tls://dns.example.com:853")
	p3.servers[0].healthy, p3.servers[0].lastProbe = false, time.Now() // probed, and down
	net3["192.0.2.53:53"] = func(q []byte) ([]byte, error) { t.Fatal("a down server was asked"); return nil, nil }
	if len(b3.sources("dns.example.com")) != 0 {
		t.Fatal("a down server is a source")
	}
	// just after a start (nothing probed yet) a server given by address is still asked before the host's resolver
	p3.servers[0].lastProbe = time.Time{}
	if got := b3.sources("dns.example.com"); len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatalf("not yet probed: %v", got)
	}
}

// The servers of the gateway the name belongs to are asked before another gateway's.
func TestBootstrapOwnGatewayFirst(t *testing.T) {
	b, _, _ := bootRig(t, "192.0.2.1:53") // another gateway, faster
	own := NewPool(DNSConfig{Servers: []string{"198.51.100.1:53", "tls://dns.example.com:853"}})
	for _, s := range own.servers {
		s.healthy, s.ewma = true, 50
	}
	b.register(own)
	if got := b.sources("dns.example.com"); len(got) != 2 || got[0] != "198.51.100.1:53" {
		t.Fatalf("%v", got)
	}
}

func TestBootstrapConfig(t *testing.T) {
	d := newDaemonConfig().DNS
	d.Bootstrap = []string{"1.1.1.1", " 9.9.9.9:5353 ", "1.1.1.1"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Bootstrap, " ") != "1.1.1.1:53 9.9.9.9:5353" {
		t.Fatalf("%v", d.Bootstrap)
	}
	bad := newDaemonConfig().DNS
	bad.Bootstrap = []string{"resolver.example.net"}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("a name was accepted as a bootstrap server: %v", err)
	}
}

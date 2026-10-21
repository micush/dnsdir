package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// fwdPool makes a pool of three fake servers: pub (public), intl (internal, zones only) and both (public + internal).
// corp holds corp.example and 10.in-addr.arpa, dev holds dev.corp.example (served by dev only).
func fwdPool(t *testing.T) (p *Pool, pub, intl, both, dev *fakeDNS) {
	t.Helper()
	pub, intl, both, dev = newFakeDNS(t), newFakeDNS(t), newFakeDNS(t), newFakeDNS(t)
	cfg := testDNSCfg(pub.addr, intl.addr, both.addr, dev.addr)
	cfg.Spread = false
	cfg.ForwardLists = []string{"corp: corp.example, 10.in-addr.arpa", "dev: dev.corp.example"}
	cfg.ServerForward = map[string]ServerForward{
		intl.addr: {Lists: []string{"corp"}, ZonesOnly: true},
		both.addr: {Lists: []string{"corp"}},
		dev.addr:  {Lists: []string{"dev"}, ZonesOnly: true},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p = NewPool(cfg)
	p.ProbeNow(context.Background())
	return
}

func fwdAsk(t *testing.T, p *Pool, name string) error {
	t.Helper()
	q, _ := buildQuery(7, name, "A")
	_, err := p.Forward(context.Background(), q, false)
	return err
}

func hitsOf(fs ...*fakeDNS) []int64 {
	out := make([]int64, len(fs))
	for i, f := range fs {
		out[i] = f.hits.Load()
	}
	return out
}

func sameHits(a, b []int64) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A name in a zone goes only to the servers of that zone, any other name only to the general servers, and the most
// specific zone wins.
func TestFwdRoutesByZone(t *testing.T) {
	p, pub, intl, both, dev := fwdPool(t)
	all := []*fakeDNS{pub, intl, both, dev}

	before := hitsOf(all...)
	for i := 0; i < 6; i++ {
		if err := fwdAsk(t, p, "www.google.com"); err != nil {
			t.Fatal(err)
		}
	}
	after := hitsOf(all...)
	if after[1] != before[1] || after[3] != before[3] {
		t.Fatalf("a public name reached a zones-only server: before %v after %v", before, after)
	}
	if after[0] == before[0] && after[2] == before[2] {
		t.Fatal("a public name reached no general server")
	}

	before = hitsOf(all...)
	for i := 0; i < 6; i++ {
		if err := fwdAsk(t, p, "host.corp.example"); err != nil {
			t.Fatal(err)
		}
		if err := fwdAsk(t, p, "7.2.2.10.in-addr.arpa"); err != nil {
			t.Fatal(err)
		}
	}
	after = hitsOf(all...)
	if after[0] != before[0] || after[3] != before[3] {
		t.Fatalf("a corp name reached the public or the dev server: before %v after %v", before, after)
	}
	if after[1] == before[1] && after[2] == before[2] {
		t.Fatal("a corp name reached none of the corp servers")
	}

	before = hitsOf(all...)
	for i := 0; i < 4; i++ {
		if err := fwdAsk(t, p, "x.dev.corp.example"); err != nil {
			t.Fatal(err)
		}
	}
	after = hitsOf(all...)
	if after[3] <= before[3] || after[0] != before[0] || after[1] != before[1] || after[2] != before[2] {
		t.Fatalf("the most specific zone (dev) must win: before %v after %v", before, after)
	}

	// the zone itself and a name that only ends like it
	before = hitsOf(all...)
	if err := fwdAsk(t, p, "corp.example"); err != nil {
		t.Fatal(err)
	}
	if err := fwdAsk(t, p, "notcorp.example"); err != nil {
		t.Fatal(err)
	}
	after = hitsOf(all...)
	if after[0] == before[0] && after[2] == before[2] {
		t.Fatal("notcorp.example is not in corp.example: it must go to a general server")
	}
}

// When every server of a zone is down the query fails; it is never sent to the general servers.
func TestFwdZoneDownDoesNotLeak(t *testing.T) {
	p, pub, intl, both, dev := fwdPool(t)
	intl.mode.Store(2)
	both.mode.Store(2)
	p.ProbeNow(context.Background())
	before := hitsOf(pub, intl, both, dev)
	if err := fwdAsk(t, p, "host.corp.example"); err == nil {
		t.Fatal("every corp server is down: the query must fail")
	}
	if after := hitsOf(pub, intl, both, dev); after[0] != before[0] || after[3] != before[3] {
		t.Fatalf("the failed corp query was sent on to another server: before %v after %v", before, after)
	}
	// the other names still work
	if err := fwdAsk(t, p, "www.google.com"); err != nil {
		t.Fatalf("a public name must still be answered: %v", err)
	}
	// and the corp servers coming back is seen
	intl.mode.Store(0)
	p.ProbeNow(context.Background())
	if err := fwdAsk(t, p, "host.corp.example"); err != nil {
		t.Fatalf("a corp server is back: %v", err)
	}
}

// A zones-only server is never asked about other names, even when every general server is down; a fallback server
// then takes over, but never for a zone.
func TestFwdGeneralDownUsesFallbackNotZoneServers(t *testing.T) {
	pub, intl, fb := newFakeDNS(t), newFakeDNS(t), newFakeDNS(t)
	cfg := testDNSCfg(pub.addr, intl.addr)
	cfg.ForwardLists = []string{"corp: corp.example"}
	cfg.ServerForward = map[string]ServerForward{intl.addr: {Lists: []string{"corp"}, ZonesOnly: true}}
	cfg.FallbackServers = []string{fb.addr}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p := NewPool(cfg)
	pub.mode.Store(2)
	p.ProbeNow(context.Background())

	before := intl.hits.Load()
	if err := fwdAsk(t, p, "www.google.com"); err != nil {
		t.Fatalf("the fallback must answer a public name: %v", err)
	}
	if intl.hits.Load() != before {
		t.Fatal("the zones-only server was asked about a public name")
	}
	if fb.hits.Load() == 0 {
		t.Fatal("the fallback was not used")
	}
	fbBefore := fb.hits.Load()
	if err := fwdAsk(t, p, "a.corp.example"); err != nil {
		t.Fatal(err)
	}
	if fb.hits.Load() != fbBefore {
		t.Fatal("a zone name went to the fallback server")
	}

	// no fallback: a public name fails rather than going to the zones-only server
	cfg.FallbackServers = nil
	p2 := NewPool(cfg)
	p2.ProbeNow(context.Background())
	before = intl.hits.Load()
	if err := fwdAsk(t, p2, "www.google.com"); err == nil {
		t.Fatal("no general server is up: the query must fail")
	}
	if intl.hits.Load() != before {
		t.Fatal("the zones-only server was asked about a public name")
	}
}

// A zones-only server with no probe queries of its own is probed with the SOA of its first zone.
func TestFwdZonesOnlyProbedWithSOA(t *testing.T) {
	cfg := testDNSCfg("10.0.0.1:53", "10.0.0.2:53")
	cfg.ForwardLists = []string{"corp: Corp.Example., 10.in-addr.arpa"}
	cfg.ServerForward = map[string]ServerForward{"10.0.0.2:53": {Lists: []string{"corp"}, ZonesOnly: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if q := cfg.queriesFor("10.0.0.2:53"); len(q) != 1 || q[0].Name != "corp.example" || q[0].Type != "SOA" {
		t.Fatalf("zones-only server probe queries: %v", q)
	}
	if q := cfg.queriesFor("10.0.0.1:53"); len(q) != 2 {
		t.Fatalf("a public server keeps the shared probe queries: %v", q)
	}
	cfg.ServerQueries = map[string][]DNSQuery{"10.0.0.2:53": {{Name: "x.corp.example", Type: "A"}}}
	if q := cfg.queriesFor("10.0.0.2:53"); q[0].Name != "x.corp.example" {
		t.Fatalf("its own probe queries win: %v", q)
	}
}

func TestFwdValidation(t *testing.T) {
	base := func() DNSConfig {
		c := testDNSCfg("10.0.0.1:53", "10.0.0.2:53")
		c.ForwardLists = []string{"corp: corp.example"}
		return c
	}
	bad := map[string]func(*DNSConfig){
		"a line with no colon":    func(c *DNSConfig) { c.ForwardLists = []string{"corp corp.example"} },
		"a list written twice":    func(c *DNSConfig) { c.ForwardLists = []string{"a: x.example", "A: y.example"} },
		"a bad zone":              func(c *DNSConfig) { c.ForwardLists = []string{"a: bad zone!.example"} },
		"the root as a zone":      func(c *DNSConfig) { c.ForwardLists = []string{"a: ."} },
		"a bad list name":         func(c *DNSConfig) { c.ForwardLists = []string{"a b: x.example"} },
		"zones only with no list": func(c *DNSConfig) { c.ServerForward = map[string]ServerForward{"10.0.0.2:53": {ZonesOnly: true}} },
		"a server that is not on the list": func(c *DNSConfig) {
			c.ServerForward = map[string]ServerForward{"10.9.9.9:53": {Lists: []string{"corp"}}}
		},
		"a list name that is not a name": func(c *DNSConfig) {
			c.ServerForward = map[string]ServerForward{"10.0.0.2:53": {Lists: []string{"c o"}}}
		},
	}
	for what, f := range bad {
		c := base()
		f(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	c := base()
	c.ForwardLists = []string{"  CORP :  Corp.Example, *.Lab.Example. ;10.in-addr.arpa corp.example", "", "empty:"}
	c.ServerForward = map[string]ServerForward{"10.0.0.2": {Lists: []string{"Corp", "corp"}}, "10.0.0.1:53": {}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"corp: corp.example, lab.example, 10.in-addr.arpa", "empty: "}
	if strings.Join(c.ForwardLists, "|") != strings.Join(want, "|") {
		t.Fatalf("lists %q, want %q", c.ForwardLists, want)
	}
	if f, ok := c.ServerForward["10.0.0.2:53"]; !ok || len(f.Lists) != 1 || f.Lists[0] != "corp" || f.fwdType() != fwdBoth {
		t.Fatalf("server forward %+v", c.ServerForward)
	}
	if _, ok := c.ServerForward["10.0.0.1:53"]; ok {
		t.Fatal("a public server needs no entry")
	}

	// a server may only serve a list the shared Settings have
	dc := DaemonConfig{LogLevel: "info", DNS: c, Groups: []GroupConfig{}}
	dc.DNS.ServerForward = map[string]ServerForward{"10.0.0.2:53": {Lists: []string{"nope"}}}
	if err := dc.Validate(); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("a missing list must be refused, got %v", err)
	}
}

// With no server carrying a list the pool behaves as before: nothing is filtered.
func TestFwdOffByDefault(t *testing.T) {
	a, b := newFakeDNS(t), newFakeDNS(t)
	cfg := testDNSCfg(a.addr, b.addr)
	cfg.ForwardLists = []string{"corp: corp.example"} // no server carries it
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p := NewPool(cfg)
	if p.fwd != nil {
		t.Fatal("no server carries a list: no router")
	}
	p.ProbeNow(context.Background())
	if err := fwdAsk(t, p, "host.corp.example"); err != nil {
		t.Fatal(err)
	}
}

// Route says what the lookup box shows.
func TestFwdRoute(t *testing.T) {
	p, pub, intl, both, dev := fwdPool(t)
	rt := p.Route("Host.Corp.Example.")
	if rt.Zone != "corp.example" || rt.General || len(rt.Lists) != 1 || rt.Lists[0] != "corp" {
		t.Fatalf("route %+v", rt)
	}
	got := map[string]bool{}
	for _, s := range rt.Servers {
		got[s.Addr] = s.Healthy
	}
	if len(got) != 2 || !got[intl.addr] || !got[both.addr] {
		t.Fatalf("corp servers %v", got)
	}
	rt = p.Route("www.google.com")
	if !rt.General || rt.Zone != "" {
		t.Fatalf("route %+v", rt)
	}
	got = map[string]bool{}
	for _, s := range rt.Servers {
		got[s.Addr] = true
	}
	if len(got) != 2 || !got[pub.addr] || !got[both.addr] {
		t.Fatalf("general servers %v", got)
	}
	_ = dev
	intl.mode.Store(2)
	both.mode.Store(2)
	p.ProbeNow(context.Background())
	rt = p.Route("a.corp.example")
	for _, s := range rt.Servers {
		if s.Healthy {
			t.Fatalf("server %s shows up but is down", s.Addr)
		}
	}
	if len(rt.Servers) != 2 {
		t.Fatalf("the down servers must still be listed: %+v", rt.Servers)
	}
}

// A policy row that only names a destination name sends the query, under the new name, to the servers of that
// name's zone.
func TestFwdPolicyRenameRoutesByDestination(t *testing.T) {
	pub, intl := newFakeDNS(t), newFakeDNS(t)
	cfg := testDNSCfg(pub.addr, intl.addr)
	cfg.ForwardLists = []string{"corp: corp.example"}
	cfg.ServerForward = map[string]ServerForward{intl.addr: {Lists: []string{"corp"}, ZonesOnly: true}}
	cfg.Spread = false
	cfg.Policy = []PolicyRule{{Client: "*", Name: "www.old.example", Servers: nil, Dest: "www.corp.example"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p := NewPool(cfg)
	p.ProbeNow(context.Background())
	before, beforeI := pub.hits.Load(), intl.hits.Load()
	q, _ := buildQuery(9, "www.old.example", "A")
	if _, err := p.ForwardFrom(context.Background(), q, false, netip.MustParseAddr("10.1.1.1")); err != nil {
		t.Fatal(err)
	}
	if pub.hits.Load() != before || intl.hits.Load() == beforeI {
		t.Fatal("the renamed query went to the public server instead of the corp server")
	}
}

func TestFwdProbeZone(t *testing.T) {
	cfg := testDNSCfg("10.0.0.1:53", "10.0.0.2:53")
	cfg.ForwardLists = []string{"corp: corp.example, 10.in-addr.arpa", "dev: dev.corp.example"}
	cfg.ServerForward = map[string]ServerForward{
		"10.0.0.2:53": {Lists: []string{"corp", "dev"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"corp.example": "corp.example", "host.corp.example": "corp.example", "x.dev.corp.example": "dev.corp.example",
		"7.2.2.10.in-addr.arpa": "10.in-addr.arpa", "notcorp.example": "", "google.com": "", "Host.Corp.Example.": "corp.example",
	} {
		if got := cfg.probeZone("10.0.0.2:53", name); got != want {
			t.Errorf("probeZone(%q) = %q, want %q", name, got, want)
		}
	}
	if got := cfg.probeZone("10.0.0.1:53", "host.corp.example"); got != "" {
		t.Errorf("a public server has no zones: %q", got)
	}
}

// A probe domain in a zone a Public + Internal server serves decides that zone only: when it fails the server keeps
// answering ordinary names, and the zone's queries go to the other servers of the zone.
func TestFwdPerZoneHealth(t *testing.T) {
	both, intl := newFakeDNS(t), newFakeDNS(t)
	cfg := testDNSCfg(both.addr, intl.addr)
	cfg.Spread = false
	cfg.ForwardLists = []string{"corp: corp.example"}
	cfg.ServerForward = map[string]ServerForward{both.addr: {Lists: []string{"corp"}}, intl.addr: {Lists: []string{"corp"}, ZonesOnly: true}}
	cfg.ServerQueries = map[string][]DNSQuery{
		both.addr: {{Name: "google.com", Type: "A"}, {Name: "ns.corp.example", Type: "A"}},
		intl.addr: {{Name: "corp.example", Type: "SOA"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p := NewPool(cfg)
	ctx := context.Background()
	p.ProbeNow(ctx)
	rt := p.Route("a.corp.example")
	if len(rt.Servers) != 2 || !rt.Servers[0].Healthy || !rt.Servers[1].Healthy {
		t.Fatalf("both servers should serve the zone: %+v", rt.Servers)
	}

	both.failSuffix.Store("corp.example") // the zone's probe fails on the Public + Internal server only
	p.ProbeNow(ctx)
	before := hitsOf(both, intl)
	for i := 0; i < 5; i++ {
		if err := fwdAsk(t, p, "x.corp.example"); err != nil {
			t.Fatal(err)
		}
	}
	after := hitsOf(both, intl)
	if after[0] != before[0] {
		t.Fatalf("a zone query went to the server whose zone probe fails: %v -> %v", before, after)
	}
	if after[1] <= before[1] {
		t.Fatal("the other server of the zone did not get the zone queries")
	}
	if err := fwdAsk(t, p, "www.google.com"); err != nil {
		t.Fatal(err)
	}
	if hitsOf(both)[0] == after[0] {
		t.Fatal("the server must keep answering ordinary names while only its zone probe fails")
	}
	var st ServerStat
	for _, s := range p.Snapshot() {
		if s.Addr == both.addr {
			st = s
		}
	}
	if !st.Healthy || len(st.ZonesDown) != 1 || st.ZonesDown[0] != "corp.example" {
		t.Fatalf("snapshot: healthy %v zones down %v", st.Healthy, st.ZonesDown)
	}
	rt = p.Route("a.corp.example")
	up := 0
	for _, s := range rt.Servers {
		if s.Healthy {
			up++
		}
	}
	if up != 1 {
		t.Fatalf("route shows %d servers up for the zone, want 1: %+v", up, rt.Servers)
	}

	// back again
	both.failSuffix.Store("")
	p.ProbeNow(ctx)
	rt = p.Route("a.corp.example")
	if !rt.Servers[0].Healthy || !rt.Servers[1].Healthy {
		t.Fatalf("both servers answer the zone again: %+v", rt.Servers)
	}
}

// An Internal server with a probe in each of two zones is out of service for the zone whose probe fails only.
func TestFwdInternalServerTwoZones(t *testing.T) {
	in := newFakeDNS(t)
	cfg := testDNSCfg(in.addr)
	cfg.ForwardLists = []string{"corp: corp.example", "lab: lab.example"}
	cfg.ServerForward = map[string]ServerForward{in.addr: {Lists: []string{"corp", "lab"}, ZonesOnly: true}}
	cfg.ServerQueries = map[string][]DNSQuery{in.addr: {{Name: "corp.example", Type: "SOA"}, {Name: "lab.example", Type: "SOA"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p := NewPool(cfg)
	ctx := context.Background()
	p.ProbeNow(ctx)
	if err := fwdAsk(t, p, "a.corp.example"); err != nil {
		t.Fatal(err)
	}
	in.failSuffix.Store("lab.example")
	p.ProbeNow(ctx)
	if err := fwdAsk(t, p, "a.corp.example"); err != nil {
		t.Fatalf("the corp zone still answers: %v", err)
	}
	if err := fwdAsk(t, p, "a.lab.example"); err == nil {
		t.Fatal("the lab zone's probe fails: its queries must fail rather than go on")
	}
}

package main

import (
	"context"
	"strings"
	"testing"
)

func fbCfg(servers, fallback []string) DNSConfig {
	d := testDNSCfg(servers...)
	d.FallbackServers = fallback
	return d
}

// Fallback servers take no queries while a normal server is up, take over when every normal server is
// down, and are dropped again as soon as one normal server answers.
func TestFallbackServersOnlyWhenAllDown(t *testing.T) {
	a, b, fb := newFakeDNS(t), newFakeDNS(t), newFakeDNS(t)
	p := NewPool(fbCfg([]string{a.addr, b.addr}, []string{fb.addr}))
	ctx := context.Background()
	p.ProbeNow(ctx)
	if got := rankedAddrs(p); len(got) != 2 || got[0] == fb.addr || got[1] == fb.addr {
		t.Fatalf("normal servers up: ranked %v must not include the fallback", got)
	}
	if p.UsingFallback() {
		t.Fatal("not using the fallback while the normal servers are up")
	}
	q, _ := buildQuery(0x1111, "www.example", "A")
	checks := fb.hits.Load() // the round's check of the fallback (fallbackcheck.go); no client query
	if checks != 1 {
		t.Fatalf("fallback asked %d times in one round, want its one check", checks)
	}
	for i := 0; i < 6; i++ {
		if _, err := p.Forward(ctx, q, false); err != nil {
			t.Fatal(err)
		}
	}
	if fb.hits.Load() != checks { // no client traffic while a normal server is up
		t.Fatalf("fallback got %d client queries, want none", fb.hits.Load()-checks)
	}

	// one normal server down: still no fallback
	a.mode.Store(2)
	p.ProbeNow(ctx)
	if p.UsingFallback() || len(p.Ranked()) != 1 {
		t.Fatalf("one server up: fallback %v ranked %v", p.UsingFallback(), rankedAddrs(p))
	}

	// all normal servers down: the fallback answers
	b.mode.Store(2)
	p.ProbeNow(ctx)
	if !p.UsingFallback() {
		t.Fatal("every normal server is down: the fallback must be in use")
	}
	if got := rankedAddrs(p); len(got) != 1 || got[0] != fb.addr {
		t.Fatalf("ranked %v, want just the fallback", got)
	}
	before := fb.hits.Load()
	if _, err := p.Forward(ctx, q, false); err != nil {
		t.Fatalf("forward through the fallback: %v", err)
	}
	if fb.hits.Load() <= before {
		t.Fatal("the query did not reach the fallback")
	}
	var marked bool
	for _, s := range p.Snapshot() {
		if s.Addr == fb.addr && s.Fallback && s.Rank == 1 {
			marked = true
		}
	}
	if !marked {
		t.Fatal("the snapshot must mark the fallback and rank it while in use")
	}

	// a normal server comes back: the fallback is dropped
	b.mode.Store(0)
	p.ProbeNow(ctx)
	if p.UsingFallback() {
		t.Fatal("a normal server is back: the fallback must no longer be used")
	}
	if got := rankedAddrs(p); len(got) != 1 || got[0] != b.addr {
		t.Fatalf("ranked %v, want just %s", got, b.addr)
	}
	before = fb.hits.Load()
	for i := 0; i < 4; i++ {
		if _, err := p.Forward(ctx, q, false); err != nil {
			t.Fatal(err)
		}
	}
	if fb.hits.Load() != before {
		t.Fatalf("the fallback still got %d queries after the switch back", fb.hits.Load()-before)
	}
}

// Without any fallback and with every server down the pool has nothing, as before.
func TestNoFallbackStillFails(t *testing.T) {
	a := newFakeDNS(t)
	a.mode.Store(2)
	p := NewPool(fbCfg([]string{a.addr}, nil))
	p.ProbeNow(context.Background())
	q, _ := buildQuery(1, "www.example", "A")
	if _, err := p.Forward(context.Background(), q, false); err == nil {
		t.Fatal("expected an error with every server down and no fallback")
	}
}

// A fallback is a last resort: it is never probed with the test domains (it may know nothing about them) and always
// counts as up.  Each round only checks that it answers at all, with ". NS"; NXDOMAIN counts as answering.
func TestFallbackOnlyCheckedAlwaysUp(t *testing.T) {
	a, fb := newFakeDNS(t), newFakeDNS(t)
	fb.mode.Store(1) // NXDOMAIN for everything: a probe with the test domains would fail it
	p := NewPool(fbCfg([]string{a.addr}, []string{fb.addr}))
	p.ProbeNow(context.Background())
	p.ProbeNow(context.Background())
	if fb.hits.Load() != 2 {
		t.Fatalf("the fallback was asked %d times in two rounds, want its two checks", fb.hits.Load())
	}
	if c := fbCheck(t, p, fb.addr); c == nil || !c.Answering || !c.LastOK || c.Error != "" {
		t.Fatalf("an NXDOMAIN answer is an answer: %+v", c)
	}
	a.mode.Store(2)
	p.ProbeNow(context.Background())
	if !p.UsingFallback() {
		t.Fatal("every normal server is down: the fallback must be in use")
	}
}

func fbCheck(t *testing.T, p *Pool, addr string) *FallbackCheck {
	t.Helper()
	for _, s := range p.Snapshot() {
		if s.Addr == addr {
			if !s.Fallback {
				t.Fatalf("%s is not marked as a fallback", addr)
			}
			return s.Check
		}
	}
	t.Fatalf("%s is not in the snapshot", addr)
	return nil
}

// A fallback that does not answer its check is reported (after fail_threshold rounds) but still used: the check only reports.
func TestFallbackCheckReportsOnly(t *testing.T) {
	a, fb := newFakeDNS(t), newFakeDNS(t)
	cfg := fbCfg([]string{a.addr}, []string{fb.addr})
	cfg.FailThreshold = 2
	p := NewPool(cfg)
	ctx := context.Background()
	if c := fbCheck(t, p, fb.addr); c != nil {
		t.Fatalf("checked before any round: %+v", c)
	}
	fb.mode.Store(3) // SERVFAIL
	p.ProbeNow(ctx)
	if c := fbCheck(t, p, fb.addr); c == nil || !c.Answering || c.LastOK || c.ConsecFails != 1 || !strings.Contains(c.Error, "SERVFAIL") {
		t.Fatalf("one miss of two allowed: %+v", c)
	}
	p.ProbeNow(ctx)
	if c := fbCheck(t, p, fb.addr); c == nil || c.Answering || c.ConsecFails != 2 {
		t.Fatalf("two misses: %+v", c)
	}
	// still a last resort: every normal server down, the fallback answers clients
	fb.mode.Store(0)
	a.mode.Store(2)
	p.ProbeNow(ctx)
	p.ProbeNow(ctx)
	if !p.UsingFallback() {
		t.Fatal("the fallback must be in use whatever its check said")
	}
	if c := fbCheck(t, p, fb.addr); c == nil || !c.Answering || c.ConsecFails != 0 || c.MS <= 0 {
		t.Fatalf("answers again: %+v", c)
	}
	// a server that does not answer at all
	fb.mode.Store(2)
	p.ProbeNow(ctx)
	p.ProbeNow(ctx)
	if c := fbCheck(t, p, fb.addr); c == nil || c.Answering || c.Error == "" {
		t.Fatalf("no answer: %+v", c)
	}
	if !p.UsingFallback() {
		t.Fatal("still the last resort")
	}
}

func TestRootNSQuery(t *testing.T) {
	q := buildRootNSQuery(0xabcd)
	want := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	if string(q) != string(want) {
		t.Fatalf("% x", q)
	}
	if fallbackCheckWords(nil) != "not checked yet" || fallbackCheckWords(&FallbackCheck{}) != "NOT ANSWERING" || fallbackCheckWords(&FallbackCheck{Answering: true, LastOK: true}) != "answering" {
		t.Fatal("words")
	}
}

func TestFallbackValidation(t *testing.T) {
	d := testDNSCfg("10.0.0.53")
	d.FallbackServers = []string{"1.1.1.1", "[2001:db8::1]", "tls://dns.example.net"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53", "[2001:db8::1]:53", "tls://dns.example.net:853"}
	for i, w := range want {
		if d.FallbackServers[i] != w {
			t.Fatalf("fallback %d = %q, want %q", i, d.FallbackServers[i], w)
		}
	}
	dup := testDNSCfg("10.0.0.53")
	dup.FallbackServers = []string{"10.0.0.53"}
	if err := dup.Validate(); err == nil || !strings.Contains(err.Error(), "also a normal server") {
		t.Fatalf("a normal server as fallback: %v", err)
	}
	twice := testDNSCfg("10.0.0.53")
	twice.FallbackServers = []string{"1.1.1.1", "1.1.1.1:53"}
	if err := twice.Validate(); err == nil {
		t.Fatal("a fallback listed twice must be refused")
	}
	bad := testDNSCfg("10.0.0.53")
	bad.FallbackServers = []string{"not a host!"}
	if err := bad.Validate(); err == nil {
		t.Fatal("a bad fallback address must be refused")
	}
	// an empty list is the same as none (and is not written out)
	none := testDNSCfg("10.0.0.53")
	none.FallbackServers = []string{}
	if err := none.Validate(); err != nil || none.FallbackServers != nil {
		t.Fatalf("empty fallback list: %v %v", err, none.FallbackServers)
	}
}

func TestFallbackReplicatesAndSurvivesClone(t *testing.T) {
	d := testDNSCfg("10.0.0.53")
	d.FallbackServers = []string{"1.1.1.1:53"}
	c := cloneDNS(d)
	c.FallbackServers[0] = "9.9.9.9:53"
	if d.FallbackServers[0] != "1.1.1.1:53" {
		t.Fatal("cloneDNS shares the fallback slice")
	}
}

func TestCanvasShowsFallbackInUse(t *testing.T) {
	a, fb := newFakeDNS(t), newFakeDNS(t)
	d := fbCfg([]string{a.addr}, []string{fb.addr})
	g := defaultGroup()
	g.DNSProxy, g.DNS = true, &d
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	p := NewPool(d)
	pools := []poolInfo{{Key: 1, Groups: []int{1}, Pool: p, Cfg: d}}
	rows := []SnapshotRow{{GroupID: 1, AF: "v4", Local: true, State: "active", DNSUp: true}}

	p.ProbeNow(context.Background())
	cv := buildCanvas(dc, rows, pools)
	if cv[0].Status != "ok" || cv[0].UsingFallback || len(cv[0].Fallback) != 1 {
		t.Fatalf("normal server up: %+v", cv[0])
	}
	if c := cv[0].FallbackCheck[fb.addr]; c == nil || !c.Answering {
		t.Fatalf("the canvas carries the fallback's check: %+v", cv[0].FallbackCheck)
	}
	a.mode.Store(2)
	p.ProbeNow(context.Background())
	cv = buildCanvas(dc, rows, pools)
	if cv[0].Status != "warn" || !cv[0].UsingFallback || !strings.Contains(cv[0].Families[0].Detail, "fallback") {
		t.Fatalf("every server down, fallback up must be amber and say so: %+v", cv[0])
	}
}

func TestCanvasEditFallback(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{defaultGroup()}
	edit := func(action, srv string) error {
		_, err := applyCanvasEdit(dc, canvasEdit{Action: action, Kind: "fallback", Group: 1, Server: srv})
		return err
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "add", Kind: "server", Group: 1, Server: "8.8.8.8", Name: "google.com"}); err != nil {
		t.Fatal(err)
	}
	if err := edit("add", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if got := dc.Groups[0].DNS.FallbackServers; len(got) != 1 || got[0] != "1.1.1.1:53" {
		t.Fatalf("fallbacks %v", got)
	}
	if edit("add", "1.1.1.1") == nil {
		t.Fatal("a second add of the same fallback must be refused")
	}
	if edit("add", "8.8.8.8") == nil {
		t.Fatal("a normal server cannot also be a fallback")
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := edit("del", "9.9.9.9"); err == nil {
		t.Fatal("deleting an unknown fallback must fail")
	}
	if err := edit("del", "1.1.1.1"); err != nil || dc.Groups[0].DNS.FallbackServers != nil {
		t.Fatalf("delete: %v %v", err, dc.Groups[0].DNS.FallbackServers)
	}
}

// Fallbacks need no probe queries, so a gateway whose servers carry their own domains (as the canvas makes them)
// or has no servers at all can still have them.
func TestFallbackNeedsNoQueries(t *testing.T) {
	d := testDNSCfg()
	d.Queries = nil
	d.FallbackServers = []string{"1.1.1.1"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

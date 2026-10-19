package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ── wire ─────────────────────────────────────────────────────────────────────

func TestNTPTimestampRoundTrip(t *testing.T) {
	for _, tm := range []time.Time{
		time.Date(2026, 10, 12, 6, 0, 0, 123456000, time.UTC),
		time.Date(1999, 12, 31, 23, 59, 59, 999000000, time.UTC),
		time.Date(2040, 1, 1, 0, 0, 0, 5000, time.UTC), // after the 2036 rollover: era 1
	} {
		got := ntpToTime(ntpTimestamp(tm))
		if d := got.Sub(tm); d < -time.Microsecond || d > time.Microsecond {
			t.Errorf("%v came back as %v (%v off)", tm, got, d)
		}
	}
}

func TestParseNTPAndBuildRequest(t *testing.T) {
	req := buildNTPRequest(0x0102030405060708)
	p, ok := parseNTP(req)
	if !ok || p.Version != 4 || p.Mode != ntpModeClient || p.Xmit != 0x0102030405060708 {
		t.Fatalf("%+v %v", p, ok)
	}
	if _, ok := parseNTP(req[:47]); ok {
		t.Fatal("a packet shorter than the header was parsed")
	}
	if ntpMode(req[:10]) != -1 || ntpVersion(req[:10]) != 0 {
		t.Fatal("short packets have no mode or version")
	}
	if x := randomXmit(); x == 0 || x == randomXmit() {
		t.Fatalf("random transmit timestamps must be non-zero and differ: %x", x)
	}
}

func TestNTPRelayable(t *testing.T) {
	mk := func(v, m byte, n int) []byte {
		b := make([]byte, n)
		b[0] = v<<3 | m
		return b
	}
	for name, c := range map[string]struct {
		pkt  []byte
		want bool
	}{
		"v4 client":        {mk(4, 3, 48), true},
		"v3 client":        {mk(3, 3, 48), true},
		"v1 client":        {mk(1, 3, 48), true},
		"v4 with a MAC":    {mk(4, 3, 68), true},
		"v0":               {mk(0, 3, 48), false},
		"v5":               {mk(5, 3, 48), false},
		"server answer":    {mk(4, 4, 48), false},
		"symmetric active": {mk(4, 1, 48), false},
		"broadcast":        {mk(4, 5, 48), false},
		"control mode 6":   {mk(2, 6, 48), false},
		"private mode 7":   {mk(2, 7, 48), false},
		"short":            {mk(4, 3, 47), false},
		"too long":         {mk(4, 3, ntpMaxPacket+1), false},
	} {
		if got := ntpRelayable(c.pkt); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestNTPAnswersMatchesTheOrigin(t *testing.T) {
	req := buildNTPRequest(0xAAAA5555AAAA5555)
	good := make([]byte, ntpHeaderLen)
	good[0] = 4<<3 | ntpModeServer
	copy(good[24:32], req[40:48])
	if !ntpAnswers(req, good) {
		t.Fatal("the matching answer was refused")
	}
	other := append([]byte(nil), good...)
	other[31] ^= 1
	if ntpAnswers(req, other) {
		t.Fatal("an answer to another request was accepted")
	}
	client := append([]byte(nil), good...)
	client[0] = 4<<3 | ntpModeClient
	if ntpAnswers(req, client) {
		t.Fatal("a client-mode packet was taken for an answer")
	}
	if ntpAnswers(req, good[:40]) || ntpAnswers(req[:40], good) {
		t.Fatal("a short packet was accepted")
	}
}

func TestKissOfDeathAndUnsyncResponses(t *testing.T) {
	req := buildNTPRequest(0x1111222233334444)
	req[0] = 3<<3 | ntpModeClient // a version 3 client is answered in version 3
	req[2] = 6
	k := kodResponse(req, kodRate)
	if kodCode(k) != "RATE" || !ntpAnswers(req, k) || ntpVersion(k) != 3 || k[2] != 6 || k[0]>>6 != ntpLeapUnsynch {
		t.Fatalf("kod: % x", k)
	}
	if kodCode(buildNTPRequest(1)) != "" || kodCode(make([]byte, 10)) != "" {
		t.Fatal("a request or a short packet is not a kiss-o'-death")
	}
	u := unsyncResponse(req)
	if u[1] != 16 || u[0]>>6 != ntpLeapUnsynch || !ntpAnswers(req, u) || kodCode(u) != "" {
		t.Fatalf("unsync: % x", u)
	}
	if kodResponse(req[:10], kodRate) != nil || unsyncResponse(req[:10]) != nil {
		t.Fatal("a request too short to answer must get nothing")
	}
	if refIDString(1, [4]byte{'G', 'P', 'S', 0}) != "GPS" || refIDString(2, [4]byte{10, 1, 2, 3}) != "10.1.2.3" || refIDString(0, [4]byte{'R', 'A', 'T', 'E'}) != "RATE" {
		t.Fatal("reference ids")
	}
}

// ── probing ──────────────────────────────────────────────────────────────────

func TestProbeMeasuresOffsetDelayAndStratum(t *testing.T) {
	f := newFakeNTP(t)
	f.stratum.Store(3)
	f.offset.Store(int64(250 * time.Millisecond))
	f.rootDel.Store(int64(40 * time.Millisecond))
	f.rootDsp.Store(int64(10 * time.Millisecond))
	s, err := ntpProbe(context.Background(), f.addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if s.Stratum != 3 || s.Leap != 0 || s.Version != 4 || s.RefID != "127.127.1.0" {
		t.Fatalf("%+v", s)
	}
	if d := s.Offset - 250*time.Millisecond; d < -20*time.Millisecond || d > 20*time.Millisecond {
		t.Fatalf("offset %v, want about 250ms", s.Offset)
	}
	if s.Delay < 0 || s.Delay > 100*time.Millisecond || s.RTT <= 0 {
		t.Fatalf("delay %v rtt %v", s.Delay, s.RTT)
	}
	// root distance: root delay/2 + root dispersion + delay/2
	if min := 30 * time.Millisecond; s.RootDist < min || s.RootDist > min+50*time.Millisecond {
		t.Fatalf("root distance %v", s.RootDist)
	}
}

func TestProbeIgnoresAnAnswerToAnotherRequest(t *testing.T) {
	f := newFakeNTP(t)
	f.mode.Store(fakeWrongOrigin)
	if _, err := ntpProbe(context.Background(), f.addr, 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("an answer with the wrong origin timestamp must be ignored, got %v", err)
	}
}

func TestProbeSeesKissOfDeathAndTimeouts(t *testing.T) {
	f := newFakeNTP(t)
	f.mode.Store(fakeKoD)
	s, err := ntpProbe(context.Background(), f.addr, time.Second)
	if err != nil || s.KoD != "DENY" {
		t.Fatalf("%+v %v", s, err)
	}
	f.mode.Store(fakeDrop)
	if _, err := ntpProbe(context.Background(), f.addr, 150*time.Millisecond); err == nil {
		t.Fatal("a silent server answered")
	}
}

func TestJudge(t *testing.T) {
	c := defaultNTP()
	ok := ntpSample{Stratum: 2, xmit: 1, recv: 1, RootDist: 10 * time.Millisecond}
	if err := c.judge(ok); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*ntpSample){
		"kod":            func(s *ntpSample) { s.KoD = "RATE" },
		"unsynchronised": func(s *ntpSample) { s.Leap = ntpLeapUnsynch },
		"stratum 16":     func(s *ntpSample) { s.Stratum = 16 },
		"no timestamps":  func(s *ntpSample) { s.xmit = 0 },
		"too deep":       func(s *ntpSample) { s.Stratum = 15; c.MaxStratum = 10 },
		"root distance":  func(s *ntpSample) { s.RootDist = 2 * time.Second },
	} {
		c = defaultNTP()
		s := ok
		mod(&s)
		if c.judge(s) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestLatencyReordersAfterChange(t *testing.T) {
	a, b := newFakeNTP(t), newFakeNTP(t)
	b.delay.Store(int64(40 * time.Millisecond))
	p := NewPool(testNTPCfg(a.addr, b.addr))
	p.ProbeNow(context.Background())
	if r := rankedAddrs(p); r[0] != a.addr {
		t.Fatalf("want a first: %v", r)
	}
	a.delay.Store(int64(120 * time.Millisecond))
	b.delay.Store(0)
	for i := 0; i < 4; i++ {
		p.ProbeNow(context.Background())
	}
	if r := rankedAddrs(p); r[0] != b.addr {
		t.Fatalf("want b first after change: %v", r)
	}
}

func TestHealthGating(t *testing.T) {
	good, kod, dead, unsync, deep := newFakeNTP(t), newFakeNTP(t), newFakeNTP(t), newFakeNTP(t), newFakeNTP(t)
	kod.mode.Store(fakeKoD)
	dead.mode.Store(fakeDrop)
	unsync.mode.Store(fakeUnsync)
	deep.stratum.Store(16)
	p := NewPool(testNTPCfg(good.addr, kod.addr, dead.addr, unsync.addr, deep.addr))
	p.ProbeNow(context.Background())
	if r := rankedAddrs(p); len(r) != 1 || r[0] != good.addr {
		t.Fatalf("only the good server should be eligible, got %v", r)
	}
	for _, s := range p.Snapshot() {
		if s.Addr != good.addr && (s.Healthy || s.LastError == "") {
			t.Fatalf("bad server %s not reported: %+v", s.Addr, s)
		}
	}
	// the kiss-o'-death server recovers and joins on the next round
	kod.mode.Store(fakeOK)
	p.ProbeNow(context.Background())
	if len(rankedAddrs(p)) != 2 {
		t.Fatalf("recovered server not re-admitted: %v", rankedAddrs(p))
	}
}

func TestFailThresholdKeepsAServerUntilItFailsEnoughTimes(t *testing.T) {
	f, g := newFakeNTP(t), newFakeNTP(t)
	cfg := testNTPCfg(f.addr, g.addr)
	cfg.FailThreshold = 3
	p := NewPool(cfg)
	p.ProbeNow(context.Background())
	f.mode.Store(fakeDrop)
	for i := 1; i <= 2; i++ {
		p.ProbeNow(context.Background())
		if len(rankedAddrs(p)) != 2 {
			t.Fatalf("taken out after %d failed probe(s), the threshold is 3", i)
		}
	}
	p.ProbeNow(context.Background())
	if r := rankedAddrs(p); len(r) != 1 || r[0] != g.addr {
		t.Fatalf("still in service after 3 failed probes: %v", r)
	}
}

func TestFalsetickerIsTakenOut(t *testing.T) {
	a, b, c, liar := newFakeNTP(t), newFakeNTP(t), newFakeNTP(t), newFakeNTP(t)
	liar.offset.Store(int64(5 * time.Second)) // five seconds ahead of the other three
	cfg := testNTPCfg(a.addr, b.addr, c.addr, liar.addr)
	p := NewPool(cfg)
	p.ProbeNow(context.Background())
	r := rankedAddrs(p)
	if len(r) != 3 {
		t.Fatalf("the falseticker must not be ranked: %v", r)
	}
	var seen bool
	for _, s := range p.Snapshot() {
		if s.Addr == liar.addr {
			seen = true
			if !s.Falseticker || s.Healthy || !strings.Contains(s.LastError, "falseticker") || s.Time == nil || s.Time.OffsetMS < 4000 {
				t.Fatalf("%+v", s)
			}
		} else if s.Falseticker || !s.Healthy {
			t.Fatalf("%s wrongly judged: %+v", s.Addr, s)
		}
	}
	if !seen {
		t.Fatal("the liar is not in the snapshot")
	}
	// it corrects its clock and comes back
	liar.offset.Store(0)
	p.ProbeNow(context.Background())
	if len(rankedAddrs(p)) != 4 {
		t.Fatalf("the corrected server did not come back: %v", rankedAddrs(p))
	}
	// the check needs three servers: with two, a difference cannot say which one is right
	two := NewPool(testNTPCfg(a.addr, liar.addr))
	liar.offset.Store(int64(5 * time.Second))
	two.ProbeNow(context.Background())
	if len(rankedAddrs(two)) != 2 {
		t.Fatalf("with two servers neither can be called a falseticker: %v", rankedAddrs(two))
	}
	// and it can be switched off
	cfg.MaxOffsetMS = 0
	off := NewPool(cfg)
	off.ProbeNow(context.Background())
	if len(rankedAddrs(off)) != 4 {
		t.Fatalf("max_offset_ms 0 must switch the check off: %v", rankedAddrs(off))
	}
}

func TestSnapshotCarriesWhatTheServerSaid(t *testing.T) {
	f := newFakeNTP(t)
	f.stratum.Store(2)
	p := NewPool(testNTPCfg(f.addr))
	p.ProbeNow(context.Background())
	s := p.Snapshot()
	if len(s) != 1 || s[0].Time == nil || s[0].Time.Stratum != 2 || s[0].Time.Version != 4 || !s[0].Healthy || s[0].Rank != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestLogServerFlips(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	f := newFakeNTP(t)
	p := NewPool(testNTPCfg(f.addr))
	p.ProbeNow(context.Background())
	if !strings.Contains(buf.String(), "is UP") {
		t.Fatalf("no UP line: %s", buf.String())
	}
	buf.Reset()
	p.ProbeNow(context.Background())
	if strings.Contains(buf.String(), "is UP") || strings.Contains(buf.String(), "is DOWN") {
		t.Fatalf("steady state logged: %s", buf.String())
	}
	f.mode.Store(fakeDrop)
	p.ProbeNow(context.Background())
	if !strings.Contains(buf.String(), "is DOWN") {
		t.Fatalf("no DOWN line: %s", buf.String())
	}
}

func TestConfigParsing(t *testing.T) {
	var d NTPConfig
	err := d.UnmarshalJSON([]byte(`{"servers":["10.0.0.123","[2001:db8::123]:1123","ntp.example.com"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if d.Servers[0] != "10.0.0.123:123" || d.Servers[1] != "[2001:db8::123]:1123" || d.Servers[2] != "ntp.example.com:123" {
		t.Fatalf("servers: %v", d.Servers)
	}
	if d.ListenPort != 123 || d.MaxStratum != 15 || d.MaxOffsetMS != 128 || !d.Spread {
		t.Fatalf("defaults: %+v", d)
	}
	if err := d.UnmarshalJSON([]byte(`{"serverz":[]}`)); err == nil {
		t.Fatal("typo'd key accepted")
	}
	for name, mod := range map[string]func(*NTPConfig){
		"bad server":   func(c *NTPConfig) { c.Servers = []string{"not a host!"} },
		"bad port":     func(c *NTPConfig) { c.Servers = []string{"10.0.0.1:99999"} },
		"stratum 0":    func(c *NTPConfig) { c.MaxStratum = 0 },
		"stratum 16":   func(c *NTPConfig) { c.MaxStratum = 16 },
		"negative off": func(c *NTPConfig) { c.MaxOffsetMS = -1 },
		"dup server":   func(c *NTPConfig) { c.Servers = []string{"10.0.0.1", "10.0.0.1:123"} },
	} {
		x := defaultNTP()
		mod(&x)
		if x.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// the listen port 53 and the like are fine: only 1-65535 is checked
	x := defaultNTP()
	x.ListenPort = 0
	if x.Validate() == nil {
		t.Error("listen port 0 accepted")
	}
}

var _ = binary.BigEndian

// ── both address families ────────────────────────────────────────────────────

// dualHost makes the name "ntp.test" resolve to the given IPv4 and IPv6 addresses for the test.
func dualHost(t *testing.T, v4, v6 []netip.Addr) {
	t.Helper()
	old := lookupServerIPs
	lookupServerIPs = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if host != "ntp.test" {
			return nil, errors.New("no such host")
		}
		if network == "ip4" {
			return v4, nil
		}
		return v6, nil
	}
	t.Cleanup(func() { lookupServerIPs = old })
}

var (
	loop4 = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	loop6 = []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.2")} // stands in for an AAAA record: this machine may have no IPv6, and the family is the one it was looked up as
)

func famByName(st ServerStat, name string) *FamStat {
	for i := range st.Families {
		if st.Families[i].Family == name {
			return &st.Families[i]
		}
	}
	return nil
}

func TestServerIsProbedOverBothFamiliesAndIPv4Wins(t *testing.T) {
	f4 := newFakeNTP(t)
	_, port, _ := net.SplitHostPort(f4.addr)
	f6, err := newFakeNTPOn(t, "udp4", "127.0.0.2:"+port)
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	f4.delay.Store(int64(30 * time.Millisecond)) // IPv4 is the slower one, and still the one that counts
	f4.stratum.Store(2)
	f6.stratum.Store(5)
	dualHost(t, loop4, loop6)
	p := NewPool(testNTPCfg("ntp.test:" + port))
	p.ProbeNow(context.Background())
	st := p.Snapshot()[0]
	if !st.Healthy || st.Via != "IPv4" || st.Time == nil || st.Time.Stratum != 2 || st.EWMAMS < 25 {
		t.Fatalf("IPv4 should supply the numbers: %+v", st)
	}
	if v4, v6 := famByName(st, "IPv4"), famByName(st, "IPv6"); v4 == nil || v6 == nil || !v4.OK || !v6.OK {
		t.Fatalf("both families should have answered: %+v", st.Families)
	}
	if f4.hits.Load() == 0 || f6.hits.Load() == 0 {
		t.Fatalf("each family should have been probed: v4 %d, v6 %d", f4.hits.Load(), f6.hits.Load())
	}
}

func TestServerStaysUpOnIPv4WhenIPv6IsDead(t *testing.T) {
	f4 := newFakeNTP(t)
	_, port, _ := net.SplitHostPort(f4.addr)
	dualHost(t, loop4, loop6) // nothing listens on 127.0.0.2:port
	p := NewPool(testNTPCfg("ntp.test:" + port))
	p.ProbeNow(context.Background())
	st := p.Snapshot()[0]
	if !st.Healthy || st.Via != "IPv4" || st.LastError != "" {
		t.Fatalf("a dead IPv6 must not hurt the server: %+v", st)
	}
	if v6 := famByName(st, "IPv6"); v6 == nil || v6.OK || v6.Error == "" {
		t.Fatalf("IPv6 should show its failure: %+v", st.Families)
	}
}

func TestServerFallsBackToIPv6WhenIPv4IsDead(t *testing.T) {
	f6, err := newFakeNTPOn(t, "udp4", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	_, port, _ := net.SplitHostPort(f6.addr)
	dualHost(t, loop4, loop6) // nothing listens on 127.0.0.1:port
	p := NewPool(testNTPCfg("ntp.test:" + port))
	p.ProbeNow(context.Background())
	st := p.Snapshot()[0]
	if !st.Healthy || st.Via != "IPv6" || st.Time == nil || st.Rank != 1 {
		t.Fatalf("IPv6 should carry the server when IPv4 does not answer: %+v", st)
	}
	if v4 := famByName(st, "IPv4"); v4 == nil || v4.OK {
		t.Fatalf("IPv4 should show its failure: %+v", st.Families)
	}
}

func TestServerDownWhenNeitherFamilyAnswers(t *testing.T) {
	f4 := newFakeNTP(t)
	f4.mode.Store(fakeDrop)
	_, port, _ := net.SplitHostPort(f4.addr)
	dualHost(t, loop4, loop6)
	p := NewPool(testNTPCfg("ntp.test:" + port))
	p.ProbeNow(context.Background())
	st := p.Snapshot()[0]
	if st.Healthy || !strings.Contains(st.LastError, "IPv4:") || !strings.Contains(st.LastError, "IPv6:") {
		t.Fatalf("the error should name both families: %+v", st)
	}
}

func TestServerWithOnlyAnIPv6AddressIsProbedOverIPv6(t *testing.T) {
	f6, err := newFakeNTPOn(t, "udp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	p := NewPool(testNTPCfg(f6.addr))
	p.ProbeNow(context.Background())
	st := p.Snapshot()[0]
	if !st.Healthy || st.Via != "IPv6" || len(st.Families) != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestServerThatDoesNotResolveIsDown(t *testing.T) {
	dualHost(t, nil, nil)
	p := NewPool(testNTPCfg("ntp.test:123"))
	p.ProbeNow(context.Background())
	st := p.Snapshot()[0]
	if st.Healthy || !strings.Contains(st.LastError, "cannot resolve ntp.test") {
		t.Fatalf("%+v", st)
	}
}

func TestProbesFeedTheServersOffsetGraph(t *testing.T) {
	f := newFakeNTP(t)
	f.offset.Store(int64(250 * time.Millisecond))
	p := NewPool(testNTPCfg(f.addr))
	p.ProbeNow(context.Background())
	h := p.servers[0].hist
	h.mu.Lock()
	n, sum := h.offN, h.offSum
	h.mu.Unlock()
	if n != 1 || sum < 230_000 || sum > 270_000 {
		t.Fatalf("offset samples %d, sum %d µs: want one sample of about 250 ms", n, sum)
	}
	// an unsynchronised clock's offset means nothing and is not graphed
	g := newFakeNTP(t)
	g.mode.Store(fakeUnsync)
	q := NewPool(testNTPCfg(g.addr))
	q.ProbeNow(context.Background())
	h = q.servers[0].hist
	h.mu.Lock()
	n = h.offN
	h.mu.Unlock()
	if n != 0 {
		t.Fatalf("an unsynchronised server left %d offset samples", n)
	}
}

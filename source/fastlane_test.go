package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// flTest is a Fast Lane whose connects are fake: the time of each address is looked up in times, an address not in
// times does not answer.
type flTest struct {
	*fastLane
	mu    sync.Mutex
	times map[string]time.Duration
	clock time.Time
}

func newFLTest(t *testing.T, spread bool, times map[string]time.Duration) *flTest {
	t.Helper()
	cfg := DNSConfig{FastLane: true, Spread: spread, SpreadBand: 20, LatencyAlpha: 1}
	x := &flTest{fastLane: newFastLane(cfg), times: times, clock: time.Unix(1_700_000_000, 0)}
	x.fastLane.dial = func(_ context.Context, a netip.Addr) (time.Duration, bool) {
		x.mu.Lock()
		defer x.mu.Unlock()
		d, ok := x.times[a.String()]
		return d, ok
	}
	x.fastLane.now = func() time.Time {
		x.mu.Lock()
		defer x.mu.Unlock()
		return x.clock
	}
	t.Cleanup(x.fastLane.stop)
	return x
}

func (x *flTest) advance(d time.Duration) {
	x.mu.Lock()
	x.clock = x.clock.Add(d)
	x.mu.Unlock()
}

// settle waits until n probes have finished.
func (x *flTest) settle(t *testing.T, n uint64) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if x.Probes.Load() >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("only %d of %d probes finished", x.Probes.Load(), n)
}

func ms(n float64) time.Duration { return time.Duration(n * float64(time.Millisecond)) }

func TestFastLaneNarrowsToTheFastest(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{"1.1.1.1": ms(30), "2.2.2.2": ms(5), "3.3.3.3": ms(50)})
	msg := sortMsg("1.1.1.1", "2.2.2.2", "3.3.3.3")
	orig := append([]byte(nil), msg...)

	// the first answer for a name goes out as it came, and the addresses are measured meanwhile
	if out := x.narrow(msg, typeA, "a.example", nil); &out[0] != &msg[0] {
		t.Fatal("the first answer was changed before anything was measured")
	}
	x.settle(t, 3)

	out := x.narrow(msg, typeA, "a.example", nil)
	if got, want := answerAddrs(t, out), []string{"2.2.2.2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("addresses %v, want %v", got, want)
	}
	if !reflect.DeepEqual(msg, orig) {
		t.Fatal("the input message was modified")
	}
	rrs, _, ok := recordsAfterQuestion(out)
	if !ok || len(rrs) != 2 || rrs[0].typ != typeCNAME || int(binary.BigEndian.Uint16(out[6:])) != 2 {
		t.Fatalf("message damaged: ok=%v rrs=%d an=%d", ok, len(rrs), binary.BigEndian.Uint16(out[6:]))
	}
	for _, rr := range rrs {
		if ttl := binary.BigEndian.Uint32(out[rr.rdataOff-6:]); ttl != flDefaultTTL {
			t.Fatalf("TTL %d, want it capped at %d", ttl, flDefaultTTL)
		}
	}
	if x.Narrowed.Load() != 1 {
		t.Fatalf("narrowed = %d", x.Narrowed.Load())
	}
}

func TestFastLaneKeepsLowerTTL(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{"1.1.1.1": ms(30), "2.2.2.2": ms(5)})
	x.ttl = 90 // more than the 60 of the answer: the answer's own TTL stays
	msg := sortMsg("1.1.1.1", "2.2.2.2")
	x.narrow(msg, typeA, "a.example", nil)
	x.settle(t, 2)
	out := x.narrow(msg, typeA, "a.example", nil)
	rrs, _, _ := recordsAfterQuestion(out)
	for _, rr := range rrs {
		if ttl := binary.BigEndian.Uint32(out[rr.rdataOff-6:]); ttl != 60 {
			t.Fatalf("TTL %d, want the answer's own 60", ttl)
		}
	}
}

func TestFastLaneSpreadTakesTurnsWithinTheBand(t *testing.T) {
	x := newFLTest(t, true, map[string]time.Duration{"1.1.1.1": ms(10), "2.2.2.2": ms(11), "3.3.3.3": ms(40)})
	msg := sortMsg("1.1.1.1", "2.2.2.2", "3.3.3.3")
	x.narrow(msg, typeA, "a.example", nil)
	x.settle(t, 3)
	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		got := answerAddrs(t, x.narrow(msg, typeA, "a.example", nil))
		if len(got) != 1 {
			t.Fatalf("got %v", got)
		}
		seen[got[0]]++
	}
	if seen["1.1.1.1"] != 5 || seen["2.2.2.2"] != 5 || seen["3.3.3.3"] != 0 {
		t.Fatalf("spread %v, want the two near-equal addresses in turn and never the slow one", seen)
	}
}

func TestFastLaneSkipsAnAddressThatDoesNotAnswer(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{"2.2.2.2": ms(20), "3.3.3.3": ms(60)}) // 1.1.1.1 is down
	msg := sortMsg("1.1.1.1", "2.2.2.2", "3.3.3.3")
	x.narrow(msg, typeA, "a.example", nil)
	x.settle(t, 3)
	if got := answerAddrs(t, x.narrow(msg, typeA, "a.example", nil)); !reflect.DeepEqual(got, []string{"2.2.2.2"}) {
		t.Fatalf("got %v", got)
	}
	st := x.stats()
	if st.ProbeFails != 1 || st.Probes != 3 || st.Addresses != 3 || !st.On {
		t.Fatalf("stats %+v", st)
	}
}

func TestFastLaneLeavesAnAnswerWhenEveryAddressFailed(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{})
	msg := sortMsg("1.1.1.1", "2.2.2.2")
	x.narrow(msg, typeA, "a.example", nil)
	x.settle(t, 2)
	if out := x.narrow(msg, typeA, "a.example", nil); &out[0] != &msg[0] {
		t.Fatal("an answer whose every address failed was changed")
	}
}

func TestFastLaneWaitsForEveryAddress(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{"1.1.1.1": ms(5), "2.2.2.2": ms(9)})
	x.narrow(sortMsg("1.1.1.1", "2.2.2.2"), typeA, "a.example", nil)
	x.settle(t, 2)
	// a third address no probe has finished for: the answer stays as it came
	msg := sortMsg("1.1.1.1", "2.2.2.2", "3.3.3.3")
	if out := x.narrow(msg, typeA, "a.example", nil); &out[0] != &msg[0] {
		t.Fatal("changed while an address was still unmeasured")
	}
}

func TestFastLaneForgetsOldResults(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{"1.1.1.1": ms(30), "2.2.2.2": ms(5)})
	msg := sortMsg("1.1.1.1", "2.2.2.2")
	x.narrow(msg, typeA, "a.example", nil)
	x.settle(t, 2)
	if len(answerAddrs(t, x.narrow(msg, typeA, "a.example", nil))) != 1 {
		t.Fatal("not narrowed")
	}
	// the faster one now answers slowly; after flFresh the next answer starts a new probe, and the result is used once done
	x.mu.Lock()
	x.times["2.2.2.2"] = ms(80)
	x.mu.Unlock()
	x.advance(flFresh + time.Second)
	x.narrow(msg, typeA, "a.example", nil) // starts the probes
	x.settle(t, 4)
	if got := answerAddrs(t, x.narrow(msg, typeA, "a.example", nil)); !reflect.DeepEqual(got, []string{"1.1.1.1"}) {
		t.Fatalf("after the change: %v", got)
	}
	// results older than flMaxAge are not used at all
	x.advance(flMaxAge + time.Second)
	if out := x.narrow(msg, typeA, "a.example", nil); &out[0] != &msg[0] {
		t.Fatal("an out-of-date result was used")
	}
}

func TestFastLaneEachFamilyOnItsOwn(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{
		"1.1.1.1": ms(30), "2.2.2.2": ms(5), "2001:db8::1": ms(7), "2001:db8::2": ms(2), "2001:db8::3": ms(9)})
	msg := sortMsg("1.1.1.1", "2001:db8::1", "2.2.2.2", "2001:db8::2", "2001:db8::3")
	x.narrow(msg, typeA, "a.example", nil)
	x.settle(t, 5)
	got := answerAddrs(t, x.narrow(msg, typeA, "a.example", nil))
	if !reflect.DeepEqual(got, []string{"2.2.2.2", "2001:db8::2"}) {
		t.Fatalf("got %v, want the fastest of each family", got)
	}
}

func TestFastLaneLeavesOthersAlone(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{"1.1.1.1": ms(30), "2.2.2.2": ms(5)})
	x.exclude = newNameSet([]string{"corp.example"})
	base := sortMsg("1.1.1.1", "2.2.2.2")
	x.narrow(base, typeA, "a.example", nil)
	x.settle(t, 2)
	if len(answerAddrs(t, x.narrow(base, typeA, "a.example", nil))) != 1 {
		t.Fatal("the plain answer was not narrowed")
	}
	withFlags := func(f func(b []byte)) []byte {
		b := append([]byte(nil), base...)
		f(b)
		return b
	}
	rrsig := append(append([]byte(nil), base...), 0xC0, 12, 0, 46, 0, 1, 0, 0, 0, 60, 0, 0)
	binary.BigEndian.PutUint16(rrsig[6:], binary.BigEndian.Uint16(rrsig[6:])+1)
	cases := []struct {
		name  string
		msg   []byte
		qtype uint16
		qname string
	}{
		{"TC bit", withFlags(func(b []byte) { b[2] |= 0x02 }), typeA, "a.example"},
		{"not a response", withFlags(func(b []byte) { b[2] &^= 0x80 }), typeA, "a.example"},
		{"NXDOMAIN", withFlags(func(b []byte) { b[3] |= 3 }), typeA, "a.example"},
		{"a signed answer (RRSIG)", rrsig, typeA, "a.example"},
		{"an MX question", base, 15, "a.example"},
		{"an excluded name", base, typeA, "corp.example"},
		{"below an excluded name", base, typeA, "www.corp.example"},
		{"a short message", base[:8], typeA, "a.example"},
	}
	for _, c := range cases {
		if out := x.narrow(c.msg, c.qtype, c.qname, nil); len(out) > 0 && &out[0] != &c.msg[0] {
			t.Errorf("%s: the answer was changed", c.name)
		}
	}
	// one address, and a name only its own family has two of
	single := sortMsg("2.2.2.2")
	if out := x.narrow(single, typeA, "a.example", nil); &out[0] != &single[0] {
		t.Error("an answer with one address was changed")
	}
}

func TestFastLaneNeverMeasuresTheNodesOwnNetwork(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{"127.0.0.1": ms(1), "2.2.2.2": ms(5)})
	msg := sortMsg("127.0.0.1", "2.2.2.2")
	x.narrow(msg, typeA, "a.example", nil)
	time.Sleep(50 * time.Millisecond)
	if x.Probes.Load() != 0 {
		t.Fatal("a loopback address was probed")
	}
	if out := x.narrow(msg, typeA, "a.example", nil); &out[0] != &msg[0] {
		t.Fatal("an answer holding a loopback address was changed")
	}
}

func TestFastLaneCompressionPointerIntoTheBlock(t *testing.T) {
	// the second address record names its owner with a pointer to the first record: dropping the first would break it
	x := newFLTest(t, false, map[string]time.Duration{"1.1.1.1": ms(30), "2.2.2.2": ms(5)})
	b := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0}
	b = append(b, 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1)
	first := len(b)
	b = append(b, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1)
	b = append(b, 0xC0, byte(first), 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 2, 2, 2, 2)
	x.narrow(sortMsg("1.1.1.1", "2.2.2.2"), typeA, "a.example", nil) // the results are in once these two are measured
	x.settle(t, 2)
	if out := x.narrow(b, typeA, "a.example", nil); &out[0] != &b[0] {
		t.Fatal("a pointer into the dropped block was not respected")
	}
}

func TestFastLaneConfig(t *testing.T) {
	d := defaultDNS()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "fastlane") {
		t.Fatalf("an unused Fast Lane must not appear in the file (older versions refuse unknown keys): %s", raw)
	}
	d.FastLane = true
	d.FastLaneExclude = []string{"Corp.Example.", "*.lab.example, lab.example", "corp.example"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"corp.example", "lab.example"}; !reflect.DeepEqual(d.FastLaneExclude, want) {
		t.Fatalf("exclude %v, want %v", d.FastLaneExclude, want)
	}
	d.FastLaneTTL = flMaxTTL + 1
	if err := d.Validate(); err == nil {
		t.Fatal("a TTL above the maximum was accepted")
	}
	d.FastLaneTTL = -1
	if err := d.Validate(); err == nil {
		t.Fatal("a negative TTL was accepted")
	}
	d.FastLaneTTL = 0
	d.FastLaneExclude = []string{"not a name!"}
	if err := d.Validate(); err == nil {
		t.Fatal("a bad name was accepted")
	}
	if got := (DNSConfig{}).fastLaneTTL(); got != flDefaultTTL {
		t.Fatalf("default TTL %d", got)
	}
}

func TestFastLaneFollowsTheSharedSettings(t *testing.T) {
	shared := defaultDNS()
	shared.FastLane, shared.FastLaneTTL, shared.FastLaneExclude = true, 45, []string{"corp.example"}
	own := defaultDNS()
	own.followSettings(shared)
	if !own.FastLane || own.FastLaneTTL != 45 || !reflect.DeepEqual(own.FastLaneExclude, []string{"corp.example"}) {
		t.Fatalf("a gateway's own pool did not follow: %+v", own)
	}
	own.FastLaneExclude[0] = "changed"
	if shared.FastLaneExclude[0] != "corp.example" {
		t.Fatal("the shared list is aliased")
	}
}

func TestFastLanePoolWiring(t *testing.T) {
	if p := NewPool(defaultDNS()); p.fl != nil {
		t.Fatal("Fast Lane is on by default")
	}
	var nilFL *fastLane
	if nilFL.stats().On {
		t.Fatal("nil stats say on")
	}
	nilFL.stop()
	cfg := defaultDNS()
	cfg.FastLane = true
	p := NewPool(cfg)
	if p.fl == nil || !p.fl.stats().On {
		t.Fatal("Fast Lane not on")
	}
	p.Stop()
}

func TestFastLaneMetrics(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = nil
	s := NewSupervisor(context.Background(), dc)
	st := &StatusServer{sup: s}
	inject := func(on bool) {
		cfg := defaultDNS()
		cfg.FastLane = on
		p := NewPool(cfg)
		t.Cleanup(p.Stop)
		s.poolMu.Lock()
		s.pools = map[int]*Pool{0: p}
		s.dnss = map[int]DNSConfig{0: cfg}
		s.poolMu.Unlock()
	}
	inject(false)
	if body := st.metricsText(); !strings.Contains(body, "dnsdir_dns_queries_total") || strings.Contains(body, "dnsdir_fastlane_") {
		t.Fatalf("with Fast Lane off the pool must be listed and show no Fast Lane metric:\n%s", body)
	}
	inject(true)
	body := st.metricsText()
	for _, m := range []string{"dnsdir_fastlane_addresses", "dnsdir_fastlane_narrowed_total", "dnsdir_fastlane_probes_total", "dnsdir_fastlane_probe_failures_total"} {
		if !strings.Contains(body, m+`{pool="shared"}`) {
			t.Errorf("metric %s missing:\n%s", m, body)
		}
	}
}

func TestICMPChecksum(t *testing.T) {
	// the echo request `ping` sends for id 0x1234, seq 1 with no payload: 08 00 cs cs 12 34 00 01
	msg := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1}
	cs := icmpChecksum(msg)
	if cs != 0xe5ca { // ^(0x0800 + 0x1234 + 0x0001) = ^0x1a35
		t.Fatalf("checksum %#04x", cs)
	}
	binary.BigEndian.PutUint16(msg[2:], cs)
	if icmpChecksum(msg) != 0 {
		t.Fatal("a message with its checksum in it must sum to zero")
	}
	if icmpChecksum([]byte{1, 2, 3}) != ^uint16(0x0102+0x0300) {
		t.Fatal("odd length")
	}
}

func TestFastLaneICMPAndTCPProbes(t *testing.T) {
	ctx := context.Background()
	// a real echo to this host: needs a raw socket, which the daemon has as root
	if c, err := net.ListenPacket("ip4:icmp", "0.0.0.0"); err != nil {
		t.Logf("no raw ICMP socket here (%v): only the fallback is exercised", err)
	} else {
		c.Close()
		if d, ok := flICMP(ctx, netip.MustParseAddr("127.0.0.1")); !ok || d <= 0 || d > time.Second {
			t.Fatalf("echo to 127.0.0.1: %v, %v", d, ok)
		}
	}
	// TCP: an open port answers, a closed one is refused and still counts
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	lo := netip.MustParseAddr("127.0.0.1")
	if d, ok := flTCP(ctx, lo, port); !ok || d <= 0 {
		t.Fatalf("open port: %v, %v", d, ok)
	}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closed, _ := net.SplitHostPort(ln2.Addr().String())
	ln2.Close()
	if _, ok := flTCP(ctx, lo, closed); !ok {
		t.Fatal("a refused connection must count as an answer")
	}
	// a probe that is cancelled (the pool stopped) reports no answer, whatever the network says
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, ok := flTCP(cctx, lo, port); ok {
		t.Fatal("a cancelled probe reported an answer")
	}
}

func TestFastLaneNarrowsAnAuthoritativeAnswer(t *testing.T) {
	// a server that is authoritative for an internal zone sets AA on every answer: those are the names this is for
	x := newFLTest(t, false, map[string]time.Duration{"10.1.0.1": ms(30), "10.2.0.1": ms(5), "10.3.0.1": ms(9)})
	msg := sortMsg("10.1.0.1", "10.2.0.1", "10.3.0.1")
	msg[2] |= 0x04
	x.narrow(msg, typeA, "a.corp", nil)
	x.settle(t, 3)
	out := x.narrow(msg, typeA, "a.corp", nil)
	if got := answerAddrs(t, out); !reflect.DeepEqual(got, []string{"10.2.0.1"}) {
		t.Fatalf("got %v", got)
	}
	if out[2]&0x04 == 0 {
		t.Fatal("the AA bit was lost")
	}
}

func TestFastLaneLeavesWhatTheNodeAnswersItself(t *testing.T) {
	x := newFLTest(t, false, map[string]time.Duration{"1.1.1.1": ms(30), "2.2.2.2": ms(5)})
	msg := sortMsg("1.1.1.1", "2.2.2.2")
	x.narrow(msg, typeA, "a.example", nil)
	x.settle(t, 2)
	calls := 0
	local := func() bool { calls++; return true }
	if out := x.narrow(msg, typeA, "a.example", local); &out[0] != &msg[0] || calls != 1 {
		t.Fatalf("an answer the node made was changed (asked %d times)", calls)
	}
	// the question is only asked when everything cheaper has passed
	calls = 0
	one := sortMsg("2.2.2.2")
	x.narrow(one, typeA, "a.example", local)
	x.narrow(msg, 15, "a.example", local)
	if calls != 0 {
		t.Fatalf("asked %d times for answers that need no change", calls)
	}
	notLocal := func() bool { return false }
	if len(answerAddrs(t, x.narrow(msg, typeA, "a.example", notLocal))) != 1 {
		t.Fatal("an answer from a server was not narrowed")
	}
}

func TestPoolAnswersLocally(t *testing.T) {
	cfg := defaultDNS()
	cfg.Policy = []PolicyRule{
		{Client: "*", Name: "own.example", Servers: []string{"A 10.5.5.5, 10.5.5.6"}},
		{Client: "*", Name: "via.example", Servers: []string{"10.9.9.9"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	p := NewPool(cfg)
	t.Cleanup(p.Stop)
	client := netip.MustParseAddr("192.0.2.1")
	ask := func(name string) bool {
		var qi qinfo
		q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, l := range strings.Split(name, ".") {
			q = append(q, byte(len(l)))
			q = append(q, l...)
		}
		q = append(q, 0, 0, 1, 0, 1)
		parseQuestion(q, &qi)
		return p.answersLocally(client, &qi)
	}
	if !ask("own.example") {
		t.Error("a row with records answers by itself")
	}
	if ask("via.example") {
		t.Error("a row that sends the query to its own servers does not answer by itself")
	}
	if ask("other.example") {
		t.Error("a name no row matches is not answered by the node")
	}
}

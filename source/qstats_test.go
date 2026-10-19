package main

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func qsTestStats(t0 time.Time) (*QStats, *time.Time) {
	s := NewQStats()
	cur := t0
	s.now = func() time.Time { return cur }
	s.start = t0
	return s, &cur
}

const (
	srvA = "10.0.0.1:123"
	srvB = "10.0.0.2:123"
)

func TestQStatsRecordAndQuery(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 30, 0, time.UTC)
	s, cur := qsTestStats(t0)
	a, b := netip.MustParseAddr("192.0.2.5"), netip.MustParseAddr("::ffff:192.0.2.6")
	s.Record(a, srvA, 4, outAnswered)
	s.Record(a, srvA, 3, outAnswered)
	s.Record(b, srvB, 4, outKoD)
	*cur = t0.Add(2 * time.Minute)
	s.Record(b, "", 4, outFailed)
	s.Record(a, "", 4, outRefused)
	s.Record(netip.MustParseAddr("2001:db8::7"), srvB, 4, outAnswered)
	*cur = t0.Add(5 * time.Minute)

	r := s.Query(t0.Add(-30*time.Minute), *cur, QFilter{})
	if r.Step != 60 || r.Sums.Total != 6 || r.Sums.Answered != 3 || r.Sums.KoD != 1 || r.Sums.Failed != 1 || r.Sums.Refused != 1 {
		t.Fatalf("sums: %+v", r.Sums)
	}
	var sum uint64
	for _, v := range r.Total {
		sum += v
	}
	if sum != 6 || r.Start%60 != 0 || len(r.Total) != len(r.Answered) {
		t.Fatalf("series: %d %v", sum, r.Total)
	}
	if r.Sums.Clients != 3 || r.Clients[0].Name != "192.0.2.5" || r.Clients[0].Count != 3 || r.Clients[1].Name != "192.0.2.6" {
		t.Fatalf("clients (the ::ffff: form must fold into the v4 address): %+v", r.Clients)
	}
	if len(r.Servers) != 3 { // two upstream servers and "(none)" for the requests no server answered
		t.Fatalf("servers: %+v", r.Servers)
	}
	if len(r.Versions) != 2 || r.Versions[0].Name != "NTPv4" || r.Versions[0].Count != 5 || r.Versions[1].Name != "NTPv3" || r.Versions[1].Count != 1 {
		t.Fatalf("versions: %+v", r.Versions)
	}
	if len(r.Families) != 2 || r.Families[0].Name != "IPv4" || r.Families[0].Count != 5 || r.Families[1].Name != "IPv6" || r.Families[1].Count != 1 {
		t.Fatalf("families: %+v", r.Families)
	}
	// a range before the first request sees nothing
	if r := s.Query(t0.Add(-3*time.Hour), t0.Add(-2*time.Hour), QFilter{}); r.Sums.Total != 0 || len(r.Clients) != 0 {
		t.Fatalf("empty range: %+v", r.Sums)
	}
	// JSON lists are [] never null
	if r.Clients == nil || r.Servers == nil || r.Versions == nil || r.Families == nil {
		t.Fatal("a list is nil")
	}
}

func TestQStatsStepsAndRetention(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s, cur := qsTestStats(t0)
	s.Record(netip.MustParseAddr("192.0.2.5"), "10.9.9.9:123", 4, outAnswered)
	*cur = t0.Add(31 * 24 * time.Hour) // the first request is now outside the 30 day window
	s.Record(netip.MustParseAddr("192.0.2.5"), srvA, 4, outAnswered)
	r := s.Query(t0, *cur, QFilter{})
	if r.Sums.Total != 1 || r.Servers[0].Name != srvA || len(r.Servers) != 1 {
		t.Fatalf("old data survived: %+v %+v", r.Sums, r.Servers)
	}
	if r.Step != 10800 || len(r.Total) > 250 {
		t.Fatalf("a 30 day range should use 3 h steps: step %d points %d", r.Step, len(r.Total))
	}
	for _, c := range []struct {
		span time.Duration
		step int64
	}{{time.Hour, 60}, {2 * time.Hour, 60}, {24 * time.Hour, 600}, {48 * time.Hour, 3600}, {7 * 24 * time.Hour, 3600}, {10 * 24 * time.Hour, 10800}} {
		if got := stepFor(c.span); got != c.step {
			t.Errorf("stepFor(%v) = %d, want %d", c.span, got, c.step)
		}
	}
	// a slot is reused after 30 days: the stale count must not leak in
	s2, cur2 := qsTestStats(t0)
	s2.Record(netip.MustParseAddr("192.0.2.5"), srvA, 4, outAnswered)
	*cur2 = t0.Add(qsRetain)
	s2.Record(netip.MustParseAddr("192.0.2.5"), srvB, 4, outAnswered)
	if r := s2.Query(t0.Add(time.Hour), *cur2, QFilter{}); r.Sums.Total != 1 {
		t.Fatalf("slot reuse leaked: %+v", r.Sums)
	}
}

func TestQStatsCapsDistinctNames(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s, cur := qsTestStats(t0)
	for i := 0; i < qsCapServers+50; i++ {
		s.Record(netip.MustParseAddr("192.0.2.5"), "10.1."+fmtN(i/200)+"."+fmtN(i%200)+":123", 4, outAnswered)
	}
	*cur = t0.Add(time.Minute)
	r := s.Query(t0.Add(-time.Hour), *cur, QFilter{})
	if r.Sums.Total != uint64(qsCapServers+50) {
		t.Fatalf("total %d", r.Sums.Total)
	}
	var others uint64
	s.flush() // the events are counted in batches; this test reads the tables directly
	s.mu.Lock()
	for _, tp := range s.fine {
		others += uint64(tp.c[outAnswered].servers[qsOthers])
	}
	s.mu.Unlock()
	if others != 50 {
		t.Fatalf("the overflow should be counted as (others): %d", others)
	}
}

func TestQStatsRange(t *testing.T) {
	f, to, err := qstatsRange("", "")
	if err != nil || to.Sub(f) != time.Hour {
		t.Fatalf("default: %v %v %v", f, to, err)
	}
	if f, to, _ := qstatsRange("30d", ""); to.Sub(f) != 30*24*time.Hour {
		t.Fatalf("30d: %v", to.Sub(f))
	}
	if f, to, err := qstatsRange("1790000000", "1790003600"); err != nil || f.Unix() != 1790000000 || to.Unix() != 1790003600 {
		t.Fatalf("explicit: %v %v %v", f, to, err)
	}
	for _, bad := range [][2]string{{"soon", ""}, {"", "x"}, {"0", ""}} {
		if _, _, err := qstatsRange(bad[0], bad[1]); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestQStatsTiers(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 5, 0, 0, time.UTC)
	s, cur := qsTestStats(t0)
	cl := netip.MustParseAddr("192.0.2.5")
	s.Record(cl, "10.9.9.9:123", 4, outAnswered) // 3 days before "now"
	*cur = t0.Add(72 * time.Hour)
	s.Record(cl, srvA, 4, outAnswered)
	// a range inside the last day reads the exact 10-minute slots
	r := s.Query(cur.Add(-time.Hour), *cur, QFilter{})
	if len(r.Servers) != 1 || r.Servers[0].Name != srvA {
		t.Fatalf("day range: %+v", r.Servers)
	}
	// a week reads the hour slots and still sees the old request
	r = s.Query(cur.Add(-7*24*time.Hour), *cur, QFilter{})
	if r.Sums.Total != 2 || len(r.Servers) != 2 {
		t.Fatalf("week range: %+v %+v", r.Sums, r.Servers)
	}
}

func TestQStatsByOutcome(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s, cur := qsTestStats(t0)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	s.Record(a, srvA, 4, outAnswered)
	s.Record(a, srvA, 4, outAnswered)
	s.Record(a, srvB, 4, outKoD)
	s.Record(b, srvB, 3, outKoD)
	s.Record(b, "", 4, outFailed)
	s.Record(b, "", 4, outRefused)
	*cur = t0.Add(time.Minute)
	from := t0.Add(-time.Hour)

	all := s.Query(from, *cur, QFilter{})
	if all.Sums.Total != 6 || len(all.Servers) != 3 {
		t.Fatalf("all: %+v", all.Servers)
	}
	kod := s.Query(from, *cur, QFilter{Outcome: "kod"})
	if kod.Outcome != "kod" || len(kod.Servers) != 1 || kod.Servers[0].Name != srvB || kod.Servers[0].Count != 2 {
		t.Fatalf("kod servers: %+v", kod.Servers)
	}
	if len(kod.Clients) != 2 || kod.Sums.Clients != 2 || kod.Sums.Total != 6 {
		t.Fatalf("kod clients %+v / the sums must stay whole: %d", kod.Clients, kod.Sums.Total)
	}
	if len(kod.Versions) != 2 {
		t.Fatalf("kod versions: %+v", kod.Versions)
	}
	for kind, want := range map[string]string{"answered": srvA, "failed": "(none)", "refused": "(none)"} {
		r := s.Query(from, *cur, QFilter{Outcome: kind})
		if len(r.Servers) != 1 || r.Servers[0].Name != want {
			t.Fatalf("%s: %+v", kind, r.Servers)
		}
	}
	// the all-outcomes list is the sum of the outcomes
	var sum uint64
	for _, d := range all.Servers {
		sum += d.Count
	}
	if sum != 6 {
		t.Fatalf("sum of all %d", sum)
	}
	// a flood of distinct clients that were turned away is capped on its own and does not touch the answered list
	for i := 0; i < qsCaps[outRefused][0]+40; i++ {
		s.Record(netip.AddrFrom4([4]byte{10, 8, byte(i / 250), byte(i % 250)}), "", 4, outRefused)
	}
	if g := s.Query(from, *cur, QFilter{Outcome: "answered"}); len(g.Clients) != 1 {
		t.Fatalf("answered list disturbed: %+v", g.Clients)
	}
	var others uint64
	s.flush()
	s.mu.Lock()
	for _, tp := range s.fine {
		others += uint64(tp.c[outRefused].clients[qsOthers])
	}
	s.mu.Unlock()
	if others == 0 {
		t.Fatal("overflow not counted as (others)")
	}
}

func TestQStatsOutcomeArg(t *testing.T) {
	for in, want := range map[string]string{"": "", "all": "", "KoD": "kod", " failed ": "failed", "refused": "refused", "answered": "answered"} {
		if got, err := qstatsOutcome(in); err != nil || got != want {
			t.Errorf("%q → %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"nx", "3", "x y"} {
		if _, err := qstatsOutcome(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestQStatsClientServerPairs(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s, cur := qsTestStats(t0)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	for i := 0; i < 3; i++ {
		s.Record(a, srvA, 4, outAnswered)
	}
	s.Record(a, srvB, 4, outAnswered)
	s.Record(b, srvA, 4, outAnswered)
	s.Record(a, srvB, 4, outKoD)
	s.Record(b, srvB, 4, outKoD)
	s.Record(b, srvB, 4, outKoD)
	*cur = t0.Add(time.Minute)
	from := t0.Add(-time.Hour)

	r := s.Query(from, *cur, QFilter{Client: "192.0.2.1"})
	if r.Client != "192.0.2.1" || len(r.Servers) != 2 || r.Servers[0].Name != srvA || r.Servers[0].Count != 3 {
		t.Fatalf("client a: %+v", r.Servers)
	}
	r = s.Query(from, *cur, QFilter{Client: "192.0.2.1", Outcome: "kod"})
	if len(r.Servers) != 1 || r.Servers[0].Name != srvB || r.Servers[0].Count != 1 {
		t.Fatalf("client a kod: %+v", r.Servers)
	}
	r = s.Query(from, *cur, QFilter{Server: srvA})
	if len(r.Clients) != 2 || r.Clients[0].Name != "192.0.2.1" || r.Clients[0].Count != 3 || r.Clients[1].Count != 1 {
		t.Fatalf("server a: %+v", r.Clients)
	}
	r = s.Query(from, *cur, QFilter{Server: srvB, Outcome: "kod"})
	if len(r.Clients) != 2 || r.Clients[0].Name != "192.0.2.2" || r.Clients[0].Count != 2 {
		t.Fatalf("server b kod: %+v", r.Clients)
	}
	if r := s.Query(from, *cur, QFilter{Client: "192.0.2.9"}); len(r.Servers) != 0 {
		t.Fatalf("unknown client: %+v", r.Servers)
	}
	// every pair is kept: they go to disk, not into a capped table
	for i := 0; i < 5000; i++ {
		s.Record(b, "10.2."+fmtN(i/200)+"."+fmtN(i%200)+":123", 4, outAnswered)
	}
	s.flush()
	u := cur.Unix() / 60 / pairUnitMin
	rows := 0
	s.pairs.scan(u-1, u+1, func(kind int, c, name string, v uint32) { rows++ })
	if rows < 5000 {
		t.Fatalf("%d pairs kept, want at least 5000", rows)
	}
}

func TestQStatsFilterArg(t *testing.T) {
	if f, err := qstatsFilter("KoD", "::ffff:192.0.2.1", ""); err != nil || f.Outcome != "kod" || f.Client != "192.0.2.1" {
		t.Fatalf("%+v %v", f, err)
	}
	if f, err := qstatsFilter("", "", "10.0.0.1:123"); err != nil || f.Server != "10.0.0.1:123" {
		t.Fatalf("%+v %v", f, err)
	}
	for _, c := range [][3]string{{"", "192.0.2.1", "10.0.0.1:123"}, {"", "not-an-ip", ""}, {"bogus", "", ""}, {"", "", "a b"}} {
		if _, err := qstatsFilter(c[0], c[1], c[2]); err == nil {
			t.Errorf("%q accepted", c)
		}
	}
}

// Requests are counted in batches a moment after they happen, but anything that reads the statistics sees them all.
func TestQStatsCountsBatchedEventsBeforeAnyRead(t *testing.T) {
	s := NewQStats()
	ip := netip.MustParseAddr("10.0.0.1")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				s.Record(ip, srvA, 4, outAnswered)
			}
		}()
	}
	wg.Wait()
	r := s.Query(time.Now().Add(-time.Hour), time.Time{}, QFilter{})
	if r.Sums.Total != 4000 {
		t.Fatalf("total = %d, want 4000", r.Sums.Total)
	}
}

func TestQStatsTimerCountsWithoutAnyRead(t *testing.T) {
	s := NewQStats()
	s.Record(netip.MustParseAddr("10.0.0.2"), srvA, 4, outAnswered)
	time.Sleep(qsFlushEvery + 400*time.Millisecond)
	n := 0
	for i := range s.pend {
		s.pend[i].mu.Lock()
		n += len(s.pend[i].ev)
		s.pend[i].mu.Unlock()
	}
	if n != 0 {
		t.Fatalf("%d events still waiting after the flush interval", n)
	}
	s.mu.Lock()
	var total uint32
	for i := range s.mins {
		total += s.mins[i].total
	}
	s.mu.Unlock()
	if total != 1 {
		t.Fatalf("counted %d, want 1", total)
	}
}

func TestQstatsRangeNow(t *testing.T) {
	from, to, err := qstatsRange("now", "")
	if err != nil {
		t.Fatal(err)
	}
	if from.Unix()%600 != 0 {
		t.Fatalf("start %v is not on a 10-minute slot", from)
	}
	if d := to.Sub(from); d < 5*time.Minute || d > 15*time.Minute+2*time.Second {
		t.Fatalf("Now covers %v, want 5 to 15 minutes", d)
	}
}

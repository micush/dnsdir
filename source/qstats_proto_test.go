package main

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func protoFixture(t *testing.T) *QStats {
	t.Helper()
	s := NewQStats()
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::3")
	for i := 0; i < 3; i++ {
		s.RecordVia(a, "a.example.com", 1, false, viaPlain, rcodeNoError)
	}
	s.RecordVia(a, "a.example.com", 1, true, viaDoT, rcodeNoError)
	s.RecordVia(b, "b.example.com", 1, true, viaDoT, rcodeNoError)
	s.RecordVia(b, "nx.example.com", 1, true, viaDoT, 3)
	s.RecordVia(c, "c.example.com", 28, false, viaPlain, rcodeNoError)
	s.flush()
	return s
}

func clientsOf(r *QStatsResult) string {
	var l []string
	for _, c := range r.Clients {
		l = append(l, c.Name+"="+strconv.FormatUint(c.Count, 10))
	}
	return strings.Join(l, " ")
}

// Top clients limited to a transport lists the clients of that transport, with their queries over it only.
func TestTopClientsByTransport(t *testing.T) {
	s := protoFixture(t)
	now := time.Now()
	q := func(f QFilter) *QStatsResult { return s.Query(now.Add(-time.Hour), now.Add(time.Minute), f) }
	if got := clientsOf(q(QFilter{Proto: "DoT · IPv4"})); got != "192.0.2.2=2 192.0.2.1=1" {
		t.Fatalf("DoT: %s", got)
	}
	r := q(QFilter{Proto: "UDP · IPv4,UDP · IPv6"})
	if got := clientsOf(r); got != "192.0.2.1=3 2001:db8::3=1" || r.Proto != "UDP · IPv4,UDP · IPv6" {
		t.Fatalf("UDP: %s (%q)", got, r.Proto)
	}
	// the tile count, the transports and the domains are not limited
	if r.Sums.Clients != 3 || len(r.Protos) != 3 || len(r.Domains) != 4 {
		t.Fatalf("not limited: clients %d, protos %+v, domains %+v", r.Sums.Clients, r.Protos, r.Domains)
	}
	// with a tile: only NXDOMAIN over DoT
	if got := clientsOf(q(QFilter{Proto: "DoT · IPv4", Rcode: "nxdomain"})); got != "192.0.2.2=1" {
		t.Fatalf("DoT, NXDOMAIN: %s", got)
	}
	// with a picked client: the domains are what it asked for (over any transport), the clients those of the transport
	r = q(QFilter{Proto: "DoT · IPv4", Client: "192.0.2.1"})
	if clientsOf(r) != "192.0.2.2=2 192.0.2.1=1" || len(r.Domains) != 1 || r.Domains[0].Count != 4 {
		t.Fatalf("with a client: %s, domains %+v", clientsOf(r), r.Domains)
	}
	// a transport nobody used: no clients
	if r := q(QFilter{Proto: "DoH · IPv6"}); len(r.Clients) != 0 {
		t.Fatalf("DoH: %+v", r.Clients)
	}
	// the filter box still applies
	if got := clientsOf(q(QFilter{Proto: "DoT · IPv4", CMatch: "192.0.2.1"})); got != "192.0.2.1=1" {
		t.Fatalf("with cmatch: %s", got)
	}
}

// Counts from before v619 have no clients by transport: they show as "(others)", so the list still adds up.
func TestTopClientsByTransportOlderCounts(t *testing.T) {
	s := protoFixture(t)
	s.mu.Lock()
	for _, tier := range [][]qsTop{s.fine[:], s.coarse[:]} {
		for i := range tier {
			for ci := range tier[i].c {
				tier[i].c[ci].cproto = [8]map[string]uint32{}
			}
		}
	}
	s.mu.Unlock()
	now := time.Now()
	if got := clientsOf(s.Query(now.Add(-time.Hour), now.Add(time.Minute), QFilter{Proto: "DoT · IPv4"})); got != "(others)=3" {
		t.Fatalf("older counts: %s", got)
	}
}

func TestTopClientsByTransportSurvivesARestart(t *testing.T) {
	s := protoFixture(t)
	var recs []pRec
	if err := s.persistTo(func(r pRec) error { recs = append(recs, r); return nil }); err != nil {
		t.Fatal(err)
	}
	s2 := NewQStats()
	for _, r := range recs {
		s2.restore(r)
	}
	now := time.Now()
	if got := clientsOf(s2.Query(now.Add(-time.Hour), now.Add(time.Minute), QFilter{Proto: "DoT · IPv4"})); got != "192.0.2.2=2 192.0.2.1=1" {
		t.Fatalf("after a restart: %s", got)
	}
}

func TestQStatsProtoArgument(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"dot":                    "DoT · IPv4,DoT · IPv6",
		"UDP4, doh6":             "UDP · IPv4,DoH · IPv6",
		"DoT · IPv4":             "DoT · IPv4",
		"dot · ipv6,DoT · IPv6":  "DoT · IPv6",
		"tcp-ipv4":               "TCP · IPv4",
		"DoH · IPv6,UDP · IPv4,": "UDP · IPv4,DoH · IPv6",
	} {
		if got, err := qstatsProto(in); err != nil || got != want {
			t.Errorf("qstatsProto(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"quic", "udp5", "DoT · IPv8"} {
		if _, err := qstatsProto(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	f := QFilter{Domain: "example.com"}
	if _, err := f.withProto("dot"); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("with a domain: %v", err)
	}
}

// In a cluster, a node before v619 answers with every client: they are left out, and its queries over the transport are "(others)".
func TestMergeTopClientsByTransport(t *testing.T) {
	mk := func(proto string, clients ...NameCount) *QStatsResult {
		return &QStatsResult{Proto: proto, Start: 0, Step: 60, Total: []uint64{10}, NoError: []uint64{10}, ServFail: []uint64{0}, NXDomain: []uint64{0},
			Refused: []uint64{0}, Other: []uint64{0}, Updates: []uint64{0}, ClientsN: []uint64{2}, Sums: QStatsSums{Total: 10, Clients: 2},
			Protos: []NameCount{{Name: "UDP · IPv4", Count: 6}, {Name: "DoT · IPv4", Count: 4}}, Clients: clients}
	}
	a := mk("DoT · IPv4", NameCount{Name: "192.0.2.1", Count: 4})
	old := mk("", NameCount{Name: "192.0.2.7", Count: 6}, NameCount{Name: "192.0.2.8", Count: 4})
	r := mergeQStats([]clusterPart[QStatsResult]{qpart("A", a), qpart("B", old)}, infosOf("A", "B"))
	if got := clientsOf(r); got != "192.0.2.1=4 (others)=4" || r.Proto != "DoT · IPv4" {
		t.Fatalf("merged: %s (%q)", got, r.Proto)
	}
	// every node older: nothing was filtered, and the answer says so
	r = mergeQStats([]clusterPart[QStatsResult]{qpart("B", old)}, infosOf("B"))
	if r.Proto != "" || len(r.Clients) != 2 {
		t.Fatalf("all older: %q %+v", r.Proto, r.Clients)
	}
}

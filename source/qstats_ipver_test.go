package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestTransportIPVersion(t *testing.T) {
	for _, c := range []struct {
		tcp  bool
		addr string
		want int
	}{
		{false, "192.0.2.1", 0}, {false, "2001:db8::1", 1}, {true, "192.0.2.1", 2}, {true, "2001:db8::1", 3},
		{false, "::ffff:192.0.2.1", 0}, // a v4-mapped client is an IPv4 client
	} {
		if got := protoIdx(c.tcp, netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("tcp=%v %s: index %d, want %d", c.tcp, c.addr, got, c.want)
		}
	}
	if protoIdx(false, netip.Addr{}) != 0 {
		t.Error("an unknown address is not counted as IPv4")
	}
}

func TestTransportSplitKeepsOldCounts(t *testing.T) {
	var k qsKind
	k.udp, k.tcp = 10, 4 // counted by an older version: no split
	k.udp += 3
	k.proto[0], k.proto[1] = 2, 1
	k.tcp += 2
	k.proto[3] = 2
	// what the result shows: the split ones by name, the rest as plain UDP / TCP
	var protos [8]uint64
	for i, n := range k.proto {
		protos[i] = uint64(n)
	}
	if rest := uint64(k.udp) - (protos[0] + protos[1]); rest != 10 {
		t.Errorf("plain UDP %d, want 10", rest)
	}
	if rest := uint64(k.tcp) - (protos[2] + protos[3]); rest != 4 {
		t.Errorf("plain TCP %d, want 4", rest)
	}
}

func TestTransportAfterClear(t *testing.T) {
	s := NewQStats()
	s.Record(netip.MustParseAddr("10.1.1.1"), "example.com", 1, false, 0)
	s.Clear()
	s.Record(netip.MustParseAddr("2001:db8::2"), "example.org", 1, true, 0)
	s.Record(netip.MustParseAddr("10.1.1.2"), "example.org", 1, false, 0)
	now := time.Now()
	r := s.Query(now.Add(-time.Hour), now.Add(time.Minute), QFilter{})
	if len(r.Protos) != 2 || r.Protos[0].Name != "UDP · IPv4" || r.Protos[1].Name != "TCP · IPv6" || r.Protos[0].Count != 1 || r.Protos[1].Count != 1 {
		t.Fatalf("protos after a clear: %+v", r.Protos)
	}
}

// DNS over TLS and HTTPS queries are counted apart from plain TCP, by IP version, and not in the plain UDP/TCP totals.
func TestTransportDoTAndDoHCountedSeparately(t *testing.T) {
	s := NewQStats()
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	s.RecordVia(v4, "a.example.com", 1, false, viaPlain, rcodeNoError) // UDP
	s.RecordVia(v4, "a.example.com", 1, true, viaPlain, rcodeNoError)  // TCP
	s.RecordVia(v4, "a.example.com", 1, true, viaDoT, rcodeNoError)
	s.RecordVia(v6, "a.example.com", 1, true, viaDoT, rcodeNoError)
	s.RecordVia(v6, "a.example.com", 1, true, viaDoH, rcodeNoError)
	s.flush()
	now := time.Now()
	r := s.Query(now.Add(-time.Hour), now.Add(time.Minute), QFilter{})
	got := map[string]uint64{}
	for _, p := range r.Protos {
		got[p.Name] = p.Count
	}
	want := map[string]uint64{"UDP · IPv4": 1, "TCP · IPv4": 1, "DoT · IPv4": 1, "DoT · IPv6": 1, "DoH · IPv6": 1}
	if len(got) != len(want) {
		t.Fatalf("transports %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], n, got)
		}
	}
}

package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestPickedServerListsEveryClient(t *testing.T) {
	s := NewQStats()
	for i := 0; i < 700; i++ {
		s.rdns[netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}).String()] = rdnsEntry{at: time.Now()} // known: no lookups for the test
		s.Record(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), "10.9.9.9:123", 4, outAnswered)
	}
	r := s.Query(time.Now().Add(-time.Hour), time.Now().Add(time.Minute), QFilter{Server: "10.9.9.9:123"})
	if len(r.Clients) < 700 {
		t.Fatalf("%d clients listed, want 700", len(r.Clients))
	}
	for _, c := range r.Clients {
		if c.Name == qsOthers {
			t.Fatalf("(others) is %d of the list", c.Count)
		}
	}
}

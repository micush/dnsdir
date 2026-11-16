package main

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

func TestFamilyFilter(t *testing.T) {
	list, err := normalizeFamilyFilter([]string{" 10.1.0.0/16:  NO-IPV6 ", "10.1.0.0/16: no-ipv6", "any: no-ipv4", ""})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.1.0.0/16: no-ipv6", "any: no-ipv4"}; !reflect.DeepEqual(list, want) {
		t.Fatalf("normalized %v", list)
	}
	for _, bad := range []string{"10.1.0.0/16", "10.1.0.0/16: no-ipv5", "nonsense: no-ipv4"} {
		if _, err := normalizeFamilyFilter([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	p := &Pool{fams: buildFamilyRules(list)}
	for _, c := range []struct {
		client string
		qt     uint16
		want   bool
	}{
		{"10.1.2.3", typeAAAA, true}, // first rule: this network gets no IPv6
		{"10.1.2.3", typeA, false},   // and keeps IPv4 (the first matching rule decides, any: no-ipv4 is not reached)
		{"192.168.0.1", typeA, true}, // everyone else: no IPv4
		{"192.168.0.1", typeAAAA, false},
		{"10.1.2.3", 15, false}, // MX is never filtered
		{"::ffff:10.1.2.3", typeAAAA, true},
	} {
		if got := p.familyDrops(netip.MustParseAddr(c.client), c.qt); got != c.want {
			t.Errorf("%s type %d: %v", c.client, c.qt, got)
		}
	}
	if (&Pool{}).familyDrops(netip.MustParseAddr("10.1.2.3"), typeAAAA) {
		t.Error("no rules filtered")
	}
}

func TestDropFamily(t *testing.T) {
	m := sortMsg("192.168.5.11", "fdf5:168:5::11", "10.0.0.1")
	out := dropFamily(m, typeAAAA)
	if got, want := answerAddrs(t, out), []string{"192.168.5.11", "10.0.0.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("no-ipv6: %v", got)
	}
	if an := binary.BigEndian.Uint16(out[6:]); an != 3 { // the CNAME and two A records
		t.Fatalf("ancount %d", an)
	}
	if got, want := answerAddrs(t, dropFamily(m, typeA)), []string{"fdf5:168:5::11"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("no-ipv4: %v", got)
	}
	if len(answerAddrs(t, m)) != 3 {
		t.Fatal("the original changed")
	}
	if got := dropFamily(sortMsg("10.0.0.1"), typeAAAA); len(got) != len(sortMsg("10.0.0.1")) {
		t.Fatal("nothing to drop, yet changed")
	}
	if got := dropFamily(m, 0); &got[0] != &m[0] {
		t.Fatal("no rule, yet copied")
	}
}

package main

import (
	"net/netip"
	"testing"
	"time"
)

func TestDomainLimitMatching(t *testing.T) {
	rules, err := parseDomainLimits([]string{"www.example.com 5", "*.zone.test 5", "ad*.cdn.test 5", "Exact.Test. 5"})
	if err != nil {
		t.Fatal(err)
	}
	d := &domainLimits{rules: rules}
	for name, want := range map[string]string{
		"www.example.com":  "www.example.com",
		"mail.example.com": "",
		"zone.test":        "*.zone.test", // the name itself
		"a.b.zone.test":    "*.zone.test", // and everything below it
		"xzone.test":       "",
		"ads1.cdn.test":    "ad*.cdn.test",
		"img.cdn.test":     "",
		"exact.test":       "exact.test",
		"sub.exact.test":   "",
		"WWW.Example.COM.": "www.example.com",
	} {
		got := ""
		for _, r := range d.rules {
			if r.matches(lowerName(name)) {
				got = r.text
				break
			}
		}
		if got != want {
			t.Errorf("%s matched %q, want %q", name, got, want)
		}
	}
}

func lowerName(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	s = string(b)
	if n := len(s); n > 0 && s[n-1] == '.' {
		s = s[:n-1]
	}
	return s
}

func TestDomainLimitIsOneBucketForAllClientsAndNames(t *testing.T) {
	c := DNSConfig{DomainLimits: []string{"*.example.com 10"}} // burst: at least 10
	d := newDomainLimits(c)
	now := time.Now()
	ok := 0
	for i := 0; i < 40; i++ { // many names, no matter who asks: one bucket
		name := []string{"a.example.com", "b.example.com", "example.com", "c.d.example.com"}[i%4]
		if v, _ := d.check(name, now); v == admitOK {
			ok++
		}
	}
	if ok != 20 {
		t.Fatalf("%d queries passed, want the burst of 20 (twice the rate)", ok)
	}
	if v, _ := d.check("other.org", now); v != admitOK {
		t.Fatal("a name no line matches must pass")
	}
	// the bucket refills at the rate
	if v, _ := d.check("a.example.com", now.Add(time.Second)); v != admitOK {
		t.Fatal("not refilled after a second")
	}
}

func TestDomainLimitAnswersLikeClientAction(t *testing.T) {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c', 0, 0, 1, 0, 1}
	for _, c := range []struct {
		action string
		tcp    bool
		want   string
	}{{"", false, "drop"}, {actDrop, false, "drop"}, {actTruncate, false, "tc"}, {actRefused, false, "refused"}, {actDrop, true, "refused"}} {
		p := &Pool{dlim: &domainLimits{action: c.action}}
		r := p.turnedAwayDomain(q, c.tcp)
		got := "drop"
		if r != nil {
			got = "refused"
			if r[2]&0x02 != 0 {
				got = "tc"
			}
		}
		if got != c.want {
			t.Errorf("action %q tcp=%v: %s, want %s", c.action, c.tcp, got, c.want)
		}
	}
}

func TestDomainLimitLoopbackIsNeverLimitedAndConfigIsChecked(t *testing.T) {
	p := &Pool{dlim: newDomainLimits(DNSConfig{DomainLimits: []string{"* 1"}})}
	for i := 0; i < 100; i++ {
		if p.admitDomain("x.test", netip.MustParseAddr("127.0.0.1")) != admitOK {
			t.Fatal("loopback was limited")
		}
	}
	for _, bad := range [][]string{{"example.com"}, {"example.com x"}, {"example.com 0"}, {"not a name 5"}, {"a.test 5", "a.test 6"}, {"**.** 5"}} {
		if _, err := parseDomainLimits(bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
	d := defaultDNS()
	d.DomainLimits = []string{"WWW.Example.com. 7", "*.zone.test 3"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if d.DomainLimits[0] != "www.example.com 7" {
		t.Fatalf("not normalised: %v", d.DomainLimits)
	}
}

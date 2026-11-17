package main

import "testing"

func TestFilterAndOr(t *testing.T) {
	cases := []struct {
		text string
		name string
		want bool
	}{
		{"ubuntu", "ntp.ubuntu.com", true},
		{"ubuntu AND ntp", "ntp.ubuntu.com", true},
		{"ubuntu AND pool", "ntp.ubuntu.com", false},
		{"pool OR ubuntu", "ntp.ubuntu.com", true},
		{"pool or debian", "ntp.ubuntu.com", false},
		{"pool AND org OR ubuntu AND com", "ntp.ubuntu.com", true},
		{"pool AND com OR ubuntu AND org", "ntp.ubuntu.com", false},
		{"ubuntu AND", "ntp.ubuntu.com", true},
		{"ubuntu AND !pool", "ntp.ubuntu.com", true},
		{"ubuntu AND !ntp", "ntp.ubuntu.com", false},
		{"ubuntu !ntp", "ntp.ubuntu.com", false},
		{"ubuntu AND NOT ntp", "ntp.ubuntu.com", false},
		{"!pool", "ntp.ubuntu.com", true},
		{"!ubuntu OR com", "ntp.ubuntu.com", true},
		{"!ubuntu AND !com", "ntp.ubuntu.com", false},
	}
	for _, c := range cases {
		if got := parseMatch(c.text).matches(c.name); got != c.want {
			t.Errorf("%q on %q: %v, want %v", c.text, c.name, got, c.want)
		}
	}
	if parseMatch("   ") != nil || parseMatch("AND OR") != nil {
		t.Error("a text with no word is a filter")
	}
	m := map[string]uint64{"ntp.ubuntu.com": 3, "pool.ntp.org": 2, "ubuntu.com": 1}
	if got := keepMatching(m, "ntp AND ubuntu OR ubuntu.com"); len(got) != 2 {
		t.Errorf("%v", got)
	}
}

func TestLogFilterNot(t *testing.T) {
	line := "2026-11-16 phx dns timeout"
	for text, want := range map[string]bool{"phx AND !dns": false, "phx AND !ntp": true, "phx !dns": false, "!dns": false, "!ntp": true, "phx dns !ntp": true, "q OR !dns": false, "q OR phx !ntp": true, "phx AND NOT dns": false, "phx NOT ntp": true, "NOT NOT dns": true, "not !dns": true, "phx AND not": true} {
		if got := logMatches(parseMatch(text), line); got != want {
			t.Errorf("%q: %v, want %v", text, got, want)
		}
	}
}

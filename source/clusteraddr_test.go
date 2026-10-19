package main

import (
	"path/filepath"
	"testing"
)

func TestValidHostPort(t *testing.T) {
	good := []string{"10.0.0.5:12381", "[2001:db8::1]:12381", "node-1.example.com:12381", "ns1:1"}
	bad := []string{"", "10.0.0.5", "10.0.0.5:0", "10.0.0.5:70000", "10.0.0.5:x", "evil@10.0.0.5:12381",
		"10.0.0.5/x:12381", "a b:1", "host?x:1", "host#x:1", "[fe80::1%eth0]:1", ":12381", "ho/st:1"}
	for _, a := range good {
		if !validHostPort(a) {
			t.Errorf("%q should be accepted", a)
		}
	}
	for _, a := range bad {
		if validHostPort(a) {
			t.Errorf("%q should be refused", a)
		}
	}
}

func TestVersionPathStaysInside(t *testing.T) {
	s := &VersionStore{dir: "/var/lib/ntpdir/versions"}
	if got := s.path("1790827200558"); got != "/var/lib/ntpdir/versions/1790827200558.json" {
		t.Fatalf("path: %s", got)
	}
	// Whatever text comes in, the file is inside the directory.
	for _, id := range []string{"../../etc/passwd", "/etc/passwd", "..", "", "1/../2", "007"} {
		if got := s.path(id); filepath.Dir(got) != s.dir {
			t.Errorf("path(%q) escaped: %s", id, got)
		}
		if validVersionID(id) {
			t.Errorf("%q should not be a valid version id", id)
		}
	}
}

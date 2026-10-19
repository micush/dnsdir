package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withDnsdir makes bgpBlocked see a dnsdir install (a marker file in a temp dir) for the test.
func withDnsdir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dnsdir")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := dnsdirMarkers
	dnsdirMarkers = []string{p}
	t.Cleanup(func() { dnsdirMarkers = old })
	return p
}

func TestBGPBlockedFollowsDnsdir(t *testing.T) {
	old := dnsdirMarkers
	dnsdirMarkers = []string{filepath.Join(t.TempDir(), "absent")}
	defer func() { dnsdirMarkers = old }()
	if bgpBlocked() != "" {
		t.Fatal("blocked without dnsdir")
	}
	p := withDnsdir(t)
	if bgpBlocked() == "" {
		t.Fatal("not blocked with dnsdir installed")
	}
	os.Remove(p)
	if bgpBlocked() != "" {
		t.Fatal("block did not lift after dnsdir went away")
	}
}

// With dnsdir installed ntpdir must not touch frr.conf, the daemons file, the marker or the FRR service, even when
// it had managed FRR before and the config still has an AS.
func TestBGPApplyLeavesFRRAloneWithDnsdir(t *testing.T) {
	calls, dir := fakeFRR(t, nil)
	state := t.TempDir()
	m := NewBGPManager(state)
	if r := m.applyNow(bgpDC(true)); !r.OK { // ntpdir managed FRR before dnsdir was installed
		t.Fatalf("%+v", r)
	}
	dm, _ := os.ReadFile(filepath.Join(dir, "daemons"))
	n := len(*calls)
	os.WriteFile(filepath.Join(dir, "frr.conf"), []byte("! dnsdir wrote this\nrouter bgp 65000\n"), 0o640)

	withDnsdir(t)
	for _, enabled := range []bool{true, false} {
		if r := m.applyNow(bgpDC(enabled)); !r.OK || !strings.Contains(r.Detail, "dnsdir") {
			t.Fatalf("enabled=%v: %+v", enabled, r)
		}
	}
	got, _ := os.ReadFile(filepath.Join(dir, "frr.conf"))
	if string(got) != "! dnsdir wrote this\nrouter bgp 65000\n" {
		t.Fatalf("frr.conf was rewritten:\n%s", got)
	}
	if now, _ := os.ReadFile(filepath.Join(dir, "daemons")); string(now) != string(dm) {
		t.Fatalf("daemons changed:\n%s", now)
	}
	if _, err := os.Stat(m.markerPath()); err != nil {
		t.Fatal("the marker was removed")
	}
	if len(*calls) != n {
		t.Fatalf("FRR was run: %v", (*calls)[n:])
	}
	if bgpDC(true).BGP.Active() {
		t.Fatal("BGP counts as active with dnsdir installed")
	}
}

func TestBGPCannotBeSetOrEnabledWithDnsdir(t *testing.T) {
	e := bgpEnv(t)
	e.login("alice", "pw")
	set := BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500}}}
	if r := e.do("PUT", "/api/bgp", set, withAuth(e, true)); r.code != 200 {
		t.Fatalf("set before dnsdir: %d %s", r.code, r.raw)
	}
	withDnsdir(t)

	if r := e.do("PUT", "/api/bgp", set, withAuth(e, true)); r.code == 200 || !strings.Contains(string(r.raw), "dnsdir") {
		t.Fatalf("settings accepted with dnsdir installed: %d %s", r.code, r.raw)
	}
	if r := e.do("PUT", "/api/bgp", BGPConfig{ASN: 64513}, withAuth(e, true)); r.code == 200 {
		t.Fatal("a new AS was accepted")
	}
	// disabling is fine, enabling is refused
	if r := e.do("POST", "/api/bgp/operate", BGPOperateArgs{Enabled: false}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	if r := e.do("POST", "/api/bgp/operate", BGPOperateArgs{Enabled: true}, withAuth(e, true)); r.code == 200 || !strings.Contains(string(r.raw), "dnsdir") {
		t.Fatalf("enable accepted: %d %s", r.code, r.raw)
	}
	r := e.do("GET", "/api/bgp", nil, withAuth(e, false))
	if r.code != 200 || !strings.Contains(string(r.raw), `"blocked":"`) {
		t.Fatalf("status does not say BGP is blocked: %d %s", r.code, r.raw)
	}
	// the settings can still be cleared
	if r := e.do("PUT", "/api/bgp", BGPConfig{}, withAuth(e, true)); r.code != 200 {
		t.Fatalf("clearing refused: %d %s", r.code, r.raw)
	}
}

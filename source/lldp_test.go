package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lldpFake replaces systemctl, the lldpd check, lldpcli and the sibling check for one test, and records what was run.
type lldpFake struct {
	active, installed, deferred bool
	calls                       []string
	cli                         []byte
}

func newLLDPFake(t *testing.T) *lldpFake {
	t.Helper()
	f := &lldpFake{installed: true}
	oDir, oRun, oInst, oCli, oDef := lldpDir, lldpRun, lldpInstalled, lldpCli, lldpDefer
	t.Cleanup(func() { lldpDir, lldpRun, lldpInstalled, lldpCli, lldpDefer = oDir, oRun, oInst, oCli, oDef })
	lldpDir = filepath.Join(t.TempDir(), "lldpd.d")
	lldpRun = func(args ...string) ([]byte, error) {
		switch args[0] {
		case "is-active":
			if f.active {
				return nil, nil
			}
			return nil, errors.New("inactive")
		case "enable":
			f.active = true
		case "disable":
			f.active = false
		}
		f.calls = append(f.calls, strings.Join(args, " "))
		return nil, nil
	}
	lldpInstalled = func() bool { return f.installed }
	lldpCli = func(args ...string) ([]byte, error) { return f.cli, nil }
	lldpDefer = func() bool { return f.deferred }
	return f
}

func (f *lldpFake) did() string { s := strings.Join(f.calls, "; "); f.calls = nil; return s }

func TestApplyLLDPStartsAndStopsOnlyItsOwn(t *testing.T) {
	f := newLLDPFake(t)
	// on: lldpd is started and marked as dnsdir's
	applyLLDP(true)
	if d := f.did(); d != "enable --now lldpd" || !fileExists(lldpOwnPath()) {
		t.Fatalf("on: %q, marker %v", d, fileExists(lldpOwnPath()))
	}
	if b, _ := os.ReadFile(lldpOwnPath()); !strings.HasPrefix(string(b), "# Managed by dnsdir") {
		t.Fatalf("marker: %q", b)
	}
	// on again: nothing to do
	applyLLDP(true)
	if d := f.did(); d != "" {
		t.Fatalf("on twice: %q", d)
	}
	// off: stopped, marker gone
	applyLLDP(false)
	if d := f.did(); d != "disable --now lldpd" || fileExists(lldpOwnPath()) {
		t.Fatalf("off: %q", d)
	}
	// someone else's lldpd: never stopped, never marked
	f.active = true
	applyLLDP(true)
	applyLLDP(false)
	if d := f.did(); d != "" || fileExists(lldpOwnPath()) || !f.active {
		t.Fatalf("not ours: %q", d)
	}
	// not installed: nothing
	f.active, f.installed = false, false
	applyLLDP(true)
	if d := f.did(); d != "" || fileExists(lldpOwnPath()) {
		t.Fatalf("not installed: %q", d)
	}
}

// dnsdir decides about lldpd on a host that has ntpdir too: it takes over an lldpd ntpdir started, and leaves the
// stopping of it to ntpdir when its own LLDP is off.
func TestApplyLLDPTakesOverFromNtpdir(t *testing.T) {
	f := newLLDPFake(t)
	// ntpdir started lldpd (its file is there): with LLDP on, dnsdir adds its own file and starts nothing
	f.active = true
	if err := os.MkdirAll(lldpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lldpSiblingPath(), []byte("# Managed by ntpdir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	applyLLDP(true)
	if d := f.did(); d != "" || !fileExists(lldpOwnPath()) {
		t.Fatalf("take-over: %q", d)
	}
	// switched off while ntpdir's file is still there: dnsdir drops its own and leaves lldpd to ntpdir
	applyLLDP(false)
	if d := f.did(); d != "" || fileExists(lldpOwnPath()) || !f.active {
		t.Fatalf("off with ntpdir's file: %q", d)
	}
	// with LLDP off and ntpdir's file there, dnsdir does not touch lldpd at all
	applyLLDP(false)
	if d := f.did(); d != "" {
		t.Fatalf("off, not ours: %q", d)
	}
	// dnsdir never defers
	if lldpDefer() {
		t.Fatal("dnsdir defers")
	}
}

func TestParseLLDPJSON0(t *testing.T) {
	b, err := os.ReadFile("testdata/lldp_neighbors_json0.json")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := parseLLDPJSON0(b)
	if err != nil || len(ns) != 2 {
		t.Fatalf("%v %+v", err, ns)
	}
	a, v := ns[0], ns[1] // sorted by interface: eth1, v0
	if a.Interface != "eth1" || a.SystemName != "core-a" || a.PortID != "Ethernet12" || strings.Join(a.MgmtIPs, ",") != "10.0.0.2,fd00::2" ||
		strings.Join(a.Capabilities, ",") != "Bridge,Router" || a.ChassisID != "00:11:22:33:44:55" || a.TTL != "120" || a.Age != "1m 10s" {
		t.Fatalf("eth1: %+v", a)
	}
	// v0 is what a real lldpd (1.0.18) answered across a veth pair, with two VLANs added
	if v.Interface != "v0" || v.SystemName != "sw1" || v.SystemDescr != "Edge switch sw1" || v.PortDescr != "GigabitEthernet1/0/7" ||
		strings.Join(v.VLANs, ",") != "5 (untagged),20" || strings.Join(v.MgmtIPs, ",") != "192.0.2.1" || v.Protocol != "LLDP" ||
		strings.Join(v.Capabilities, ",") != "Station" || v.Age == "" {
		t.Fatalf("v0: %+v", v)
	}
	// no neighbors: lldpcli's json0 for that
	if ns, err := parseLLDPJSON0([]byte(`{"lldp":[{}]}`)); err != nil || len(ns) != 0 || ns == nil {
		t.Fatalf("none: %v %#v", err, ns)
	}
	for in, want := range map[string]string{"0 day, 00:00:19": "19s", "0 day, 00:03:05": "3m 5s", "0 day, 02:03:04": "2h 3m", "3 days, 01:00:00": "3d 1h", "soon": "soon"} {
		if got := lldpAge(in); got != want {
			t.Errorf("lldpAge(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := parseLLDPJSON0([]byte("lldpcli: unknown command")); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestLLDPStatusAndText(t *testing.T) {
	f := newLLDPFake(t)
	f.cli, _ = os.ReadFile("testdata/lldp_neighbors_json0.json")
	if st := lldpStatus(false); st.Running || st.ManagedBy != "" || len(st.Neighbors) != 0 || st.Neighbors == nil {
		t.Fatalf("stopped: %+v", st)
	}
	f.active = true
	st := lldpStatus(false)
	if st.ManagedBy != "other" || len(st.Neighbors) != 2 {
		t.Fatalf("someone else's: %+v", st)
	}
	if txt := lldpStatusText(st); !strings.Contains(txt, "started outside dnsdir") || !strings.Contains(txt, "GigabitEthernet1/0/7 (") || !strings.Contains(txt, "5 (untagged), 20") {
		t.Fatalf("text:\n%s", txt)
	}
	f.active = false
	applyLLDP(true)
	if st := lldpStatus(true); st.ManagedBy != "dnsdir" || !st.Running {
		t.Fatalf("ours: %+v", st)
	}
	f.installed = false
	if txt := lldpStatusText(lldpStatus(true)); !strings.Contains(txt, "not installed") || strings.Contains(txt, "INTERFACE") {
		t.Fatalf("not installed:\n%s", txt)
	}
}

// The setting is shared, and absent while off, so a cluster that never used it keeps the hash older versions compute.
func TestLLDPSettingSharedAndOmittedWhenOff(t *testing.T) {
	b, _ := json.Marshal(sharedOf(newDaemonConfig()))
	if strings.Contains(string(b), "lldp") {
		t.Fatalf("off is written: %s", b)
	}
	dc := newDaemonConfig()
	dc.DNS.LLDP = true
	b, _ = json.Marshal(sharedOf(dc))
	if !strings.Contains(string(b), `"lldp":true`) {
		t.Fatalf("on is not shared: %s", b)
	}
}

func TestLLDPOverTheAPIAndMCP(t *testing.T) {
	f := newLLDPFake(t)
	f.cli, _ = os.ReadFile("testdata/lldp_neighbors_json0.json")
	e, post := mcpEnv(t, "127.0.0.1 rw")
	call := func(name, args string) (string, bool) {
		t.Helper()
		_, m := post(mcpCall(name, args))
		return toolResult(t, m)
	}
	if txt, isErr := call("get_lldp", `{}`); isErr || !strings.Contains(txt, `"enabled":false`) || !strings.Contains(txt, `"neighbors":[]`) {
		t.Fatalf("off: %s", txt)
	}
	if err := e.mg.LLDPSet(true, "test"); err != nil {
		t.Fatal(err)
	}
	if dc, err := loadConfig(e.conf); err != nil || !dc.DNS.LLDP {
		t.Fatalf("not saved: %v", err)
	}
	f.active = true
	if txt, isErr := call("get_lldp", `{}`); isErr || !strings.Contains(txt, `"enabled":true`) || !strings.Contains(txt, `"system_name":"core-a"`) {
		t.Fatalf("on: %s", txt)
	}
	if txt, isErr := call("api_get", `{"path":"/api/lldp"}`); isErr || !strings.Contains(txt, `"port_descr":"GigabitEthernet1/0/7"`) {
		t.Fatalf("api_get: %s", txt)
	}
	// the Settings page saves it with the rest of the dns block
	if txt, isErr := call("edit_config", `{"set":{"dns":{"lldp":false}}}`); isErr {
		t.Fatalf("edit_config: %s", txt)
	}
	if dc, _ := loadConfig(e.conf); dc.DNS.LLDP {
		t.Fatal("not switched off")
	}
	found := false
	for _, v := range e.mg.VersionsList() {
		if strings.Contains(v.Note, "lldp: on") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no history entry: %+v", e.mg.VersionsList())
	}
}

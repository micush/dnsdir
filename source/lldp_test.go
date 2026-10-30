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
	active, enabled, installed, deferred bool
	calls                                []string
	cli                                  []byte
}

func newLLDPFake(t *testing.T) *lldpFake {
	t.Helper()
	f := &lldpFake{installed: true}
	oDir, oRun, oInst, oCli, oDef := lldpDir, lldpRun, lldpInstalled, lldpCli, lldpDefer
	t.Cleanup(func() { lldpDir, lldpRun, lldpInstalled, lldpCli, lldpDefer = oDir, oRun, oInst, oCli, oDef })
	lldpDir = filepath.Join(t.TempDir(), "lldpd.d")
	lldpRun = func(args ...string) ([]byte, error) {
		switch args[0] {
		case "is-active", "is-enabled":
			if (args[0] == "is-active" && f.active) || (args[0] == "is-enabled" && f.enabled) {
				return nil, nil
			}
			return nil, errors.New("no")
		case "enable":
			f.active, f.enabled = true, true
		case "disable":
			f.active, f.enabled = false, false
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

// The setting decides, whoever started lldpd.
func TestApplyLLDPFollowsTheSetting(t *testing.T) {
	f := newLLDPFake(t)
	// off and lldpd stopped: nothing to do
	applyLLDP(false)
	if d := f.did(); d != "" {
		t.Fatalf("off, stopped: %q", d)
	}
	// on: enabled, started, and the file for the uninstaller written
	applyLLDP(true)
	if d := f.did(); d != "enable --now lldpd" || !fileExists(lldpOwnPath()) {
		t.Fatalf("on: %q, file %v", d, fileExists(lldpOwnPath()))
	}
	if b, _ := os.ReadFile(lldpOwnPath()); !strings.HasPrefix(string(b), "# Managed by dnsdir (Configure") {
		t.Fatalf("file: %q", b)
	}
	applyLLDP(true)
	if d := f.did(); d != "" {
		t.Fatalf("on twice: %q", d)
	}
	// running but not enabled at boot (someone ran systemctl start): enabled too
	f.enabled = false
	applyLLDP(true)
	if d := f.did(); d != "enable --now lldpd" {
		t.Fatalf("not enabled: %q", d)
	}
	// off: stopped and disabled, the file removed
	applyLLDP(false)
	if d := f.did(); d != "disable --now lldpd" || fileExists(lldpOwnPath()) {
		t.Fatalf("off: %q", d)
	}
	// started behind dnsdir's back (a package that starts it on install, or by hand): stopped again
	f.active = true
	applyLLDP(false)
	if d := f.did(); d != "disable --now lldpd" || f.active {
		t.Fatalf("started outside: %q", d)
	}
	// only enabled at boot, not running: disabled
	f.enabled = true
	applyLLDP(false)
	if d := f.did(); d != "disable --now lldpd" || f.enabled {
		t.Fatalf("enabled only: %q", d)
	}
	// not installed: nothing run
	f.installed = false
	applyLLDP(true)
	applyLLDP(false)
	if d := f.did(); d != "" {
		t.Fatalf("not installed: %q", d)
	}
}

// dnsdir decides on a host that has ntpdir too: it never defers, and the setting rules whatever ntpdir's file says.
func TestApplyLLDPNeverDefers(t *testing.T) {
	f := newLLDPFake(t)
	if lldpDefer() {
		t.Fatal("dnsdir defers")
	}
	f.active, f.enabled = true, true
	if err := os.MkdirAll(lldpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lldpSiblingPath(), []byte("# Managed by ntpdir\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	applyLLDP(false)
	if d := f.did(); d != "disable --now lldpd" {
		t.Fatalf("off with ntpdir's file: %q", d)
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
	if st := lldpStatus(false); st.Running || st.ManagedBy != "dnsdir" || len(st.Neighbors) != 0 || st.Neighbors == nil {
		t.Fatalf("stopped: %+v", st)
	}
	applyLLDP(true)
	st := lldpStatus(true)
	if st.ManagedBy != "dnsdir" || !st.Running || len(st.Neighbors) != 2 {
		t.Fatalf("on: %+v", st)
	}
	if txt := lldpStatusText(st); !strings.Contains(txt, "lldpd on this node: running") || !strings.Contains(txt, "GigabitEthernet1/0/7 (") || !strings.Contains(txt, "5 (untagged), 20") {
		t.Fatalf("text:\n%s", txt)
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

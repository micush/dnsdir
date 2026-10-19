package main

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestGroupsKeyMeaning(t *testing.T) {
	load := func(js string) *DaemonConfig {
		t.Helper()
		dc := newDaemonConfig()
		if err := json.Unmarshal([]byte(js), dc); err != nil {
			t.Fatal(err)
		}
		return dc
	}
	if n := len(load(`{}`).Groups); n != 1 {
		t.Fatalf("absent groups = default group, got %d", n)
	}
	if n := len(load(`{"groups":null}`).Groups); n != 1 {
		t.Fatalf("null groups = default group, got %d", n)
	}
	dc := load(`{"groups":[]}`)
	if dc.Groups == nil || len(dc.Groups) != 0 {
		t.Fatalf("explicit empty groups must stay empty: %v", dc.Groups)
	}
	if err := dc.Validate(); err != nil {
		t.Fatalf("a config with no gateways is valid: %v", err)
	}
	// and it survives a save/load round trip as [] (not null, not the default)
	path := t.TempDir() + "/c.json"
	if err := dc.save(path); err != nil {
		t.Fatal(err)
	}
	back, err := loadConfig(path)
	if err != nil || len(back.Groups) != 0 {
		t.Fatalf("round trip: %v %v", back, err)
	}
}

func TestDuplicateSharedAddressRefused(t *testing.T) {
	dc := newDaemonConfig()
	g2 := defaultGroup()
	g2.GroupID = 2
	dc.Groups = append(dc.Groups, g2) // same 10.0.0.1/24 as group 1
	err := dc.Validate()
	if err == nil || !strings.Contains(err.Error(), "shared address") {
		t.Fatalf("two gateways on one address must be refused: %v", err)
	}
	dc.Groups[1].VIP4 = "10.0.1.1/24"
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorPerGroupPools(t *testing.T) {
	a, b, shared := newFakeNTP(t), newFakeNTP(t), newFakeNTP(t)
	mk := func(id int, vip string, own *NTPConfig) GroupConfig {
		g := defaultGroup()
		g.GroupID, g.VIP4, g.NTP = id, vip, own
		return g
	}
	da, db := testNTPCfg(a.addr), testNTPCfg(b.addr)
	dc := newDaemonConfig()
	dc.NTP = testNTPCfg(shared.addr)
	dc.Groups = []GroupConfig{mk(1, "10.1.0.1/24", &da), mk(2, "10.2.0.1/24", &db), mk(3, "10.3.0.1/24", nil)}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewSupervisor(context.Background(), dc)
	s.refreshPool(dc, true)
	t.Cleanup(func() { s.StopAll() })
	if n := len(s.poolList()); n != 3 {
		t.Fatalf("want 3 pools (two own + shared), got %d", n)
	}
	addrOf := func(gid int) string { return s.poolFor(gid).servers[0].Addr }
	if addrOf(1) != a.addr || addrOf(2) != b.addr || addrOf(3) != shared.addr {
		t.Fatalf("groups use the wrong pools: %s %s %s", addrOf(1), addrOf(2), addrOf(3))
	}
	// an unchanged pool is kept (same object), a changed one replaced, a removed one stopped
	p1, p2 := s.poolFor(1), s.poolFor(2)
	nu := *dc
	db2 := da
	db2.ListenPort = 12300
	nu.Groups = []GroupConfig{mk(1, "10.1.0.1/24", &da), mk(2, "10.2.0.1/24", &db2)}
	s.refreshPool(&nu, true)
	if s.poolFor(1) != p1 {
		t.Fatal("unchanged pool must be kept")
	}
	if s.poolFor(2) == p2 {
		t.Fatal("changed pool must be replaced")
	}
	if s.poolFor(3) != nil || len(s.poolList()) != 2 { // only the topology feeds chrony: the shared list is not a pool of its own
		t.Fatal("removed group's pool must be gone")
	}
	if s.ntpFor(2).ListenPort != 12300 {
		t.Fatal("ntpFor must follow the new settings")
	}
}

func TestSharedConfigCarriesGroupPools(t *testing.T) {
	g := defaultGroup()
	d := testNTPCfg("1.1.1.1")
	d.ServerNames = map[string]string{"1.1.1.1": "one"}
	g.NTP = &d
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	dc.NTP = testNTPCfg("9.9.9.9")
	if err := dc.Validate(); err != nil { // normalises addresses, as every real save does
		t.Fatal(err)
	}
	sh := sharedOf(dc)
	h1 := sh.hash()

	// the replica starts without the group's pool and adopts it
	rep := newDaemonConfig()
	rep.NTP = testNTPCfg("9.9.9.9")
	rg := defaultGroup()
	rg.Interface = "eth7"
	rg.GroupID, rg.VIP4 = 1, g.VIP4
	rep.Groups = []GroupConfig{rg}
	changed, err := mergeShared(rep, sh, seedsOf(dc))
	if err != nil || !changed {
		t.Fatalf("merge: %v %v", changed, err)
	}
	if rep.Groups[0].NTP == nil || len(rep.Groups[0].NTP.ServerNames) != 1 {
		t.Fatalf("the pool must replicate: %+v", rep.Groups[0].NTP)
	}
	if rep.Groups[0].Interface != "eth7" {
		t.Fatal("the interface stays local")
	}
	if sharedOf(rep).hash() != h1 {
		t.Fatal("after the merge both nodes must hash the same")
	}
	// zero gateways replicate too
	empty := SharedConfig{NTP: dc.NTP, Groups: []SharedGroup{}}
	if err := empty.Validate(); err != nil {
		t.Fatalf("an empty shared config is valid: %v", err)
	}
	if _, err := mergeShared(rep, empty, nil); err != nil || len(rep.Groups) != 0 {
		t.Fatalf("empty merge: %v %d", err, len(rep.Groups))
	}
}

func TestApplyCanvasEdit(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{}
	do := func(e canvasEdit) {
		t.Helper()
		if _, err := applyCanvasEdit(dc, e); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
	}
	fail := func(e canvasEdit, want string) {
		t.Helper()
		if _, err := applyCanvasEdit(dc, e); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%+v: want error containing %q, got %v", e, want, err)
		}
	}
	do(canvasEdit{Action: "add", Kind: "gateway", VIP: "10.0.0.1/24", Interface: "eth0"})
	if err := dc.Validate(); err != nil {
		t.Fatalf("a bare gateway (no DNS yet) is valid: %v", err)
	}
	do(canvasEdit{Action: "add", Kind: "gateway", VIP: "2001:db8::1/64"})
	if len(dc.Groups) != 2 || dc.Groups[0].GroupID != 100 || dc.Groups[1].GroupID != 101 || dc.Groups[1].VIP6 == "" || dc.Groups[1].Interface != "eth0" {
		t.Fatalf("gateways: %+v", dc.Groups)
	}
	fail(canvasEdit{Action: "add", Kind: "gateway", Group: 100, VIP: "10.9.9.9/24"}, "already exists")
	fail(canvasEdit{Action: "add", Kind: "gateway"}, "--vip")
	// a server and domains
	do(canvasEdit{Action: "add", Kind: "server", Group: 100, Server: "8.8.8.8"})
	fail(canvasEdit{Action: "add", Kind: "server", Group: 100, Server: "8.8.8.8:123"}, "already")
	fail(canvasEdit{Action: "add", Kind: "server", Group: 9, Server: "8.8.8.8"}, "no gateway")
	do(canvasEdit{Action: "add", Kind: "server", Group: 100, Server: "8.8.4.4"})
	do(canvasEdit{Action: "add", Kind: "server", Group: 101, Server: "9.9.9.9"})
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	g1 := dc.Groups[0].NTP
	if len(g1.Servers) != 4+2 { // the four a gateway starts with, and the two added
		t.Fatalf("group 1 pool: %+v", g1)
	}
	// a gateway can be drawn complete in one step
	do(canvasEdit{Action: "add", Kind: "gateway", Group: 7, VIP: "10.7.0.1/24", Server: "4.4.4.4"})
	if g := dc.Groups[2]; g.GroupID != 7 || g.NTP == nil || g.NTP.Servers[len(g.NTP.Servers)-1] != "4.4.4.4:123" {
		t.Fatalf("one-step gateway: %+v", g)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	do(canvasEdit{Action: "del", Kind: "gateway", Group: 7})
	// delete a square: siblings stay
	do(canvasEdit{Action: "del", Kind: "server", Group: 100, Server: "8.8.8.8"})
	g1 = dc.Groups[0].NTP
	if len(g1.Servers) != 4+1 || g1.Servers[len(g1.Servers)-1] != "8.8.4.4:123" || containsStr(g1.Servers, "8.8.8.8:123") {
		t.Fatalf("after server delete: %+v", g1)
	}
	// delete a circle: the whole gateway goes, the other one is untouched
	do(canvasEdit{Action: "del", Kind: "gateway", Group: 100})
	if len(dc.Groups) != 1 || dc.Groups[0].GroupID != 101 || len(dc.Groups[0].NTP.Servers) != 4+1 {
		t.Fatalf("after gateway delete: %+v", dc.Groups)
	}
	do(canvasEdit{Action: "del", Kind: "gateway", Group: 101})
	if len(dc.Groups) != 0 {
		t.Fatal("deleting the last circle leaves no configuration")
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	fail(canvasEdit{Action: "del", Kind: "gateway", Group: 101}, "no gateway")
	fail(canvasEdit{Action: "zap", Kind: "gateway"}, "unknown canvas edit")
}

func TestCanvasEditFromSharedPoolCopiesIt(t *testing.T) {
	dc := newDaemonConfig() // group 1 uses the shared dns block
	dc.Groups[0].GroupID = 1
	dc.NTP = testNTPCfg("1.1.1.1")
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "add", Kind: "server", Group: 1, Server: "2.2.2.2"}); err != nil {
		t.Fatal(err)
	}
	if len(dc.NTP.Servers) != 1 {
		t.Fatalf("the shared pool must not change: %v", dc.NTP.Servers)
	}
	if g := dc.Groups[0].NTP; g == nil || len(g.Servers) != 2 {
		t.Fatalf("the group gets its own copy: %+v", g)
	}
}

func TestBuildCanvasColours(t *testing.T) {
	good, bad := newFakeNTP(t), newFakeNTP(t)
	bad.mode.Store(3)
	d := testNTPCfg(good.addr, bad.addr)
	g := defaultGroup()
	g.NTP = &d
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	s := NewSupervisor(context.Background(), dc)
	s.refreshPool(dc, true)
	t.Cleanup(func() { s.StopAll() })

	// not running: grey circle
	cv := buildCanvas(dc, nil, s.poolList())
	if cv[0].Status != "idle" || cv[0].Servers[0].Status == "" {
		t.Fatalf("not running: %+v", cv[0])
	}
	rows := []SnapshotRow{{GroupID: 1, AF: "v4", Local: true, State: "active", NTPUp: true}}
	cv = buildCanvas(dc, rows, s.poolList())
	gw := cv[0]
	if gw.Status != "warn" {
		t.Fatalf("one server down => yellow, got %s (%s)", gw.Status, gw.Detail)
	}
	by := map[string]CanvasServer{}
	for _, sv := range gw.Servers {
		by[sv.Addr] = sv
	}
	if by[good.addr].Status != "ok" || by[bad.addr].Status != "bad" {
		t.Fatalf("server colours: good=%s bad=%s", by[good.addr].Status, by[bad.addr].Status)
	}
	if by[good.addr].Time == nil || by[good.addr].Time.Stratum != 2 {
		t.Fatalf("a working server shows what its clock said: %+v", by[good.addr].Time)
	}
	// every server down => red; healthy but not serving yet => yellow
	// the pool's own probe loop runs beside the test's probes, so a round that started before the change can
	// land after it: probe again until the colour settles instead of trusting the first round
	settle := func(want string) []CanvasGateway {
		var out []CanvasGateway
		for i := 0; i < 40; i++ {
			s.poolFor(1).ProbeNow(context.Background())
			if out = buildCanvas(dc, rows, s.poolList()); out[0].Status == want {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		return out
	}
	good.mode.Store(3)
	if cv = settle("bad"); cv[0].Status != "bad" {
		t.Fatalf("all servers down => red, got %s", cv[0].Status)
	}
	good.mode.Store(0)
	bad.mode.Store(0)
	if cv = settle("ok"); cv[0].Status != "ok" {
		t.Fatalf("all fine => green, got %s (%s)", cv[0].Status, cv[0].Detail)
	}
	standby := []SnapshotRow{{GroupID: 1, AF: "v4", Local: true, State: "listen"}}
	if cv = buildCanvas(dc, standby, s.poolList()); cv[0].Status != "warn" {
		t.Fatalf("not serving => yellow, got %s", cv[0].Status)
	}
}

func TestWebCanvasEndpoint(t *testing.T) {
	e := newWebEnv(t)
	e.login("alice", "pw")
	r := e.do("GET", "/api/canvas", nil, withAuth(e, false))
	if r.code != 200 {
		t.Fatalf("canvas: %d %s", r.code, r.raw)
	}
	if _, ok := r.body["data"].([]any); !ok {
		t.Fatalf("data must be a list: %s", r.raw)
	}
	if r2 := e.do("GET", "/api/canvas", nil); r2.code != 401 {
		t.Fatalf("canvas needs a login: %d", r2.code)
	}
}

func TestHistoryDescribesCanvasChanges(t *testing.T) {
	mk := func(mut func(*GroupConfig)) *DaemonConfig {
		dc := newDaemonConfig()
		d := testNTPCfg("1.1.1.1:123")
		dc.Groups[0].NTP = &d
		if mut != nil {
			mut(&dc.Groups[0])
		}
		return dc
	}
	before := mk(nil)
	after := mk(func(g *GroupConfig) {
		g.NTP.Servers = append(g.NTP.Servers, "2.2.2.2:123")
	})
	var detail string
	for _, s := range configSections(before, after) {
		detail += s.Label + ": " + s.Detail + "\n"
	}
	for _, want := range []string{"servers added 2.2.2.2:123"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("history should say %q, got:\n%s", want, detail)
		}
	}
}

func TestCanvasDualStackAndStratumEdits(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{}
	do := func(e canvasEdit) {
		t.Helper()
		if _, err := applyCanvasEdit(dc, e); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
	}
	do(canvasEdit{Action: "add", Kind: "gateway", VIP: "10.0.0.1/24", VIP6: "2001:db8::1/64",
		Server: "2001:db8::123"})
	g := dc.Groups[0]
	if g.VIP4 != "10.0.0.1/24" || g.VIP6 != "2001:db8::1/64" {
		t.Fatalf("both addresses: %q %q", g.VIP4, g.VIP6)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if last := g.NTP.Servers[len(g.NTP.Servers)-1]; last != "[2001:db8::123]:123" {
		t.Fatalf("an IPv6 server is stored bracketed with its port: %q", last)
	}
	// an IPv6 address in --vip goes to the IPv6 slot
	do(canvasEdit{Action: "add", Kind: "gateway", VIP: "2001:db8:2::1/64"})
	if g2 := dc.Groups[1]; g2.VIP6 == "" || g2.VIP4 != "" {
		t.Fatalf("v6-only gateway: %+v", g2)
	}
	// set: change address, interface and the highest stratum
	do(canvasEdit{Action: "set", Kind: "gateway", Group: 100, VIP: "10.0.9.1/24", Interface: "eth5", MaxStratum: 8})
	g = dc.Groups[0]
	if g.VIP4 != "10.0.9.1/24" || g.VIP6 != "2001:db8::1/64" || g.Interface != "eth5" || g.NTP.LB == nil || g.NTP.LB.MaxStratum != 8 {
		t.Fatalf("after set: %+v %+v", g, g.NTP)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: 100}); err == nil {
		t.Fatal("set without anything to change must say so")
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: 9, MaxStratum: 3}); err == nil {
		t.Fatal("unknown gateway")
	}
	// setting a value on a gateway that used the shared pool copies the pool first
	dc2 := newDaemonConfig()
	dc2.NTP = testNTPCfg("1.1.1.1")
	if _, err := applyCanvasEdit(dc2, canvasEdit{Action: "set", Kind: "gateway", Group: 100, MaxStratum: 3}); err != nil {
		t.Fatal(err)
	}
	if dc2.NTP.MaxStratum == 3 || dc2.Groups[0].NTP == nil || len(dc2.Groups[0].NTP.Servers) != 1 {
		t.Fatalf("shared pool must stay as it was; group gets a copy: %+v", dc2.Groups[0].NTP)
	}
}

func TestBuildCanvasPerFamilyStatus(t *testing.T) {
	good := newFakeNTP(t)
	d := testNTPCfg(good.addr)
	g := defaultGroup()
	g.VIP6 = "2001:db8::1/64"
	g.NTP = &d
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	s := NewSupervisor(context.Background(), dc)
	s.refreshPool(dc, true)
	t.Cleanup(func() { s.StopAll() })

	v4ok := SnapshotRow{GroupID: 1, AF: "v4", Local: true, State: "active", NTPUp: true}
	v6ok := SnapshotRow{GroupID: 1, AF: "v6", Local: true, State: "active", NTPUp: true}
	v6wait := SnapshotRow{GroupID: 1, AF: "v6", Local: true, State: "listen"}

	both := buildCanvas(dc, []SnapshotRow{v4ok, v6ok}, s.poolList())[0]
	if both.Status != "ok" || len(both.Families) != 2 {
		t.Fatalf("both families fine: %s %+v", both.Status, both.Families)
	}
	mixed := buildCanvas(dc, []SnapshotRow{v4ok, v6wait}, s.poolList())[0]
	if mixed.Status != "warn" || mixed.Families[0].Status != "ok" || mixed.Families[1].Status != "warn" {
		t.Fatalf("IPv6 not serving must not hide behind a healthy IPv4: %s %+v", mixed.Status, mixed.Families)
	}
	if !strings.Contains(mixed.Detail, "IPv6") || !strings.Contains(mixed.Detail, "IPv4") {
		t.Fatalf("the detail must name both families: %q", mixed.Detail)
	}
	missing := buildCanvas(dc, []SnapshotRow{v4ok}, s.poolList())[0]
	if missing.Status != "warn" || missing.Families[1].Status != "idle" {
		t.Fatalf("an IPv6 engine that is missing is a warning: %s %+v", missing.Status, missing.Families)
	}
	none := buildCanvas(dc, nil, s.poolList())[0]
	if none.Status != "idle" {
		t.Fatalf("nothing running: %s", none.Status)
	}
}

func TestCanvasMembers(t *testing.T) {
	rows := []SnapshotRow{
		{GroupID: 1, AF: "v4", PeerIP: "10.0.0.5", Local: true, AfnID: 1, Weight: 100, AGCIP: "10.0.0.5"},
		{GroupID: 1, AF: "v6", PeerIP: "10.0.0.5", Local: true, AfnID: 1, Weight: 100, AGCIP: "10.0.0.5"},
		{GroupID: 1, AF: "v4", PeerIP: "10.0.0.6", AfnID: 2, State: "active", AGCIP: "10.0.0.5"},
		{GroupID: 1, AF: "v4", PeerIP: "10.0.0.7", AfnID: 3, State: "expired"}, // gone quiet
		{GroupID: 1, AF: "v4", PeerIP: "10.0.0.8", AfnID: 0, State: "active"},  // no slot, not serving
		{GroupID: 2, AF: "v4", PeerIP: "10.0.0.9", AfnID: 1, State: "active"},  // another gateway
	}
	m := membersOf(rows, 1)
	if len(m) != 2 || m[0].IP != "10.0.0.5" || !m[0].Local || !m[0].AGC || m[0].AFs != "v4+v6" || m[1].IP != "10.0.0.6" || m[1].AGC {
		t.Fatalf("members: %+v", m)
	}
	if got := membersOf(nil, 1); got == nil || len(got) != 0 {
		t.Fatalf("empty must be a non-nil list for JSON: %#v", got)
	}
}

func TestPauseServerAndGateway(t *testing.T) {
	a, b := newFakeNTP(t), newFakeNTP(t)
	d := testNTPCfg(a.addr, b.addr)
	g := defaultGroup()
	g.NTP = &d
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}

	// pausing a server takes it out of the live pool but keeps it in the config
	if msg, err := applyCanvasEdit(dc, canvasEdit{Action: "pause", Kind: "server", Group: 1, Server: b.addr}); err != nil || !strings.Contains(msg, "paused") {
		t.Fatalf("pause server: %q %v", msg, err)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	own := dc.Groups[0].NTP
	if len(own.Servers) != 2 || !own.isPaused(b.addr) || own.isPaused(a.addr) {
		t.Fatalf("config after pause: %+v", own)
	}
	if lv := own.live(); len(lv.Servers) != 1 || lv.Servers[0] != a.addr || lv.PausedServers != nil {
		t.Fatalf("live pool config: %+v", lv)
	}
	s := NewSupervisor(context.Background(), dc)
	s.refreshPool(dc, true)
	t.Cleanup(func() { s.StopAll() })
	if n := len(s.poolFor(1).servers); n != 1 {
		t.Fatalf("a paused server must not be in the running pool, pool has %d", n)
	}
	rows := []SnapshotRow{{GroupID: 1, AF: "v4", Local: true, State: "active", NTPUp: true}}
	cv := buildCanvas(dc, rows, s.poolList())[0]
	by := map[string]CanvasServer{}
	for _, sv := range cv.Servers {
		by[sv.Addr] = sv
	}
	if by[b.addr].Status != "paused" || by[a.addr].Status != "ok" {
		t.Fatalf("paused colours: %+v", cv.Servers)
	}
	if cv.Status != "ok" {
		t.Fatalf("a paused server is not a fault, got %s (%s)", cv.Status, cv.Detail)
	}
	// every server paused: clients cannot be answered
	do := func(e canvasEdit) {
		t.Helper()
		if _, err := applyCanvasEdit(dc, e); err != nil {
			t.Fatal(err)
		}
	}
	// the last server in service cannot be paused while the gateway has no fallback servers
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "pause", Kind: "server", Group: 1, Server: a.addr}); err == nil || !strings.Contains(err.Error(), "fallback") {
		t.Fatalf("the last server was paused without a fallback server: %v", err)
	}
	own.FallbackServers = []string{"192.0.2.99"}
	do(canvasEdit{Action: "pause", Kind: "server", Group: 1, Server: a.addr}) // with a fallback server it is allowed
	own.FallbackServers = nil
	_ = dc.Validate()
	s.refreshPool(dc, true)
	if cv = buildCanvas(dc, rows, s.poolList())[0]; cv.Status != "bad" || !strings.Contains(cv.Detail, "paused") {
		t.Fatalf("all paused => red: %s (%s)", cv.Status, cv.Detail)
	}
	// resume; deleting a paused server forgets the pause
	do(canvasEdit{Action: "resume", Kind: "server", Group: 1, Server: a.addr})
	do(canvasEdit{Action: "del", Kind: "server", Group: 1, Server: b.addr})
	_ = dc.Validate()
	if p := dc.Groups[0].NTP.PausedServers; len(p) != 0 {
		t.Fatalf("pause must go with the server: %v", p)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "pause", Kind: "server", Group: 1, Server: "10.9.9.9"}); err == nil {
		t.Fatal("pausing a server that is not there must fail")
	}

	// gateway: paused is local, shows as paused, and starts no engines
	do(canvasEdit{Action: "pause", Kind: "gateway", Group: 1})
	if !dc.Groups[0].Paused {
		t.Fatal("not paused")
	}
	if cv = buildCanvas(dc, nil, s.poolList())[0]; cv.Status != "paused" || !cv.Paused || cv.Families[0].Status != "paused" {
		t.Fatalf("paused gateway: %+v", cv)
	}
	if sh := sharedOf(dc); strings.Contains(string(mustJSON(t, sh)), "paused\":true") {
		t.Fatal("the gateway pause is per node and must not be replicated")
	}
	sup := NewSupervisor(context.Background(), dc)
	sup.StartAll()
	if n := len(sup.engineList()); n != 0 {
		t.Fatalf("a paused gateway must start no engines, got %d", n)
	}
	if k := sup.poolFor(1); k == nil {
		t.Fatal("a paused gateway keeps its pool: its servers are still the node's time sources")
	}
	sup.StopAll()
	do(canvasEdit{Action: "resume", Kind: "gateway", Group: 1})
	if dc.Groups[0].Paused {
		t.Fatal("still paused")
	}
	// history reads in words
	old, nu := *dc, *dc
	old.Groups = []GroupConfig{g}
	nu.Groups = []GroupConfig{g}
	nu.Groups[0].Paused = true
	if txt := string(mustJSON(t, configSections(&old, &nu))); !strings.Contains(txt, "paused on this node") {
		t.Fatalf("history wording: %s", txt)
	}
}

// A gateway always serves DNS; one with no servers yet is amber, not green: it
// is up but cannot answer clients.
func TestBuildCanvasGatewayWithoutServers(t *testing.T) {
	d := testNTPCfg()
	g := defaultGroup()
	g.NTP = &d
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	s := NewSupervisor(context.Background(), dc)
	s.refreshPool(dc, true)
	t.Cleanup(func() { s.StopAll() })
	rows := []SnapshotRow{{GroupID: 1, AF: "v4", Local: true, State: "active", NTPUp: true}}
	cv := buildCanvas(dc, rows, s.poolList())
	if cv[0].Status != "warn" || !strings.Contains(cv[0].Detail, "no NTP server") {
		t.Fatalf("no servers: %s (%s)", cv[0].Status, cv[0].Detail)
	}
}

// Dragging in the drawing (and --canvas-move) reorders servers, a server's domains and the anycast addresses.
func TestCanvasMove(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups[0].GroupID = 1
	dc.NTP = testNTPCfg("1.1.1.1", "2.2.2.2", "3.3.3.3")
	dc.Groups[0].ExtraVIPs = []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	must := func(e canvasEdit) {
		t.Helper()
		e.Group = 1
		if _, err := applyCanvasEdit(dc, e); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
	}
	must(canvasEdit{Action: "move", Kind: "server", Server: "3.3.3.3", Pos: 1})
	if got := dc.Groups[0].NTP.Servers; got[0] != "3.3.3.3" || got[1] != "1.1.1.1" || got[2] != "2.2.2.2" {
		t.Fatalf("servers after move: %v", got)
	}
	if len(dc.NTP.Servers) != 3 || dc.NTP.Servers[0] != "1.1.1.1" {
		t.Fatalf("the shared pool must not change: %v", dc.NTP.Servers)
	}
	must(canvasEdit{Action: "move", Kind: "server", Server: "3.3.3.3", Pos: 99}) // past the end: last
	if got := dc.Groups[0].NTP.Servers; got[2] != "3.3.3.3" {
		t.Fatalf("clamped to the end: %v", got)
	}
	must(canvasEdit{Action: "move", Kind: "anycast", Address: "203.0.113.3", Pos: 1})
	if got := dc.Groups[0].ExtraVIPs; got[0] != "203.0.113.3" || got[1] != "203.0.113.1" || got[2] != "203.0.113.2" {
		t.Fatalf("anycast after move: %v", got)
	}
	for _, e := range []canvasEdit{
		{Action: "move", Kind: "server", Group: 1, Server: "9.9.9.9", Pos: 1},
		{Action: "move", Kind: "server", Group: 1, Server: "1.1.1.1"},
		{Action: "move", Kind: "anycast", Group: 1, Address: "203.0.113.99", Pos: 1},
	} {
		if _, err := applyCanvasEdit(dc, e); err == nil {
			t.Fatalf("%+v must be refused", e)
		}
	}
	if err := dc.Validate(); err != nil {
		t.Fatalf("a moved configuration must stay valid: %v", err)
	}
}

// With several servers and only one left in service, the gateway is amber: it works, but one failure from being down.
func TestOnlyOneServerLeftIsAmber(t *testing.T) {
	a, b, c := newFakeNTP(t), newFakeNTP(t), newFakeNTP(t)
	d := testNTPCfg(a.addr, b.addr, c.addr)
	g := defaultGroup()
	g.NTP = &d
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	pause := func(addr string) {
		t.Helper()
		if _, err := applyCanvasEdit(dc, canvasEdit{Action: "pause", Kind: "server", Group: 1, Server: addr}); err != nil {
			t.Fatal(err)
		}
	}
	rows := []SnapshotRow{{GroupID: 1, AF: "v4", Local: true, State: "active", NTPUp: true}}
	status := func() CanvasGateway {
		t.Helper()
		_ = dc.Validate()
		s := NewSupervisor(context.Background(), dc)
		s.refreshPool(dc, true)
		defer s.StopAll()
		return buildCanvas(dc, rows, s.poolList())[0]
	}
	pause(c.addr)
	if cv := status(); cv.Status != "ok" {
		t.Fatalf("one of three paused: %s (%s)", cv.Status, cv.Detail)
	}
	pause(b.addr)
	if cv := status(); cv.Status != "warn" || !strings.Contains(cv.Detail, "only one") {
		t.Fatalf("two of three paused: %s (%s)", cv.Status, cv.Detail)
	}
}

// A gateway created now starts with the four public servers, which are ordinary servers: any of them can be removed,
// and a server named at creation that is one of them is not added twice.  A config read from a file is not touched.
func TestNewGatewayStartsWithDefaultServers(t *testing.T) {
	want := []string{"pool.ntp.org:123", "time.nist.gov:123", "time.google.com:123", "time.cloudflare.com:123"}
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "add", Kind: "gateway", VIP: "10.0.0.1/24", Interface: "eth0"}); err != nil {
		t.Fatal(err)
	}
	if got := dc.Groups[0].NTP.Servers; !reflect.DeepEqual(got, want) {
		t.Fatalf("a new gateway's servers: %v, want %v", got, want)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "del", Kind: "server", Group: 100, Server: "time.nist.gov"}); err != nil {
		t.Fatalf("a starting server can be removed: %v", err)
	}
	if got := dc.Groups[0].NTP.Servers; len(got) != 3 || containsStr(got, "time.nist.gov:123") {
		t.Fatalf("after removing one: %v", got)
	}
	// naming one of the starting servers at creation is not an error and not a duplicate
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "add", Kind: "gateway", VIP: "10.1.0.1/24", Server: "Time.Google.com"}); err != nil {
		t.Fatal(err)
	}
	if got := dc.Groups[1].NTP.Servers; !reflect.DeepEqual(got, want) {
		t.Fatalf("with a named server that is already one: %v", got)
	}
	// a shared default does not change: a config with no servers still has none
	if d := defaultNTP(); len(d.Servers) != 0 {
		t.Fatalf("defaultNTP has servers: %v", d.Servers)
	}
	var back DaemonConfig
	if err := json.Unmarshal([]byte(`{"groups":[{"group_id":1,"vip4":"10.0.0.1/24"}]}`), &back); err != nil || back.Groups[0].NTP != nil {
		t.Fatalf("a gateway read from a file gets no servers: %v %+v", err, back.Groups)
	}
}

// The GUI's New gateway form starts from the same list as the command line (DEFAULT_SERVERS in app.js).
func TestDefaultServersMatchTheGUI(t *testing.T) {
	b, err := os.ReadFile("webui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const DEFAULT_SERVERS = \[([^\]]*)\];`).FindSubmatch(b)
	if m == nil {
		t.Fatal("DEFAULT_SERVERS not found in app.js")
	}
	var js []string
	for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(m[1], -1) {
		js = append(js, string(q[1]))
	}
	if !reflect.DeepEqual(js, defaultGatewayServers) {
		t.Fatalf("app.js has %v, config.go has %v", js, defaultGatewayServers)
	}
}

// A dual-stack gateway has two engines per node, and each speaks from its own address, so membersOf sees a node twice.
// The circle's tooltip counts nodes: 4 nodes with IPv4 and IPv6 running said "Serving nodes: 8".
func TestMergeFamilyMembersCountsNodes(t *testing.T) {
	var rows []SnapshotRow
	names := map[string]string{}
	for i := 1; i <= 4; i++ {
		v4, v6 := "192.168.5."+string(rune('0'+i)), "fe80::"+string(rune('0'+i))
		names[v4], names[v6] = "ntp"+string(rune('0'+i)), "ntp"+string(rune('0'+i))
		rows = append(rows,
			SnapshotRow{GroupID: 100, AF: "v6", PeerIP: v6, AfnID: i, Weight: 100, State: "active", Local: i == 1, AGCIP: "fe80::1"},
			SnapshotRow{GroupID: 100, AF: "v4", PeerIP: v4, AfnID: i, Weight: 100, State: "active", Local: i == 1, AGCIP: "192.168.5.1"})
	}
	rows = append(rows, SnapshotRow{GroupID: 100, AF: "v4", PeerIP: "192.168.5.99", AfnID: 9, State: "active"}) // an address no node owns
	gs := []CanvasGateway{{GroupID: 100, Members: membersOf(rows, 100)}}
	if len(gs[0].Members) != 9 {
		t.Fatalf("membersOf sees %d, want 9 (8 per-family entries and the stranger)", len(gs[0].Members))
	}
	mergeFamilyMembers(gs, names)
	ms := gs[0].Members
	if len(ms) != 5 {
		t.Fatalf("members after merging: %d, want 4 nodes and the unknown address: %+v", len(ms), ms)
	}
	for _, m := range ms {
		if m.IP == "192.168.5.99" {
			continue
		}
		if m.AFs != "v4+v6" || !strings.HasPrefix(m.IP, "192.168.5.") {
			t.Fatalf("a node is listed by its IPv4 address with both families: %+v", m)
		}
	}
	for _, m := range ms {
		if m.IP == "192.168.5.1" && (!m.Local || !m.AGC) {
			t.Fatalf("local and controller survive the merge: %+v", m)
		}
	}
}

// A dual-stack gateway elects its controllers per family: each node says which families it is the controller for, and
// the merge keeps that apart (the drawing shows the IPv6-only controller in blue).
func TestMergeFamilyMembersKeepsControllerFamilies(t *testing.T) {
	var rows []SnapshotRow
	names := map[string]string{}
	for i := 1; i <= 2; i++ {
		v4, v6 := "192.168.5."+string(rune('0'+i)), "fe80::"+string(rune('0'+i))
		names[v4], names[v6] = "ntp"+string(rune('0'+i)), "ntp"+string(rune('0'+i))
		rows = append(rows,
			SnapshotRow{GroupID: 1, AF: "v6", PeerIP: v6, AfnID: i, State: "active", Local: i == 1, AGCIP: "fe80::2"},
			SnapshotRow{GroupID: 1, AF: "v4", PeerIP: v4, AfnID: i, State: "active", Local: i == 1, AGCIP: "192.168.5.1"})
	}
	gs := []CanvasGateway{{GroupID: 1, Members: membersOf(rows, 1)}}
	mergeFamilyMembers(gs, names)
	ms := gs[0].Members
	if len(ms) != 2 || ms[0].IP != "192.168.5.1" || ms[0].AGCAFs != "v4" || ms[1].IP != "192.168.5.2" || ms[1].AGCAFs != "v6" || !ms[0].AGC || !ms[1].AGC {
		t.Fatalf("IPv4 controller on ntp1, IPv6 controller on ntp2: %+v", ms)
	}
	// both families on one node: one entry that says both
	for i := range rows {
		rows[i].AGCIP = map[string]string{"v4": "192.168.5.1", "v6": "fe80::1"}[rows[i].AF]
	}
	gs = []CanvasGateway{{GroupID: 1, Members: membersOf(rows, 1)}}
	mergeFamilyMembers(gs, names)
	if ms := gs[0].Members; ms[0].AGCAFs != "v4+v6" || ms[1].AGC || ms[1].AGCAFs != "" {
		t.Fatalf("both controllers on ntp1: %+v", ms)
	}
}

func TestPoolsSkipExcludedGateways(t *testing.T) {
	a, b := newFakeNTP(t), newFakeNTP(t)
	mk := func(id int, vip string, own NTPConfig, excl ...string) GroupConfig {
		g := defaultGroup()
		g.GroupID, g.VIP4, g.NTP, g.ExcludedNodes = id, vip, &own, excl
		return g
	}
	old := localNodeID()
	setLocalNodeID("aaaaaaaaaaaaaaaa")
	t.Cleanup(func() { setLocalNodeID(old) })
	dc := newDaemonConfig()
	dc.NTP = testNTPCfg(a.addr)
	dc.Groups = []GroupConfig{mk(1, "10.1.0.1/24", testNTPCfg(a.addr)), mk(2, "10.2.0.1/24", testNTPCfg(b.addr), "aaaaaaaaaaaaaaaa")}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewSupervisor(context.Background(), dc)
	s.refreshPool(dc, true)
	t.Cleanup(func() { s.StopAll() })
	if s.poolFor(1) == nil || s.poolFor(2) != nil || len(s.poolList()) != 1 {
		t.Fatalf("a gateway this node was removed from must have no pool here: %d pools", len(s.poolList()))
	}
	// removed from every gateway: no pool at all
	dc.Groups[0].ExcludedNodes = []string{"aaaaaaaaaaaaaaaa"}
	s.refreshPool(dc, true)
	if len(s.poolList()) != 0 {
		t.Fatalf("a node removed from every gateway has no pools, got %d", len(s.poolList()))
	}
}

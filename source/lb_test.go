package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func lbTestConfig() *DaemonConfig {
	dc := newDaemonConfig()
	dc.NTP.Servers = []string{"192.0.2.1:123"}
	g := dc.Groups[0]
	own := defaultNTP()
	own.Servers = []string{"192.0.2.9:123"}
	g.NTP = &own
	dc.Groups = []GroupConfig{g}
	return dc
}

// A gateway's own pool follows Settings for load balancing until it is given its own values.
func TestGatewayPoolFollowsSettingsLoadBalancing(t *testing.T) {
	dc := lbTestConfig()
	dc.NTP.SpreadBand, dc.NTP.MaxAttempts, dc.NTP.Spread = 200, 5, false
	_, c := dc.poolFor(&dc.Groups[0])
	if c.SpreadBand != 200 || c.MaxAttempts != 5 || c.Spread {
		t.Fatalf("a pool at the defaults must follow Settings, got band %d attempts %d spread %v", c.SpreadBand, c.MaxAttempts, c.Spread)
	}
	if c.Servers[0] != "192.0.2.9:123" {
		t.Fatalf("the gateway's own servers must stay: %v", c.Servers)
	}
	// its own values win, and a later Settings change does not touch them
	lb := LBConfig{Spread: true, SpreadBand: 50, MaxStratum: 6, FailThreshold: 4, MaxAttempts: 2, LatencyAlpha: 0.5}
	dc.Groups[0].NTP.LB = &lb
	dc.NTP.SpreadBand = 300
	_, c = dc.poolFor(&dc.Groups[0])
	if c.SpreadBand != 50 || c.MaxStratum != 6 || c.FailThreshold != 4 || c.MaxAttempts != 2 || c.LatencyAlpha != 0.5 || !c.Spread || c.LB != nil {
		t.Fatalf("own load balancing: %+v", c)
	}
	// a gateway without its own pool is the shared pool itself
	dc.Groups[0].NTP = nil
	if k, c := dc.poolFor(&dc.Groups[0]); k != 0 || c.SpreadBand != 300 {
		t.Fatalf("shared pool: key %d band %d", k, c.SpreadBand)
	}
}

// A pool written before LB existed, at values other than the defaults, keeps them (they were set on purpose).
func TestLegacyGatewayPoolKeepsItsOwnValues(t *testing.T) {
	dc := lbTestConfig()
	dc.NTP.SpreadBand = 200
	dc.Groups[0].NTP.SpreadBand = 75
	if l, own := dc.Groups[0].NTP.ownLB(); !own || l.SpreadBand != 75 {
		t.Fatalf("a legacy pool at non-default values is the gateway's own: %+v %v", l, own)
	}
	if _, c := dc.poolFor(&dc.Groups[0]); c.SpreadBand != 75 {
		t.Fatalf("band %d, want the pool's own 75", c.SpreadBand)
	}
	dc.Groups[0].NTP.SpreadBand = 20
	if _, own := dc.Groups[0].NTP.ownLB(); own {
		t.Fatal("a pool at the defaults follows Settings")
	}
}

func TestCanvasSetOwnLoadBalancingAndBack(t *testing.T) {
	dc := lbTestConfig()
	dc.NTP.MaxRootDistanceMS, dc.NTP.FailThreshold = 900, 4
	gid := dc.Groups[0].GroupID
	msg, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: gid, MaxStratum: 8})
	if err != nil || !strings.Contains(msg, "own health checks") {
		t.Fatalf("set: %q %v", msg, err)
	}
	lb := dc.Groups[0].NTP.LB
	if lb == nil || lb.MaxStratum != 8 || lb.MaxRootDistanceMS != 900 || lb.FailThreshold != 4 {
		t.Fatalf("the rest must start from what the gateway used (Settings): %+v", lb)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: gid, MaxStratum: 50}); err == nil {
		t.Fatal("a stratum of 50 must be refused")
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: gid, LB: "settings", MaxStratum: 10}); err == nil {
		t.Fatal("--lb settings with values must be refused")
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: gid, LB: "own"}); err == nil {
		t.Fatal("--lb only takes settings")
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: gid, LB: "settings"}); err != nil {
		t.Fatal(err)
	}
	if dc.Groups[0].NTP.LB != nil {
		t.Fatal("lb must be gone")
	}
	if _, own := dc.Groups[0].NTP.ownLB(); own {
		t.Fatal("after --lb settings the pool must not count as own again")
	}
	if _, c := dc.poolFor(&dc.Groups[0]); c.MaxRootDistanceMS != 900 || c.FailThreshold != 4 {
		t.Fatalf("back to Settings: root distance %d failures %d", c.MaxRootDistanceMS, c.FailThreshold)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Giving a gateway its own pool (adding a server or a fallback) must not freeze today's Settings values into it.
func TestNewOwnPoolStillFollowsSettings(t *testing.T) {
	dc := newDaemonConfig()
	dc.NTP.SpreadBand = 200
	dc.Groups[0].NTP = nil
	gid := dc.Groups[0].GroupID
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "add", Kind: "fallback", Group: gid, Server: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if _, own := dc.Groups[0].NTP.ownLB(); own {
		t.Fatalf("a pool made by adding a fallback server must follow Settings, has band %d", dc.Groups[0].NTP.SpreadBand)
	}
	dc.NTP.SpreadBand = 300
	if _, c := dc.poolFor(&dc.Groups[0]); c.SpreadBand != 300 {
		t.Fatalf("band %d, want 300 after Settings changed", c.SpreadBand)
	}
}

func TestLoadBalancingConfigRules(t *testing.T) {
	dc := lbTestConfig()
	dc.Groups[0].NTP.LB = &LBConfig{Spread: true, SpreadBand: 0, MaxStratum: 15, MaxRootDistanceMS: 1500, MaxOffsetMS: 128, FailThreshold: 2, MaxAttempts: 3, LatencyAlpha: 0.3}
	if err := dc.Validate(); err == nil || !strings.Contains(err.Error(), "spread_band") {
		t.Fatalf("a gateway's lb is validated: %v", err)
	}
	dc = lbTestConfig()
	dc.NTP.LB = &LBConfig{Spread: true, SpreadBand: 20, MaxStratum: 15, MaxRootDistanceMS: 1500, MaxOffsetMS: 128, FailThreshold: 2, MaxAttempts: 3, LatencyAlpha: 0.3}
	if err := dc.Validate(); err == nil {
		t.Fatal("the shared pool has no lb of its own")
	}
	// absent unless used, so an older version can still read the file
	b, _ := json.Marshal(defaultNTP())
	if strings.Contains(string(b), `"lb"`) {
		t.Fatalf("lb must be omitted when unused: %s", b)
	}
	// round trip, and a deep copy
	d := defaultNTP()
	d.LB = &LBConfig{Spread: true, SpreadBand: 33, MaxStratum: 15, MaxRootDistanceMS: 1500, MaxOffsetMS: 128, FailThreshold: 2, MaxAttempts: 3, LatencyAlpha: 0.3}
	b, _ = json.Marshal(d)
	var back NTPConfig
	if err := json.Unmarshal(b, &back); err != nil || back.LB == nil || back.LB.SpreadBand != 33 {
		t.Fatalf("round trip: %v %+v", err, back.LB)
	}
	c := cloneNTP(d)
	c.LB.SpreadBand = 1
	if d.LB.SpreadBand != 33 {
		t.Fatal("cloneNTP must copy lb")
	}
}

func TestCanvasShowsLoadBalancingInUse(t *testing.T) {
	dc := lbTestConfig()
	dc.NTP.SpreadBand = 200
	cg := buildCanvas(dc, nil, nil)[0]
	if cg.LB.SpreadBand != 200 || cg.LBOwn {
		t.Fatalf("following Settings: %+v own=%v", cg.LB, cg.LBOwn)
	}
	dc.Groups[0].NTP.LB = &LBConfig{Spread: true, SpreadBand: 40, MaxStratum: 15, MaxRootDistanceMS: 1500, MaxOffsetMS: 128, FailThreshold: 2, MaxAttempts: 3, LatencyAlpha: 0.3}
	cg = buildCanvas(dc, nil, nil)[0]
	if cg.LB.SpreadBand != 40 || !cg.LBOwn {
		t.Fatalf("own: %+v own=%v", cg.LB, cg.LBOwn)
	}
}

func TestCanvasSetStratumRootDistanceOffset(t *testing.T) {
	dc := lbTestConfig()
	gid := dc.Groups[0].GroupID
	off := 0
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: gid, MaxStratum: 4, MaxRootDist: 300, MaxOffset: &off}); err != nil {
		t.Fatal(err)
	}
	lb := dc.Groups[0].NTP.LB
	if lb == nil || lb.MaxStratum != 4 || lb.MaxRootDistanceMS != 300 || lb.MaxOffsetMS != 0 {
		t.Fatalf("own values: %+v", lb)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, c := dc.poolFor(&dc.Groups[0]); c.MaxStratum != 4 || c.MaxRootDistanceMS != 300 || c.MaxOffsetMS != 0 {
		t.Fatalf("pool: %+v", c)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "gateway", Group: gid, MaxStratum: 99}); err == nil {
		if dc.Validate() == nil {
			t.Fatal("stratum 99 accepted")
		}
	}
}

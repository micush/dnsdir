package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ospfDC(on bool) *DaemonConfig {
	dc := newDaemonConfig()
	dc.Groups[0].ExtraVIPs = []string{"203.0.113.53", "2001:db8::53"}
	if on {
		dc.OSPF = &OSPFConfig{RouterID: "192.0.2.10", Interfaces: []OSPFInterface{{Name: "eth0", Network: "point-to-point"}}}
	}
	return dc
}

func TestOSPFValidate(t *testing.T) {
	ok := OSPFConfig{RouterID: "192.0.2.10", Interfaces: []OSPFInterface{{Name: "eth0", Area: "1"}, {Name: "eth1"}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Interfaces[0].Area != "0.0.0.1" || ok.Interfaces[1].Area != "0.0.0.0" {
		t.Errorf("areas not normalised: %+v", ok.Interfaces)
	}
	bad := map[string]OSPFConfig{
		"router id needed":    {Interfaces: []OSPFInterface{{Name: "eth0"}}},
		"router id v6":        {RouterID: "2001:db8::1", Interfaces: []OSPFInterface{{Name: "eth0"}}},
		"name with space":     {RouterID: "192.0.2.1", Interfaces: []OSPFInterface{{Name: "eth0 x"}}},
		"name with newline":   {RouterID: "192.0.2.1", Interfaces: []OSPFInterface{{Name: "eth0\nrouter bgp 1"}}},
		"duplicate":           {RouterID: "192.0.2.1", Interfaces: []OSPFInterface{{Name: "eth0"}, {Name: "eth0"}}},
		"bad area":            {RouterID: "192.0.2.1", Interfaces: []OSPFInterface{{Name: "eth0", Area: "x"}}},
		"bad network":         {RouterID: "192.0.2.1", Interfaces: []OSPFInterface{{Name: "eth0", Network: "nbma"}}},
		"key too long":        {RouterID: "192.0.2.1", Interfaces: []OSPFInterface{{Name: "eth0", Password: strings.Repeat("a", 17)}}},
		"key with space":      {RouterID: "192.0.2.1", Interfaces: []OSPFInterface{{Name: "eth0", Password: "a b"}}},
		"hello not < dead":    {RouterID: "192.0.2.1", Hello: 50, Interfaces: []OSPFInterface{{Name: "eth0"}}},
		"dead not > hello":    {RouterID: "192.0.2.1", Dead: 5, Hello: 5, Interfaces: []OSPFInterface{{Name: "eth0"}}},
		"metric out of range": {RouterID: "192.0.2.1", Metric: 1 << 30, Interfaces: []OSPFInterface{{Name: "eth0"}}},
	}
	for name, c := range bad {
		c := c
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// without an interface there is nothing to run: router id and disabled flag are dropped
	e := OSPFConfig{RouterID: "192.0.2.1", Disabled: true}
	if err := e.Validate(); err != nil || e.RouterID != "" || e.Disabled || e.Configured() || e.Active() {
		t.Errorf("empty settings: %+v %v", e, err)
	}
}

func TestRenderFRROSPF(t *testing.T) {
	v4, v6 := []string{"203.0.113.53"}, []string{"2001:db8::53"}
	o := &OSPFConfig{RouterID: "192.0.2.10", Metric: 50, Interfaces: []OSPFInterface{
		{Name: "eth0", Area: "0.0.0.0", Network: "point-to-point", Password: "s3cret"},
		{Name: "eth1", Area: "0.0.0.1", Disabled: true}}}
	c := renderFRRAll(nil, o, v4, v6, "x")
	for _, want := range []string{
		"ip prefix-list DNSDIR-ANYCAST-V4 seq 10 permit 203.0.113.53/32\n",
		"ipv6 prefix-list DNSDIR-ANYCAST-V6 seq 10 permit 2001:db8::53/128\n",
		"route-map DNSDIR-OSPF-V4 permit 10\n match ip address prefix-list DNSDIR-ANYCAST-V4\n",
		"route-map DNSDIR-OSPF-IN deny 10\n",
		"interface eth0\n ip ospf area 0.0.0.0\n ipv6 ospf6 area 0.0.0.0\n ip ospf network point-to-point\n ipv6 ospf6 network point-to-point\n",
		" ip ospf authentication message-digest\n ip ospf message-digest-key 1 md5 s3cret\n",
		" ip ospf bfd\n ipv6 ospf6 bfd\n",
		"interface eth1\n ip ospf area 0.0.0.1\n ipv6 ospf6 area 0.0.0.1\n ip ospf bfd\n ipv6 ospf6 bfd\n ip ospf passive\n ipv6 ospf6 passive\n",
		"router ospf\n ospf router-id 192.0.2.10\n redistribute connected metric 50 metric-type 1 route-map DNSDIR-OSPF-V4\n",
		"router ospf6\n ospf6 router-id 192.0.2.10\n redistribute connected metric 50 metric-type 1 route-map DNSDIR-OSPF-V6\n",
		"ip protocol ospf route-map DNSDIR-OSPF-IN\nipv6 protocol ospf6 route-map DNSDIR-OSPF-IN\n",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q in:\n%s", want, c)
		}
	}
	if strings.Contains(c, "router bgp") || strings.Contains(c, "hello-interval") {
		t.Errorf("unexpected BGP or timers in:\n%s", c)
	}
	if !strings.HasSuffix(c, "line vty\n!\n") {
		t.Errorf("does not end with the vty line:\n%s", c)
	}
	// timers appear once set
	o.Hello, o.Dead = 2, 6
	if c := renderFRRAll(nil, o, v4, v6, "x"); !strings.Contains(c, " ip ospf hello-interval 2\n ip ospf dead-interval 6\n ipv6 ospf6 hello-interval 2\n ipv6 ospf6 dead-interval 6\n") {
		t.Errorf("timers missing:\n%s", c)
	}
	// both protocols in one file
	b := &BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500}}}
	both := renderFRRAll(b, o, v4, v6, "x")
	if !strings.Contains(both, "router bgp 64512") || !strings.Contains(both, "router ospf6") || strings.Count(both, "ip prefix-list DNSDIR-ANYCAST-V4 seq 1000") != 1 || strings.Count(both, "line vty") != 1 {
		t.Errorf("combined file wrong:\n%s", both)
	}
	// BGP alone is unchanged by the OSPF code
	if renderFRRAll(b, nil, v4, v6, "x") != renderFRR(b, v4, v6, "x") || strings.Contains(renderFRR(b, v4, v6, "x"), "ospf") {
		t.Error("BGP-only output changed")
	}
	// inactive OSPF renders nothing
	if c := renderFRRAll(nil, &OSPFConfig{RouterID: "192.0.2.10", Disabled: true, Interfaces: o.Interfaces}, v4, v6, "x"); strings.Contains(c, "ospf") || strings.Contains(c, "203.0.113.53") {
		t.Errorf("disabled OSPF rendered:\n%s", c)
	}
}

// ospfd and ospf6d run only while OSPF is set up, and are switched off again when it is cleared or disabled; BGP
// and OSPF do not switch each other's daemons.
func TestOSPFDaemonsOnlyWhileConfigured(t *testing.T) {
	calls, dir := fakeFRR(t, nil)
	m := NewBGPManager(t.TempDir())
	read := func() string { b, _ := os.ReadFile(filepath.Join(dir, "daemons")); return string(b) }
	daemon := func(name string) string {
		for _, l := range strings.Split(read(), "\n") {
			if strings.HasPrefix(l, name+"=") {
				return l
			}
		}
		return name + " missing"
	}

	// never configured: nothing touched
	if r := m.applyNow(ospfDC(false)); !r.OK || len(*calls) != 0 || strings.Contains(read(), "ospf") {
		t.Fatalf("unconfigured OSPF did something: %+v %v\n%s", r, *calls, read())
	}
	// configured: both OSPF daemons and bfdd on, bgpd stays off
	if r := m.applyNow(ospfDC(true)); !r.OK {
		t.Fatalf("%+v", r)
	}
	for _, d := range []string{"ospfd=yes", "ospf6d=yes", "bfdd=yes", "bgpd=no"} {
		if !strings.Contains(read(), d+"\n") {
			t.Errorf("%s missing:\n%s", d, read())
		}
	}
	conf, _ := os.ReadFile(filepath.Join(dir, "frr.conf"))
	if !strings.Contains(string(conf), "router ospf6") {
		t.Fatalf("OSPF not in frr.conf:\n%s", conf)
	}
	if _, err := os.Stat(m.markerPath()); err != nil {
		t.Fatal("no marker after enabling OSPF")
	}
	// BGP joins: bgpd on too, the OSPF daemons stay on
	both := ospfDC(true)
	both.BGP = &BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500}}}
	if r := m.applyNow(both); !r.OK {
		t.Fatal(r)
	}
	if daemon("bgpd") != "bgpd=yes" || daemon("ospfd") != "ospfd=yes" || daemon("ospf6d") != "ospf6d=yes" || daemon("bfdd") != "bfdd=yes" {
		t.Errorf("both on:\n%s", read())
	}
	// OSPF disabled: the OSPF daemons go off, bgpd and bfdd stay (BGP still uses them)
	both.OSPF.Disabled = true
	if r := m.applyNow(both); !r.OK {
		t.Fatal(r)
	}
	if daemon("ospfd") != "ospfd=no" || daemon("ospf6d") != "ospf6d=no" || daemon("bgpd") != "bgpd=yes" || daemon("bfdd") != "bfdd=yes" {
		t.Errorf("OSPF disabled:\n%s", read())
	}
	if c, _ := os.ReadFile(filepath.Join(dir, "frr.conf")); strings.Contains(string(c), "ospf") || !strings.Contains(string(c), "router bgp") {
		t.Errorf("frr.conf after disabling OSPF:\n%s", c)
	}
	// BGP cleared and OSPF back: only OSPF runs
	only := ospfDC(true)
	if r := m.applyNow(only); !r.OK {
		t.Fatal(r)
	}
	if daemon("bgpd") != "bgpd=no" || daemon("ospfd") != "ospfd=yes" || daemon("ospf6d") != "ospf6d=yes" {
		t.Errorf("OSPF only:\n%s", read())
	}
	// everything cleared: all of it off, marker gone, frr.conf is the header only
	if r := m.applyNow(ospfDC(false)); !r.OK || !strings.Contains(r.Detail, "off") {
		t.Fatalf("%+v", r)
	}
	for _, d := range []string{"bgpd=no", "ospfd=no", "ospf6d=no", "bfdd=no"} {
		if !strings.Contains(read(), d+"\n") {
			t.Errorf("%s missing after clearing:\n%s", d, read())
		}
	}
	if _, err := os.Stat(m.markerPath()); err == nil {
		t.Error("marker kept after clearing")
	}
	if c, _ := os.ReadFile(filepath.Join(dir, "frr.conf")); strings.Contains(string(c), "ospf") || strings.Contains(string(c), "router") {
		t.Errorf("routing config left behind:\n%s", c)
	}
}

func TestParseOSPFNeighbors(t *testing.T) {
	v2new := `{"neighbors":{"192.0.2.1":[{"priority":1,"state":"Full/DR","converged":"Full","address":"10.0.0.2","ifaceName":"eth0:10.0.0.1","upTime":"1m"}]}}`
	v2old := `{"192.0.2.1":[{"priority":1,"state":"Full/Backup","address":"10.0.0.2","ifaceName":"eth0:10.0.0.1"}],"192.0.2.2":[{"state":"2-Way/DROther","address":"10.0.0.3","ifaceName":"eth1:10.0.1.1"}]}`
	p, err := parseOSPFNeighbors([]byte(v2new))
	if err != nil || len(p) != 1 || p[0].State != "Full" || p[0].Interface != "eth0" || p[0].AF != "ipv4" || p[0].Address != "10.0.0.2" || p[0].Uptime != "1m" {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = parseOSPFNeighbors([]byte(v2old))
	if err != nil || len(p) != 2 || p[0].State != "Full" || p[1].State != "2-Way" || p[1].Interface != "eth1" {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = parseOSPF6Neighbors([]byte(`{"neighbors":[{"neighborId":"192.0.2.1","priority":1,"state":"Full","interfaceName":"eth0","duration":"00:01:02"}]}`))
	if err != nil || len(p) != 1 || p[0].AF != "ipv6" || p[0].State != "Full" || p[0].Interface != "eth0" || p[0].Neighbor != "192.0.2.1" || p[0].Uptime != "00:01:02" {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err = parseOSPF6Neighbors([]byte(`{}`)); err != nil || len(p) != 0 {
		t.Fatalf("empty: %+v %v", p, err)
	}
	if _, err := parseOSPFNeighbors([]byte(`not json`)); err == nil {
		t.Error("garbage accepted")
	}
}

func TestAnycastOSPFStatus(t *testing.T) {
	ifs := []OSPFInterface{{Name: "eth0"}, {Name: "eth1"}}
	full := func(af, ifc string) OSPFPeer { return OSPFPeer{AF: af, Interface: ifc, State: "Full"} }
	cases := []struct {
		name   string
		addr   string
		ifs    []OSPFInterface
		peers  []OSPFPeer
		known  bool
		status string
		kind   string
	}{
		{"all full", "203.0.113.1", ifs, []OSPFPeer{full("ipv4", "eth0"), full("ipv4", "eth1")}, true, "ok", ""},
		{"one full", "203.0.113.1", ifs, []OSPFPeer{full("ipv4", "eth0")}, true, "warn", "partial"},
		{"none full", "203.0.113.1", ifs, []OSPFPeer{{AF: "ipv4", Interface: "eth0", State: "ExStart"}}, true, "bad", "down"},
		{"v6 needs ospfv3", "2001:db8::1", ifs, []OSPFPeer{full("ipv4", "eth0"), full("ipv4", "eth1")}, true, "bad", "down"},
		{"v6 full", "2001:db8::1", ifs[:1], []OSPFPeer{full("ipv6", "eth0")}, true, "ok", ""},
		{"disabled interface ignored", "203.0.113.1", []OSPFInterface{{Name: "eth0"}, {Name: "eth1", Disabled: true}}, []OSPFPeer{full("ipv4", "eth0")}, true, "ok", ""},
		{"all disabled", "203.0.113.1", []OSPFInterface{{Name: "eth0", Disabled: true}}, nil, true, "bad", "none"},
		{"frr silent", "203.0.113.1", ifs, nil, false, "bad", "down"},
	}
	for _, c := range cases {
		s, _, k := anycastOSPFStatus(c.addr, c.ifs, c.peers, c.known)
		if s != c.status || k != c.kind {
			t.Errorf("%s: got %s/%s, want %s/%s", c.name, s, k, c.status, c.kind)
		}
	}
}

func TestAnycastRouteGateCombines(t *testing.T) {
	oldB, oldO := anycastGateFn, anycastOSPFGateFn
	defer func() { anycastGateFn, anycastOSPFGateFn = oldB, oldO }()
	bgpOK, bgpNo := func(*BGPConfig, string) string { return "" }, func(*BGPConfig, string) string { return "BGP: down" }
	ospfOK, ospfNo := func(*OSPFConfig, string) string { return "" }, func(*OSPFConfig, string) string { return "OSPF: down" }
	bgp := &BGPConfig{ASN: 64512}
	osp := &OSPFConfig{RouterID: "192.0.2.1", Interfaces: []OSPFInterface{{Name: "eth0"}}}
	dis := &OSPFConfig{RouterID: "192.0.2.1", Disabled: true, Interfaces: []OSPFInterface{{Name: "eth0"}}}
	for _, c := range []struct {
		name string
		b    func(*BGPConfig, string) string
		o    func(*OSPFConfig, string) string
		cfg  *OSPFConfig
		want string
	}{
		{"bgp carries", bgpOK, ospfNo, osp, ""},
		{"ospf carries", bgpNo, ospfOK, osp, ""},
		{"neither", bgpNo, ospfNo, osp, "BGP: down; OSPF: down"},
		{"ospf off: bgp reason only", bgpNo, ospfOK, nil, "BGP: down"},
		{"ospf disabled: bgp reason only", bgpNo, ospfOK, dis, "BGP: down"},
	} {
		anycastGateFn, anycastOSPFGateFn = c.b, c.o
		if got := anycastRouteGate(bgp, c.cfg, "192.0.2.9"); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// BGP not in use: only OSPF's reason, and OSPF alone can open the gate
	anycastGateFn, anycastOSPFGateFn = bgpNo, ospfNo
	if got := anycastRouteGate(nil, osp, "192.0.2.9"); got != "OSPF: down" {
		t.Errorf("ospf only, down: %q", got)
	}
	anycastOSPFGateFn = ospfOK
	if got := anycastRouteGate(nil, osp, "192.0.2.9"); got != "" {
		t.Errorf("ospf only, up: %q", got)
	}
	// the real gates' words
	if anycastOSPFGate(nil, "192.0.2.1") == "" || anycastOSPFGate(&OSPFConfig{Interfaces: []OSPFInterface{{Name: "eth0"}}, Disabled: true}, "192.0.2.1") == "" {
		t.Error("unconfigured or disabled OSPF must close its gate")
	}
}

func TestAnycastRouteStatusPicksBest(t *testing.T) {
	cfg := ospfDC(true)
	cfg.BGP = &BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500}}}
	up := []OSPFPeer{{AF: "ipv4", Interface: "eth0", State: "Full"}}
	down := []BGPPeer{{Peer: "192.0.2.1", State: "Active"}}
	if s, _, _ := anycastRouteStatus(cfg, "203.0.113.53", down, true, up, true); s != "ok" {
		t.Errorf("OSPF up should rescue a BGP-down address: %s", s)
	}
	if s, _, _ := anycastRouteStatus(cfg, "203.0.113.53", down, true, nil, true); s != "bad" {
		t.Errorf("both down: %s", s)
	}
	cfg.BGP = nil
	if s, _, _ := anycastRouteStatus(cfg, "203.0.113.53", nil, false, up, true); s != "ok" {
		t.Errorf("OSPF only: %s", s)
	}
}

func TestOSPFSetOperateAndKeyOmitted(t *testing.T) {
	e := bgpEnv(t)
	if err := e.mg.OSPFSet(OSPFConfig{RouterID: "192.0.2.10"}, "t"); err == nil {
		t.Error("router id without interface accepted")
	}
	if err := e.mg.OSPFSet(OSPFConfig{RouterID: "192.0.2.10", Interfaces: []OSPFInterface{{Name: "eth0"}, {Name: "eth1"}}}, "t"); err != nil {
		t.Fatal(err)
	}
	dc, _, _ := e.mg.LiveConfig()
	if !dc.OSPF.Active() || len(dc.OSPF.Interfaces) != 2 {
		t.Fatalf("%+v", dc.OSPF)
	}
	if err := e.mg.OSPFOperate(OSPFOperateArgs{Interface: "eth1", Enabled: false}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.mg.OSPFOperate(OSPFOperateArgs{Interface: "nope", Enabled: false}, "t"); err == nil {
		t.Error("unknown interface accepted")
	}
	// saving the settings again keeps the disabled flag
	if err := e.mg.OSPFSet(OSPFConfig{RouterID: "192.0.2.11", Interfaces: []OSPFInterface{{Name: "eth0"}, {Name: "eth1"}}}, "t"); err != nil {
		t.Fatal(err)
	}
	dc, _, _ = e.mg.LiveConfig()
	if !dc.OSPF.Interfaces[1].Disabled || dc.OSPF.Interfaces[0].Disabled || dc.OSPF.RouterID != "192.0.2.11" {
		t.Fatalf("flags not carried: %+v", dc.OSPF)
	}
	if err := e.mg.OSPFOperate(OSPFOperateArgs{Enabled: false}, "t"); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.mg.OSPFStatus(); !st.Config.Disabled || st.Config.Active() {
		t.Errorf("not disabled: %+v", st.Config)
	}
	// clearing the interfaces removes the block (and the disabled flag with it)
	if err := e.mg.OSPFSet(OSPFConfig{}, "t"); err != nil {
		t.Fatal(err)
	}
	dc, _, _ = e.mg.LiveConfig()
	if dc.OSPF != nil {
		t.Errorf("block kept: %+v", dc.OSPF)
	}
	if err := e.mg.OSPFOperate(OSPFOperateArgs{Enabled: true}, "t"); err == nil {
		t.Error("operate without interfaces accepted")
	}
	raw, _ := os.ReadFile(e.mg.confPath)
	if strings.Contains(string(raw), `"ospf"`) {
		t.Error("ospf key written while unused")
	}
}

// The output of `vtysh -c "show ip ospf neighbor json"` from a real FRR 8.4.4 with one point-to-point neighbor.
const realOSPFNeighborJSON = `{
  "neighbors":{
    "10.77.0.2":[
      {
        "priority":1,
        "state":"Full\/-",
        "nbrPriority":1,
        "nbrState":"Full\/-",
        "converged":"Full",
        "role":"DROther",
        "upTimeInMsec":38856,
        "deadTimeMsecs":31362,
        "routerDeadIntervalTimerDueMsec":31362,
        "upTime":"38.856s",
        "deadTime":"31.362s",
        "address":"10.77.0.2",
        "ifaceAddress":"10.77.0.2",
        "ifaceName":"vA:10.77.0.1",
        "retransmitCounter":0,
        "linkStateRetransmissionListCounter":0,
        "requestCounter":0,
        "linkStateRequestListCounter":0,
        "dbSummaryCounter":0,
        "databaseSummaryListCounter":0
      }
    ]
  }
}`

func TestParseRealFRROSPFNeighbor(t *testing.T) {
	p, err := parseOSPFNeighbors([]byte(realOSPFNeighborJSON))
	if err != nil || len(p) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
	if p[0].Neighbor != "10.77.0.2" || p[0].State != "Full" || p[0].Interface != "vA" || p[0].Address != "10.77.0.2" || p[0].AF != "ipv4" {
		t.Errorf("%+v", p[0])
	}
	if s, _, _ := anycastOSPFStatus("203.0.113.53", []OSPFInterface{{Name: "vA"}}, p, true); s != "ok" {
		t.Errorf("a Full neighbor on the interface must be green, got %s", s)
	}
	if n, err := parseOSPF6Neighbors([]byte("{\n  \"neighbors\":[]\n}\n")); err != nil || len(n) != 0 {
		t.Errorf("empty OSPFv3 list: %+v %v", n, err)
	}
}

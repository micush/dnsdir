package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OSPF: the second way (after BGP, bgp.go) to carry the anycast addresses off the node.  dnsdir drives FRR's ospfd
// (OSPFv2, for the IPv4 addresses) and ospf6d (OSPFv3, for the IPv6 addresses) the same way it drives bgpd: the whole
// frr.conf is rendered by one pure function, and the two daemons are switched on in /etc/frr/daemons only while OSPF
// is set up on this node (and off again when it is cleared or disabled), so they do not run when nobody uses them.
//
// The settings are per node and never replicated.  The posture matches BGP's: the node announces its anycast
// addresses and nothing else (connected routes are redistributed through a route-map that permits only those
// addresses), and learns nothing: a route-map on zebra's OSPF routes denies every route, so a neighbor cannot change
// this host's routing table.  An address exists in FRR only while it is held on lo, so withdrawal follows anycast.go.

// OSPFInterface is one interface the node speaks OSPF on (both OSPFv2 and OSPFv3 run on it).
type OSPFInterface struct {
	Name string `json:"name"`           // e.g. eth0
	Area string `json:"area,omitempty"` // dotted quad or number; empty = 0.0.0.0
	// Network is the link type: "" = FRR's default for the interface, "point-to-point" (no designated router, the usual
	// choice for a routed link) or "broadcast".
	Network  string `json:"network,omitempty"`
	Password string `json:"password,omitempty"` // OSPFv2 MD5 key (up to 16 characters); OSPFv3 does not use it
	// Disabled keeps the interface in the settings but makes it passive (no hellos, no neighbors) until enabled again
	// (Operate ▸ Anycast).
	Disabled bool `json:"disabled,omitempty"`
}

// OSPFConfig is the node's OSPF settings.
type OSPFConfig struct {
	RouterID   string          `json:"router_id,omitempty"` // IPv4 dotted quad; required once there is an interface
	Hello      int             `json:"hello,omitempty"`     // seconds; 0 = FRR's 10
	Dead       int             `json:"dead,omitempty"`      // seconds; 0 = FRR's 40
	Metric     int             `json:"metric,omitempty"`    // cost of the announced addresses; 0 = FRR's 20; a higher one makes this node the less preferred
	Interfaces []OSPFInterface `json:"interfaces"`
	// Disabled stops OSPF on this node without forgetting the settings (Operate ▸ Anycast): ospfd and ospf6d go
	// off and the OSPF sections leave frr.conf, as if the interfaces were cleared.
	Disabled bool `json:"disabled,omitempty"`
}

const ospfHello, ospfDead = 10, 40

// timers returns the hello and dead interval in seconds, FRR's defaults when unset.
func (o *OSPFConfig) timers() (int, int) {
	h, d := o.Hello, o.Dead
	if h == 0 {
		h = ospfHello
	}
	if d == 0 {
		d = ospfDead
	}
	return h, d
}

// Configured reports whether there is an interface to run OSPF on (the prerequisite for everything else).
func (o *OSPFConfig) Configured() bool { return o != nil && len(o.Interfaces) > 0 }

// Active reports whether OSPF runs on this node: an interface is set and OSPF is not disabled.
func (o *OSPFConfig) Active() bool { return o.Configured() && !o.Disabled && frrBlocked() == "" }

func (o *OSPFConfig) clone() *OSPFConfig {
	if o == nil {
		return nil
	}
	c := *o
	c.Interfaces = append([]OSPFInterface{}, o.Interfaces...)
	return &c
}

var ospfIfaceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,14}$`)

// ospfArea normalises an area given as a dotted quad or a number to a dotted quad.
func ospfArea(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "0.0.0.0", nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return a.String(), nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return "", fmt.Errorf("area %q must be a number (0 is the backbone) or a dotted address such as 0.0.0.1", s)
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(n>>24), byte(n>>16), byte(n>>8), byte(n)), nil
}

// Validate normalises the settings in place.  Everything that ends up in frr.conf is checked here.
func (o *OSPFConfig) Validate() error {
	if o.Interfaces == nil {
		o.Interfaces = []OSPFInterface{}
	}
	if len(o.Interfaces) == 0 {
		// Without an interface there is nothing to run, so nothing to disable and no router ID to keep.
		o.RouterID, o.Disabled = "", false
	}
	if o.RouterID != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(o.RouterID))
		if err != nil || !a.Is4() || a.IsUnspecified() {
			return fmt.Errorf("ospf: router id %q must be an IPv4 address, e.g. 192.0.2.1", o.RouterID)
		}
		o.RouterID = a.String()
	} else if len(o.Interfaces) > 0 {
		return fmt.Errorf("ospf: a router id is needed (an IPv4 address that is unique among your routers, e.g. this node's loopback or LAN address)")
	}
	if o.Hello < 0 || o.Hello > 65535 {
		return fmt.Errorf("ospf: hello interval %d must be 1-65535 seconds (empty = %d)", o.Hello, ospfHello)
	}
	if o.Dead < 0 || o.Dead > 65535 {
		return fmt.Errorf("ospf: dead interval %d must be 1-65535 seconds (empty = %d)", o.Dead, ospfDead)
	}
	if h, d := o.timers(); h >= d {
		return fmt.Errorf("ospf: the hello interval (%d s) must be shorter than the dead interval (%d s)", h, d)
	}
	if o.Metric < 0 || o.Metric > 16777214 {
		return fmt.Errorf("ospf: metric %d must be 1-16777214 (empty = 20)", o.Metric)
	}
	seen := map[string]bool{}
	for i := range o.Interfaces {
		f := &o.Interfaces[i]
		f.Name = strings.TrimSpace(f.Name)
		if !ospfIfaceRe.MatchString(f.Name) {
			return fmt.Errorf("ospf: interface %q must be the name of a network interface on this node, e.g. eth0", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("ospf: interface %s is listed twice", f.Name)
		}
		seen[f.Name] = true
		area, err := ospfArea(f.Area)
		if err != nil {
			return fmt.Errorf("ospf: interface %s: %v", f.Name, err)
		}
		f.Area = area
		switch f.Network {
		case "", "point-to-point", "broadcast":
		default:
			return fmt.Errorf("ospf: interface %s: the link type must be empty, point-to-point or broadcast", f.Name)
		}
		if len(f.Password) > 16 {
			return fmt.Errorf("ospf: interface %s: the OSPF key can be at most 16 characters", f.Name)
		}
		for _, r := range f.Password {
			if r < 0x21 || r > 0x7e {
				return fmt.Errorf("ospf: interface %s: the key may use printable characters without spaces only", f.Name)
			}
		}
	}
	return nil
}

// ── frr.conf ─────────────────────────────────────────────────────────────────

// renderOSPFRouteMaps is the route-maps OSPF needs: what may be redistributed (the anycast addresses only) and what
// zebra may take from OSPF (nothing).
func renderOSPFRouteMaps() string {
	return "route-map DNSDIR-OSPF-V4 permit 10\n match ip address prefix-list DNSDIR-ANYCAST-V4\n" +
		"route-map DNSDIR-OSPF-V6 permit 10\n match ipv6 address prefix-list DNSDIR-ANYCAST-V6\n" +
		"route-map DNSDIR-OSPF-IN deny 10\n!\n"
}

// renderOSPF is the interface, router ospf, router ospf6 and zebra sections of frr.conf.
func renderOSPF(o *OSPFConfig) string {
	var s strings.Builder
	hello, dead := o.timers()
	for _, f := range o.Interfaces {
		s.WriteString("interface " + f.Name + "\n")
		area := f.Area
		if area == "" {
			area = "0.0.0.0"
		}
		s.WriteString(" ip ospf area " + area + "\n ipv6 ospf6 area " + area + "\n")
		if f.Network != "" {
			s.WriteString(" ip ospf network " + f.Network + "\n ipv6 ospf6 network " + f.Network + "\n")
		}
		if o.Hello != 0 || o.Dead != 0 {
			s.WriteString(fmt.Sprintf(" ip ospf hello-interval %d\n ip ospf dead-interval %d\n", hello, dead))
			s.WriteString(fmt.Sprintf(" ipv6 ospf6 hello-interval %d\n ipv6 ospf6 dead-interval %d\n", hello, dead))
		}
		if f.Password != "" {
			s.WriteString(" ip ospf authentication message-digest\n ip ospf message-digest-key 1 md5 " + f.Password + "\n")
		}
		s.WriteString(" ip ospf bfd\n ipv6 ospf6 bfd\n") // fast failure detection, always
		if f.Disabled {
			s.WriteString(" ip ospf passive\n ipv6 ospf6 passive\n") // administratively down: kept, no neighbors
		}
		s.WriteString("!\n")
	}
	redist := "redistribute connected"
	if o.Metric > 0 {
		redist += fmt.Sprintf(" metric %d", o.Metric)
	}
	redist += " metric-type 1 route-map "
	s.WriteString("router ospf\n ospf router-id " + o.RouterID + "\n " + redist + "DNSDIR-OSPF-V4\n!\n")
	s.WriteString("router ospf6\n ospf6 router-id " + o.RouterID + "\n " + redist + "DNSDIR-OSPF-V6\n!\n")
	s.WriteString("ip protocol ospf route-map DNSDIR-OSPF-IN\nipv6 protocol ospf6 route-map DNSDIR-OSPF-IN\n!\n")
	return s.String()
}

// ── status ───────────────────────────────────────────────────────────────────

// OSPFPeer is one neighbor as FRR reports it.
type OSPFPeer struct {
	Neighbor  string `json:"neighbor"`  // the neighbor's router id
	AF        string `json:"af"`        // ipv4 (OSPFv2) | ipv6 (OSPFv3)
	Interface string `json:"interface"` // eth0
	Address   string `json:"address,omitempty"`
	State     string `json:"state"` // Full, 2-Way, ExStart, Init, Down …
	Uptime    string `json:"uptime,omitempty"`
	BFD       string `json:"bfd,omitempty"` // up | down | init | shutdown; empty = FRR has no BFD session for it
}

// OSPFStatus is the OSPF page / --ospf view.
type OSPFStatus struct {
	Config     OSPFConfig     `json:"config"`
	Applied    BGPApplied     `json:"applied"`
	Installed  bool           `json:"installed"`
	Running    bool           `json:"running"` // ospfd answered
	Peers      []OSPFPeer     `json:"peers"`
	Announce   []string       `json:"announce"`  // anycast addresses this node is set up to announce
	Addresses  []AnycastState `json:"addresses"` // the same, and whether each is announced right now
	Interfaces []string       `json:"host_interfaces"`
	Blocked    string         `json:"blocked,omitempty"`
	Notes      []string       `json:"notes"`
}

// vtyshOSPF and vtyshOSPF6 ask FRR for the neighbors (replaceable in tests).
var (
	vtyshOSPF  = func() ([]byte, error) { return frrRun("vtysh", "-c", "show ip ospf neighbor json") }
	vtyshOSPF6 = func() ([]byte, error) { return frrRun("vtysh", "-c", "show ipv6 ospf6 neighbor json") }
)

// ospfState reduces "Full/DR" to "Full".
func ospfState(s string) string {
	if i := strings.IndexByte(s, '/'); i > 0 {
		return s[:i]
	}
	return s
}

// parseOSPFNeighbors reads `show ip ospf neighbor json` (OSPFv2): a map from router id to a list of adjacencies,
// either at the top or under "neighbors" depending on the FRR release.
func parseOSPFNeighbors(raw []byte) ([]OSPFPeer, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	body := top
	if n, ok := top["neighbors"]; ok {
		body = nil
		if err := json.Unmarshal(n, &body); err != nil {
			return nil, err
		}
	}
	type nb struct {
		State     string `json:"state"`
		Converged string `json:"converged"`
		Address   string `json:"address"`
		IfaceName string `json:"ifaceName"`
		UpTime    string `json:"upTime"`
	}
	var out []OSPFPeer
	for rid, blob := range body {
		var list []nb
		if err := json.Unmarshal(blob, &list); err != nil {
			var one nb
			if err := json.Unmarshal(blob, &one); err != nil {
				continue // not a neighbor entry
			}
			list = []nb{one}
		}
		for _, n := range list {
			st := n.Converged
			if st == "" {
				st = ospfState(n.State)
			}
			ifc := n.IfaceName
			if i := strings.IndexByte(ifc, ':'); i > 0 { // "eth0:10.0.0.1"
				ifc = ifc[:i]
			}
			out = append(out, OSPFPeer{Neighbor: rid, AF: "ipv4", Interface: ifc, Address: n.Address, State: st, Uptime: n.UpTime})
		}
	}
	sortOSPFPeers(out)
	return out, nil
}

// parseOSPF6Neighbors reads `show ipv6 ospf6 neighbor json` (OSPFv3): a list under "neighbors".
func parseOSPF6Neighbors(raw []byte) ([]OSPFPeer, error) {
	var top struct {
		Neighbors json.RawMessage `json:"neighbors"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	type nb struct {
		ID        string `json:"neighborId"`
		State     string `json:"state"`
		Iface     string `json:"interfaceName"`
		Address   string `json:"address"`
		Duration  string `json:"duration"`
		UpTime    string `json:"upTime"`
		Converged string `json:"converged"`
	}
	var list []nb
	if len(top.Neighbors) > 0 {
		if err := json.Unmarshal(top.Neighbors, &list); err != nil {
			var m map[string]nb
			if err := json.Unmarshal(top.Neighbors, &m); err != nil {
				return nil, err
			}
			for id, n := range m {
				if n.ID == "" {
					n.ID = id
				}
				list = append(list, n)
			}
		}
	}
	var out []OSPFPeer
	for _, n := range list {
		st := n.Converged
		if st == "" {
			st = ospfState(n.State)
		}
		up := n.UpTime
		if up == "" {
			up = n.Duration
		}
		out = append(out, OSPFPeer{Neighbor: n.ID, AF: "ipv6", Interface: n.Iface, Address: n.Address, State: st, Uptime: up})
	}
	sortOSPFPeers(out)
	return out, nil
}

func sortOSPFPeers(p []OSPFPeer) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].AF != p[j].AF {
			return p[i].AF < p[j].AF
		}
		if p[i].Interface != p[j].Interface {
			return p[i].Interface < p[j].Interface
		}
		return p[i].Neighbor < p[j].Neighbor
	})
}

// ospfNeighbors asks FRR for the OSPFv2 and OSPFv3 neighbors.  ok is false when neither daemon answered.
func ospfNeighbors() (peers []OSPFPeer, ok bool) {
	if raw, err := vtyshOSPF(); err == nil {
		if p, err := parseOSPFNeighbors(raw); err == nil {
			peers, ok = append(peers, p...), true
		}
	}
	if raw, err := vtyshOSPF6(); err == nil {
		if p, err := parseOSPF6Neighbors(raw); err == nil {
			peers, ok = append(peers, p...), true
		}
	}
	return peers, ok
}

func hostInterfaceNames() []string {
	out := []string{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || !ospfIfaceRe.MatchString(i.Name) {
			continue
		}
		out = append(out, i.Name)
	}
	sort.Strings(out)
	return out
}

// Status gathers the node's OSPF configuration, what was applied and live neighbor state.
func (m *Mgmt) OSPFStatus() (*OSPFStatus, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	st := &OSPFStatus{Config: OSPFConfig{Interfaces: []OSPFInterface{}}, Peers: []OSPFPeer{}, Announce: []string{}, Addresses: []AnycastState{}, Interfaces: hostInterfaceNames(), Notes: []string{}}
	if dc.OSPF != nil {
		st.Config = *dc.OSPF.clone()
	}
	st.Blocked = frrBlocked()
	st.Applied = m.bgp.Last()
	if _, err := os.Stat(frrDir); err == nil {
		st.Installed = true
	}
	v4, v6 := anycastAddresses(dc)
	st.Announce = append(append(st.Announce, v4...), v6...)
	if m.anycastFn != nil {
		st.Addresses = append(st.Addresses, m.anycastFn()...)
	}
	if st.Config.Active() && st.Installed {
		if peers, ok := ospfNeighbors(); ok {
			st.Running = true
			st.Peers = peers
			if raw, err := vtyshBFD(); err == nil {
				if bfd, err := parseBFDPeers(raw); err == nil {
					for i := range st.Peers {
						st.Peers[i].BFD = bfd[st.Peers[i].Address]
					}
				}
			}
		}
	}
	if st.Config.Active() {
		if st.Installed && !frrCanReload() {
			st.Notes = append(st.Notes, "FRR cannot reload its config here (frr-reload.py was not found; Debian and Ubuntu have it in the frr-pythontools package), so every OSPF change restarts FRR and drops the sessions briefly.")
		}
		if len(st.Announce) == 0 {
			st.Notes = append(st.Notes, "Nothing is announced yet: add an anycast address to a gateway on the Topology page.")
		}
	}
	return st, nil
}

// OSPFSet replaces this node's OSPF settings.  The disabled flags (Operate ▸ Anycast) are not part of the settings and
// are carried over from the running config, so editing the settings never switches anything on or off.
func (m *Mgmt) OSPFSet(c OSPFConfig, actor string) error {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if len(c.Interfaces) == 0 && strings.TrimSpace(c.RouterID) != "" {
		return fmt.Errorf("ospf: a router id needs an interface; add one first")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if why := frrBlocked(); why != "" && len(c.Interfaces) > 0 {
		return fmt.Errorf("ospf: %s", why) // clearing the settings is still allowed
	}
	was := map[string]bool{}
	if dc.OSPF != nil {
		for _, f := range dc.OSPF.Interfaces {
			was[f.Name] = f.Disabled
		}
		if c.Configured() {
			c.Disabled = dc.OSPF.Disabled
		}
	}
	for i := range c.Interfaces {
		c.Interfaces[i].Disabled = was[c.Interfaces[i].Name]
	}
	note := "ospf: "
	switch {
	case dc.OSPF == nil && len(c.Interfaces) == 0:
		return nil
	case c.Active():
		note += fmt.Sprintf("%d interface(s)", len(c.Interfaces))
	default:
		note += "off"
	}
	cc := c
	if len(cc.Interfaces) == 0 {
		dc.OSPF = nil
	} else {
		dc.OSPF = &cc
	}
	return m.PutConfig(dc, actor, note)
}

// OSPFOperateArgs switches the OSPF process (Interface empty) or one interface on or off.
type OSPFOperateArgs struct {
	Interface string `json:"interface,omitempty"`
	Enabled   bool   `json:"enabled"`
}

// OSPFOperate enables or disables OSPF on this node, or one of its interfaces, without touching the settings.
func (m *Mgmt) OSPFOperate(a OSPFOperateArgs, actor string) error {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if !dc.OSPF.Configured() {
		return fmt.Errorf("ospf: add an interface first")
	}
	if why := frrBlocked(); why != "" && a.Enabled {
		return fmt.Errorf("ospf: %s", why)
	}
	c := dc.OSPF.clone()
	var note string
	if n := strings.TrimSpace(a.Interface); n == "" {
		if c.Disabled == !a.Enabled {
			return nil
		}
		c.Disabled = !a.Enabled
		note = "ospf: " + map[bool]string{true: "enabled", false: "disabled"}[a.Enabled]
	} else {
		found := false
		for i := range c.Interfaces {
			if c.Interfaces[i].Name != n {
				continue
			}
			found = true
			if c.Interfaces[i].Disabled == !a.Enabled {
				return nil
			}
			c.Interfaces[i].Disabled = !a.Enabled
		}
		if !found {
			return fmt.Errorf("ospf: there is no interface %s", n)
		}
		note = "ospf: interface " + n + map[bool]string{true: " enabled", false: " disabled"}[a.Enabled]
	}
	dc.OSPF = c
	return m.PutConfig(dc, actor, note)
}

// ── announce gate and colour ─────────────────────────────────────────────────

// anycastOSPFStatus says how an announced anycast address looks given this node's OSPF interfaces: green when every
// enabled interface has a neighbor in state Full for the address's family (OSPFv2 for IPv4, OSPFv3 for IPv6), amber
// when some do and some do not, red when none does (or no interface is enabled, or FRR does not answer).  kind is
// "" (green), down, none or partial, as for BGP.
func anycastOSPFStatus(addr string, ifaces []OSPFInterface, peers []OSPFPeer, known bool) (status, detail, kind string) {
	af, label := "ipv4", "OSPFv2"
	if ip, err := netip.ParseAddr(addr); err == nil && ip.Unmap().Is6() {
		af, label = "ipv6", "OSPFv3"
	}
	if !known {
		return "bad", "OSPF is not answering: no neighbor, so the address is not reachable", "down"
	}
	full := map[string]bool{}
	for _, p := range peers {
		if p.AF == af && p.State == "Full" {
			full[p.Interface] = true
		}
	}
	var n, est int
	for _, f := range ifaces {
		if f.Disabled {
			continue
		}
		n++
		if full[f.Name] {
			est++
		}
	}
	switch {
	case n == 0:
		return "bad", "No OSPF interface is enabled: the address is not announced to anyone", "none"
	case est == n:
		return "ok", "", ""
	case est > 0:
		return "warn", fmt.Sprintf("%d of %d OSPF interfaces have no %s neighbor in state Full", n-est, n, label), "partial"
	}
	return "bad", "No " + label + " neighbor is in state Full: the address is not reachable", "down"
}

var ospfLive struct {
	sync.Mutex
	at    time.Time
	peers []OSPFPeer
	ok    bool
}

// liveOSPFPeers is the neighbor list from FRR, kept for 3 s so a busy canvas does not run vtysh on every poll.
func liveOSPFPeers() ([]OSPFPeer, bool) {
	ospfLive.Lock()
	defer ospfLive.Unlock()
	if !ospfLive.at.IsZero() && time.Since(ospfLive.at) < 3*time.Second {
		return ospfLive.peers, ospfLive.ok
	}
	ospfLive.at, ospfLive.peers, ospfLive.ok = time.Now(), nil, false
	if _, err := os.Stat(frrDir); err != nil {
		return nil, false
	}
	ospfLive.peers, ospfLive.ok = ospfNeighbors()
	return ospfLive.peers, ospfLive.ok
}

// anycastOSPFGate says why OSPF cannot carry an anycast address: "" means it can.
func anycastOSPFGate(cfg *OSPFConfig, addr string) string {
	switch {
	case !cfg.Configured():
		return "OSPF is not configured: nothing announces the address"
	case cfg.Disabled:
		return "OSPF is disabled on this node: the address is not announced"
	}
	peers, known := liveOSPFPeers()
	if st, detail, _ := anycastOSPFStatus(addr, cfg.Interfaces, peers, known); st == "bad" {
		return "OSPF: " + detail
	}
	return ""
}

// anycastOSPFGateFn is the OSPF side of the announce gate (replaceable in tests that are not about OSPF).
var anycastOSPFGateFn = anycastOSPFGate

// anycastRouteGate combines the two: an address is held while BGP or OSPF can carry it.
func anycastRouteGate(bgp *BGPConfig, ospf *OSPFConfig, addr string) string {
	bw := anycastGateFn(bgp, addr)
	if bw == "" {
		return ""
	}
	if !ospf.Active() {
		return bw
	}
	ow := anycastOSPFGateFn(ospf, addr)
	switch {
	case ow == "":
		return ""
	case !bgp.Active():
		return ow
	}
	return bw + "; " + ow
}

// anycastRouteStatus picks the better of the BGP and OSPF pictures for an announced address (the address is reachable
// as long as either carries it).  active says whether either protocol runs on this node.
func anycastRouteStatus(cfg *DaemonConfig, addr string, bgpPeers []BGPPeer, bgpOK bool, ospfPeers []OSPFPeer, ospfOK bool) (status, detail, kind string) {
	rank := map[string]int{"ok": 0, "warn": 1, "bad": 2}
	first := true
	try := func(s, d, k string) {
		if first || rank[s] < rank[status] {
			status, detail, kind, first = s, d, k, false
		}
	}
	if cfg.BGP.Active() {
		try(anycastBGPStatus(addr, cfg.BGP.Neighbors, bgpPeers, bgpOK))
	}
	if cfg.OSPF.Active() {
		try(anycastOSPFStatus(addr, cfg.OSPF.Interfaces, ospfPeers, ospfOK))
	}
	return status, detail, kind
}

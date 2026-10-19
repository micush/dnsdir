package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// Everything ntpdir keeps lives in /var/lib/ntpdir: the config, the GUI
	// certificate, config history, cluster identity and update data.
	confPath     = "/var/lib/ntpdir/ntpdir.conf"
	statusSocket = "/run/ntpdir/ntpdir.sock"

	// Releases before v15 kept the config under /etc/liras.
	legacyConfPath = "/etc/liras/ntpdir.conf"
)

// canonicalConf turns the pre-v15 path into the real one.  A service unit that was
// never rewritten (an in-place update does not touch it) still starts the daemon
// with `--config /etc/liras/ntpdir.conf`; nothing may be read from or written to
// /etc/liras any more, so that path means the config in /var/lib/ntpdir.
func canonicalConf(path string) string {
	if filepath.Clean(path) == legacyConfPath {
		return confPath
	}
	return path
}

// migrateLegacyConfig moves a pre-v15 /etc/liras config (and the self-signed
// GUI certificate next to it) to the default location.  It only acts when the
// new file does not exist yet and never overwrites anything.  It is a real move:
// each old file is removed once its copy is written and read back intact, and the
// directory goes when it is empty, so nothing is left in /etc/liras.  Errors are not fatal:
// the daemon then simply starts without a config, as for a fresh install.
func migrateLegacyConfig(dst, legacy string) (moved bool, err error) {
	if _, err := os.Stat(dst); err == nil {
		return false, nil
	}
	b, err := os.ReadFile(legacy)
	if err != nil {
		return false, nil // nothing to migrate
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return false, err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(legacy); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		return false, err
	}
	for _, f := range []string{"ntpdir-web.crt", "ntpdir-web.key"} {
		src, to := filepath.Join(filepath.Dir(legacy), f), filepath.Join(filepath.Dir(dst), f)
		if _, err := os.Stat(to); err == nil {
			continue
		}
		if cb, err := os.ReadFile(src); err == nil {
			if os.WriteFile(to, cb, 0o600) == nil {
				if back, err := os.ReadFile(to); err == nil && bytes.Equal(back, cb) {
					_ = os.Remove(src)
				}
			}
		}
	}
	if back, err := os.ReadFile(dst); err == nil && bytes.Equal(back, b) {
		_ = os.Remove(legacy)
	}
	_ = os.Remove(filepath.Dir(legacy)) // only succeeds when it is empty
	return true, nil
}

// ── Group config ─────────────────────────────────────────────────────────────

// GroupConfig holds per-group settings.  Each group gets its own engine(s).
type GroupConfig struct {
	// Name is an optional label shown instead of the address in the GUI and CLI.
	// Shared across the cluster.
	Name      string `json:"name,omitempty"`
	GroupID   int    `json:"group_id"`
	Interface string `json:"interface"`
	VIP4      string `json:"vip4"`
	VIP6      string `json:"vip6"`
	// MoreVIP4 and MoreVIP6 are further shared addresses inside the subnet of VIP4 / VIP6 (bare addresses, no prefix length:
	// they take the primary's).  They move with the gateway like the primary does and answer NTP the same way; the
	// primary stays the one in the hello packets.  Omitted when none, so older versions read the same file.
	MoreVIP4 []string `json:"more_vip4,omitempty"`
	MoreVIP6 []string `json:"more_vip6,omitempty"`
	Priority int      `json:"priority"`
	LBMethod LBMethod `json:"lb_method"`
	// RealMACs turns the virtual MACs off: no macvlan interfaces, and the controller answers ARP and neighbor
	// solicitations for the VIP with the real MAC address of the node it picks.  Every node then holds the VIP on lo.  For
	// where virtual MACs cannot work (a VMware port group that is not promiscuous, a cloud that allows one MAC per
	// interface); the price is failover that depends on the neighbors honoring an unsolicited ARP.  Off (the usual way) is
	// not written to the file, so a configuration that never used it stays readable by older versions.
	RealMACs  bool     `json:"real_macs,omitempty"`
	Weight    int      `json:"weight"`
	HelloMS   int      `json:"hello_ms"`
	HoldMS    int      `json:"hold_ms"`
	Preempt   bool     `json:"preempt"`
	MaxAFNs   int      `json:"max_afns"`
	Key       string   `json:"key"`
	Neighbors []string `json:"neighbors"`
	// NTP is this group's own upstream pool (what the canvas writes).  When
	// absent the group uses the top-level "ntp" block, which several groups may
	// share.
	NTP *NTPConfig `json:"ntp,omitempty"`
	// ExtraVIPs are anycast addresses: extra addresses of any subnet (no check
	// against the interface) that every running node holds on lo and answers NTP
	// on, while this gateway's NTP pool is healthy.  Shared across the cluster.
	ExtraVIPs []string `json:"extra_vips,omitempty"`
	// DNSDirVIPs are anycast addresses of the Anyname DNS Director (dnsdir) on the same host that this gateway also
	// answers NTP on (dnsdir.go).  ntpdir only listens on them: dnsdir holds and announces them.  Shared.
	DNSDirVIPs []string `json:"dnsdir_vips,omitempty"`
	// PausedVIPs are anycast addresses whose announcing is paused on every node (shared); PausedVIPsHere the ones
	// paused on this node only (never replicated).  A paused address stays in ExtraVIPs but is taken off lo, so the
	// route is withdrawn until it is resumed.
	PausedVIPs []string `json:"paused_vips,omitempty"`
	// PausedAll pauses the gateway on every node (shared); Paused below pauses it on this node only.
	PausedAll      bool     `json:"paused_all,omitempty"`
	PausedVIPsHere []string `json:"paused_vips_here,omitempty"`
	// Paused takes this node out of the gateway for maintenance: it resigns and
	// stops answering, other nodes carry on.  Local to the node, never replicated.
	Paused bool `json:"paused,omitempty"`
	// ExcludedNodes are the cluster nodes (by node ID) that do not serve this gateway: shared, so every node agrees.  A
	// node not listed serves it.  A node that joins the cluster is added to every gateway's list by the primary at that moment.  Omitted when empty, so a configuration that never used it
	// stays readable by older versions.  ExcludedHere is set by effective() when this node is one of them (never written).
	ExcludedNodes []string `json:"excluded_nodes,omitempty"`
	ExcludedHere  bool     `json:"-"`
	// NodeOrder is the order the cluster's nodes are drawn in beside this gateway (node IDs; drag them on Topology): shared.
	// A node not listed comes after the listed ones, by name.  Omitted when empty.
	NodeOrder []string `json:"node_order,omitempty"`
}

// newGatewayGroup is the starting point of a gateway that is created now (first start, Add gateway, --canvas-add,
// --configure): the same as defaultGroup but with real MAC addresses on, which is what most networks need (a VMware
// port group, a cloud, a switch with port security).  defaultGroup itself stays off: a group read from a file that does
// not say real_macs is off, as it always was, so an upgrade changes no running gateway.
// firstGroupID is the group number a new gateway gets first (the next free one counts up from here).
const firstGroupID = 100

func newGatewayGroup() GroupConfig {
	g := defaultGroup()
	g.GroupID = firstGroupID
	g.Key = newGroupKey() // a gateway someone adds does not start with a key everybody knows
	g.RealMACs = true
	return g
}

func defaultGroup() GroupConfig {
	return GroupConfig{
		GroupID:   1,
		Interface: "eth0",
		VIP4:      "10.0.0.1/24",
		Priority:  100,
		LBMethod:  lbRoundRobin,
		Weight:    100,
		HelloMS:   150,
		HoldMS:    750,
		MaxAFNs:   defaultMaxAFNs,
		Key:       "ntpdir",
		Neighbors: []string{},
	}
}

func (m LBMethod) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }

func (m *LBMethod) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := parseLB(s)
	if err != nil {
		return err
	}
	*m = v
	return nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (g *GroupConfig) UnmarshalJSON(b []byte) error {
	type alias GroupConfig
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	a := alias(defaultGroup())
	// back-compat: old configs have "vip" instead of vip4
	if v, ok := raw["vip"]; ok {
		if _, has := raw["vip4"]; !has {
			raw["vip4"] = v
		}
		delete(raw, "vip")
		b, _ = json.Marshal(raw)
	}
	if err := strictUnmarshal(b, &a); err != nil {
		return err
	}
	*g = GroupConfig(a)
	return nil
}

func (g *GroupConfig) keyBytes() []byte {
	if g.Key == "" {
		return []byte("ntpdir")
	}
	return []byte(g.Key)
}

func (g *GroupConfig) vipFor(af AF) string {
	if af == afIPv4 {
		return g.VIP4
	}
	return g.VIP6
}

// maxMoreVIPs is how many further addresses a gateway may hold per family.
const maxMoreVIPs = 32

func (g *GroupConfig) moreFor(af AF) []string {
	if af == afIPv4 {
		return g.MoreVIP4
	}
	return g.MoreVIP6
}

// vipsFor is every shared address of the family with its prefix length, the primary first.
func (g *GroupConfig) vipsFor(af AF) []string {
	p := g.vipFor(af)
	if p == "" {
		return nil
	}
	out := []string{p}
	pfx, err := netip.ParsePrefix(p)
	if err != nil {
		return out
	}
	for _, a := range g.moreFor(af) {
		out = append(out, fmt.Sprintf("%s/%d", a, pfx.Bits()))
	}
	return out
}

// cleanMoreVIPs checks the further addresses of one family against the primary: right family, inside its subnet, not the
// primary itself, not listed twice.  It returns them in canonical form.
func cleanMoreVIPs(list []string, primary string, v6 bool, pre, field string) ([]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	fam := map[bool]string{false: "IPv4", true: "IPv6"}[v6]
	if primary == "" {
		return nil, fmt.Errorf("%s: %s needs the gateway's %s address first", pre, field, fam)
	}
	if len(list) > maxMoreVIPs {
		return nil, fmt.Errorf("%s: %s holds at most %d addresses", pre, field, maxMoreVIPs)
	}
	pfx, err := netip.ParsePrefix(primary)
	if err != nil {
		return nil, fmt.Errorf("%s: %s: the gateway's address %q is not valid", pre, field, primary)
	}
	seen := map[netip.Addr]bool{pfx.Addr(): true}
	out := make([]string, 0, len(list))
	for _, s := range list {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || a.Is6() != v6 || a.Is4In6() {
			return nil, fmt.Errorf("%s: %s: %q is not an %s address", pre, field, s, fam)
		}
		if !pfx.Contains(a) {
			return nil, fmt.Errorf("%s: %s: %s is not in the gateway's subnet %s", pre, field, a, pfx.Masked())
		}
		if a == pfx.Masked().Addr() || (!v6 && a == lastV4(pfx)) {
			return nil, fmt.Errorf("%s: %s: %s is the subnet's network or broadcast address", pre, field, a)
		}
		if a.IsMulticast() || a.IsUnspecified() {
			return nil, fmt.Errorf("%s: %s: %s cannot be used", pre, field, a)
		}
		if seen[a] {
			return nil, fmt.Errorf("%s: %s: %s is listed twice or is the gateway's own address", pre, field, a)
		}
		seen[a] = true
		out = append(out, a.String())
	}
	return out, nil
}

// lastV4 is the broadcast address of an IPv4 prefix (only for a prefix short enough to have one).
func lastV4(p netip.Prefix) netip.Addr {
	if p.Bits() >= 31 {
		return netip.Addr{}
	}
	b := p.Masked().Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom4(b)
}

func (g *GroupConfig) wants(af AF) bool { return g.vipFor(af) != "" }

// unicastMode is true when explicit neighbors are configured.
func (g *GroupConfig) unicastMode() bool { return len(g.Neighbors) > 0 }

func (g *GroupConfig) Validate() error {
	pre := fmt.Sprintf("group %d", g.GroupID)
	if g.GroupID < 1 || g.GroupID > 255 {
		return fmt.Errorf("%s: group_id must be 1-255", pre)
	}
	if err := validGatewayName(g.Name); err != nil {
		return fmt.Errorf("%s: %v", pre, err)
	}
	if g.VIP4 == "" && g.VIP6 == "" {
		return fmt.Errorf("%s: at least one of vip4 or vip6 must be set", pre)
	}
	if g.VIP4 != "" {
		p, err := netip.ParsePrefix(g.VIP4)
		if err != nil || !p.Addr().Is4() {
			return fmt.Errorf("%s: vip4 %q must be IPv4 address/prefix, e.g. 10.0.0.1/24", pre, g.VIP4)
		}
	}
	if g.VIP6 != "" {
		p, err := netip.ParsePrefix(g.VIP6)
		if err != nil || !p.Addr().Is6() {
			return fmt.Errorf("%s: vip6 %q must be IPv6 address/prefix, e.g. 2001:db8::1/64", pre, g.VIP6)
		}
	}
	var err error
	if g.MoreVIP4, err = cleanMoreVIPs(g.MoreVIP4, g.VIP4, false, pre, "more_vip4"); err != nil {
		return err
	}
	if g.MoreVIP6, err = cleanMoreVIPs(g.MoreVIP6, g.VIP6, true, pre, "more_vip6"); err != nil {
		return err
	}
	for i, a := range g.ExtraVIPs {
		n, err := normalizeAnycast(a)
		if err != nil {
			return fmt.Errorf("%s: %v", pre, err)
		}
		g.ExtraVIPs[i] = n
	}
	for i, a := range g.DNSDirVIPs {
		n, err := normalizeAnycast(a)
		if err != nil {
			return fmt.Errorf("%s: dnsdir_vips: %v", pre, err)
		}
		g.DNSDirVIPs[i] = n
	}
	g.PausedVIPs = keepAnycast(g.PausedVIPs, g.ExtraVIPs)
	g.PausedVIPsHere = keepAnycast(g.PausedVIPsHere, g.ExtraVIPs)
	if l, err := cleanNodeOrder(g.NodeOrder); err != nil {
		return fmt.Errorf("%s: node_order: %v", pre, err)
	} else {
		g.NodeOrder = l
	}
	if l, err := cleanNodeIDs(g.ExcludedNodes); err != nil {
		return fmt.Errorf("%s: excluded_nodes: %v", pre, err)
	} else {
		g.ExcludedNodes = l
	}
	for _, f := range []struct {
		name      string
		v, lo, hi int
	}{
		{"priority", g.Priority, 0, 255},
		{"weight", g.Weight, 0, 255},
		{"max_afns", g.MaxAFNs, 1, 255},
		{"hello_ms", g.HelloMS, 1, 65535},
		{"hold_ms", g.HoldMS, 1, 65535},
	} {
		if f.v < f.lo || f.v > f.hi {
			return fmt.Errorf("%s: %s must be %d-%d", pre, f.name, f.lo, f.hi)
		}
	}
	if g.HelloMS > g.HoldMS {
		return fmt.Errorf("%s: hello_ms (%d) cannot be larger than hold_ms (%d): a neighbour would be declared gone between two hellos", pre, g.HelloMS, g.HoldMS)
	}
	if g.Interface == "" {
		return fmt.Errorf("%s: interface must be set", pre)
	}
	for _, n := range g.Neighbors {
		if _, err := netip.ParseAddr(n); err != nil {
			return fmt.Errorf("%s: invalid neighbor address %q", pre, n)
		}
	}
	return nil
}

// restartDiffers reports whether a change between a and b needs an engine restart.
func restartDiffers(a, b *GroupConfig) bool {
	return a.Paused != b.Paused || a.Interface != b.Interface || a.VIP4 != b.VIP4 || a.VIP6 != b.VIP6 ||
		!sameList(a.MoreVIP4, b.MoreVIP4) || !sameList(a.MoreVIP6, b.MoreVIP6) ||
		a.Key != b.Key || a.RealMACs != b.RealMACs || // the MAC mode changes what the node sets up: restart the gateway
		!reflect.DeepEqual(a.Neighbors, b.Neighbors)
}

// sameList compares two string lists, treating nil and empty as equal.
func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// normalizeAnycast turns an anycast address into its canonical bare form.  A
// /32 (IPv4) or /128 (IPv6) suffix is accepted; any other prefix length is
// refused, since the address is a single host and a prefix would suggest it
// belongs to a subnet.  Loopback, link-local, multicast and unspecified
// addresses are refused.
func normalizeAnycast(s string) (string, error) {
	t := strings.TrimSpace(s)
	var a netip.Addr
	if p, err := netip.ParsePrefix(t); err == nil {
		if p.Bits() != p.Addr().BitLen() {
			return "", fmt.Errorf("anycast address %q: give the address alone (or /%d), not a subnet", s, p.Addr().BitLen())
		}
		a = p.Addr()
	} else if a, err = netip.ParseAddr(t); err != nil {
		return "", fmt.Errorf("anycast address %q must be an IPv4 or IPv6 address, e.g. 203.0.113.53 or 2001:db8::53", s)
	}
	a = a.Unmap()
	if a.Zone() != "" || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return "", fmt.Errorf("anycast address %q is not a usable unicast address", s)
	}
	return a.String(), nil
}

// ── NTP config ─────────────────────────────────────────────────────────

// NTPConfig describes the upstream pool and how it is probed.
type NTPConfig struct {
	// Servers are upstream NTP servers: "10.0.0.123", "10.0.0.123:1123", "[2001:db8::123]:123", "ntp.example.com".
	Servers []string `json:"servers"`
	// ServerNames gives servers an optional name shown on the Topology page instead of the address,
	// keyed by the server as written in Servers (the same rules as a gateway's name).  It only labels:
	// it is left out of the pool's own configuration, so renaming never restarts a pool.
	ServerNames map[string]string `json:"server_names,omitempty"`
	// FallbackServers are a last resort, used only while no server in Servers is in service (all down or paused,
	// or none listed): the pool then answers from them, and goes back to Servers as soon as one of those answers
	// again.  Same address forms as Servers.  They are never probed and always count as up.
	FallbackServers []string `json:"fallback_servers,omitempty"`
	// PausedServers are listed servers that are taken out of service (no
	// requests, no probes) until resumed, e.g. during maintenance.  Replicated
	// with the rest of the NTP block.
	PausedServers []string `json:"paused_servers,omitempty"`
	// PausedServersHere is this node's own pause of the same thing (DaemonConfig keeps it, effective() hands it to
	// the pools).  Never replicated and never written from here.
	PausedServersHere []string `json:"-"`
	// ListenPort is the UDP port chrony serves on.
	ListenPort int `json:"listen_port"`
	// AllowedClients are the networks (10.0.0.0/8, 192.168.1.5, 2001:db8::/32) that may use this node (chrony `allow`);
	// empty means everyone. The node itself always may.
	AllowedClients []string `json:"allowed_clients,omitempty"`
	// BlockedClients are clients or networks that get no answers (chrony `deny`), whatever AllowedClients says: a block is
	// the more specific rule even when it names a network inside an allowed one.  Statistics ▸ Top Clients ▸ right-click ▸
	// Block adds an address here.  This node itself (loopback) cannot be blocked.
	BlockedClients []string `json:"blocked_clients,omitempty"`
	// SNMPCommunities and SNMPContact are the cluster-wide part of the SNMP settings (Configure ▸ SNMP), replicated like
	// AllowedClients: every node answers the same communities and reports the same contact.  The location is per node and
	// lives in DaemonConfig.SNMP.  See snmp.go.
	SNMPCommunities []string `json:"snmp_communities,omitempty"`
	// Keys, ServerAuth, NTSServer, LeapTZ, LeapMode and LeapSmear: authentication and leap seconds for chrony (see auth.go).
	Keys        []string `json:"keys,omitempty"`
	ServerAuth  []string `json:"server_auth,omitempty"`
	NTSServer   bool     `json:"nts_server,omitempty"`
	LeapTZ      string   `json:"leap_tz,omitempty"`
	LeapMode    string   `json:"leap_mode,omitempty"`
	LeapSmear   bool     `json:"leap_smear,omitempty"`
	SNMPContact string   `json:"snmp_contact,omitempty"`
	// Schedule is the scheduler's task list (Operate ▸ Scheduler), replicated with the rest; see scheduler.go.
	Schedule []SchedTask `json:"schedule,omitempty"`
	// ClientRate limits each client (an IPv4 address or an IPv6 /64) to this many requests a second; 0 (the default)
	// is no limit. ClientBurst is how many it may send at once (0 = twice the rate, at least 10). ClientAction is what
	// a client over its rate gets: "drop" (the default, kept as empty in the file) or "kod" (a kiss-o'-death RATE,
	// which tells a well-behaved client to slow down). ClientExempt are networks never limited.
	ClientRate   int      `json:"client_rate,omitempty"`
	ClientBurst  int      `json:"client_burst,omitempty"`
	ClientAction string   `json:"client_action,omitempty"`
	ClientExempt []string `json:"client_exempt,omitempty"`
	// ClientLimits give single clients or networks a rate of their own: "192.168.1.5 50" (requests per second).  They apply
	// even when ClientRate is 0 and before ClientExempt (see clientlimit.go).
	ClientLimits []string `json:"client_limits,omitempty"`
	// ClientNames are names given to clients by hand (Statistics ▸ Top clients ▸ right-click ▸ Name…): address -> name.  They are
	// shown instead of the reverse-DNS name and can be filtered on.  Only the shared Settings' copy is used.
	ClientNames map[string]string `json:"client_names,omitempty"`
	// Spread shares the requests out: the servers within SpreadBand percent of the fastest one's latency
	// (default 20) take turns instead of the fastest getting everything; slower ones are still only fallbacks.
	Spread     bool `json:"spread"`
	SpreadBand int  `json:"spread_band"`
	// MaxStratum is the highest stratum a server may report and still be used (default 15; 16 is a clock that is
	// not synchronised).  MaxRootDistanceMS is the largest error its time may have (root delay / 2 + root dispersion
	// + delay / 2; default 1500).  MaxOffsetMS is how far a server's time may be from the median of the servers' (needs
	// at least three servers; default 128, 0 = off): one that is further away is a falseticker and is taken out.
	MaxStratum        int `json:"max_stratum"`
	MaxRootDistanceMS int `json:"max_root_distance_ms"`
	MaxOffsetMS       int `json:"max_offset_ms"`
	// MaxRTTMS is the longest round trip a server may have and still be used (default 500, 0 = off): a server that
	// is further away than that is too slow and is taken out as a source.
	MaxRTTMS int `json:"max_rtt_ms"`
	// ServeOffsetMS is how far this node's clock may be from what chrony measures against the servers (default 50, 0 = off) and
	// the node still serves: beyond it chrony answers nobody and the node leaves the gateway and its anycast addresses, so
	// every serving node is within this of the same servers.
	ServeOffsetMS   int `json:"serve_offset_ms"`
	ProbeIntervalMS int `json:"probe_interval_ms"`
	ProbeTimeoutMS  int `json:"probe_timeout_ms"`
	QueryTimeoutMS  int `json:"query_timeout_ms"`
	MaxAttempts     int `json:"max_attempts"`
	FailThreshold   int `json:"fail_threshold"`
	// LatencyAlpha is the EWMA smoothing of a server's round-trip time.
	LatencyAlpha float64 `json:"latency_alpha"`
	// LB is a gateway's own load-balancing settings (see LBConfig).  Only meaningful in a gateway's own pool; nil
	// means the gateway follows Settings.  A pointer with omitempty so a config that never used it stays readable
	// by older versions.
	LB *LBConfig `json:"lb,omitempty"`
}

// LBConfig is the set of health-check settings (Configure ▸ NTP ▸ Health): when a server counts as down.  The spread and
// attempts fields are kept so older files load; they have no effect.  A gateway that has its own pool follows the shared values unless its own
// pool carries an LBConfig.
type LBConfig struct {
	Spread            bool    `json:"spread"`
	SpreadBand        int     `json:"spread_band"`
	MaxStratum        int     `json:"max_stratum"`
	MaxRootDistanceMS int     `json:"max_root_distance_ms"`
	MaxOffsetMS       int     `json:"max_offset_ms"`
	FailThreshold     int     `json:"fail_threshold"`
	MaxAttempts       int     `json:"max_attempts"`
	LatencyAlpha      float64 `json:"latency_alpha"`
}

func (d NTPConfig) lbValues() LBConfig {
	return LBConfig{Spread: d.Spread, SpreadBand: d.SpreadBand, MaxStratum: d.MaxStratum, MaxRootDistanceMS: d.MaxRootDistanceMS,
		MaxOffsetMS: d.MaxOffsetMS, FailThreshold: d.FailThreshold, MaxAttempts: d.MaxAttempts, LatencyAlpha: d.LatencyAlpha}
}

func (d *NTPConfig) setLBValues(l LBConfig) {
	d.Spread, d.SpreadBand, d.MaxStratum, d.MaxRootDistanceMS, d.MaxOffsetMS = l.Spread, l.SpreadBand, l.MaxStratum, l.MaxRootDistanceMS, l.MaxOffsetMS
	d.FailThreshold, d.MaxAttempts, d.LatencyAlpha = l.FailThreshold, l.MaxAttempts, l.LatencyAlpha
}

func (l LBConfig) validate() error {
	if l.SpreadBand < 1 || l.SpreadBand > 1000 {
		return errors.New("spread_band must be 1-1000 percent")
	}
	if l.MaxStratum < 1 || l.MaxStratum > 15 {
		return errors.New("max_stratum must be 1-15")
	}
	if l.MaxRootDistanceMS < 0 || l.MaxRootDistanceMS > 60000 {
		return errors.New("max_root_distance_ms must be 0 (off) to 60000")
	}
	if l.MaxOffsetMS < 0 || l.MaxOffsetMS > 3600000 {
		return errors.New("max_offset_ms must be 0 (off) to 3600000")
	}
	if l.FailThreshold < 1 {
		return errors.New("fail_threshold must be >= 1")
	}
	if l.MaxAttempts < 1 {
		return errors.New("max_attempts must be >= 1")
	}
	if l.LatencyAlpha <= 0 || l.LatencyAlpha > 1 {
		return errors.New("latency_alpha must be in (0, 1]")
	}
	return nil
}

// ownLB says whether a gateway's own pool has load-balancing settings of its own, and what they are.  An explicit LB
// does.  So does a pool whose load-balancing values differ from the defaults: those were set on purpose (or copied
// from Settings when the pool was made), and the gateway keeps them.  A pool that sits at the defaults follows
// Settings, which is what its owner expects.
func (d *NTPConfig) ownLB() (LBConfig, bool) {
	if d.LB != nil {
		return *d.LB, true
	}
	def := defaultNTP()
	if l := d.lbValues(); l != def.lbValues() {
		return l, true
	}
	return LBConfig{}, false
}

// defaultGatewayServers are the NTP servers a gateway starts with when it is created now (the GUI's New gateway and
// --canvas-add gateway).  They are ordinary servers of the gateway: remove the ones you do not want.  webui/app.js has
// the same list (DEFAULT_SERVERS), and a test keeps the two equal.  defaultNTP itself stays empty: a config read from a
// file that lists no servers has none, as it always did.
var defaultGatewayServers = []string{"pool.ntp.org", "time.nist.gov", "time.google.com", "time.cloudflare.com"}

// newGatewayServers is defaultGatewayServers in the form the config stores (host:port).
func newGatewayServers() []string {
	out := make([]string, 0, len(defaultGatewayServers))
	for _, s := range defaultGatewayServers {
		n, err := normalizeServer(s)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

func defaultNTP() NTPConfig {
	return NTPConfig{
		Servers:           []string{},
		ListenPort:        123,
		Spread:            true,
		SpreadBand:        20,
		MaxStratum:        15,
		MaxRootDistanceMS: 1500,
		MaxOffsetMS:       128,
		MaxRTTMS:          500,
		ServeOffsetMS:     50,
		ProbeIntervalMS:   16000,
		ProbeTimeoutMS:    1000,
		QueryTimeoutMS:    800,
		MaxAttempts:       2,
		FailThreshold:     2,
		LatencyAlpha:      0.3,
	}
}

func (d *NTPConfig) UnmarshalJSON(b []byte) error {
	type alias NTPConfig
	a := alias(defaultNTP())
	if err := strictUnmarshal(b, &a); err != nil {
		return err
	}
	*d = NTPConfig(a)
	return nil
}

func (d NTPConfig) probeInterval() time.Duration {
	return time.Duration(d.ProbeIntervalMS) * time.Millisecond
}
func (d NTPConfig) probeTimeout() time.Duration {
	return time.Duration(d.ProbeTimeoutMS) * time.Millisecond
}
func (d NTPConfig) queryTimeout() time.Duration {
	return time.Duration(d.QueryTimeoutMS) * time.Millisecond
}

// defaultServerPort is the port an NTP server is spoken to on when the address names none.
const defaultServerPort = "123"

// normalizeServer turns a server string into a canonical "host:port".  The
// host is an IP address or a host name (resolved each time it is probed).
func normalizeServer(s string) (string, error) {
	return normalizePlain(strings.TrimSpace(s), defaultServerPort)
}

func normalizePlain(s, defPort string) (string, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	t := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if a, err := netip.ParseAddr(t); err == nil {
		return net.JoinHostPort(a.String(), defPort), nil
	}
	host, port := s, defPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid ntp server %q (bad port)", s)
		}
	}
	if validHostname(host) {
		return net.JoinHostPort(strings.ToLower(host), port), nil
	}
	return "", fmt.Errorf("invalid ntp server %q (need an IP address or host name, optionally with :port)", s)
}

func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func (d *NTPConfig) Validate() error {
	// No servers is valid: a gateway just drawn has none yet, and its proxy answers
	// as an unsynchronised server until the first one is added.
	seen := map[string]bool{}
	for i, s := range d.Servers {
		n, err := normalizeServer(s)
		if err != nil {
			return fmt.Errorf("ntp: %w", err)
		}
		if seen[n] {
			return fmt.Errorf("ntp: duplicate server %q", s)
		}
		seen[n] = true
		d.Servers[i] = n
	}
	if len(d.FallbackServers) > 0 {
		fb := make([]string, 0, len(d.FallbackServers))
		for _, s := range d.FallbackServers {
			n, err := normalizeServer(s)
			if err != nil {
				return fmt.Errorf("ntp: fallback server: %w", err)
			}
			if seen[n] {
				return fmt.Errorf("ntp: fallback server %q is also a normal server", s)
			}
			seen[n] = true // for the duplicate check only; the maps below look at Servers
			fb = append(fb, n)
		}
		d.FallbackServers = fb
		for _, n := range fb {
			delete(seen, n)
		}
	} else {
		d.FallbackServers = nil
	}
	if len(d.PausedServers) > 0 { // keep only real, distinct servers
		keep := []string{}
		done := map[string]bool{}
		for _, p := range d.PausedServers {
			if n, err := normalizeServer(p); err == nil && seen[n] && !done[n] {
				done[n] = true
				keep = append(keep, n)
			}
		}
		d.PausedServers = keep
		if len(keep) == 0 {
			d.PausedServers = nil
		}
	}
	names := map[string]string{}
	for k, name := range d.ServerNames {
		n, err := normalizeServer(k)
		if err != nil || !seen[n] {
			return fmt.Errorf("ntp: server_names entry %q is not one of the servers", k)
		}
		name = strings.TrimSpace(name)
		if err := validGatewayName(name); err != nil {
			return fmt.Errorf("ntp: name of server %s: %w", k, err)
		}
		if name != "" {
			names[n] = name
		}
	}
	d.ServerNames = names
	if len(names) == 0 {
		d.ServerNames = nil
	}
	if d.ListenPort < 1 || d.ListenPort > 65535 {
		return errors.New("ntp: listen_port must be 1-65535")
	}
	if d.ServeOffsetMS < 0 || d.ServeOffsetMS > 3600000 {
		return errors.New("ntp: serve_offset_ms must be 0-3600000 (0 = off)")
	}
	if d.MaxRTTMS < 0 || d.MaxRTTMS > 60000 {
		return errors.New("ntp: max_rtt_ms must be 0-60000 (0 = off)")
	}
	for _, f := range []struct {
		name string
		v    int
	}{
		{"probe_interval_ms", d.ProbeIntervalMS}, {"probe_timeout_ms", d.ProbeTimeoutMS},
		{"query_timeout_ms", d.QueryTimeoutMS}, {"max_attempts", d.MaxAttempts},
		{"fail_threshold", d.FailThreshold},
	} {
		if f.v < 1 {
			return fmt.Errorf("ntp: %s must be >= 1", f.name)
		}
	}
	if err := d.validateAuth(); err != nil {
		return err
	}
	if err := d.validateClientNames(); err != nil {
		return err
	}
	if err := d.validateClients(); err != nil {
		return err
	}
	if err := d.lbValues().validate(); err != nil {
		return fmt.Errorf("ntp: %w", err)
	}
	if d.LB != nil {
		if err := d.LB.validate(); err != nil {
			return fmt.Errorf("ntp: lb: %w", err)
		}
	}
	return nil
}

// ── Daemon config ────────────────────────────────────────────────────────────

type DaemonConfig struct {
	LogLevel string        `json:"log_level"`
	Groups   []GroupConfig `json:"groups"`
	NTP      NTPConfig     `json:"ntp"`
	Web      WebConfig     `json:"web"`
	Cluster  ClusterConfig `json:"cluster"`
	// BGP is this node's FRR/BGP settings (see bgp.go).  A pointer with omitempty so
	// a config that never used BGP has no "bgp" key and older versions still read it.
	BGP *BGPConfig `json:"bgp,omitempty"`
	// SNMP is this node's snmpd settings (see snmp.go).  A pointer with omitempty so a config that never used SNMP has no
	// "snmp" key and older versions still read it.  Local to the node, never replicated.
	SNMP *SNMPConfig `json:"snmp,omitempty"`
	// NodePaused takes the whole node out of service for maintenance, the same as
	// pausing every gateway on it (present and future): it resigns, stops answering
	// and stops probing, and the other nodes carry on.  Local to the node, never
	// replicated; omitempty so a config that never used it stays readable by older
	// versions.
	NodePaused bool `json:"node_paused,omitempty"`
	// PausedServersHere are the NTP servers paused on this node only (the shared list lives in the NTP block).
	// Local, never replicated.
	PausedServersHere []string `json:"paused_servers_here,omitempty"`
}

// effective is the configuration the supervisor runs: with the node paused every
// gateway is paused.  The file keeps each gateway's own flag, so resuming the
// node puts back exactly what was paused before.
func (dc *DaemonConfig) effective() *DaemonConfig {
	if dc == nil {
		return dc
	}
	c := *dc
	c.Groups = append([]GroupConfig(nil), dc.Groups...)
	here := func(d NTPConfig) NTPConfig {
		d.PausedServersHere = dc.PausedServersHere
		return d
	}
	c.NTP = here(c.NTP)
	for i := range c.Groups {
		if dc.NodePaused || c.Groups[i].PausedAll { // paused on every node, or this whole node is
			c.Groups[i].Paused = true
		}
		if id := localNodeID(); id != "" && containsStr(c.Groups[i].ExcludedNodes, id) { // removed from this gateway: it serves nothing here
			c.Groups[i].Paused, c.Groups[i].ExcludedHere = true, true
		}
		if c.Groups[i].NTP != nil {
			d := here(*c.Groups[i].NTP)
			c.Groups[i].NTP = &d
		}
	}
	return &c
}

func newDaemonConfig() *DaemonConfig {
	return &DaemonConfig{LogLevel: "info", Groups: []GroupConfig{newGatewayGroup()},
		NTP: defaultNTP(), Web: defaultWeb(), Cluster: defaultCluster()}
}

func (dc *DaemonConfig) UnmarshalJSON(b []byte) error {
	type alias DaemonConfig
	a := alias(*newDaemonConfig())
	a.Groups = nil
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	// A missing "groups" key means the default group; an explicit empty list
	// really is "no gateways" (what deleting the last canvas produces).
	var probe struct {
		Groups json.RawMessage `json:"groups"`
	}
	_ = json.Unmarshal(b, &probe)
	if a.Groups == nil && (len(probe.Groups) == 0 || string(probe.Groups) == "null") {
		a.Groups = []GroupConfig{newGatewayGroup()}
	}
	if a.Groups == nil {
		a.Groups = []GroupConfig{}
	}
	*dc = DaemonConfig(a)
	return nil
}

// poolFor returns the pool key and NTP settings for a group: its own pool
// (keyed by group id) or the shared one (key 0).
func (dc *DaemonConfig) poolFor(g *GroupConfig) (int, NTPConfig) {
	if g.NTP != nil {
		c := *g.NTP
		lb, own := g.NTP.ownLB()
		if !own {
			lb = dc.NTP.lbValues() // follows Settings
		}
		c.setLBValues(lb)
		c.LB = nil
		c.followSettings(dc.NTP)
		return g.GroupID, c
	}
	return 0, dc.NTP
}

// followSettings makes c use the client rules (allowed clients, rate, burst, action, exemptions) of the shared
// Settings.  They are edited only on the Settings page, so a gateway's own pool must not keep the copy it was made
// with: it would go on limiting after Settings said otherwise.
func (c *NTPConfig) followSettings(shared NTPConfig) {
	c.AllowedClients = append([]string(nil), shared.AllowedClients...)
	if len(c.AllowedClients) == 0 {
		c.AllowedClients = nil
	}
	c.BlockedClients = append([]string(nil), shared.BlockedClients...)
	if len(c.BlockedClients) == 0 {
		c.BlockedClients = nil
	}
	c.ClientExempt = append([]string(nil), shared.ClientExempt...)
	if len(c.ClientExempt) == 0 {
		c.ClientExempt = nil
	}
	c.ClientLimits = append([]string(nil), shared.ClientLimits...)
	if len(c.ClientLimits) == 0 {
		c.ClientLimits = nil
	}
	c.ClientRate, c.ClientBurst, c.ClientAction = shared.ClientRate, shared.ClientBurst, shared.ClientAction
}

func (dc *DaemonConfig) Validate() error {
	ids := map[int]bool{}
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if err := g.Validate(); err != nil {
			return err
		}
		if ids[g.GroupID] {
			return fmt.Errorf("duplicate group_id %d", g.GroupID)
		}
		ids[g.GroupID] = true
	}
	// two gateways cannot own the same shared address, and an anycast address is not a gateway's shared address; the same
	// anycast address on several gateways is how an anycast service is run (it is held while any of them can answer)
	vips := map[string]int{}
	norm := func(v string) string {
		if p, err := netip.ParsePrefix(v); err == nil {
			return p.Addr().String()
		}
		return v
	}
	for _, g := range dc.Groups {
		for _, v := range append(append([]string{g.VIP4, g.VIP6}, g.MoreVIP4...), g.MoreVIP6...) {
			if v == "" {
				continue
			}
			a := norm(v)
			if other, dup := vips[a]; dup {
				return fmt.Errorf("groups %d and %d both use the shared address %s", other, g.GroupID, a)
			}
			vips[a] = g.GroupID
		}
	}
	dnsdirOwner := map[string]int{}
	for _, g := range dc.Groups {
		seen := map[string]bool{}
		for _, v := range g.DNSDirVIPs {
			a := norm(v)
			if other, dup := vips[a]; dup {
				return fmt.Errorf("group %d: dnsdir address %s is the shared address of group %d", g.GroupID, a, other)
			}
			if seen[a] {
				return fmt.Errorf("group %d lists the dnsdir address %s twice", g.GroupID, a)
			}
			if other, dup := dnsdirOwner[a]; dup {
				return fmt.Errorf("groups %d and %d both answer on the dnsdir address %s", other, g.GroupID, a)
			}
			for _, o := range dc.Groups {
				for _, x := range o.ExtraVIPs {
					if norm(x) == a {
						return fmt.Errorf("group %d: %s is also an anycast address of group %d: an address is either ntpdir's own or dnsdir's", g.GroupID, a, o.GroupID)
					}
				}
			}
			seen[a] = true
			dnsdirOwner[a] = g.GroupID
		}
	}
	for _, g := range dc.Groups {
		seen := map[string]bool{}
		for _, v := range g.ExtraVIPs {
			a := norm(v)
			if other, dup := vips[a]; dup {
				return fmt.Errorf("group %d: anycast address %s is the shared address of group %d", g.GroupID, a, other)
			}
			if seen[a] {
				return fmt.Errorf("group %d lists the anycast address %s twice", g.GroupID, a)
			}
			seen[a] = true
		}
	}
	// this node's own pauses must still name a server that exists somewhere
	hereServers := map[string]bool{}
	blocks := []*NTPConfig{&dc.NTP}
	for i := range dc.Groups {
		if dc.Groups[i].NTP != nil {
			blocks = append(blocks, dc.Groups[i].NTP)
		}
	}
	for _, b := range blocks {
		for _, sv := range b.Servers {
			hereServers[sv] = true
		}
	}
	dc.PausedServersHere = keepStrings(dc.PausedServersHere, hereServers)
	switch strings.ToLower(dc.LogLevel) {
	case "debug", "info", "warning", "error":
	default:
		return fmt.Errorf("log_level %q must be debug|info|warning|error", dc.LogLevel)
	}
	if dc.NTP.LB != nil {
		return errors.New("ntp: lb belongs to a gateway's own pool (the shared settings are the load-balancing settings themselves)")
	}
	needGlobal := false
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if g.NTP == nil {
			needGlobal = true
			continue
		}
		if err := g.NTP.Validate(); err != nil {
			return fmt.Errorf("group %d: %w", g.GroupID, err)
		}
	}
	if needGlobal {
		if err := dc.NTP.Validate(); err != nil {
			return err
		}
	}
	if err := dc.Web.Validate(); err != nil {
		return err
	}
	if err := validateSchedule(dc.NTP.Schedule); err != nil {
		return err
	}
	if len(dc.NTP.Schedule) == 0 {
		dc.NTP.Schedule = nil
	}
	{
		sc := SNMPConfig{Communities: dc.NTP.SNMPCommunities, Contact: dc.NTP.SNMPContact}
		if err := sc.Validate(); err != nil {
			return err
		}
		dc.NTP.SNMPCommunities, dc.NTP.SNMPContact = sc.Communities, sc.Contact
	}
	if dc.SNMP != nil {
		// v49 kept communities and contact on the node; they are cluster settings now, so move them over once
		if len(dc.NTP.SNMPCommunities) == 0 && dc.NTP.SNMPContact == "" && (len(dc.SNMP.Communities) > 0 || dc.SNMP.Contact != "") {
			dc.NTP.SNMPCommunities, dc.NTP.SNMPContact = dc.SNMP.Communities, dc.SNMP.Contact
		}
		dc.SNMP.Communities, dc.SNMP.Contact = nil, ""
		if err := dc.SNMP.Validate(); err != nil {
			return err
		}
		if dc.SNMP.empty() {
			dc.SNMP = nil
		}
	}
	if dc.BGP != nil {
		if err := dc.BGP.Validate(); err != nil {
			return err
		}
	}
	return dc.Cluster.Validate()
}

func loadConfig(path string) (*DaemonConfig, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		// No file yet: defaults, and no gateways (a gateway is something you draw;
		// inventing one would claim an address on the network).
		dc := newDaemonConfig()
		dc.Groups = []GroupConfig{}
		return dc, nil
	}
	if err != nil {
		return nil, err
	}
	dc := newDaemonConfig()
	if err := json.Unmarshal(b, dc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return dc, nil
}

func (dc *DaemonConfig) save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if dc.Groups == nil {
		dc.Groups = []GroupConfig{}
	}
	b, err := json.MarshalIndent(dc, "", "  ")
	if err != nil {
		return err
	}
	// The file holds the groups' shared HMAC keys: keep the mode of an existing
	// file (other tools may read it), and create new files private.
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil { // WriteFile is subject to umask
		return err
	}
	return os.Rename(tmp, path)
}

// ── Web GUI config ───────────────────────────────────────────────────────────

// WebConfig describes the HTTPS management GUI.
type WebConfig struct {
	// LegacyEnabled is the old "enabled" switch: the GUI is always on now.  The
	// key is still accepted so existing config files load; it is dropped on save.
	LegacyEnabled *bool `json:"enabled,omitempty"`
	// Listen is the address:port to serve HTTPS on (default ":12380").
	Listen string `json:"listen"`
	// CertFile/KeyFile: PEM certificate and key.  Leave both empty to use an
	// auto-generated self-signed certificate stored next to the config file.
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// Group is the system group whose members may log in: one name, or several separated by commas (the default is the
	// local group and a group of the same name with "-users" for a directory such as Active Directory).
	Group string `json:"group"`
	// PAMService is the /etc/pam.d service used to check passwords.
	PAMService string `json:"pam_service"`
	// SessionIdleMinutes logs a browser out after this much inactivity.
	SessionIdleMinutes int `json:"session_idle_minutes"`
	// Failed-login lockout: MaxFailedLogins wrong attempts within
	// FailedLoginWindowMinutes lock that address (and that user name) out for
	// LockoutMinutes.
	MaxFailedLogins          int `json:"max_failed_logins"`
	FailedLoginWindowMinutes int `json:"failed_login_window_minutes"`
	LockoutMinutes           int `json:"lockout_minutes"`
	// MinPasswordLength is the fewest characters a password set on the Users page (or with --user-add and
	// --user-password) may have.  0, which is also what an absent key means and what is not written to the file
	// (so a config that never set it stays readable by older versions), is the default, 8.
	MinPasswordLength int `json:"min_password_length,omitempty"`
}

const (
	defaultWebPort       = 12380
	defaultMinPassword   = 8
	maxMinPasswordLength = 128
)

// minPassword is the effective minimum password length.
func (w WebConfig) minPassword() int {
	if w.MinPasswordLength <= 0 {
		return defaultMinPassword
	}
	return w.MinPasswordLength
}

func defaultWeb() WebConfig {
	return WebConfig{
		Listen:                   fmt.Sprintf(":%d", defaultWebPort),
		Group:                    "ntpdir,ntpdir-users",
		PAMService:               "ntpdir",
		SessionIdleMinutes:       30,
		MaxFailedLogins:          3,
		FailedLoginWindowMinutes: 1,
		LockoutMinutes:           15,
	}
}

func (w *WebConfig) UnmarshalJSON(b []byte) error {
	type alias WebConfig
	a := alias(defaultWeb())
	if err := strictUnmarshal(b, &a); err != nil {
		return err
	}
	a.LegacyEnabled = nil
	*w = WebConfig(a)
	return nil
}

func (w *WebConfig) Validate() error {
	_, port, err := net.SplitHostPort(w.Listen)
	if err != nil {
		return fmt.Errorf("web: listen %q must be host:port, e.g. \":12380\"", w.Listen)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("web: listen port %q must be 1-65535", port)
	}
	if (w.CertFile == "") != (w.KeyFile == "") {
		return errors.New("web: cert_file and key_file must be set together (or both empty for a self-signed certificate)")
	}
	if w.Group == "" || w.PAMService == "" {
		return errors.New("web: group and pam_service must not be empty")
	}
	if w.SessionIdleMinutes < 1 {
		return errors.New("web: session_idle_minutes must be >= 1")
	}
	if w.MaxFailedLogins < 1 || w.MaxFailedLogins > 1000 {
		return errors.New("web: max_failed_logins must be 1-1000")
	}
	if w.FailedLoginWindowMinutes < 1 || w.FailedLoginWindowMinutes > 10080 {
		return errors.New("web: failed_login_window_minutes must be 1-10080")
	}
	if w.LockoutMinutes < 1 || w.LockoutMinutes > 10080 {
		return errors.New("web: lockout_minutes must be 1-10080")
	}
	if w.MinPasswordLength < 0 || w.MinPasswordLength > maxMinPasswordLength {
		return fmt.Errorf("web: min_password_length must be 1-%d (empty or 0 means the default, %d)", maxMinPasswordLength, defaultMinPassword)
	}
	return nil
}

func (w WebConfig) failWindow() time.Duration {
	return time.Duration(w.FailedLoginWindowMinutes) * time.Minute
}

func (w WebConfig) lockout() time.Duration { return time.Duration(w.LockoutMinutes) * time.Minute }

func (w WebConfig) sessionIdle() time.Duration {
	return time.Duration(w.SessionIdleMinutes) * time.Minute
}

// ── Management cluster config ────────────────────────────────────────────────

// ClusterConfig describes this node's membership of the management cluster
// (config replication, shared certificate, coordinated updates).  It is
// per-node and never replicated.  The gateway protocol itself (AGC/AFN
// election) is independent of it.
type ClusterConfig struct {
	// Enabled starts the cluster listener.  Always true (the key is only kept so
	// older files still load).  Every node is the primary of its own
	// single-node cluster until it joins another.
	Enabled bool `json:"-"`
	// Listen is the address:port of the peer-to-peer listener (default ":12381").
	Listen string `json:"listen"`
	// Self is the host:port other nodes use to reach this one.  Empty means
	// "this host's name and the listen port".
	Self string `json:"self"`
	// SyncIntervalSec is how often replicas pull state and peers are polled.
	SyncIntervalSec int `json:"sync_interval_sec"`
	// ShareCert replicates the certificate installed through the GUI/CLI to
	// every member.  Always true, like Enabled.
	ShareCert bool `json:"-"`
}

const defaultClusterPort = 12381

func defaultCluster() ClusterConfig {
	return ClusterConfig{
		Enabled:         true,
		Listen:          fmt.Sprintf(":%d", defaultClusterPort),
		SyncIntervalSec: 5,
		ShareCert:       true,
	}
}

func (c *ClusterConfig) UnmarshalJSON(b []byte) error {
	type alias ClusterConfig
	a := struct {
		alias
		LegacyEnabled   *bool `json:"enabled"`
		LegacyShareCert *bool `json:"share_cert"`
	}{alias: alias(defaultCluster())}
	if err := strictUnmarshal(b, &a); err != nil {
		return err
	}
	*c = ClusterConfig(a.alias)
	// Clustering and certificate sharing are not options any more.  Older files
	// still carry the keys: accepted, ignored, and not written back.
	c.Enabled, c.ShareCert = true, true
	return nil
}

func (c *ClusterConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if _, port, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("cluster: listen %q must be host:port, e.g. \":12381\"", c.Listen)
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("cluster: listen port %q must be 1-65535", port)
	}
	if c.Self != "" {
		if _, _, err := net.SplitHostPort(c.Self); err != nil {
			return fmt.Errorf("cluster: self %q must be host:port", c.Self)
		}
	}
	if c.SyncIntervalSec < 1 || c.SyncIntervalSec > 3600 {
		return errors.New("cluster: sync_interval_sec must be 1-3600")
	}
	return nil
}

// isPaused reports whether the server (as written in Servers) is paused, on every node or on this one.
func (d *NTPConfig) isPaused(addr string) bool { return d.serverPausedScope(addr) != "" }

// serverPausedScope says where the server is paused: "all" (every node), "node" (this one) or "" (not paused).
func (d *NTPConfig) serverPausedScope(addr string) string {
	if containsStr(d.PausedServers, addr) {
		return "all"
	}
	if containsStr(d.PausedServersHere, addr) {
		return "node"
	}
	return ""
}

// keepStrings returns the distinct entries of l that are in valid (nil when none).
func keepStrings(l []string, valid map[string]bool) []string {
	var out []string
	for _, k := range l {
		if valid[k] && !containsStr(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// live is the configuration the probe pool runs with: paused servers left out.
func (d NTPConfig) live() NTPConfig {
	d.ServerNames = nil // labels only: a rename must not restart the pool
	d.clearNodeWide()   // chrony's and SNMP's, not the pool's
	if len(d.PausedServers) != 0 || len(d.PausedServersHere) != 0 {
		var up []string
		for _, s := range d.Servers {
			if !d.isPaused(s) {
				up = append(up, s)
			}
		}
		d.Servers = up
	}
	d.PausedServers, d.PausedServersHere = nil, nil
	return d
}

// maxGatewayName is the longest label a gateway may carry.
const maxGatewayName = 40

// validGatewayName accepts an empty name or up to 40 characters with no control characters.
func validGatewayName(n string) error {
	if utf8.RuneCountInString(n) > maxGatewayName {
		return fmt.Errorf("name is longer than %d characters", maxGatewayName)
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return errors.New("name must not contain control characters")
		}
	}
	return nil
}

const (
	maxClientNames   = 5000
	maxClientNameLen = 64
)

// validateClientNames checks the hand-given client names and writes the addresses in their canonical form (in place).
func (d *NTPConfig) validateClientNames() error {
	if len(d.ClientNames) == 0 {
		d.ClientNames = nil
		return nil
	}
	if len(d.ClientNames) > maxClientNames {
		return fmt.Errorf("ntp: client_names holds at most %d names", maxClientNames)
	}
	out := make(map[string]string, len(d.ClientNames))
	for k, v := range d.ClientNames {
		a, err := netip.ParseAddr(strings.TrimSpace(k))
		if err != nil {
			return fmt.Errorf("ntp: client_names: %q is not an address", k)
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue // an empty name is no name
		}
		if len(v) > maxClientNameLen || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return fmt.Errorf("ntp: client_names: the name of %s is too long (at most %d characters) or has control characters", a, maxClientNameLen)
		}
		out[a.Unmap().String()] = v
	}
	if len(out) == 0 {
		out = nil
	}
	d.ClientNames = out
	return nil
}

// validateClients checks and normalises the client list, exemptions, rate and action (in place).
func (d *NTPConfig) validateClients() error {
	for _, f := range []struct {
		name string
		list *[]string
	}{{"allowed_clients", &d.AllowedClients}, {"blocked_clients", &d.BlockedClients}, {"client_exempt", &d.ClientExempt}} {
		if len(*f.list) == 0 {
			*f.list = nil
			continue
		}
		nets, err := parseClientNets(*f.list)
		if err != nil {
			return fmt.Errorf("ntp: %s: %w", f.name, err)
		}
		norm := make([]string, 0, len(nets))
		seen := map[string]bool{}
		for _, n := range nets {
			if s := n.String(); !seen[s] {
				seen[s] = true
				norm = append(norm, s)
			}
		}
		*f.list = norm
	}
	for _, s := range d.BlockedClients {
		n, _ := netip.ParsePrefix(s)
		if n.Contains(netip.MustParseAddr("127.0.0.1")) || n.Contains(netip.MustParseAddr("::1")) {
			return fmt.Errorf("ntp: blocked_clients: %s covers this node itself, which always may ask", s)
		}
	}
	if len(d.ClientLimits) == 0 {
		d.ClientLimits = nil
	} else {
		ov, err := parseClientLimits(d.ClientLimits)
		if err != nil {
			return fmt.Errorf("ntp: client_limits: %w", err)
		}
		norm, seen := make([]string, 0, len(ov)), map[string]bool{}
		for _, o := range ov {
			n := o.net.String()
			if o.net.IsSingleIP() {
				n = o.net.Addr().String()
			}
			if seen[n] {
				return fmt.Errorf("ntp: client_limits: %s is listed twice", n)
			}
			seen[n] = true
			norm = append(norm, n+" "+strconv.Itoa(int(o.rate)))
		}
		d.ClientLimits = norm
	}
	if d.ClientRate < 0 || d.ClientRate > 10_000_000 {
		return errors.New("ntp: client_rate must be 0-10000000 requests per second")
	}
	if d.ClientBurst < 0 || d.ClientBurst > 100_000_000 {
		return errors.New("ntp: client_burst must be 0-100000000")
	}
	switch d.ClientAction {
	case "", actDrop:
		d.ClientAction = "" // the default is not written
	case actKoD:
	default:
		return fmt.Errorf("ntp: client_action must be drop or kod, not %q", d.ClientAction)
	}
	return nil
}

// keepAnycast returns the distinct members of paused that are still anycast addresses of the gateway, normalised
// (nil when none): deleting or editing an address drops its pause.
func keepAnycast(paused, extra []string) []string {
	var out []string
	for _, p := range paused {
		n, err := normalizeAnycast(p)
		if err != nil || !containsStr(extra, n) || containsStr(out, n) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// pausedAnycast says, per anycast address of the gateway, where its announcing is paused: "all" (every node) or
// "node" (this one).
func (g GroupConfig) pausedAnycast() map[string]string {
	out := map[string]string{}
	for _, a := range g.PausedVIPsHere {
		out[a] = "node"
	}
	for _, a := range g.PausedVIPs {
		out[a] = "all"
	}
	return out
}

// snmpSettings is the whole SNMP configuration of this node: the cluster's communities and contact, this node's location.
func (dc *DaemonConfig) snmpSettings() SNMPConfig {
	c := SNMPConfig{Communities: dc.NTP.SNMPCommunities, Contact: dc.NTP.SNMPContact}
	if dc.SNMP != nil {
		c.Location = dc.SNMP.Location
	}
	return c
}

// clearNodeWide drops the settings that belong to the node as a whole (SNMP, keys, NTS, leap seconds): a gateway's own pool and
// the probe pool have no use for them, and a copy of them would only go stale.
func (d *NTPConfig) clearNodeWide() {
	d.SNMPCommunities, d.SNMPContact = nil, ""
	d.Keys, d.ServerAuth, d.NTSServer, d.LeapTZ, d.LeapMode, d.LeapSmear = nil, nil, false, "", "", false
	d.Schedule = nil
}

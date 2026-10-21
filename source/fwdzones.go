package main

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Conditional forwarding: named lists of zones (Configure ▸ DNS proxy ▸ Conditional Forwarding, shared by every
// gateway) and, per server, which lists it serves.  A query whose name falls under a zone of a list goes only to the
// servers that carry that list (the most specific zone wins); every other query goes to the servers that also serve
// everything else.  Inside either set the pool works as it always did: health probes, fastest first, spread, failover.
//
// A server has one of three types:
//
//	public             no lists: answers everything except the zones other servers carry (the default)
//	internal           lists, zones_only: answers only those zones and is never asked about anything else
//	public + internal  lists, not zones_only: answers its zones and everything else
//
// If every server of a zone is down the client gets SERVFAIL: the query is never passed on to the other servers, so
// an internal name cannot leak to a public resolver.

// ServerForward is what one server serves besides (or instead of) everything.
type ServerForward struct {
	Lists     []string `json:"lists,omitempty"`      // the names of the zone lists it serves
	ZonesOnly bool     `json:"zones_only,omitempty"` // it serves only those zones, not everything else
}

const (
	fwdMaxLists = 500
	fwdMaxZones = 20000
)

// The server types as the web page and the command line name them.
const (
	fwdPublic   = "public"
	fwdInternal = "internal"
	fwdBoth     = "both"
)

// fwdType is the type of a server with this setting.
func (f ServerForward) fwdType() string {
	switch {
	case len(f.Lists) == 0:
		return fwdPublic
	case f.ZonesOnly:
		return fwdInternal
	}
	return fwdBoth
}

// validListName says whether s can name a zone list.
func validListName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// normZone lower-cases a zone and takes off a trailing dot and a leading "*.".  The root is not a zone.
func normZone(z string) (string, error) {
	z = strings.ToLower(strings.TrimSpace(z))
	z = strings.TrimPrefix(z, "*.")
	z = strings.TrimSuffix(z, ".")
	if z == "" {
		return "", errors.New("an empty zone (the root \".\" cannot be a conditional zone: that is every name)")
	}
	if !validHostname(z) {
		return "", fmt.Errorf("%q is not a zone name", z)
	}
	return z, nil
}

// parseForwardList reads one line of the list setting: "name: zone, zone zone".  The name is lower-cased.
func parseForwardList(line string) (string, []string, error) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", nil, fmt.Errorf("%q: write it as  name: zone, zone", strings.TrimSpace(line))
	}
	name := strings.ToLower(strings.TrimSpace(line[:i]))
	if !validListName(name) {
		return "", nil, fmt.Errorf("%q is not a list name (1-64 letters, digits, - _ .)", strings.TrimSpace(line[:i]))
	}
	var zones []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(line[i+1:], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' }) {
		z, err := normZone(f)
		if err != nil {
			return "", nil, fmt.Errorf("list %s: %w", name, err)
		}
		if !seen[z] {
			seen[z] = true
			zones = append(zones, z)
		}
	}
	return name, zones, nil
}

// normalizeForwardLists checks the lists and returns them in their plain form, one "name: zone, zone" per list.
func normalizeForwardLists(lines []string) ([]string, error) {
	var out []string
	names := map[string]bool{}
	total := 0
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		name, zones, err := parseForwardList(l)
		if err != nil {
			return nil, fmt.Errorf("dns: conditional forwarding: %w", err)
		}
		if names[name] {
			return nil, fmt.Errorf("dns: conditional forwarding: the list %s is written twice", name)
		}
		names[name] = true
		total += len(zones)
		out = append(out, name+": "+strings.Join(zones, ", "))
	}
	if len(out) > fwdMaxLists {
		return nil, fmt.Errorf("dns: conditional forwarding: at most %d lists", fwdMaxLists)
	}
	if total > fwdMaxZones {
		return nil, fmt.Errorf("dns: conditional forwarding: at most %d zones in all", fwdMaxZones)
	}
	return out, nil
}

// forwardListMap returns the zones of each list by name (lines that do not parse are skipped: they were checked when
// the configuration was loaded).
func (d *DNSConfig) forwardListMap() map[string][]string {
	m := make(map[string][]string, len(d.ForwardLists))
	for _, l := range d.ForwardLists {
		if name, zones, err := parseForwardList(l); err == nil {
			m[name] = zones
		}
	}
	return m
}

// zonesOnlyFirstZone is the zone a server that serves only zones is probed with when it has no probe queries of its
// own: the SOA of the first zone of its first list that has one.
func (d DNSConfig) zonesOnlyFirstZone(addr string) string {
	f, ok := d.ServerForward[addr]
	if !ok || !f.ZonesOnly {
		return ""
	}
	lm := d.forwardListMap()
	for _, ln := range f.Lists {
		if z := lm[ln]; len(z) > 0 {
			return z[0]
		}
	}
	return ""
}

// validateForwarding checks and tidies the conditional-forwarding settings of a DNS block.  servers are its normal
// servers (normalised).  That a server's lists exist is checked by DaemonConfig.Validate, which sees the shared lists.
func (d *DNSConfig) validateForwarding(servers map[string]bool) error {
	fl, err := normalizeForwardLists(d.ForwardLists)
	if err != nil {
		return err
	}
	d.ForwardLists = fl
	if len(d.ServerForward) == 0 {
		d.ServerForward = nil
		return nil
	}
	out := make(map[string]ServerForward, len(d.ServerForward))
	for k, f := range d.ServerForward {
		n, err := normalizeServer(k)
		if err != nil || !servers[n] {
			return fmt.Errorf("dns: server_forward entry %q is not one of the servers", k)
		}
		var lists []string
		for _, ln := range f.Lists {
			ln = strings.ToLower(strings.TrimSpace(ln))
			if !validListName(ln) {
				return fmt.Errorf("dns: server %s: %q is not a list name", n, ln)
			}
			if !containsStr(lists, ln) {
				lists = append(lists, ln)
			}
		}
		if len(lists) == 0 {
			if f.ZonesOnly {
				return fmt.Errorf("dns: server %s serves only zones but has no list of zones", n)
			}
			continue // a public server needs no entry
		}
		out[n] = ServerForward{Lists: lists, ZonesOnly: f.ZonesOnly}
	}
	d.ServerForward = out
	if len(out) == 0 {
		d.ServerForward = nil
	}
	return nil
}

// checkForwardLists says which list a server of this block names that the shared Settings do not have.
func (d *DNSConfig) checkForwardLists(shared *DNSConfig, where string) error {
	if len(d.ServerForward) == 0 {
		return nil
	}
	have := shared.forwardListMap()
	addrs := make([]string, 0, len(d.ServerForward))
	for a := range d.ServerForward {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	for _, a := range addrs {
		for _, ln := range d.ServerForward[a].Lists {
			if _, ok := have[ln]; !ok {
				return fmt.Errorf("%s: server %s serves the zone list %q, which does not exist (Configure ▸ DNS proxy ▸ Conditional Forwarding)", where, a, ln)
			}
		}
	}
	return nil
}

// ── Routing ──────────────────────────────────────────────────────────────────

// fwdRouter sends a query to the servers of its zone.  It is nil in a pool where no server carries a list.
type fwdRouter struct {
	zones map[string][]*Server // zone -> the servers that carry a list with it
	lists map[string][]string  // zone -> the names of the lists with it
	snaps sync.Map             // scope -> *rankSnap: the ranking of the servers of one zone ("" = the general servers)
}

func newFwdRouter(cfg DNSConfig, servers []*Server) *fwdRouter {
	if len(cfg.ServerForward) == 0 {
		return nil
	}
	lm := cfg.forwardListMap()
	r := &fwdRouter{zones: map[string][]*Server{}, lists: map[string][]string{}}
	for _, s := range servers {
		if s.Fallback {
			continue
		}
		for _, ln := range s.lists {
			for _, z := range lm[ln] {
				if !containsServer(r.zones[z], s) {
					r.zones[z] = append(r.zones[z], s)
				}
				if !containsStr(r.lists[z], ln) {
					r.lists[z] = append(r.lists[z], ln)
				}
			}
		}
	}
	if len(r.zones) == 0 {
		return nil // lists no zone of which has a server: everything is general
	}
	return r
}

func containsServer(l []*Server, s *Server) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// match returns the most specific zone that name (lower case, no trailing dot) is in, and its servers; "" if none.
func (r *fwdRouter) match(name []byte) (string, []*Server) {
	for i := 0; i < len(name); {
		if srv, ok := r.zones[string(name[i:])]; ok { // the conversion in a map index does not allocate
			return string(name[i:]), srv
		}
		j := bytes.IndexByte(name[i:], '.')
		if j < 0 {
			break
		}
		i += j + 1
	}
	return "", nil
}

// upForLocked says whether the server is in service for a zone ("" = for ordinary names): by its probe domains in that
// zone when it has any, by its general state otherwise.  s.mu is held.
func (s *Server) upForLocked(zone string) bool {
	if zone != "" && s.zoneProbed[zone] {
		return s.zoneUp[zone]
	}
	return s.healthy
}

// rankedWhere is Ranked for the servers keep accepts (nil = all).  Fallback servers are used, while no normal server
// that was accepted is up, only when fallbacks says so.
func (p *Pool) rankedWhere(keep func(*Server) bool, fallbacks bool, zone string) []*Server {
	type ent struct {
		s *Server
		l float64
	}
	var es, fbs []ent
	for _, s := range p.servers {
		if keep != nil && !keep(s) {
			continue
		}
		s.mu.Lock()
		if s.upForLocked(zone) {
			if s.Fallback {
				fbs = append(fbs, ent{s, s.ewma})
			} else {
				es = append(es, ent{s, s.ewma})
			}
		}
		s.mu.Unlock()
	}
	if len(es) == 0 && fallbacks { // every normal server is down: the fallback servers take over until one is back
		es = fbs
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].l != es[j].l {
			return es[i].l < es[j].l
		}
		return es[i].s.Addr < es[j].s.Addr
	})
	out := make([]*Server, len(es))
	for i, e := range es {
		out[i] = e.s
	}
	return out
}

// scopedSnap is rankedSnap for one scope: the servers of a zone (keep accepts them, no fallback servers) or, for the
// scope "", the general servers (those that do not serve only zones, and the fallback servers).
func (p *Pool) scopedSnap(scope string, keep func(*Server) bool, fallbacks bool) *rankSnap {
	now := time.Now().UnixNano()
	gen := p.rankGen.Load()
	if v, ok := p.fwd.snaps.Load(scope); ok {
		if sn := v.(*rankSnap); sn.gen == gen && now-sn.at < int64(rankMaxAge) {
			return sn
		}
	}
	sn := &rankSnap{at: now, gen: gen, list: p.rankedWhere(keep, fallbacks, scope)}
	sn.lat = make([]float64, len(sn.list))
	for i, s := range sn.list {
		s.mu.Lock()
		sn.lat[i] = s.ewma
		s.mu.Unlock()
	}
	p.fwd.snaps.Store(scope, sn)
	return sn
}

func serverIsGeneral(s *Server) bool { return !s.zonesOnly }

// candidatesFor is Candidates for the query qi: with conditional forwarding on, the servers of the query's zone, or
// the general servers when it is in none.  With spread on, the ones within the band of the fastest take turns.
func (p *Pool) candidatesFor(qi *qinfo) []*Server {
	if p.fwd == nil {
		return p.Candidates()
	}
	var sn *rankSnap
	if qi.ok && qi.n > 0 {
		if zone, set := p.fwd.match(qi.buf[:qi.n]); zone != "" {
			sn = p.scopedSnap(zone, func(s *Server) bool { return containsServer(set, s) }, false)
		}
	}
	if sn == nil {
		sn = p.scopedSnap("", serverIsGeneral, true)
	}
	if !p.cfg.Spread || len(sn.list) < 2 {
		return sn.list
	}
	return spreadOrder(sn.list, sn.lat, p.cfg.SpreadBand, p.rr.Add(1)-1)
}

// FwdRoute says where a name would go: for the lookup box on the Conditional Forwarding settings.
type FwdRoute struct {
	Name    string     `json:"name"`
	Zone    string     `json:"zone,omitempty"`  // the most specific zone it is in; empty when in none
	Lists   []string   `json:"lists,omitempty"` // the lists that have that zone
	General bool       `json:"general"`         // it goes to the general servers (it is in no zone that has a server)
	Servers []FwdServe `json:"servers"`         // who would be asked, first choice first (down servers last, marked)
}

// FwdServe is one server in a FwdRoute.
type FwdServe struct {
	Addr    string  `json:"addr"`
	Healthy bool    `json:"healthy"`
	MS      float64 `json:"ms"`
	Type    string  `json:"type"`
}

// Route works out where a query for name would go now, without sending anything.
func (p *Pool) Route(name string) FwdRoute {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	rt := FwdRoute{Name: name, General: true}
	var keep func(*Server) bool
	fallbacks := true
	keep = serverIsGeneral
	if p.fwd != nil && name != "" {
		if zone, set := p.fwd.match([]byte(name)); zone != "" {
			rt.Zone, rt.Lists, rt.General = zone, append([]string(nil), p.fwd.lists[zone]...), false
			keep = func(s *Server) bool { return containsServer(set, s) }
			fallbacks = false
		}
	}
	if p.fwd == nil {
		keep = nil
	}
	up := map[*Server]bool{}
	for _, s := range p.rankedWhere(keep, fallbacks, rt.Zone) {
		up[s] = true
		rt.Servers = append(rt.Servers, p.serveOf(s, true))
	}
	for _, s := range p.servers { // the rest, so a zone whose servers are all down shows them
		if (keep == nil || keep(s)) && !up[s] && (!s.Fallback || rt.General) {
			rt.Servers = append(rt.Servers, p.serveOf(s, false))
		}
	}
	return rt
}

func (p *Pool) serveOf(s *Server, up bool) FwdServe {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := fwdPublic
	switch {
	case s.Fallback:
		t = "fallback"
	case s.zonesOnly:
		t = fwdInternal
	case len(s.lists) > 0:
		t = fwdBoth
	}
	return FwdServe{Addr: s.Addr, Healthy: up, MS: round2(s.ewma), Type: t}
}

// fwdWarnings are the problems with conditional forwarding in one pool's configuration: the zone lists that no server
// of it serves (their zones then go to its general servers, which is not what a list of internal zones is for).
func fwdWarnings(cfg DNSConfig) []string {
	if len(cfg.ForwardLists) == 0 {
		return nil
	}
	used := map[string]bool{}
	for _, s := range cfg.Servers {
		for _, ln := range cfg.ServerForward[s].Lists {
			used[ln] = true
		}
	}
	var out []string
	for _, l := range cfg.ForwardLists {
		name, zones, err := parseForwardList(l)
		if err != nil || len(zones) == 0 || used[name] {
			continue
		}
		out = append(out, fmt.Sprintf("the zone list %s is not served by any server here: its zones go to the other servers", name))
	}
	return out
}

// setServerForward changes what one server serves (--canvas-set server --server-type / --lists).  typ is public,
// internal or both ("" leaves it); lists are zone list names separated by commas, or "-" for none ("" leaves them).
func setServerForward(dc *DaemonConfig, d *DNSConfig, addr, typ, lists string) (string, error) {
	cur := d.ServerForward[addr]
	typ = strings.ToLower(strings.TrimSpace(typ))
	switch typ {
	case "", fwdPublic, fwdInternal, fwdBoth:
	default:
		return "", errors.New("--server-type must be public, internal or both")
	}
	if l := strings.TrimSpace(lists); l != "" {
		cur.Lists = nil
		if l != "-" {
			have := dc.DNS.forwardListMap()
			for _, f := range strings.FieldsFunc(l, func(r rune) bool { return r == ',' || r == ' ' }) {
				f = strings.ToLower(f)
				if _, ok := have[f]; !ok {
					return "", fmt.Errorf("there is no zone list %q (Configure ▸ DNS proxy ▸ Conditional Forwarding)", f)
				}
				if !containsStr(cur.Lists, f) {
					cur.Lists = append(cur.Lists, f)
				}
			}
		}
	}
	switch typ {
	case fwdPublic:
		if len(cur.Lists) > 0 && strings.TrimSpace(lists) != "" && strings.TrimSpace(lists) != "-" {
			return "", errors.New("a public server has no zone lists: use --server-type internal or both with --lists, or leave --lists out")
		}
		cur = ServerForward{}
	case fwdInternal:
		cur.ZonesOnly = true
	case fwdBoth:
		cur.ZonesOnly = false
	}
	if len(cur.Lists) == 0 {
		if typ == fwdInternal || typ == fwdBoth {
			return "", errors.New("--server-type internal or both needs zone lists: give --lists NAME,NAME")
		}
		cur = ServerForward{}
	}
	if d.ServerForward == nil {
		d.ServerForward = map[string]ServerForward{}
	}
	if len(cur.Lists) == 0 {
		delete(d.ServerForward, addr)
	} else {
		d.ServerForward[addr] = cur
	}
	if len(d.ServerForward) == 0 {
		d.ServerForward = nil
	}
	return fmt.Sprintf("server %s: %s", addr, describeForward(cur)), nil
}

// describeForward says in words what a server with this setting serves.
func describeForward(f ServerForward) string {
	switch f.fwdType() {
	case fwdInternal:
		return "internal: answers only the zones of " + strings.Join(f.Lists, ", ")
	case fwdBoth:
		return "public + internal: answers the zones of " + strings.Join(f.Lists, ", ") + " and everything else"
	}
	return "public: answers everything except the zones other servers carry"
}

// printFwdRoute prints a FwdRoute for --fwd-route.
func printFwdRoute(r FwdRoute) {
	if r.General {
		fmt.Printf("%s is in no zone with a server: it goes to the general servers\n", r.Name)
	} else {
		fmt.Printf("%s is in the zone %s (list %s): it goes only to the servers of that zone\n", r.Name, r.Zone, strings.Join(r.Lists, ", "))
	}
	for i, s := range r.Servers {
		state := "up"
		if !s.Healthy {
			state = "DOWN"
		}
		order := "  "
		if s.Healthy && i == 0 {
			order = "1."
		}
		fmt.Printf("  %s %s  %-8s %s  %.1f ms\n", order, s.Addr, s.Type, state, s.MS)
	}
	if len(r.Servers) == 0 {
		fmt.Println("  no server")
	}
}

// serverZones is the set of zones of the lists a server serves.
func (d DNSConfig) serverZones(addr string) map[string]bool {
	f, ok := d.ServerForward[addr]
	if !ok || len(f.Lists) == 0 {
		return nil
	}
	lm := d.forwardListMap()
	set := map[string]bool{}
	for _, ln := range f.Lists {
		for _, z := range lm[ln] {
			set[z] = true
		}
	}
	return set
}

// zoneOfName returns the most specific zone of set that name (lower case, no trailing dot) is in, "" if none.
func zoneOfName(set map[string]bool, name string) string {
	if len(set) == 0 {
		return ""
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for i := 0; i < len(name); {
		if set[name[i:]] {
			return name[i:]
		}
		j := strings.IndexByte(name[i:], '.')
		if j < 0 {
			break
		}
		i += j + 1
	}
	return ""
}

// probeZone is the zone a probe domain of a server is for: the most specific zone of the lists the server serves that
// the name is in, "" for a probe of ordinary names (see Server.upForLocked).
func (d DNSConfig) probeZone(addr, name string) string {
	return zoneOfName(d.serverZones(addr), name)
}

// probeZones gives the zone of each probe query qs of a server, and the set of zones some probe is for.
func (d DNSConfig) probeZones(addr string, qs []DNSQuery) ([]string, map[string]bool) {
	set := d.serverZones(addr)
	zq := make([]string, len(qs))
	probed := map[string]bool{}
	for i, q := range qs {
		if z := zoneOfName(set, q.Name); z != "" {
			zq[i] = z
			probed[z] = true
		}
	}
	return zq, probed
}

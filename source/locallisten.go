package main

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Listening on the node's own addresses.
//
// With dns.listen_local on, the node also answers DNS (and DNS over TLS and HTTPS, on their ports) on the addresses
// of its own network interfaces, next to the shared address and the anycast addresses.  Those answer on every node
// at all times, whether or not the node holds the shared address, so a client, a monitoring system or an admin can
// ask one particular node.  The addresses that belong to a gateway (its shared addresses, the further addresses of
// them and the anycast addresses) are left to the gateway; loopback and link-local addresses are not used.
//
// The queries go through the pool of the lowest-numbered gateway that is running here (the shared pool when there is
// none), with that gateway's rules for who may ask.

var localEvery = 10 * time.Second // how often the interfaces are looked at again (addresses come and go)

// localAddrsFn lists the unicast addresses of this node's interfaces (replaceable in tests).
var localAddrsFn = func() []netip.Addr {
	var out []netip.Addr
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		n := ifc.Name
		if strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "virbr") || strings.HasPrefix(n, "br-") {
			continue
		}
		as, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ad, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ad = ad.Unmap()
			if ad.IsLoopback() || ad.IsLinkLocalUnicast() || ad.IsMulticast() || ad.IsUnspecified() {
				continue
			}
			out = append(out, ad)
		}
	}
	return out
}

type localListeners struct {
	mu      sync.Mutex
	fes     map[netip.Addr]*DNSFrontend
	failed  map[netip.Addr]string // why an address could not be opened, so it is said once
	stopped bool                  // the supervisor is stopping: nothing is opened again
}

// localPool is the pool the node's own addresses use: the lowest-numbered running gateway's, else the shared one.
func (s *Supervisor) localPool() *Pool {
	s.poolMu.RLock()
	defer s.poolMu.RUnlock()
	best, found := 0, false
	for gid := range s.keyOf {
		if !found || gid < best {
			best, found = gid, true
		}
	}
	if found {
		return s.pools[s.keyOf[best]]
	}
	return s.pools[0]
}

// gatewayAddrs are the addresses that belong to gateways: the node's own listeners must not take them.
func gatewayAddrs(dc *DaemonConfig) map[netip.Addr]bool {
	m := map[netip.Addr]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			m[p.Addr().Unmap()] = true
		} else if a, err := netip.ParseAddr(s); err == nil {
			m[a.Unmap()] = true
		}
	}
	for _, g := range dc.Groups {
		add(g.VIP4)
		add(g.VIP6)
		for _, a := range g.MoreVIP4 {
			add(a)
		}
		for _, a := range g.MoreVIP6 {
			add(a)
		}
		for _, a := range g.ExtraVIPs {
			add(a)
		}
	}
	return m
}

// reconcileLocal makes the listeners match the setting and the interfaces now.
func (s *Supervisor) reconcileLocal() {
	s.mu.Lock()
	dc := s.dc
	s.mu.Unlock()
	if dc == nil {
		return
	}
	l := &s.local
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		return
	}
	if l.fes == nil {
		l.fes, l.failed = map[netip.Addr]*DNSFrontend{}, map[netip.Addr]string{}
	}
	want := map[netip.Addr]bool{}
	if dc.DNS.ListenLocal {
		skip := gatewayAddrs(dc)
		for _, a := range localAddrsFn() {
			if !skip[a] {
				want[a] = true
			}
		}
	}
	port, dot, doh := dc.DNS.ListenPort, dc.DNS.DoTPort, dc.DNS.DoHPort
	var stop []*DNSFrontend
	for a, f := range l.fes {
		if !want[a] || f.port != port || f.dotPort != dot || f.dohPort != doh {
			stop = append(stop, f)
			delete(l.fes, a)
			if !want[a] {
				delete(l.failed, a)
			}
		}
	}
	for _, f := range stop {
		f.Stop()
	}
	for a := range want {
		if l.fes[a] != nil {
			continue
		}
		f := NewDNSFrontend(a, port, s.localPool)
		f.dotPort, f.dohPort = dot, doh
		if err := f.Start(); err != nil {
			if l.failed[a] != err.Error() {
				l.failed[a] = err.Error()
				errorf("dns: cannot listen on this node's own address %s: %v", f.listenAddr(), err)
			}
			continue
		}
		delete(l.failed, a)
		l.fes[a] = f
	}
}

// stopLocal closes the node's own listeners.
func (s *Supervisor) stopLocal() {
	l := &s.local
	l.mu.Lock()
	fes := l.fes
	l.fes, l.failed, l.stopped = nil, nil, true
	l.mu.Unlock()
	for _, f := range fes {
		f.Stop()
	}
}

// localLoop looks at the interfaces from time to time while the supervisor runs.
func (s *Supervisor) localLoop(ctx context.Context) {
	t := time.NewTicker(localEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reconcileLocal()
		}
	}
}

// localListenerNames are the node's own listening addresses, for the status page.
func (s *Supervisor) localListenerNames() []string {
	l := &s.local
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, f := range l.fes {
		out = append(out, "this node "+f.listenAddr())
	}
	sort.Strings(out)
	return out
}

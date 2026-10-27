package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Upstream names (bootstrap).  An upstream given by name (tls://dns.example.com, https://dns.example.com/dns-query) has
// to be turned into an address before it can be dialled.  Asking the host's resolver for it is a loop when the host's
// resolver is this node's own VIP: the name is then only as good as the upstreams it is meant to reach.  So the name
// is asked of the upstreams that are given by address and are up (a plain server, or tls:// / https:// with an IP),
// those of the server's own gateway first, fastest first; then of the bootstrap servers of the dns block; and only when
// there is none of those, of the host's resolver.  An answer is kept for its TTL (30 s to 1 h), and the last good one is
// used for as long as no fresh one can be had, so a resolver that stumbles does not take a working server out.

const (
	bootMinTTL   = 30 * time.Second
	bootMaxTTL   = time.Hour
	bootTimeout  = 2 * time.Second
	bootSources  = 4 // servers asked at the most for one name, in order, before giving up on them
	bootHostNote = "host resolver"
)

type bootEntry struct {
	ips []string  // IPv4 first
	exp time.Time // fresh until then
	via string    // the server that answered, or bootHostNote
}

type bootResolver struct {
	mu        sync.Mutex
	cache     map[string]*bootEntry
	pools     map[*Pool]bool
	extra     []string // dns.bootstrap: plain servers to ask when no upstream given by address is up
	inflight  map[string]chan struct{}
	exchange  func(ctx context.Context, addr string, q []byte) ([]byte, error) // replaced in tests
	hostLook  func(ctx context.Context, host string) ([]string, error)         // replaced in tests
	now       func() time.Time
	warnedFor map[string]time.Time
}

var boot = newBootResolver()

func newBootResolver() *bootResolver {
	// exchange is left nil (bootExchange is used): naming it here would make the package's start-up go round in a circle
	return &bootResolver{cache: map[string]*bootEntry{}, pools: map[*Pool]bool{}, inflight: map[string]chan struct{}{}, warnedFor: map[string]time.Time{},
		hostLook: net.DefaultResolver.LookupHost,
		now:      time.Now,
	}
}

func bootExchange(ctx context.Context, addr string, q []byte) ([]byte, error) {
	b, _, err := exchange(ctx, addr, q, false, bootTimeout)
	return b, err
}

func (b *bootResolver) register(p *Pool) {
	b.mu.Lock()
	b.pools[p] = true
	b.mu.Unlock()
}

func (b *bootResolver) unregister(p *Pool) {
	b.mu.Lock()
	delete(b.pools, p)
	b.mu.Unlock()
}

// setExtra sets the bootstrap servers of the dns block (normalised plain addresses).
func (b *bootResolver) setExtra(l []string) {
	b.mu.Lock()
	b.extra = append([]string(nil), l...)
	b.mu.Unlock()
}

// upstreamHost is the host part of an upstream address: a name or an IP.
func upstreamHost(addr string) string {
	if strings.HasPrefix(addr, dohScheme) {
		if u, err := url.Parse(addr); err == nil {
			return u.Hostname()
		}
		return ""
	}
	hp := strings.TrimPrefix(addr, dotScheme)
	if h, _, err := net.SplitHostPort(hp); err == nil {
		return h
	}
	return hp
}

func isIPHost(h string) bool { return net.ParseIP(h) != nil }

// sources are the servers to ask for host, best first: the upstreams given by address that are up, those of a pool that
// has a server called host first, each pool's fastest first; then the bootstrap servers.
func (b *bootResolver) sources(host string) []string {
	b.mu.Lock()
	pools := make([]*Pool, 0, len(b.pools))
	for p := range b.pools {
		pools = append(pools, p)
	}
	extra := append([]string(nil), b.extra...)
	b.mu.Unlock()
	owns := func(p *Pool) bool {
		for _, s := range p.servers {
			if upstreamHost(s.Addr) == host {
				return true
			}
		}
		return false
	}
	sort.SliceStable(pools, func(i, j int) bool { return owns(pools[i]) && !owns(pools[j]) })
	var out []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, p := range pools {
		for _, s := range p.Ranked() {
			if !s.zonesOnly && isIPHost(upstreamHost(s.Addr)) {
				add(s.Addr)
			}
		}
	}
	// just after a start nothing has been probed yet: the servers given by address that are not known to be down
	// still come before the host's resolver
	for _, p := range pools {
		for _, s := range p.servers {
			s.mu.Lock()
			unknown := s.lastProbe.IsZero()
			s.mu.Unlock()
			if unknown && !s.Fallback && !s.zonesOnly && isIPHost(upstreamHost(s.Addr)) {
				add(s.Addr)
			}
		}
	}
	for _, a := range extra {
		add(a)
	}
	return out
}

// lookup returns the addresses of host (IPv4 first) and which server gave them.
func (b *bootResolver) lookup(ctx context.Context, host string) ([]string, string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for {
		b.mu.Lock()
		e := b.cache[host]
		if e != nil && b.now().Before(e.exp) {
			b.mu.Unlock()
			return e.ips, e.via, nil
		}
		if ch := b.inflight[host]; ch != nil { // someone is asking already: wait for that answer
			b.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, "", ctx.Err()
			}
		}
		ch := make(chan struct{})
		b.inflight[host] = ch
		b.mu.Unlock()
		ips, via, ttl, err := b.resolve(ctx, host)
		b.mu.Lock()
		delete(b.inflight, host)
		close(ch)
		switch {
		case err == nil:
			b.cache[host] = &bootEntry{ips: ips, exp: b.now().Add(ttl), via: via}
		case e != nil && len(e.ips) > 0:
			// no fresh answer: the last good one stays in use, asked again in a while
			e.exp = b.now().Add(bootMinTTL)
			ips, via, err = e.ips, e.via, nil
		}
		b.mu.Unlock()
		return ips, via, err
	}
}

func (b *bootResolver) resolve(ctx context.Context, host string) ([]string, string, time.Duration, error) {
	srcs := b.sources(host)
	var lastErr error
	for i, src := range srcs {
		if i == bootSources {
			break
		}
		ips, ttl, err := b.ask(ctx, src, host)
		if err == nil {
			return ips, upstreamHost(src), ttl, nil
		}
		lastErr = fmt.Errorf("%s: %w", upstreamHost(src), err)
		if ctx.Err() != nil {
			break
		}
	}
	if len(srcs) > 0 {
		return nil, "", 0, lastErr
	}
	// no upstream given by address and no bootstrap server: the host's resolver, which may be this node itself
	b.warnLoop(host)
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := b.hostLook(hctx, host)
	if err != nil {
		return nil, "", 0, err
	}
	return ipv4First(ips), bootHostNote, bootMinTTL * 2, nil
}

func (b *bootResolver) warnLoop(host string) {
	b.mu.Lock()
	last := b.warnedFor[host]
	if b.now().Sub(last) < time.Hour {
		b.mu.Unlock()
		return
	}
	b.warnedFor[host] = b.now()
	b.mu.Unlock()
	warnf("dns: %s is looked up through the host's resolver: no upstream server given by IP address is up and no bootstrap server is set; if the host's resolver is this node, the server can only be reached while another one answers", host)
}

// ask asks one server for the A and AAAA records of host.
func (b *bootResolver) ask(ctx context.Context, src, host string) ([]string, time.Duration, error) {
	var ips []string
	ttl := bootMaxTTL
	var firstErr error
	answered := false
	for _, qt := range []string{"A", "AAAA"} {
		q, err := buildQuery(uint16(rand.Uint32()), host, qt)
		if err != nil {
			return nil, 0, err
		}
		qctx, cancel := context.WithTimeout(ctx, bootTimeout)
		ex := b.exchange
		if ex == nil {
			ex = bootExchange
		}
		resp, err := ex(qctx, src, q)
		cancel()
		if err == nil {
			var got []string
			var t time.Duration
			got, t, err = answerIPs(resp, qt)
			if err == nil {
				answered = true
				ips = append(ips, got...)
				if len(got) > 0 && t < ttl {
					ttl = t
				}
			}
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if len(ips) == 0 {
		if firstErr == nil || answered {
			firstErr = errors.New("no address for " + host)
		}
		return nil, 0, firstErr
	}
	if ttl < bootMinTTL {
		ttl = bootMinTTL
	}
	return ipv4First(ips), ttl, nil
}

// answerIPs takes the addresses of type qt out of a response, and the smallest TTL among them.
func answerIPs(resp []byte, qt string) ([]string, time.Duration, error) {
	h, ok := parseHeader(resp)
	if !ok || !h.qr {
		return nil, 0, errors.New("malformed answer")
	}
	switch h.rcode {
	case rcodeNoError:
	case 3:
		return nil, 0, errors.New("no such name")
	default:
		return nil, 0, fmt.Errorf("the server answered %s", rcodeText(h.rcode))
	}
	rrs, err := parseRRs(resp)
	if err != nil {
		return nil, 0, err
	}
	want, size := uint16(1), 4
	if qt == "AAAA" {
		want, size = 28, 16
	}
	var out []string
	ttl := bootMaxTTL
	for _, rr := range rrs {
		if rr.sec != 0 || rr.typ != want || rr.length != size {
			continue
		}
		out = append(out, net.IP(resp[rr.off:rr.off+size]).String())
		if t := time.Duration(rr.ttl) * time.Second; t < ttl {
			ttl = t
		}
	}
	return out, ttl, nil
}

func rcodeText(rc int) string {
	switch rc {
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return fmt.Sprintf("rcode %d", rc)
}

// resolvedVia says, for an upstream given by name, what it resolves to and from where ("" for one given by address
// or not looked up yet).
func (b *bootResolver) resolvedVia(addr string) (ips []string, via string) {
	h := upstreamHost(addr)
	if h == "" || isIPHost(h) {
		return nil, ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.cache[strings.ToLower(h)]; e != nil {
		return e.ips, e.via
	}
	return nil, ""
}

// dialUpstream dials an upstream's host:port, looking a name up as above.  The TLS name check (done by the caller)
// still uses the name, so how the address was found does not weaken it.
func dialUpstream(ctx context.Context, d *net.Dialer, network, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || isIPHost(host) {
		return dialPrefer4(ctx, d, network, hostport)
	}
	ips, _, err := boot.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %v", host, err)
	}
	var lastErr error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return c, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("cannot resolve " + host + ": no address")
	}
	return nil, lastErr
}

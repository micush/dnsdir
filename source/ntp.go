package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ── Upstream exchange ────────────────────────────────────────────────────────

// dialUDP opens a connected UDP socket to a server (a probe uses one of its own, so a late answer to an earlier probe is
// never mistaken for this one's).
func dialUDP(ctx context.Context, addr string) (*net.UDPConn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

// ── Probing over both address families ───────────────────────────────────────

// A server named by host is probed over IPv4 and over IPv6 (when it has an A and an AAAA record), each on a socket of its own.
// The server is up when either family answers well; the measurements that count (round trip, offset, stratum) are IPv4's when
// IPv4 answers well, IPv6's only when it does not — IPv4 is preferred.  A server given as an address has the one family.
const (
	fam4 = 0
	fam6 = 1
)

var famName = [2]string{"IPv4", "IPv6"}

// lookupServerIPs resolves host for one family ("ip4" or "ip6"); replaced in tests.
var lookupServerIPs = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// famResult is what one family's probe of a server came to.
type famResult struct {
	Tried bool   // the server has an address of this family
	Addr  string // the address (host:port) that was probed
	s     ntpSample
	err   error // the probe failed or the answer was not good enough (see NTPConfig.judge)
}

// probeFamilies probes addr (host:port) over each family it has an address for.  The families are probed at the same time.
func (p *Pool) probeFamilies(ctx context.Context, addr string) (res [2]famResult) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		res[fam4] = famResult{Tried: true, Addr: addr, err: err}
		return res
	}
	timeout := p.cfg.probeTimeout()
	var target [2]string
	var lookupErr [2]error
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ip = ip.Unmap()
		f := fam6
		if ip.Is4() {
			f = fam4
		}
		target[f] = addr
	} else {
		lctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var wg sync.WaitGroup
		for f, network := range [2]string{"ip4", "ip6"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ips, err := lookupServerIPs(lctx, network, host)
				if err != nil {
					lookupErr[f] = err
				}
				if len(ips) > 0 {
					target[f] = net.JoinHostPort(ips[0].Unmap().String(), port)
				}
			}()
		}
		wg.Wait()
		if target[fam4] == "" && target[fam6] == "" {
			err := lookupErr[fam4]
			if err == nil {
				err = lookupErr[fam6]
			}
			if err == nil {
				err = errors.New("no address")
			}
			res[fam4] = famResult{Tried: true, Addr: addr, err: fmt.Errorf("cannot resolve %s: %v", host, err)}
			return res
		}
	}
	var wg sync.WaitGroup
	for f := range target {
		if target[f] == "" {
			continue
		}
		res[f].Tried, res[f].Addr = true, target[f]
		wg.Add(1)
		go func() {
			defer wg.Done()
			smp, err := ntpProbe(ctx, target[f], timeout)
			if err == nil {
				err = p.cfg.judge(smp)
			}
			res[f].s, res[f].err = smp, err
		}()
	}
	wg.Wait()
	return res
}

// foldFamilies is the one result a server has for the round: the first family (IPv4, then IPv6) that answered well, else
// the failure, which names both families when both were tried.  via is the family the result comes from.
func foldFamilies(res [2]famResult) (smp ntpSample, err error, via int) {
	for f := range res {
		if res[f].Tried && res[f].err == nil {
			return res[f].s, nil, f
		}
	}
	var msgs []string
	via = fam4
	first := true
	for f := range res {
		if !res[f].Tried {
			continue
		}
		if first {
			smp, via, first = res[f].s, f, false
		}
		msgs = append(msgs, res[f].err.Error())
	}
	switch len(msgs) {
	case 0:
		return smp, errors.New("no address to probe"), via
	case 1:
		return smp, errors.New(msgs[0]), via
	}
	return smp, fmt.Errorf("IPv4: %s; IPv6: %s", msgs[0], msgs[1]), via
}

// ntpSample is what one probe of a server found out.
type ntpSample struct {
	RTT       time.Duration // round trip as this side measured it
	Offset    time.Duration // the server's clock minus this node's (positive: the server is ahead)
	Delay     time.Duration // the round trip without the time the server held the packet
	Stratum   uint8
	Leap      uint8
	Version   uint8
	RefID     string
	RootDelay time.Duration
	RootDisp  time.Duration
	RootDist  time.Duration // the largest error the server's time can have: root delay/2 + root dispersion + delay/2
	KoD       string        // the kiss-o'-death code, when that is what came back
	xmit      uint64
	recv      uint64
}

// ntpProbe asks addr for the time on a socket of its own and works out the offset and delay from the four
// timestamps (RFC 5905, section 8).  It returns an error for a server that does not answer; whether the answer is
// good enough is for NTPConfig.judge.
func ntpProbe(ctx context.Context, addr string, timeout time.Duration) (ntpSample, error) {
	var s ntpSample
	c, err := dialUDP(ctx, addr)
	if err != nil {
		return s, err
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	c.SetDeadline(deadline)
	req := buildNTPRequest(randomXmit())
	t1 := time.Now()
	if _, err := c.Write(req); err != nil {
		return s, err
	}
	buf := make([]byte, ntpMaxPacket)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				return s, errors.New("no answer (timeout)")
			}
			return s, err
		}
		t4 := time.Now()
		if !ntpAnswers(req, buf[:n]) {
			continue // not for this request: keep waiting until the deadline
		}
		p, _ := parseNTP(buf[:n])
		s.RTT = t4.Sub(t1)
		s.Stratum, s.Leap, s.Version = p.Stratum, p.Leap, p.Version
		s.RefID = refIDString(p.Stratum, p.RefID)
		s.RootDelay, s.RootDisp = p.RootDelay, p.RootDisp
		s.xmit, s.recv = p.Xmit, p.Recv
		if p.Stratum == 0 {
			s.KoD = kodCode(buf[:n])
			return s, nil
		}
		if p.Recv != 0 && p.Xmit != 0 {
			t2, t3 := ntpToTime(p.Recv), ntpToTime(p.Xmit)
			hold := t3.Sub(t2)
			if hold < 0 {
				hold = 0
			}
			s.Delay = s.RTT - hold
			if s.Delay < 0 {
				s.Delay = 0
			}
			s.Offset = (t2.Sub(t1) + t3.Sub(t4)) / 2
		} else {
			s.Delay = s.RTT
		}
		s.RootDist = s.RootDelay/2 + s.RootDisp + s.Delay/2
		return s, nil
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// judge says whether a probe's answer is one the server may be used on: it must be a real answer from a
// synchronised clock that is near enough to its own source of time.  The error says why not.
func (c NTPConfig) judge(s ntpSample) error {
	switch {
	case s.KoD != "":
		return fmt.Errorf("kiss-o'-death %s: the server refuses to answer", s.KoD)
	case s.Leap == ntpLeapUnsynch || s.Stratum >= 16:
		return errors.New("the server's clock is not synchronised")
	case s.xmit == 0 || s.recv == 0:
		return errors.New("the answer carries no timestamps")
	case int(s.Stratum) > c.MaxStratum:
		return fmt.Errorf("stratum %d is more than max_stratum (%d)", s.Stratum, c.MaxStratum)
	case c.MaxRTTMS > 0 && s.RTT > time.Duration(c.MaxRTTMS)*time.Millisecond:
		return fmt.Errorf("round trip %.1f ms is more than max_rtt_ms (%d): too slow", ms(s.RTT), c.MaxRTTMS)
	case c.MaxRootDistanceMS > 0 && s.RootDist > time.Duration(c.MaxRootDistanceMS)*time.Millisecond:
		return fmt.Errorf("root distance %.1f ms is more than max_root_distance_ms (%d)", ms(s.RootDist), c.MaxRootDistanceMS)
	}
	return nil
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// ── Server pool ──────────────────────────────────────────────────────────────

// Server is one upstream NTP server with health and latency state.
type Server struct {
	Addr     string
	Fallback bool // used only while no normal server is healthy

	ipOnce   sync.Once // ip: the address of Addr (invalid for a server named by host)
	ip       netip.Addr
	loopSeen atomic.Int64 // when the "this server sends us its requests" warning was last logged (unix seconds)

	hist *srvSeries // this server's per-minute history (srvhist.go); shared by every pool that lists the address; nil in a hand-made Server

	mu          sync.Mutex
	healthy     bool
	ewma        float64 // ms, 0 until first sample
	last        float64
	fails       int // consecutive failures
	okCount     uint64
	failCount   uint64
	lastErr     string
	lastProbe   time.Time
	info        ntpSample // the last answer a probe got, whatever it was
	haveInfo    bool
	falseticker bool        // the last round found its time far from that of the other servers
	round       *probeRound // this round's result, until the pool has judged all servers together
	fam         [2]famState // what each address family found at the last probe
	via         int         // the family the server's numbers come from (IPv4 whenever it answers well)
}

// probeRound is one server's result in the round under way.
type probeRound struct {
	s   ntpSample
	err error
}

// famState is what a server's probes over one address family have found, for the server list.
type famState struct {
	tried bool
	addr  string
	ok    bool
	ewma  float64 // ms
	err   string
}

// ServerStat is the exported snapshot of a Server.
type ServerStat struct {
	Addr         string  `json:"addr"`
	Name         string  `json:"name,omitempty"` // the name given to the server on the Topology page, if any
	Healthy      bool    `json:"healthy"`
	Fallback     bool    `json:"fallback,omitempty"` // a fallback server: in use only while every normal server is down
	Rank         int     `json:"rank"`               // 1 = fastest healthy; 0 = not eligible
	EWMAMS       float64 `json:"ewma_ms"`
	LastMS       float64 `json:"last_ms"`
	ConsecFails  int     `json:"consec_fails"`
	Successes    uint64  `json:"successes"`
	Failures     uint64  `json:"failures"`
	LastError    string  `json:"last_error,omitempty"`
	LastProbeAgo float64 `json:"last_probe_ago_s"`
	// What the last probe found.  Absent until the server has answered once.
	Time *TimeStat `json:"time,omitempty"`
	// Falseticker: its time differs from that of the other servers by more than max_offset_ms.
	Chrony      string `json:"chrony,omitempty"` // chrony's mark for this server when it is one of its sources (see ChronySrc)
	Falseticker bool   `json:"falseticker,omitempty"`
	// Auth says how the authentication of the server goes when it is set to use NTS or a key (Configure ▸ NTP ▸ Security).
	Auth *AuthStat `json:"auth,omitempty"`
	// Which address families the server was probed over; Via is the one its numbers come from (IPv4 when it answers well).
	Via      string    `json:"via,omitempty"`
	Families []FamStat `json:"families,omitempty"`
}

// FamStat is one address family's part of a server's probes.
type FamStat struct {
	Family string  `json:"family"` // IPv4 or IPv6
	Addr   string  `json:"addr"`   // the address that was probed
	OK     bool    `json:"ok"`
	EWMAMS float64 `json:"ewma_ms,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// TimeStat is what a server's last answer said about its clock.
type TimeStat struct {
	Stratum    int     `json:"stratum"`
	Leap       int     `json:"leap"`
	Version    int     `json:"version"`
	RefID      string  `json:"refid"`
	OffsetMS   float64 `json:"offset_ms"`
	DelayMS    float64 `json:"delay_ms"`
	RootDelay  float64 `json:"root_delay_ms"`
	RootDisp   float64 `json:"root_dispersion_ms"`
	RootDist   float64 `json:"root_distance_ms"`
	KissOfDeth string  `json:"kod,omitempty"`
}

func (s *Server) sample(rtt time.Duration, alpha float64) {
	m := float64(rtt.Microseconds()) / 1000
	s.last = m
	if s.ewma == 0 {
		s.ewma = m
	} else {
		s.ewma = alpha*m + (1-alpha)*s.ewma
	}
}

// Pool probes the configured servers and forwards traffic to the fastest eligible server first.
type Pool struct {
	cfg        NTPConfig
	servers    []*Server
	onFallback atomic.Bool // the pool is answering from its fallback servers (for logging the change)

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewPool(cfg NTPConfig) *Pool {
	p := &Pool{cfg: cfg}
	for _, a := range cfg.Servers {
		p.servers = append(p.servers, &Server{Addr: a, hist: srvhist.series(a)})
	}
	for _, a := range cfg.FallbackServers {
		// a fallback is a last resort: it is never probed and always counts as up
		p.servers = append(p.servers, &Server{Addr: a, Fallback: true, healthy: true, hist: srvhist.series(a)})
	}
	return p
}

// Start launches the background probe loop (first round runs immediately).
func (p *Pool) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.ProbeNow(ctx)
		t := time.NewTicker(p.cfg.probeInterval())
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.ProbeNow(ctx)
			}
		}
	}()
}

func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
}

// ProbeNow runs one probe round against every server concurrently, then judges the servers together: a server
// whose time disagrees with the others' is a falseticker and is taken out like one that does not answer.
func (p *Pool) ProbeNow(ctx context.Context) {
	var wg sync.WaitGroup
	var probed []*Server
	for _, s := range p.servers {
		if s.Fallback {
			continue
		}
		probed = append(probed, s)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverPanic("a probe of " + s.Addr)
			p.probeServer(ctx, s)
		}()
	}
	wg.Wait()
	if ctx.Err() == nil {
		p.judgeRound(probed)
	}
	p.noteFallback()
}

// noteFallback logs the moment the pool starts or stops answering from its fallback servers.
func (p *Pool) noteFallback() {
	use := p.UsingFallback()
	if p.onFallback.Swap(use) == use {
		return
	}
	switch {
	case use:
		warnf("ntp: every configured server is down — answering from the fallback servers")
	case p.normalUp():
		infof("ntp: a configured server answers again — the fallback servers are no longer used")
	default:
		warnf("ntp: the fallback servers are down too — nothing can answer")
	}
}

// UsingFallback reports whether the pool is answering from its fallback servers: no normal server is
// healthy and at least one fallback is.
func (p *Pool) UsingFallback() bool {
	var fb, normal bool
	for _, s := range p.servers {
		s.mu.Lock()
		h := s.healthy
		s.mu.Unlock()
		if !h {
			continue
		}
		if s.Fallback {
			fb = true
		} else {
			normal = true
		}
	}
	return fb && !normal
}

// normalUp reports whether any normal (non-fallback) server is healthy.
func (p *Pool) normalUp() bool {
	for _, s := range p.servers {
		s.mu.Lock()
		h := s.healthy
		s.mu.Unlock()
		if h && !s.Fallback {
			return true
		}
	}
	return false
}

// nNormal is how many servers the pool has apart from the fallback ones.
func (p *Pool) nNormal() int {
	n := 0
	for _, s := range p.servers {
		if !s.Fallback {
			n++
		}
	}
	return n
}

// probeServer asks s for the time once and keeps the answer for judgeRound.
func (p *Pool) probeServer(ctx context.Context, s *Server) {
	res := p.probeFamilies(ctx, s.Addr)
	if ctx.Err() != nil {
		return
	}
	smp, err, via := foldFamilies(res)
	s.mu.Lock()
	for f := range res {
		st := &s.fam[f]
		st.tried, st.addr, st.ok, st.err = res[f].Tried, res[f].Addr, res[f].Tried && res[f].err == nil, ""
		switch {
		case !res[f].Tried:
			st.ewma = 0
		case res[f].err != nil:
			st.err = res[f].err.Error()
		default:
			m := ms(res[f].s.RTT)
			if st.ewma == 0 {
				st.ewma = m
			} else {
				st.ewma = p.cfg.LatencyAlpha*m + (1-p.cfg.LatencyAlpha)*st.ewma
			}
		}
	}
	s.via = via
	s.round = &probeRound{s: smp, err: err}
	if smp.RTT > 0 || smp.Stratum > 0 || smp.KoD != "" {
		s.info, s.haveInfo = smp, true
	}
	s.mu.Unlock()
}

// judgeRound turns the round's results into health.  A server passes when its probe did and, if at least three
// servers passed, its offset is within max_offset_ms (plus half its own delay, which bounds how well the offset can
// be known) of the median: with two servers there is nobody to say which of them is wrong.
func (p *Pool) judgeRound(probed []*Server) {
	type res struct {
		s   *Server
		r   *probeRound
		off float64
	}
	var all, good []res
	for _, s := range probed {
		s.mu.Lock()
		r := s.round
		s.round = nil
		s.mu.Unlock()
		if r == nil {
			continue
		}
		x := res{s: s, r: r, off: ms(r.s.Offset)}
		all = append(all, x)
		if r.err == nil {
			good = append(good, x)
		}
	}
	fals := map[*Server]error{}
	if p.cfg.MaxOffsetMS > 0 && len(good) >= 3 {
		offs := make([]float64, len(good))
		for i, g := range good {
			offs[i] = g.off
		}
		sort.Float64s(offs)
		med := offs[len(offs)/2]
		if len(offs)%2 == 0 {
			med = (offs[len(offs)/2-1] + offs[len(offs)/2]) / 2
		}
		for _, g := range good {
			tol := float64(p.cfg.MaxOffsetMS) + ms(g.r.s.Delay)/2
			if d := g.off - med; d > tol || -d > tol {
				fals[g.s] = fmt.Errorf("falseticker: its time is %.1f ms from the median of the servers (max_offset_ms is %d)", d, p.cfg.MaxOffsetMS)
			}
		}
	}
	for _, x := range all {
		err := x.r.err
		ft := false
		if fe, bad := fals[x.s]; bad {
			err, ft = fe, true
		}
		p.apply(x.s, x.r.s, err, ft)
	}
}

// apply folds one round's verdict on s into its health.
func (p *Pool) apply(s *Server, smp ntpSample, err error, falseticker bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastProbe = time.Now()
	if s.falseticker != falseticker {
		if falseticker {
			warnf("ntp: server %s is a falseticker: %v", s.Addr, err)
		} else {
			infof("ntp: server %s agrees with the other servers again", s.Addr)
		}
	}
	s.falseticker = falseticker
	// the offset graph of the server's statistics: every real, synchronised answer counts, a falseticker's too (that is what
	// the graph is for), but not a refusal or an unsynchronised clock
	if smp.xmit != 0 && smp.recv != 0 && smp.KoD == "" && smp.Leap != ntpLeapUnsynch && smp.Stratum < 16 {
		s.hist.off(smp.Offset)
	}
	if err == nil {
		s.sample(smp.RTT, p.cfg.LatencyAlpha)
		s.okCount++
		s.fails = 0
		s.lastErr = ""
		s.hist.addPrOK()
		s.hist.lat(smp.RTT)
		if !s.healthy {
			s.healthy = true
			infof("ntp: server %s is UP (%.1fms, stratum %d, offset %+.1fms)", s.Addr, s.ewma, smp.Stratum, ms(smp.Offset))
		}
		return
	}
	s.failCount++
	s.fails++
	s.lastErr = err.Error()
	s.hist.addPrFail()
	debugf("ntp: probe of %s failed (%d consecutive): %v", s.Addr, s.fails, err)
	if s.healthy && s.fails >= p.cfg.FailThreshold {
		s.healthy = false
		warnf("ntp: server %s is DOWN: %v", s.Addr, err)
	}
}

// Ranked returns the eligible servers, fastest first.
func (p *Pool) Ranked() []*Server {
	type ent struct {
		s *Server
		l float64
	}
	var es, fbs []ent
	for _, s := range p.servers {
		s.mu.Lock()
		if s.healthy {
			if s.Fallback {
				fbs = append(fbs, ent{s, s.ewma})
			} else {
				es = append(es, ent{s, s.ewma})
			}
		}
		s.mu.Unlock()
	}
	if len(es) == 0 { // every normal server is down: the fallback servers take over until one is back
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

func (p *Pool) Snapshot() []ServerStat {
	rank := map[*Server]int{}
	for i, s := range p.Ranked() {
		rank[s] = i + 1
	}
	out := make([]ServerStat, 0, len(p.servers))
	for _, s := range p.servers {
		s.mu.Lock()
		st := ServerStat{
			Addr: s.Addr, Fallback: s.Fallback, Healthy: s.healthy, Rank: rank[s],
			EWMAMS: round2(s.ewma), LastMS: round2(s.last),
			ConsecFails: s.fails, Successes: s.okCount, Failures: s.failCount,
			LastError: s.lastErr, Falseticker: s.falseticker,
		}
		if s.haveInfo {
			i := s.info
			st.Time = &TimeStat{
				Stratum: int(i.Stratum), Leap: int(i.Leap), Version: int(i.Version), RefID: i.RefID,
				OffsetMS: round2(ms(i.Offset)), DelayMS: round2(ms(i.Delay)),
				RootDelay: round2(ms(i.RootDelay)), RootDisp: round2(ms(i.RootDisp)), RootDist: round2(ms(i.RootDist)),
				KissOfDeth: i.KoD,
			}
		}
		if !s.lastProbe.IsZero() {
			st.Via = famName[s.via]
		}
		for f, fs := range s.fam {
			if fs.tried {
				st.Families = append(st.Families, FamStat{Family: famName[f], Addr: fs.addr, OK: fs.ok, EWMAMS: round2(fs.ewma), Error: fs.err})
			}
		}
		if !s.lastProbe.IsZero() {
			st.LastProbeAgo = round2(time.Since(s.lastProbe).Seconds())
		}
		s.mu.Unlock()
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Rank == 0) != (b.Rank == 0) {
			return a.Rank != 0
		}
		if a.Rank != b.Rank {
			return a.Rank < b.Rank
		}
		return a.Addr < b.Addr
	})
	return out
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

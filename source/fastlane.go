package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Fast Lane (the dns block's "fastlane", shared by every gateway): when an answer holds several addresses of one family
// for a name, the node measures how long each takes to answer and sends the client only the fastest.
//
// The measuring is done in the background and never on the query path: the first answer for a name goes out as the
// servers gave it, and the addresses are probed meanwhile.  An address is asked with an ICMP echo first, which any host
// can answer whatever it serves, and, when that gets no reply, with a TCP connection to port 443 (a refused connection
// counts: it still proves the host is there and takes one round trip).  A result is used for flMaxAge, and an address that is asked for again after
// flFresh is probed again.  Until every address of a family has a result the answer is left as it came, and so it is when
// every address failed.  The choice is made as the answer is sent, so the cached answer is not changed.
//
// What it leaves alone, always: an answer that is not a plain NOERROR answer to an A or AAAA question, one with the AA or
// TC bit, one with anything but CNAME and address records in it (a signed answer carries RRSIGs, and a client that
// validates would reject an RRset with records missing), a name in fastlane_exclude, and a family with fewer than two
// addresses.  The records kept get a TTL of at most fastlane_ttl seconds, so that a client does not keep a choice that
// has gone bad for as long as the servers' TTL.

const (
	flDefaultTTL  = 30
	flMaxTTL      = 3600
	flMaxExcludes = 1000
	flMaxAddrs    = 20000
	flFresh       = 60 * time.Second // an address asked for again after this long is probed again
	flMaxAge      = 10 * time.Minute // a result older than this is not used
	flWorkers     = 8
	flQueue       = 512
	flDialTimeout = time.Second
)

// flAddr is what is known about one address.
type flAddr struct {
	rtt  float64   // smoothed connect time, ms
	up   bool      // the last probe got an answer
	have bool      // a probe has finished
	busy bool      // queued or being probed
	at   time.Time // when the last probe finished
	used time.Time // when an answer last held it
}

type fastLane struct {
	mu      sync.Mutex
	addrs   map[netip.Addr]*flAddr
	q       chan netip.Addr
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started sync.Once
	ttl     uint32
	spread  bool
	band    float64 // percent
	alpha   float64
	exclude nameSet
	rr      atomic.Uint64

	Narrowed   atomic.Uint64 // answers cut down to the fastest address
	Probes     atomic.Uint64 // addresses probed
	ProbeFails atomic.Uint64 // probes that got no answer

	// replaced by the tests
	dial func(ctx context.Context, a netip.Addr) (time.Duration, bool)
	now  func() time.Time
}

// flStats is what the DNS views and the metrics show.
type flStats struct {
	On         bool   `json:"on"`
	TTL        int    `json:"ttl"`
	Addresses  int    `json:"addresses"`
	Narrowed   uint64 `json:"narrowed"`
	Probes     uint64 `json:"probes"`
	ProbeFails uint64 `json:"probe_failed"`
}

func newFastLane(cfg DNSConfig) *fastLane {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fastLane{
		addrs:   map[netip.Addr]*flAddr{},
		q:       make(chan netip.Addr, flQueue),
		ctx:     ctx,
		cancel:  cancel,
		ttl:     uint32(cfg.fastLaneTTL()),
		spread:  cfg.Spread,
		band:    float64(cfg.SpreadBand),
		alpha:   cfg.LatencyAlpha,
		exclude: newNameSet(cfg.FastLaneExclude),
		dial:    flDial,
		now:     time.Now,
	}
	if f.alpha <= 0 || f.alpha > 1 {
		f.alpha = 0.3
	}
	if f.band < 1 {
		f.band = 20
	}
	return f
}

// fastLaneTTL is the most seconds a narrowed answer may be kept by a client.
func (d DNSConfig) fastLaneTTL() int {
	if d.FastLaneTTL <= 0 {
		return flDefaultTTL
	}
	return d.FastLaneTTL
}

// stop ends the probing; the probes in flight are cut short.
func (f *fastLane) stop() {
	if f == nil {
		return
	}
	f.cancel()
	f.wg.Wait()
}

func (f *fastLane) stats() flStats {
	if f == nil {
		return flStats{}
	}
	f.mu.Lock()
	n := len(f.addrs)
	f.mu.Unlock()
	return flStats{On: true, TTL: int(f.ttl), Addresses: n, Narrowed: f.Narrowed.Load(), Probes: f.Probes.Load(), ProbeFails: f.ProbeFails.Load()}
}

// normalizeFastLaneExclude turns the exclude entries into plain lower case names (a name covers everything below it).
func normalizeFastLaneExclude(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		for _, f := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r' }) {
			n := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(f, "*"), "."), "."))
			if !validHostname(n) {
				return nil, fmt.Errorf("dns: fastlane_exclude entry %q is not a domain name like example.com", f)
			}
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	if len(out) > flMaxExcludes {
		return nil, fmt.Errorf("dns: at most %d fastlane_exclude entries", flMaxExcludes)
	}
	return out, nil
}

// ---- probing ----

// flDial measures one address: the round trip of an ICMP echo, else the time a TCP connection to port 443 takes to be
// answered.  An address that answers neither is reported as not answering.
func flDial(ctx context.Context, a netip.Addr) (time.Duration, bool) {
	if d, ok := flICMP(ctx, a); ok {
		return d, true
	}
	if ctx.Err() != nil {
		return 0, false
	}
	return flTCP(ctx, a, "443")
}

// flTCP times a TCP connection.  A refused connection counts as an answer (the host is there, and the refusal took one
// round trip); a timeout or an unreachable network does not.
func flTCP(ctx context.Context, a netip.Addr, port string) (time.Duration, bool) {
	t0 := time.Now()
	d := net.Dialer{Timeout: flDialTimeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), port))
	el := time.Since(t0)
	if err == nil {
		c.Close()
		return el, true
	}
	return el, ctx.Err() == nil && errors.Is(err, syscall.ECONNREFUSED)
}

var (
	flICMPSeq  atomic.Uint32
	flICMPWarn sync.Once
)

// flICMP sends one echo request and times the reply.  It needs a raw socket (the daemon runs as root); without one it
// says so once and every address is measured with TCP alone.
func flICMP(ctx context.Context, a netip.Addr) (time.Duration, bool) {
	network, listen, reqType, repType := "ip4:icmp", "0.0.0.0", byte(8), byte(0)
	if a.Is6() {
		network, listen, reqType, repType = "ip6:ipv6-icmp", "::", byte(128), byte(129)
	}
	c, err := net.ListenPacket(network, listen)
	if err != nil {
		flICMPWarn.Do(func() {
			warnf("fast lane: cannot open a raw ICMP socket (%v); addresses are timed with TCP to port 443 alone", err)
		})
		return 0, false
	}
	defer c.Close()
	id := uint16(flICMPSeq.Add(1))
	msg := make([]byte, 8+16)
	msg[0] = reqType
	binary.BigEndian.PutUint16(msg[4:], id)
	binary.BigEndian.PutUint16(msg[6:], 1)
	copy(msg[8:], "dnsdir fast lane")
	if a.Is4() { // for ICMPv6 the kernel fills the checksum in
		binary.BigEndian.PutUint16(msg[2:], icmpChecksum(msg))
	}
	_ = c.SetDeadline(time.Now().Add(flDialTimeout))
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	t0 := time.Now()
	if _, err := c.WriteTo(msg, &net.IPAddr{IP: a.AsSlice()}); err != nil {
		return 0, false
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return 0, false
		}
		el := time.Since(t0)
		if ip, ok := from.(*net.IPAddr); !ok || !ip.IP.Equal(a.AsSlice()) {
			continue // somebody else's ICMP
		}
		if n >= 8 && buf[0] == repType && binary.BigEndian.Uint16(buf[4:]) == id && binary.BigEndian.Uint16(buf[6:]) == 1 {
			return el, true
		}
	}
}

// icmpChecksum is the Internet checksum (RFC 1071) of an ICMPv4 message whose checksum field is zero.
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// flProbeable says whether an address may be measured: not the node's own network or a special address.
func flProbeable(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
}

func (f *fastLane) startWorkers() {
	f.started.Do(func() {
		for i := 0; i < flWorkers; i++ {
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer recoverPanic("a Fast Lane probe")
				for {
					select {
					case <-f.ctx.Done():
						return
					case a := <-f.q:
						f.probe(a)
					}
				}
			}()
		}
	})
}

func (f *fastLane) probe(a netip.Addr) {
	samples := 1
	f.mu.Lock()
	if e := f.addrs[a]; e == nil || !e.have {
		samples = 2 // the first look takes the better of two, so one slow handshake does not decide
	}
	f.mu.Unlock()
	var best time.Duration
	ok := false
	for i := 0; i < samples; i++ {
		d, got := f.dial(f.ctx, a)
		if !got {
			break // an address that does not answer is not asked twice: that would only hold the choice up
		}
		if !ok || d < best {
			best, ok = d, true
		}
	}
	if f.ctx.Err() != nil {
		return
	}
	f.Probes.Add(1)
	if !ok {
		f.ProbeFails.Add(1)
	}
	f.record(a, best, ok)
}

// record stores the result of a probe.
func (f *fastLane) record(a netip.Addr, d time.Duration, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.addrs[a]
	if e == nil {
		return // forgotten while it was being probed
	}
	e.busy, e.have, e.at = false, true, f.now()
	if !ok {
		e.up = false
		return
	}
	ms := float64(d) / float64(time.Millisecond)
	if !e.up || e.rtt <= 0 {
		e.rtt = ms
	} else {
		e.rtt = f.alpha*ms + (1-f.alpha)*e.rtt
	}
	e.up = true
}

// choose picks which of addrs (one family, in the order of the answer) to keep, as an index, or -1 to leave the answer
// as it came.  It also queues the addresses that have no result yet or an old one.
func (f *fastLane) choose(addrs []netip.Addr) int {
	for _, a := range addrs {
		if !flProbeable(a) {
			return -1
		}
	}
	now := f.now()
	var todo []netip.Addr
	unknown := false
	f.mu.Lock()
	for _, a := range addrs {
		e := f.addrs[a]
		if e == nil {
			if len(f.addrs) >= flMaxAddrs {
				f.sweepLocked(now)
			}
			if len(f.addrs) >= flMaxAddrs {
				unknown = true
				continue
			}
			e = &flAddr{}
			f.addrs[a] = e
		}
		e.used = now
		if !e.busy && (!e.have || now.Sub(e.at) > flFresh) {
			e.busy = true
			todo = append(todo, a)
		}
		if !e.have || now.Sub(e.at) > flMaxAge {
			unknown = true
		}
	}
	pick := -1
	if !unknown {
		best := -1.0
		for _, a := range addrs {
			if e := f.addrs[a]; e.up && (best < 0 || e.rtt < best) {
				best = e.rtt
			}
		}
		if best >= 0 {
			// the addresses within the spread band of the fastest take turns; without spread only the fastest is used
			limit := best
			if f.spread {
				limit = best * (1 + f.band/100)
			}
			var cands []int
			for i, a := range addrs {
				if e := f.addrs[a]; e.up && e.rtt <= limit {
					cands = append(cands, i)
				}
			}
			pick = cands[int(f.rr.Add(1)%uint64(len(cands)))]
		}
	}
	f.mu.Unlock()
	if len(todo) > 0 {
		f.startWorkers()
		for _, a := range todo {
			select {
			case f.q <- a:
			default: // the queue is full: ask again with a later answer
				f.mu.Lock()
				if e := f.addrs[a]; e != nil {
					e.busy = false
				}
				f.mu.Unlock()
			}
		}
	}
	return pick
}

// sweepLocked forgets the addresses no answer has held for flMaxAge.
func (f *fastLane) sweepLocked(now time.Time) {
	for a, e := range f.addrs {
		if !e.busy && now.Sub(e.used) > flMaxAge {
			delete(f.addrs, a)
		}
	}
}

// ---- the answer ----

// narrow returns resp with only the fastest address of each family that has several, or resp itself when nothing is
// to change.  resp is never modified (it may be a cached message).
func (f *fastLane) narrow(resp []byte, qtype uint16, name string) []byte {
	if f == nil || len(resp) < 12 || (qtype != typeA && qtype != typeAAAA) {
		return resp
	}
	flags := binary.BigEndian.Uint16(resp[2:])
	// a response (QR), a query opcode, no AA, no TC, NOERROR
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x0400 != 0 || flags&0x0200 != 0 || flags&0x000F != 0 {
		return resp
	}
	an := int(binary.BigEndian.Uint16(resp[6:]))
	if an < 2 || f.exclude.has(name) {
		return resp
	}
	rrs, addStart, ok := recordsAfterQuestion(resp)
	if !ok || addStart < an {
		return resp
	}
	var v4, v6 []int // indexes into rrs
	for i, rr := range rrs {
		switch {
		case i < an && rr.class == 1 && rr.typ == typeA && rr.rdlen == 4:
			v4 = append(v4, i)
		case i < an && rr.class == 1 && rr.typ == typeAAAA && rr.rdlen == 16:
			v6 = append(v6, i)
		case i < an && rr.typ == typeCNAME:
		case i >= an && rr.typ == typeOPT:
		default:
			return resp
		}
	}
	if len(v4) < 2 && len(v6) < 2 {
		return resp
	}
	// the address records must be one block (CNAMEs may come before or after it, not inside), and no name may point
	// into it, or taking records out would break a compression pointer
	var all []int
	all = append(append(all, v4...), v6...)
	sort.Ints(all)
	if all[len(all)-1]-all[0] != len(all)-1 {
		return resp
	}
	lo, hi := rrs[all[0]].start, rrs[all[len(all)-1]].end
	for _, rr := range rrs {
		if ptrInto(resp, rr.start, lo, hi) {
			return resp
		}
		if rr.typ == typeCNAME && ptrInto(resp, rr.rdataOff, lo, hi) {
			return resp
		}
	}
	drop := map[int]bool{}
	for _, fam := range [][]int{v4, v6} {
		if len(fam) < 2 {
			continue
		}
		addrs := make([]netip.Addr, len(fam))
		for k, i := range fam {
			addrs[k], _ = netip.AddrFromSlice(resp[rrs[i].rdataOff:rrs[i].end])
			addrs[k] = addrs[k].Unmap()
		}
		pick := f.choose(addrs)
		if pick < 0 {
			continue
		}
		for k, i := range fam {
			if k != pick {
				drop[i] = true
			}
		}
	}
	if len(drop) == 0 {
		return resp
	}
	out := make([]byte, 0, len(resp))
	out = append(out, resp[:lo]...)
	for i := range rrs {
		if i >= an || drop[i] || (rrs[i].typ != typeA && rrs[i].typ != typeAAAA) {
			continue
		}
		out = append(out, resp[rrs[i].start:rrs[i].end]...)
	}
	// the block may hold only address records (checked above), so what follows it is the additional section
	out = append(out, resp[hi:]...)
	binary.BigEndian.PutUint16(out[6:], uint16(an-len(drop)))
	f.capTTLs(out, an-len(drop))
	f.Narrowed.Add(1)
	return out
}

// capTTLs lowers the TTL of the first n records after the question to at most the Fast Lane TTL.
func (f *fastLane) capTTLs(msg []byte, n int) {
	rrs, _, ok := recordsAfterQuestion(msg)
	if !ok || len(rrs) < n {
		return
	}
	for _, rr := range rrs[:n] {
		o := rr.rdataOff - 6
		if o < 0 || o+4 > len(msg) {
			continue
		}
		if binary.BigEndian.Uint32(msg[o:]) > f.ttl {
			binary.BigEndian.PutUint32(msg[o:], f.ttl)
		}
	}
}

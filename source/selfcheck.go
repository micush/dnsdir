package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Self-check.
//
// A node announces its VIP and anycast addresses for as long as its process says it can answer: the gateway runs, the
// listener is up, some upstream is healthy.  None of that notices a resolver that has stopped answering while the process
// is still alive (a lock held forever in the cache, a worker pool that never frees up, a listener nobody reads).  The
// anycast renewal then keeps going and the VIP stays with this node, and queries time out.
//
// So every few seconds the node asks each DNS listener it has open a real question over UDP, from the listener's own
// address.  After selfFails misses in a row it pauses itself, in memory only, the same as Operate ▸ Node ▸ pause: its
// gateways resign, the VIP and the anycast addresses come off, and the other nodes carry on.  The file is not changed and a
// restart starts clean.  After a while (selfHold, doubling up to selfHoldMax while it keeps failing) it lets the gateways
// start again and watches them; selfOKs good answers in a row end the trouble.  A person who pauses or resumes the node
// takes over.  Switched by "self_check" in the node's settings (on by default).

const (
	selfCheckName = "selfcheck.dnsdir.invalid"
	selfEvery     = 5 * time.Second
	selfTimeout   = 2 * time.Second
	selfFails     = 3 // misses in a row before the node pauses itself
	selfOKs       = 6 // answers in a row, after a trial start, before it is trusted again
	selfHold      = time.Minute
	selfHoldMax   = 10 * time.Minute
)

var (
	selfPaused atomic.Bool
	selfWhyMu  sync.Mutex
	selfWhy    string
)

func selfPauseActive() bool { return selfPaused.Load() }

func selfPausedWhy() string {
	selfWhyMu.Lock()
	defer selfWhyMu.Unlock()
	if !selfPaused.Load() {
		return ""
	}
	return selfWhy
}

func setSelfPause(on bool, why string) {
	selfWhyMu.Lock()
	selfWhy = why
	selfWhyMu.Unlock()
	selfPaused.Store(on)
}

func clearSelfPause() { setSelfPause(false, "") }

// nodePausedNow is whether the node is out of service: paused by a person (kept in the file) or by the self-check.
func (dc *DaemonConfig) nodePausedNow() bool {
	return dc != nil && (dc.NodePaused || selfPaused.Load())
}

// isSelfCheckQuery says whether q is the self-check's question.  resolve() accepts it only from the listener's own
// address, so nobody else can use the name to get past the client rules.
func isSelfCheckQuery(q []byte) bool {
	var qi qinfo
	parseQuestion(q, &qi)
	return qi.ok && strings.EqualFold(strings.TrimSuffix(qi.name(), "."), selfCheckName)
}

// probeDNS asks addr one question, from addr itself.  ok: an answer came back (any rcode); skip: the question could not
// be sent from here (the address is not on this machine yet), which says nothing about the listener.
func probeDNS(ap netip.AddrPort, timeout time.Duration) (ok, skip bool) {
	id := uint16(time.Now().UnixNano())
	q, err := buildQuery(id, selfCheckName, "A")
	if err != nil {
		return true, true
	}
	d := net.Dialer{Timeout: timeout, LocalAddr: &net.UDPAddr{IP: ap.Addr().AsSlice()}}
	c, err := d.Dial("udp", ap.String())
	if err != nil {
		return true, true
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(q); err != nil {
		return true, true
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return false, false
		}
		if n >= 12 && uint16(buf[0])<<8|uint16(buf[1]) == id && buf[2]&0x80 != 0 {
			return true, false
		}
	}
}

// selfCheck runs the check.  The functions are filled in by main (and by the tests).
type selfCheck struct {
	enabled func() bool
	targets func() []netip.AddrPort
	probe   func(netip.AddrPort) (ok, skip bool)
	guard   func() string                // why the node must not pause itself ("" when it may)
	apply   func(pause bool, why string) // pause or resume this node's gateways now
	now     func() time.Time

	bad, good  int
	paused     bool // paused by this check
	trial      bool // started again to see whether it answers; not yet trusted
	retryAt    time.Time
	hold       time.Duration
	refusedLog bool
}

func (s *selfCheck) tick() {
	now := s.now()
	if s.paused && !selfPauseActive() { // a person resumed or paused the node: this check lets go
		s.paused, s.trial, s.bad, s.good, s.hold = false, false, 0, 0, 0
	}
	if !s.enabled() {
		if s.paused {
			infof("self-check: switched off — resuming this node")
			s.resume()
			s.hold = 0
		}
		s.bad, s.good = 0, 0
		return
	}
	if s.paused {
		if !now.Before(s.retryAt) {
			infof("self-check: starting this node's gateways again to see whether they answer")
			s.resume()
			s.trial, s.bad, s.good = true, 0, 0
		}
		return
	}
	var miss string
	asked := 0
	for _, ap := range s.targets() {
		ok, skip := s.probe(ap)
		if skip {
			continue
		}
		asked++
		if !ok && miss == "" {
			miss = ap.String()
		}
	}
	if asked == 0 {
		s.bad = 0
		return
	}
	if miss == "" {
		s.bad = 0
		s.good++
		s.refusedLog = false
		if s.trial && s.good >= selfOKs {
			s.trial, s.hold = false, 0
			infof("self-check: this node's DNS answers again")
		}
		return
	}
	s.good = 0
	s.bad++
	if s.bad == 1 {
		warnf("self-check: %s did not answer its own question within %s", miss, selfTimeout)
	}
	if s.bad < selfFails {
		return
	}
	if why := s.guard(); why != "" {
		if !s.refusedLog {
			warnf("self-check: %s has stopped answering, but this node is not pausing itself: %s", miss, why)
			s.refusedLog = true
		}
		s.bad = selfFails
		return
	}
	if s.hold == 0 {
		s.hold = selfHold
	} else if s.hold *= 2; s.hold > selfHoldMax {
		s.hold = selfHoldMax
	}
	why := fmt.Sprintf("%s stopped answering its own questions (%d misses in a row)", miss, s.bad)
	errorf("self-check: %s — pausing this node; it tries again in %s", why, s.hold)
	setSelfPause(true, why)
	s.paused, s.trial, s.bad = true, false, 0
	s.retryAt = now.Add(s.hold)
	s.apply(true, why)
}

func (s *selfCheck) resume() {
	clearSelfPause()
	s.paused = false
	s.apply(false, "")
}

func (s *selfCheck) run(ctx context.Context) {
	t := time.NewTicker(selfEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.tick()
		}
	}
}

// selfCheckTargets lists the listeners this node has open: each gateway's shared address(es) and the anycast ones.
func selfCheckTargets(sup *Supervisor) []netip.AddrPort {
	seen := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	add := func(f *DNSFrontend) {
		if f == nil || f.port <= 0 || f.port > 65535 {
			return
		}
		ap := netip.AddrPortFrom(f.addr, uint16(f.port))
		if !seen[ap] {
			seen[ap] = true
			out = append(out, ap)
		}
	}
	for _, e := range sup.engineList() {
		for _, f := range e.frontends() {
			add(f)
		}
	}
	anycastReg.Lock()
	for _, f := range anycastReg.fes {
		if f.Listening() {
			add(f)
		}
	}
	anycastReg.Unlock()
	return out
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

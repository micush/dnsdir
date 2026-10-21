package main

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func newTestCheck(t *testing.T) (*selfCheck, *bool, *[]bool, *time.Time) {
	t.Helper()
	clearSelfPause()
	t.Cleanup(clearSelfPause)
	answer := true
	var applied []bool
	clock := time.Unix(1000, 0)
	s := &selfCheck{
		enabled: func() bool { return true },
		targets: func() []netip.AddrPort { return []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:53")} },
		probe:   func(netip.AddrPort) (bool, bool) { return answer, false },
		guard:   func() string { return "" },
		apply:   func(p bool, _ string) { applied = append(applied, p) },
		now:     func() time.Time { return clock },
	}
	return s, &answer, &applied, &clock
}

func TestSelfCheckPausesAndComesBack(t *testing.T) {
	s, answer, applied, clock := newTestCheck(t)
	for i := 0; i < 5; i++ {
		s.tick()
	}
	if selfPauseActive() || len(*applied) != 0 {
		t.Fatal("a node that answers must not be paused")
	}
	*answer = false
	s.tick()
	s.tick()
	if selfPauseActive() {
		t.Fatal("two misses must not pause it")
	}
	s.tick()
	if !selfPauseActive() || len(*applied) != 1 || !(*applied)[0] {
		t.Fatalf("three misses must pause it: %v", *applied)
	}
	if !(&DaemonConfig{}).nodePausedNow() {
		t.Fatal("the node must now count as paused")
	}
	if got := newDaemonConfig().effective(); got == nil {
		t.Fatal("effective")
	}
	cfg := newDaemonConfig()
	cfg.Groups = []GroupConfig{{GroupID: 1}}
	if !cfg.effective().Groups[0].Paused {
		t.Fatal("a self-paused node must run every gateway paused")
	}
	if cfg.NodePaused {
		t.Fatal("the saved configuration must not change")
	}
	// waits for the hold, then a trial start
	*clock = clock.Add(selfHold - time.Second)
	s.tick()
	if len(*applied) != 1 {
		t.Fatal("it must wait for the hold before starting again")
	}
	*clock = clock.Add(2 * time.Second)
	s.tick()
	if len(*applied) != 2 || (*applied)[1] || selfPauseActive() {
		t.Fatalf("after the hold the gateways start again: %v", *applied)
	}
	// still wedged: pauses again, for twice as long
	s.tick()
	s.tick()
	s.tick()
	if !selfPauseActive() || s.hold != 2*selfHold {
		t.Fatalf("a failed trial pauses again for longer: hold %v", s.hold)
	}
	*clock = clock.Add(3 * selfHold)
	s.tick()
	*answer = true
	for i := 0; i < selfOKs; i++ {
		s.tick()
	}
	if selfPauseActive() || s.trial || s.hold != 0 {
		t.Fatalf("answers in a row end the trouble: trial %v hold %v", s.trial, s.hold)
	}
}

func TestSelfCheckWillNotPauseTheLastNodeAndCanBeSwitchedOff(t *testing.T) {
	s, answer, applied, _ := newTestCheck(t)
	s.guard = func() string { return "it is the only node in service" }
	*answer = false
	for i := 0; i < 10; i++ {
		s.tick()
	}
	if selfPauseActive() || len(*applied) != 0 {
		t.Fatal("the only node in service must not pause itself")
	}
	s.guard = func() string { return "" }
	s.tick()
	if !selfPauseActive() {
		t.Fatal("it pauses once another node can carry on")
	}
	s.enabled = func() bool { return false }
	s.tick()
	if selfPauseActive() || len(*applied) != 2 || (*applied)[1] {
		t.Fatalf("switching the check off resumes the node: %v", *applied)
	}
	clearSelfPause()
}

func TestSelfCheckLetsGoWhenAPersonTakesOver(t *testing.T) {
	s, answer, applied, _ := newTestCheck(t)
	*answer = false
	s.tick()
	s.tick()
	s.tick()
	if !selfPauseActive() {
		t.Fatal("not paused")
	}
	clearSelfPause() // what NodePause does
	*answer = true
	s.tick()
	if s.paused || len(*applied) != 1 {
		t.Fatalf("the check must let go: %v", *applied)
	}
}

func TestSelfCheckQuestionAndProbe(t *testing.T) {
	q, _ := buildQuery(7, selfCheckName, "A")
	if !isSelfCheckQuery(q) {
		t.Fatal("its own question is not recognised")
	}
	other, _ := buildQuery(7, "example.com", "A")
	if isSelfCheckQuery(other) {
		t.Fatal("another name must not count")
	}
	// a listener that answers
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 512)
		for {
			n, a, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			r := append([]byte(nil), b[:n]...)
			r[2] |= 0x80
			pc.WriteTo(r, a)
		}
	}()
	ap := netip.MustParseAddrPort(pc.LocalAddr().String())
	if ok, skip := probeDNS(ap, time.Second); !ok || skip {
		t.Fatalf("an answering listener: ok %v skip %v", ok, skip)
	}
	// one that reads and never answers
	dead, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer dead.Close()
	if ok, skip := probeDNS(netip.MustParseAddrPort(dead.LocalAddr().String()), 300*time.Millisecond); ok || skip {
		t.Fatalf("a silent listener must fail: ok %v skip %v", ok, skip)
	}
}

// The real listener answers the check, and the check is not counted as a client.
func TestSelfCheckAgainstARealFrontendIsNotCounted(t *testing.T) {
	l, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	f := NewDNSFrontend(netip.MustParseAddr("127.0.0.1"), port, func() *Pool { return nil })
	if err := f.Start(); err != nil {
		t.Skip(err)
	}
	defer f.Stop()
	before := qstats.pendN.Load()
	ap := netip.AddrPortFrom(f.addr, uint16(port))
	if ok, skip := probeDNS(ap, 2*time.Second); !ok || skip {
		t.Fatalf("the listener must answer its own question: ok %v skip %v", ok, skip)
	}
	if qstats.pendN.Load() != before {
		t.Fatal("the self-check was counted in the statistics")
	}
}

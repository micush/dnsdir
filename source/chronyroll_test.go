package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChronyMayGo(t *testing.T) {
	pv := func(addr string, self bool, roll string) PeerView {
		return PeerView{Addr: addr, Self: self, Reachable: true, ChronyRoll: roll}
	}
	cases := []struct {
		name  string
		peers []PeerView
		ok    bool
		why   string
	}{
		{"alone", []PeerView{pv("b", true, "pending")}, true, ""},
		{"nobody else busy", []PeerView{pv("b", true, "pending"), pv("a", false, ""), pv("c", false, "")}, true, ""},
		{"a lower address is waiting", []PeerView{pv("b", true, "pending"), pv("a", false, "pending")}, false, "a is first"},
		{"a higher address waits for us", []PeerView{pv("b", true, "pending"), pv("c", false, "pending")}, true, ""},
		{"someone is restarting", []PeerView{pv("b", true, "pending"), pv("c", false, "restarting")}, false, "c is restarting"},
		{"someone failed", []PeerView{pv("b", true, "pending"), pv("c", false, "failed")}, false, "c failed"},
		{"someone is updating", []PeerView{pv("b", true, "pending"), {Addr: "c", Reachable: true, Updating: true}}, false, "c is installing"},
	}
	for _, c := range cases {
		ok, why := chronyMayGo(c.peers)
		if ok != c.ok || !strings.Contains(why, c.why) {
			t.Errorf("%s: got %v %q", c.name, ok, why)
		}
	}
	// a member that cannot be reached is not waited for
	down := pv("a", false, "restarting")
	down.Reachable = false
	if ok, _ := chronyMayGo([]PeerView{pv("b", true, "pending"), down}); !ok {
		t.Error("an unreachable member held the roll")
	}
}

func TestApplyClientsNeverRestartsAndTracksTheKey(t *testing.T) {
	f := hookChrony(t)
	m := chrony
	m.keyFile = t.TempDir() + "/applied"
	d := defaultNTP()
	if err := m.applyClients(d); err != nil || f.restarts != 0 || m.needsRestart() {
		t.Fatalf("defaults: %v restarts %d need %v", err, f.restarts, m.needsRestart())
	}
	d.ClientRate = 16
	if err := m.applyClients(d); err != nil || f.restarts != 0 || !m.needsRestart() {
		t.Fatalf("new rate: %v restarts %d need %v", err, f.restarts, m.needsRestart())
	}
	m.markApplied()
	if m.needsRestart() {
		t.Fatal("still needed after it was applied")
	}
	d.AllowedClients = []string{"10.0.0.0/8"} // allow rules are live
	if err := m.applyClients(d); err != nil || m.needsRestart() {
		t.Fatalf("allow list: %v need %v", err, m.needsRestart())
	}
	d.ListenPort = 1123
	if err := m.applyClients(d); err != nil || !m.needsRestart() {
		t.Fatalf("port: %v need %v", err, m.needsRestart())
	}
}

// The node is paused, chrony restarted, and the node resumed only when chrony is synchronised again.
func TestChronyRollPausesRestartsWaitsResumes(t *testing.T) {
	f := hookChrony(t)
	od, os_ := chronyDrainWait, chronySyncWait
	chronyDrainWait, chronySyncWait = 10*time.Millisecond, 5*time.Second
	t.Cleanup(func() { chronyDrainWait, chronySyncWait = od, os_ })
	mg := newPowerMgmt(t)
	if err := newDaemonConfig().save(mg.confPath); err != nil {
		t.Fatal(err)
	}
	mg.othersFn = func() int { return 1 }
	chrony.keyFile = t.TempDir() + "/applied"
	d := defaultNTP()
	d.ClientRate = 8
	chrony.applyClients(d)
	if !chrony.needsRestart() {
		t.Fatal("no restart is waiting")
	}
	// chrony is up and synchronised only after the restart
	f.answers["-c -m tracking sources -n"] = ""
	synced := false
	pausedAtRestart := false
	chronyRestart = func() error {
		st, _ := mg.NodePauseStatus()
		pausedAtRestart = st.Paused
		synced = true
		return nil
	}
	ot := chronyRollTrack
	chronyRollTrack = func() ChronyState { return ChronyState{Running: true, Synced: synced} }
	t.Cleanup(func() { chronyRollTrack = ot })

	mg.croll.running.Store(true)
	mg.chronyRollRun(context.Background())
	if !pausedAtRestart {
		t.Fatal("chrony was restarted before the node was paused")
	}
	if st, _ := mg.NodePauseStatus(); st.Paused {
		t.Fatal("the node was not resumed")
	}
	if chrony.needsRestart() {
		t.Fatal("the new settings were not marked as applied")
	}
	if _, err := os.Stat(mg.rollMarkerPath()); err == nil {
		t.Fatal("the marker was left behind")
	}
	if mg.ChronyRollLabel() != "" {
		t.Fatalf("label %q", mg.ChronyRollLabel())
	}
}

// A node that cannot be taken out of service (it is the last) restarts chrony anyway; one that was paused before stays paused.
func TestChronyRollWithoutPauseAndFailure(t *testing.T) {
	hookChrony(t)
	od, os_ := chronyDrainWait, chronySyncWait
	chronyDrainWait, chronySyncWait = 10*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { chronyDrainWait, chronySyncWait = od, os_ })
	mg := newPowerMgmt(t)
	if err := newDaemonConfig().save(mg.confPath); err != nil {
		t.Fatal(err)
	}
	mg.othersFn = func() int { return 0 } // alone: the pause is refused
	chrony.keyFile = t.TempDir() + "/applied"
	d := defaultNTP()
	d.ListenPort = 1123
	chrony.applyClients(d)
	restarted := false
	chronyRestart = func() error { restarted = true; return nil }
	ot := chronyRollTrack
	chronyRollTrack = func() ChronyState { return ChronyState{Running: true, Synced: false} } // never synchronises
	t.Cleanup(func() { chronyRollTrack = ot })
	mg.croll.running.Store(true)
	mg.chronyRollRun(context.Background())
	if !restarted {
		t.Fatal("not restarted")
	}
	if st, _ := mg.NodePauseStatus(); st.Paused {
		t.Fatal("an unpausable node was paused")
	}
	if mg.ChronyRollLabel() != rollFailed {
		t.Fatalf("a chrony that does not synchronise is a failure, label %q", mg.ChronyRollLabel())
	}
}

func TestNoServerInServiceMutesChronyAndRestoresIt(t *testing.T) {
	f := hookChrony(t)
	d := NTPConfig{}
	if err := chrony.applyClients(d); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		b, _ := os.ReadFile(filepath.Join(chronyConfDir, "ntpdir.conf"))
		return string(b)
	}
	if !strings.Contains(read(), "allow all") {
		t.Fatal("clients are allowed while a server is in service")
	}
	if !chrony.setServing(false, d) || strings.Contains(read(), "allow") {
		t.Fatalf("no server in service must leave no allow line:\n%s", read())
	}
	if chrony.setServing(false, d) {
		t.Fatal("a second call with the same answer changes nothing")
	}
	last := f.calls[len(f.calls)-1]
	if strings.Join(last, " ") != "deny all" {
		t.Fatalf("the live rules must end with deny all, got %v", last)
	}
	if !chrony.setServing(true, d) || !strings.Contains(read(), "allow all") || f.restarts != 0 {
		t.Fatalf("a server back restores the clients without a restart:\n%s", read())
	}
}

func TestNodeClockReportsNowAndChrony(t *testing.T) {
	hookChrony(t)
	c := nodeClock()
	if d := time.Since(time.UnixMilli(c.NowMS)); d < 0 || d > 5*time.Second {
		t.Fatalf("now_ms is %v off", d)
	}
}

func TestTooFarHasHysteresisAndCanBeOff(t *testing.T) {
	m := &chronyMgr{warned: map[string]time.Time{}}
	st := func(off float64) ChronyState { return ChronyState{Running: true, Synced: true, OffsetMS: off} }
	if m.tooFar(st(500)) {
		t.Fatal("no limit set: never too far")
	}
	m.setOffsetLimit(50)
	for _, c := range []struct {
		off  float64
		want bool
	}{{10, false}, {50, false}, {51, true}, {-45, true}, {-41, true}, {39, false}, {-39, false}, {60, true}} {
		if got := m.tooFar(st(c.off)); got != c.want {
			t.Fatalf("offset %v: tooFar = %v, want %v", c.off, got, c.want)
		}
	}
	m.setOffsetLimit(0)
	if m.tooFar(st(900)) {
		t.Fatal("0 turns the check off")
	}
}

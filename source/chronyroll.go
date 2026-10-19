package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// The rolling chrony restart.  chrony reads its port and rate limit only when it starts, so a change of either needs a
// restart, and a restart means the node answers nothing for a while (chrony comes back unsynchronised and has to poll
// its sources again).  So the nodes do it one at a time, and each takes itself out of service first:
//
//	pause the node (its gateways resign and the others take over), restart chrony, wait until it is synchronised,
//	resume the node.
//
// There is no coordinator: every node looks at what the others say about themselves (the "chrony_roll" field of the
// cluster status: pending, restarting or failed) and goes when nobody is restarting or failed and no node with a lower
// address is waiting.  A node that is alone, or whose gateways nobody else could carry, restarts without pausing (the
// pause itself is refused then): that is the gap, and the help says so.

const (
	rollPending    = "pending"
	rollRestarting = "restarting"
	rollFailed     = "failed"
)

var (
	chronyDrainWait  = 5 * time.Second  // after pausing: the other nodes take over before chrony stops
	chronySyncWait   = 3 * time.Minute  // how long chrony may take to synchronise again
	chronyRetryWait  = 10 * time.Minute // a failed node tries again after this, and holds the others until then
	chronyStartAfter = 15 * time.Second // how long a change is known before a node starts: the others have seen it by then
)

// chronyRollTrack reads chrony's state while the roll waits for it to synchronise (tests replace it).
var chronyRollTrack = func() ChronyState { return chrony.readState() }

type chronyRoll struct {
	mu       sync.Mutex
	running  atomic.Bool
	failed   string
	failedAt time.Time
	waiting  string
	since    time.Time // since when this node has had a restart to do
}

// label is what the cluster status carries: "" when this node has nothing to do.
func (r *chronyRoll) label(need bool) string {
	switch {
	case r.running.Load():
		return rollRestarting
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.failed != "":
		return rollFailed
	case need:
		return rollPending
	}
	return ""
}

// text is a few words for the NTP page.
func (r *chronyRoll) text(need bool) string {
	switch r.label(need) {
	case rollRestarting:
		return "restarting chrony"
	case rollFailed:
		r.mu.Lock()
		defer r.mu.Unlock()
		return "restart failed: " + r.failed
	case rollPending:
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.waiting != "" {
			return "restart waiting: " + r.waiting
		}
		return "restart waiting"
	}
	return ""
}

func (r *chronyRoll) setWaiting(w string) { r.mu.Lock(); r.waiting = w; r.mu.Unlock() }

func (r *chronyRoll) fail(why string) {
	r.mu.Lock()
	r.failed, r.failedAt = why, time.Now()
	r.mu.Unlock()
}

// ChronyRollLabel is this node's part in the rolling restart, for the cluster status.
func (m *Mgmt) ChronyRollLabel() string { return m.croll.label(chrony.needsRestart()) }

// ChronyRollText is the same in words, for the NTP page and --show-ntp.
func (m *Mgmt) ChronyRollText() string { return m.croll.text(chrony.needsRestart()) }

// chronyMayGo says whether this node may restart chrony now, given what the members say.  peers includes this node
// (Self).  Members that are not reachable are ignored: they cannot be waited for.
func chronyMayGo(peers []PeerView) (bool, string) {
	self := ""
	for _, p := range peers {
		if p.Self {
			self = p.Addr
		}
	}
	for _, p := range peers {
		if p.Self || !p.Reachable {
			continue
		}
		switch {
		case p.ChronyRoll == rollRestarting:
			return false, p.Addr + " is restarting chrony"
		case p.ChronyRoll == rollFailed:
			return false, p.Addr + " failed to restart chrony"
		case p.Updating:
			return false, p.Addr + " is installing an update"
		case p.ChronyRoll == rollPending && p.Addr < self:
			return false, p.Addr + " is first"
		}
	}
	return true, ""
}

type rollMarker struct {
	Paused bool `json:"paused"` // this roll paused the node, so it must resume it
}

func (m *Mgmt) rollMarkerPath() string { return filepath.Join(m.stateDir, "chrony-roll.json") }

func (m *Mgmt) loadRollMarker() (rollMarker, bool) {
	var mk rollMarker
	b, err := os.ReadFile(m.rollMarkerPath())
	if err != nil || json.Unmarshal(b, &mk) != nil {
		return mk, false
	}
	return mk, true
}

func (m *Mgmt) saveRollMarker(mk rollMarker) {
	b, _ := json.Marshal(mk)
	_ = os.WriteFile(m.rollMarkerPath(), b, 0o600)
}

// chronyRollTick looks, every few seconds, whether this node has a chrony restart to do and whether it is its turn.
func (m *Mgmt) chronyRollTick(ctx context.Context) {
	r := &m.croll
	if r.running.Load() {
		return
	}
	_, leftover := m.loadRollMarker() // a roll that was cut short (the daemon stopped) while the node was paused by it
	need := chrony.needsRestart()
	if !need && !leftover {
		r.mu.Lock()
		r.failed, r.waiting, r.since = "", "", time.Time{}
		r.mu.Unlock()
		return
	}
	r.mu.Lock()
	if r.failed != "" && time.Since(r.failedAt) < chronyRetryWait {
		r.mu.Unlock()
		return
	}
	r.failed = ""
	if r.since.IsZero() {
		r.since = time.Now()
	}
	young := !leftover && time.Since(r.since) < chronyStartAfter
	r.mu.Unlock()
	if young {
		return
	}
	if m.upd != nil && m.upd.Busy() {
		r.setWaiting("an update is being installed here")
		return
	}
	if !leftover && m.cl != nil && m.cl.Enabled() {
		if ok, why := chronyMayGo(m.cl.View().Peers); !ok {
			r.setWaiting(why)
			return
		}
	}
	r.setWaiting("")
	if r.running.CompareAndSwap(false, true) {
		go m.chronyRollRun(ctx)
	}
}

// chronyRollRun is one node's turn.
func (m *Mgmt) chronyRollRun(ctx context.Context) {
	r := &m.croll
	defer r.running.Store(false)
	mk, leftover := m.loadRollMarker()
	infof("chrony: restarting chrony to apply a new port or rate limit")
	if !leftover {
		if st, err := m.NodePauseStatus(); err == nil && !st.Paused {
			if _, err := m.NodePause(true, "chrony restart"); err != nil {
				// alone, or the last node serving a gateway: nobody could take over, so the gap is accepted
				infof("chrony: restarting without taking the node out of service (%v)", err)
			} else {
				mk.Paused = true
				m.saveRollMarker(mk)
				select { // the other nodes take over
				case <-ctx.Done():
					return
				case <-time.After(chronyDrainWait):
				}
			}
		}
		if err := chronyRestart(); err != nil {
			warnf("chrony: restart failed: %v", err)
			r.fail(err.Error())
			m.chronyRollResume(mk)
			return
		}
		chrony.markApplied()
		chrony.mu.Lock()
		chrony.pending = true // the sources added at run time are gone: write them again
		chrony.mu.Unlock()
	}
	ok := false
	deadline := time.Now().Add(chronySyncWait)
	for time.Now().Before(deadline) {
		if st := chronyRollTrack(); st.Running && st.Synced {
			ok = true
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	m.chronyRollResume(mk)
	if !ok {
		why := "chrony was not synchronised after " + chronySyncWait.String()
		warnf("chrony: %s; the other nodes wait until this is looked at", why)
		r.fail(why)
		return
	}
	infof("chrony: restarted and synchronised")
}

// chronyRollResume puts the node back into service if this roll paused it.
func (m *Mgmt) chronyRollResume(mk rollMarker) {
	if !mk.Paused {
		return
	}
	if _, err := m.NodePause(false, "chrony restart"); err != nil {
		warnf("chrony: could not resume the node: %v", err)
		return
	}
	_ = os.Remove(m.rollMarkerPath())
}

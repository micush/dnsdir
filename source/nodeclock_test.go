package main

import (
	"math"
	"testing"
)

func TestClockSpreadComparesReachableSynchronisedNodes(t *testing.T) {
	pv := func(host string, reach, sync bool, off float64) PeerView {
		return PeerView{Hostname: host, Addr: host + ":1", Reachable: reach, Clock: &ClockReading{OffsetMS: off, Synced: sync}}
	}
	peers := []PeerView{pv("a", true, true, 0.4), pv("b", true, true, -1.1), pv("c", true, true, 0.9), pv("far", false, true, 500), pv("unsynced", true, false, 900)}
	s := clockSpread(peers)
	if s == nil || s.Nodes != 3 || math.Abs(s.MS-2.0) > 1e-9 || s.Apart != "b ↔ c" {
		t.Fatalf("%+v", s)
	}
	if clockSpread(peers[:1]) != nil {
		t.Fatal("one node has nothing to compare with")
	}
	noClock := []PeerView{pv("a", true, true, 1), {Hostname: "old", Reachable: true}}
	if clockSpread(noClock) != nil {
		t.Fatal("a node that does not say its clock (an older version) is left out")
	}
}

func TestStatusMessageCarriesTheNodeClock(t *testing.T) {
	chrony.mu.Lock()
	old := chrony.state
	chrony.state = ChronyState{Running: true, Synced: true, Stratum: 3, OffsetMS: 0.25, At: 1}
	chrony.mu.Unlock()
	defer func() { chrony.mu.Lock(); chrony.state = old; chrony.mu.Unlock() }()
	c := clockReading()
	if c == nil || !c.Synced || c.OffsetMS != 0.25 || c.Stratum != 3 {
		t.Fatalf("%+v", c)
	}
	chrony.mu.Lock()
	chrony.state = ChronyState{}
	chrony.mu.Unlock()
	if clockReading() != nil {
		t.Fatal("no reading while chrony is not running")
	}
}

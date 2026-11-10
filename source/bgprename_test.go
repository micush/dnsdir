package main

import (
	"os"
	"strings"
	"testing"
)

// A neighbor's address can be changed (Configure ▸ Anycast): it stays the same neighbor, so one that was switched off
// stays off, and the old address is not kept or written to the file.
func TestBGPNeighborAddressCanBeChanged(t *testing.T) {
	e := bgpEnv(t)
	set := BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500, Description: "r1"}, {Peer: "192.0.2.2", RemoteAS: 64500}}}
	if err := e.mg.BGPSet(set, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.mg.BGPOperate(BGPOperateArgs{Peer: "192.0.2.1", Enabled: false}, "t"); err != nil {
		t.Fatal(err)
	}
	set.Neighbors[0] = BGPNeighbor{Peer: "192.0.2.9", Was: "192.0.2.1", RemoteAS: 64500, Description: "r1"}
	if err := e.mg.BGPSet(set, "t"); err != nil {
		t.Fatal(err)
	}
	dc, raw, _ := e.mg.LiveConfig()
	n := dc.BGP.Neighbors
	if len(n) != 2 || n[0].Peer != "192.0.2.9" || !n[0].Disabled || n[0].Description != "r1" || n[1].Disabled {
		t.Fatalf("after the change: %+v", n)
	}
	file, _ := os.ReadFile(e.mg.confPath)
	if strings.Contains(string(raw), `"was"`) || strings.Contains(string(file), `"was"`) || strings.Contains(string(file), "192.0.2.1\"") {
		t.Fatalf("the old address was kept:\n%s", file)
	}
	// without "was" it is a new neighbor, which starts switched on; an address already in the list is refused
	set.Neighbors[0] = BGPNeighbor{Peer: "192.0.2.7", RemoteAS: 64500}
	if err := e.mg.BGPSet(set, "t"); err != nil {
		t.Fatal(err)
	}
	if dc, _, _ := e.mg.LiveConfig(); dc.BGP.Neighbors[0].Disabled {
		t.Fatal("a new neighbor took over the state of the removed one")
	}
	set.Neighbors[0] = BGPNeighbor{Peer: "192.0.2.2", Was: "192.0.2.7", RemoteAS: 64500}
	if err := e.mg.BGPSet(set, "t"); err == nil {
		t.Fatal("two neighbors with one address were accepted")
	}
	if err := e.mg.BGPSet(BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{{Peer: "not-an-address", Was: "192.0.2.7", RemoteAS: 64500}}}, "t"); err == nil {
		t.Fatal("a bad address was accepted")
	}
}

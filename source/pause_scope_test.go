package main

import "testing"

func TestPauseScopeGatewayAndServer(t *testing.T) {
	dc := pauseTestConfig()
	ed := func(kind, action, scope string) error {
		_, err := applyCanvasEdit(dc, canvasEdit{Action: action, Kind: kind, Group: 1, Server: "192.0.2.1:123", Scope: scope})
		return err
	}
	// gateway: default node, all is shared
	if err := ed("gateway", "pause", ""); err != nil || !dc.Groups[0].Paused {
		t.Fatalf("gateway default scope: %v %v", err, dc.Groups[0].Paused)
	}
	if err := ed("gateway", "pause", "all"); err != nil || !dc.Groups[0].PausedAll {
		t.Fatalf("gateway all: %v", err)
	}
	// server: default all, node is local
	if err := ed("server", "pause", ""); err != nil || len(dc.Groups[0].NTP.PausedServers) != 1 {
		t.Fatalf("server default scope: %v %v", err, dc.Groups[0].NTP.PausedServers)
	}
	if err := ed("server", "pause", "node"); err != nil || len(dc.PausedServersHere) != 1 {
		t.Fatalf("server node: %v", err)
	}
	if err := ed("server", "resume", "node"); err != nil || len(dc.PausedServersHere) != 0 {
		t.Fatalf("server resume: %v", err)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPauseScopeEffectiveLiveShared(t *testing.T) {
	dc := pauseTestConfig()
	dc.PausedServersHere = []string{"192.0.2.2:123"}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	eff := dc.effective()
	if eff.NTP.serverPausedScope("192.0.2.2:123") != "node" {
		t.Fatal("effective config lost the node-local pause")
	}
	live := eff.NTP.live()
	if len(live.Servers) != 1 || live.Servers[0] != "192.0.2.1:123" {
		t.Fatalf("live servers: %v", live.Servers)
	}
	// the node-local list is never replicated; the shared one is
	if sharedOf(dc).hash() != sharedOf(pauseTestConfig()).hash() {
		t.Fatal("node-local pauses changed the shared hash")
	}
	dc.NTP.PausedServers = []string{"192.0.2.2:123"}
	if sharedOf(dc).hash() == sharedOf(pauseTestConfig()).hash() {
		t.Fatal("shared server pause not replicated")
	}
}

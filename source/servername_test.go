package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestServerNamesValidation(t *testing.T) {
	d := defaultNTP()
	d.Servers = []string{"192.0.2.8", "[2001:db8::53]:5353"}
	d.ServerNames = map[string]string{"192.0.2.8:123": "  ntp-a  ", "[2001:db8::53]:5353": "", "192.0.2.8": "ntp-a"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(d.ServerNames) != 1 || d.ServerNames["192.0.2.8:123"] != "ntp-a" {
		t.Fatalf("names are keyed by the normalised server, trimmed, and an empty one is dropped: %v", d.ServerNames)
	}
	// none left at all: the key disappears from the file
	d.ServerNames = map[string]string{"192.0.2.8": " "}
	if err := d.Validate(); err != nil || d.ServerNames != nil {
		t.Fatalf("empty names: %v %v", d.ServerNames, err)
	}
	if b, _ := json.Marshal(d); strings.Contains(string(b), "server_names") {
		t.Fatalf("an empty map is written out: %s", b)
	}
	for name, d2 := range map[string]map[string]string{
		"not a server": {"9.9.9.9": "x"},
		"too long":     {"192.0.2.8": strings.Repeat("a", 41)},
		"control char": {"192.0.2.8": "bad\x07name"},
	} {
		d.ServerNames = d2
		if d.Validate() == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	d.ServerNames = map[string]string{"192.0.2.8": strings.Repeat("é", 40)}
	if err := d.Validate(); err != nil {
		t.Fatalf("40 characters (not bytes) are allowed: %v", err)
	}
	// round trip through the file
	d.ServerNames = map[string]string{"192.0.2.8": "ntp-a"}
	b, _ := json.Marshal(d)
	var back NTPConfig
	if err := back.UnmarshalJSON(b); err != nil || back.ServerNames["192.0.2.8"] != "ntp-a" {
		t.Fatalf("round trip: %v %v", back.ServerNames, err)
	}
}

func TestCanvasEditServerNames(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{}
	do := func(e canvasEdit) string {
		t.Helper()
		msg, err := applyCanvasEdit(dc, e)
		if err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
		return msg
	}
	do(canvasEdit{Action: "add", Kind: "gateway", VIP: "10.0.0.1/24", Interface: "eth0"})
	do(canvasEdit{Action: "add", Kind: "server", Group: 100, Server: "10.0.0.53", Label: "ntp-a"})
	do(canvasEdit{Action: "add", Kind: "server", Group: 100, Server: "10.0.0.54"})
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	d := dc.Groups[0].NTP
	if d.ServerNames["10.0.0.53:123"] != "ntp-a" || len(d.ServerNames) != 1 {
		t.Fatalf("a name given while adding: %v", d.ServerNames)
	}
	if g := dc.Groups[0]; g.Name != "" {
		t.Fatalf("the gateway must not take the server's name: %q", g.Name)
	}
	do(canvasEdit{Action: "set", Kind: "server", Group: 100, Server: "10.0.0.54", Label: "ntp-b"})
	do(canvasEdit{Action: "set", Kind: "server", Group: 100, Server: "10.0.0.53", Label: "primary"})
	if err := dc.Validate(); err != nil || d.ServerNames["10.0.0.53:123"] != "primary" || d.ServerNames["10.0.0.54:123"] != "ntp-b" {
		t.Fatalf("renamed: %v %v", d.ServerNames, err)
	}
	do(canvasEdit{Action: "set", Kind: "server", Group: 100, Server: "10.0.0.53", Label: "-"})
	if _, has := d.ServerNames["10.0.0.53:123"]; has {
		t.Fatalf("not cleared: %v", d.ServerNames)
	}
	for e, want := range map[canvasEdit]string{
		{Action: "set", Kind: "server", Group: 100, Server: "10.0.0.99", Label: "x"}: "not on gateway",
		{Action: "set", Kind: "server", Group: 100, Server: "10.0.0.53"}:             "--label",
		{Action: "set", Kind: "server", Group: 100, Label: "x"}:                      "--server",
	} {
		if _, err := applyCanvasEdit(dc, e); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%+v: want %q, got %v", e, want, err)
		}
	}
	// a name too long is refused when the config is validated
	do(canvasEdit{Action: "set", Kind: "server", Group: 100, Server: "10.0.0.54", Label: strings.Repeat("x", 60)})
	if dc.Validate() == nil {
		t.Fatal("a 60-character name was accepted")
	}
	do(canvasEdit{Action: "set", Kind: "server", Group: 100, Server: "10.0.0.54", Label: "ntp-b"})
	// deleting the server takes its name along (a stale name would make the config invalid)
	do(canvasEdit{Action: "del", Kind: "server", Group: 100, Server: "10.0.0.54"})
	if err := dc.Validate(); err != nil || len(d.ServerNames) != 0 {
		t.Fatalf("after deleting: %v %v", d.ServerNames, err)
	}
}

func TestCanvasCarriesServerNames(t *testing.T) {
	a, b := newFakeNTP(t), newFakeNTP(t)
	d := testNTPCfg(a.addr, b.addr)
	d.ServerNames = map[string]string{a.addr: "ntp-a"}
	g := defaultGroup()
	g.NTP = &d
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	s := NewSupervisor(context.Background(), dc)
	s.refreshPool(dc, true)
	t.Cleanup(func() { s.StopAll() })
	cv := buildCanvas(dc, nil, s.poolList())
	got := map[string]string{}
	for _, sv := range cv[0].Servers {
		got[sv.Addr] = sv.Name
	}
	if got[a.addr] != "ntp-a" || got[b.addr] != "" {
		t.Fatalf("names on the canvas: %v", got)
	}
	js, _ := json.Marshal(cv[0].Servers)
	var raw []map[string]any
	if err := json.Unmarshal(js, &raw); err != nil {
		t.Fatal(err)
	}
	withName := 0
	for _, m := range raw {
		if _, ok := m["name"]; ok {
			withName++
		}
	}
	if withName != 1 {
		t.Fatalf("only the named server carries a name field: %s", js)
	}

	// a rename is only a label: the pool keeps running (probe history, cache) and is not rebuilt
	p := s.poolFor(1)
	nu := *dc
	d2 := d
	d2.ServerNames = map[string]string{a.addr: "renamed", b.addr: "ntp-b"}
	g2 := g
	g2.NTP = &d2
	nu.Groups = []GroupConfig{g2}
	s.refreshPool(&nu, true)
	if s.poolFor(1) != p {
		t.Fatal("renaming a server restarted its pool")
	}
	if cv := buildCanvas(&nu, nil, s.poolList()); cv[0].Servers[0].Name != "renamed" && cv[0].Servers[1].Name != "renamed" {
		t.Fatalf("the new name is not drawn: %+v", cv[0].Servers)
	}
}

func TestServerNamesInHistoryAndClone(t *testing.T) {
	d := defaultNTP()
	d.ServerNames = map[string]string{"8.8.8.8:123": "a"}
	c := cloneNTP(d)
	c.ServerNames["8.8.8.8:123"] = "changed"
	if d.ServerNames["8.8.8.8:123"] != "a" {
		t.Fatal("cloneNTP shares the names map")
	}
	a, b := newDaemonConfig(), newDaemonConfig()
	a.NTP, b.NTP = d, d
	b.NTP.ServerNames = map[string]string{"8.8.8.8:123": "b"}
	found := false
	for _, s := range configSections(a, b) {
		if s.Label == "NTP server names" {
			found = true
		}
	}
	if !found {
		t.Fatal("a rename is not in the history entry")
	}
}

package main

import (
	"strings"
	"testing"
)

// A test domain is renamed or given another type in its place, and its pauses go with it.
func TestCanvasSetDomain(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "add", Kind: "gateway", VIP: "10.0.0.1/24", Server: "1.1.1.1", Name: "example.org"}); err != nil {
		t.Fatal(err)
	}
	g := dc.Groups[0].GroupID
	srv := "8.8.8.8:53" // one of the defaults: google.com and amazon.com
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "pause", Kind: "domain", Group: g, Server: srv, Name: "google.com", Scope: "all"}); err != nil {
		t.Fatal(err)
	}
	msg, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "domain", Group: g, Server: srv, Name: "google.com", NewName: "cloudflare.com", NewType: "aaaa"})
	if err != nil {
		t.Fatal(err)
	}
	q := dc.Groups[0].DNS.ServerQueries[srv]
	if q[0].Name != "cloudflare.com" || q[0].Type != "AAAA" || q[1].Name != "amazon.com" {
		t.Fatalf("%s: %v", msg, q)
	}
	if p := dc.Groups[0].DNS.PausedQueries; len(p) != 1 || p[0] != queryKey(srv, "cloudflare.com", "AAAA") {
		t.Fatalf("the pause did not follow: %v", p)
	}
	for _, c := range []struct {
		e    canvasEdit
		want string
	}{
		{canvasEdit{Action: "set", Kind: "domain", Group: g, Server: srv, Name: "cloudflare.com", NewName: "amazon.com", NewType: "A"}, "already tested"},
		{canvasEdit{Action: "set", Kind: "domain", Group: g, Server: srv, Name: "nope.com", NewName: "x.com"}, "not tested"},
		{canvasEdit{Action: "set", Kind: "domain", Group: g, Server: srv, Name: "amazon.com", NewType: "BOGUS"}, "record type"},
	} {
		if _, err := applyCanvasEdit(dc, c.e); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c.e, err)
		}
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "set", Kind: "domain", Group: g, Server: srv, Name: "amazon.com", NewType: "A"}); err != errNoChange {
		t.Fatalf("no change: %v", err)
	}
}

// Only the entries of nodes no longer in the cluster are dropped, from one gateway or all.
func TestCanvasPruneLeftNodes(t *testing.T) {
	dc := newDaemonConfig()
	a, b := defaultGroup(), defaultGroup()
	a.GroupID, a.ExcludedNodes = 1, []string{"member01", "gone0001", "gone0002"}
	b.GroupID, b.ExcludedNodes = 2, []string{"gone0001"}
	dc.Groups = []GroupConfig{a, b}
	msg, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node", Group: 1, members: "member01,member02"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dc.Groups[0].ExcludedNodes, ",") != "member01" || len(dc.Groups[1].ExcludedNodes) != 1 {
		t.Fatalf("%s: %v %v", msg, dc.Groups[0].ExcludedNodes, dc.Groups[1].ExcludedNodes)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node", members: "member01"}); err != nil || len(dc.Groups[1].ExcludedNodes) != 0 {
		t.Fatalf("every gateway: %v %v", err, dc.Groups[1].ExcludedNodes)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node", members: "member01"}); err != errNoChange {
		t.Fatalf("nothing left: %v", err)
	}
	if _, err := applyCanvasEdit(dc, canvasEdit{Action: "prune", Kind: "node"}); err == nil {
		t.Fatal("pruned without knowing the cluster")
	}
}

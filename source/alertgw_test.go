package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// An alert about a pool or a gateway carries the gateways it is about, and follows them while it is open.
func TestAlertCarriesItsGateways(t *testing.T) {
	g := newAlertRig(t, "upstream_down", AlertRule{Mode: "in_a_row", After: 1, ClearMode: "checks", Clear: 2})
	gws := []int{1, 3}
	g.e.sample = func(time.Time) []alertSample {
		return []alertSample{{Rule: g.rule, Subject: "s1", Bad: g.bad, Message: "msg", Gateways: gws}}
	}
	g.step(true, 1)
	if a := g.e.View().Alerts; len(a) != 1 || fmt.Sprint(a[0].Gateways) != "[1 3]" {
		t.Fatalf("%+v", a)
	}
	gws = []int{2}
	g.step(true, 1)
	if a := g.e.View().Alerts[0]; fmt.Sprint(a.Gateways) != "[2]" {
		t.Fatalf("not followed: %v", a.Gateways)
	}
}

func TestGatewayCaptureFilter(t *testing.T) {
	gc := &GroupConfig{VIP4: "192.0.2.10/24", VIP6: "2001:db8::10/64", MoreVIP4: []string{"192.0.2.11", "192.0.2.10"}, ExtraVIPs: []string{"198.51.100.53/32"}}
	got := gatewayCapHosts(gc)
	if got != "host 192.0.2.10 or host 2001:db8::10 or host 192.0.2.11 or host 198.51.100.53" {
		t.Fatalf("%q", got)
	}
	for _, f := range []string{got, "(" + got + ") and (udp and port 53)"} {
		if _, err := compileCapFilter(f); err != nil {
			t.Fatalf("%q: %v", f, err)
		}
	}
	if gatewayCapHosts(&GroupConfig{}) != "" {
		t.Fatal("no address, no filter")
	}
}

// A gateway's capture runs on its interface, keeps only its addresses, and refuses a gateway that does not exist.
func TestClusterCaptureOfAGateway(t *testing.T) {
	e := newWebEnv(t)
	dc := newDaemonConfig()
	dc.Cluster.Enabled = false
	g := defaultGroup()
	g.GroupID, g.Interface, g.VIP4, g.VIP6 = 7, "lo", "127.0.0.77/8", ""
	dc.Groups = []GroupConfig{g}
	b, _ := json.MarshalIndent(dc, "", "  ")
	if err := os.WriteFile(e.conf, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(e.conf); err != nil {
		t.Fatal(err)
	}
	gc := dc.Groups[0]
	job, err := e.mg.CaptureClusterStart("", "udp", 1, gc.GroupID, "t")
	if err != nil {
		t.Fatal(err)
	}
	if job.Iface != gc.Interface || job.Gateway != gc.GroupID || job.Filter != "(host 127.0.0.77) and (udp)" || !strings.HasSuffix(job.Filter, ") and (udp)") {
		t.Fatalf("%+v", job)
	}
	for i := 0; i < 100; i++ { // let it finish
		if st := e.mg.CaptureClusterStatus(); st != nil {
			st.mu.Lock()
			done := st.Done
			st.mu.Unlock()
			if done {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := e.mg.CaptureClusterStart("", "", 1, 999, "t"); err == nil {
		t.Fatal("a gateway that does not exist was accepted")
	}
}

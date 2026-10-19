package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDNSDir pretends dnsdir is installed here and announces the given anycast addresses; the returned func
// removes the install, and the second rewrites dnsdir's list.
func fakeDNSDir(t *testing.T, offered ...string) (uninstall func(), setOffered func(...string)) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "dnsdir")
	os.WriteFile(bin, []byte("x"), 0o755)
	conf := filepath.Join(dir, "dnsdir.conf")
	om, oc := dnsdirMarkers, dnsdirConfPath
	dnsdirMarkers, dnsdirConfPath = []string{bin}, conf
	t.Cleanup(func() { dnsdirMarkers, dnsdirConfPath = om, oc })
	set := func(a ...string) {
		q := make([]string, len(a))
		for i, x := range a {
			q[i] = `"` + x + `"`
		}
		os.WriteFile(conf, []byte(`{"groups":[{"group_id":1,"extra_vips":[`+strings.Join(q, ",")+`]},{"group_id":2}]}`), 0o600)
	}
	set(offered...)
	return func() { os.Remove(bin) }, set
}

func TestDNSDirOffered(t *testing.T) {
	_, set := fakeDNSDir(t, "203.0.113.53/32", "2001:DB8::1", "203.0.113.53", "127.0.0.1", "junk")
	got := dnsdirOffered()
	if len(got) != 2 || got[0] != "2001:db8::1" || got[1] != "203.0.113.53" {
		t.Fatalf("offered: %v", got)
	}
	os.WriteFile(dnsdirConfPath, []byte("not json"), 0o600)
	if len(dnsdirOffered()) != 0 {
		t.Fatal("an unreadable dnsdir config offered something")
	}
	set("198.51.100.7")
	os.Remove(dnsdirMarkers[0])
	if len(dnsdirOffered()) != 0 || dnsdirInfo().Present {
		t.Fatal("offered while dnsdir is not installed")
	}
}

func TestDNSDirVIPConfigRules(t *testing.T) {
	g := defaultGroup()
	g.DNSDirVIPs = []string{"203.0.113.53/32", "2001:DB8::1"}
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := dc.Groups[0].DNSDirVIPs; got[0] != "203.0.113.53" || got[1] != "2001:db8::1" {
		t.Fatalf("not normalised: %v", got)
	}
	bad := func(name string, f func(dc *DaemonConfig)) {
		t.Helper()
		d := newDaemonConfig()
		g := defaultGroup()
		g.DNSDirVIPs = []string{"203.0.113.53"}
		d.Groups = []GroupConfig{g}
		f(d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	bad("junk", func(d *DaemonConfig) { d.Groups[0].DNSDirVIPs = []string{"x"} })
	bad("twice", func(d *DaemonConfig) { d.Groups[0].DNSDirVIPs = []string{"203.0.113.53", "203.0.113.53"} })
	bad("shared address", func(d *DaemonConfig) { d.Groups[0].DNSDirVIPs = []string{"10.0.0.1"} })
	bad("own anycast", func(d *DaemonConfig) { d.Groups[0].ExtraVIPs = []string{"203.0.113.53"} })
	bad("two gateways", func(d *DaemonConfig) {
		g2 := defaultGroup()
		g2.GroupID, g2.VIP4, g2.DNSDirVIPs = 2, "10.9.0.1/24", []string{"203.0.113.53"}
		d.Groups = append(d.Groups, g2)
	})
	// a listener restart is not needed: the list is applied in place, like the anycast list
	a, b := defaultGroup(), defaultGroup()
	b.DNSDirVIPs = []string{"203.0.113.53"}
	if restartDiffers(&a, &b) {
		t.Fatal("changing the dnsdir list restarts the gateway")
	}
}

func TestDNSDirVIPSharedAcrossCluster(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{defaultGroup()}
	plain := sharedOf(dc).hash()
	dc.Groups[0].DNSDirVIPs = []string{}
	if sharedOf(dc).hash() != plain {
		t.Fatal("an empty list changes the cluster hash")
	}
	dc.Groups[0].DNSDirVIPs = []string{"203.0.113.53"}
	sh := sharedOf(dc)
	if sh.hash() == plain {
		t.Fatal("the dnsdir addresses are not shared")
	}
	rep := newDaemonConfig()
	rep.Groups = []GroupConfig{defaultGroup()}
	if changed, err := mergeShared(rep, sh, nil); err != nil || !changed || len(rep.Groups[0].DNSDirVIPs) != 1 {
		t.Fatalf("replica did not receive it: %v %v %v", changed, err, rep.Groups[0].DNSDirVIPs)
	}
}

func TestDNSDirVIPCheckOnAdd(t *testing.T) {
	cur := newDaemonConfig()
	cur.Groups = []GroupConfig{defaultGroup()}
	next := newDaemonConfig()
	g := defaultGroup()
	g.DNSDirVIPs = []string{"203.0.113.53"}
	next.Groups = []GroupConfig{g}

	om := dnsdirMarkers
	dnsdirMarkers = []string{filepath.Join(t.TempDir(), "absent")}
	if err := checkDNSDirAdded(cur, next); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("added without dnsdir: %v", err)
	}
	dnsdirMarkers = om

	_, set := fakeDNSDir(t, "198.51.100.7")
	if err := checkDNSDirAdded(cur, next); err == nil || !strings.Contains(err.Error(), "not an anycast address of dnsdir") {
		t.Fatalf("added an address dnsdir does not announce: %v", err)
	}
	set("203.0.113.53")
	if err := checkDNSDirAdded(cur, next); err != nil {
		t.Fatalf("an announced address refused: %v", err)
	}
	// already in the configuration: kept even when dnsdir is gone
	os.Remove(dnsdirMarkers[0])
	if err := checkDNSDirAdded(next, next); err != nil {
		t.Fatalf("an address already saved was re-checked: %v", err)
	}
}

func TestDNSDirCanvasEdit(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{defaultGroup()}
	ed := func(action, addr string) error {
		_, err := applyCanvasEdit(dc, canvasEdit{Action: action, Kind: "dnsdirvip", Group: 1, Address: addr})
		return err
	}
	if err := ed("add", "203.0.113.53"); err != nil {
		t.Fatal(err)
	}
	if ed("add", "203.0.113.53") == nil || ed("add", "") == nil || ed("add", "10.0.0.0/8") == nil || ed("del", "203.0.113.99") == nil {
		t.Fatal("a bad edit was accepted")
	}
	if got := dc.Groups[0].DNSDirVIPs; len(got) != 1 || got[0] != "203.0.113.53" {
		t.Fatalf("got %v", got)
	}
	if err := ed("del", "203.0.113.53"); err != nil || len(dc.Groups[0].DNSDirVIPs) != 0 {
		t.Fatalf("not removed: %v %v", err, dc.Groups[0].DNSDirVIPs)
	}
}

// ntpdir listens on a dnsdir address while dnsdir is installed and announces it, and never adds it to or takes it off lo.
func TestDNSDirVIPListensAndNeverTouchesLo(t *testing.T) {
	lo := hookLo(t)
	uninstall, set := fakeDNSDir(t, "203.0.113.53")
	onLo := false
	oo := addrOnLoFn
	addrOnLoFn = func(string) bool { return onLo }
	t.Cleanup(func() { addrOnLoFn = oo })

	up := newFakeNTP(t)
	p := NewPool(testNTPCfg(up.addr))
	p.ProbeNow(context.Background())
	const addr = "203.0.113.53"
	a := newAnycastSet(1, nil, func() *Pool { return p })
	a.addExternal([]string{addr})
	// chrony answers on the address once dnsdir has it on lo; ntpdir only says whether that is so
	listening := func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.extOK[addr]
	}

	a.step()
	st := a.state()[0]
	if !listening() || !st.External || st.Up || !strings.Contains(st.Reason, "not announcing") {
		t.Fatalf("listener up, dnsdir not holding it yet: %+v listening=%v", st, listening())
	}
	onLo = true
	a.step()
	if st := a.state()[0]; !st.Up || st.Reason != "" {
		t.Fatalf("dnsdir holds it and a server answers: %+v", st)
	}
	up.mode.Store(2)
	p.ProbeNow(context.Background())
	a.step()
	if st := a.state()[0]; !st.Up || !strings.Contains(st.Reason, "no NTP server") || !listening() {
		t.Fatalf("a dead pool must be said, and the address left to dnsdir: %+v", st)
	}
	up.mode.Store(0)
	p.ProbeNow(context.Background())

	set("198.51.100.7") // dnsdir stops announcing it
	a.step()
	if listening() || a.state()[0].Up || !strings.Contains(a.state()[0].Reason, "does not announce") {
		t.Fatalf("still listening on an address dnsdir dropped: %+v", a.state()[0])
	}
	set(addr)
	a.step()
	if !listening() {
		t.Fatal("not listening again when dnsdir announces it")
	}
	uninstall()
	a.step()
	if listening() || !strings.Contains(a.state()[0].Reason, "not installed") {
		t.Fatalf("still listening after dnsdir was removed: %+v", a.state()[0])
	}

	a.step()
	a.cancel = func() {}
	a.done = make(chan struct{})
	close(a.done)
	a.stop()
	if lo.adds != 0 || lo.dels != 0 {
		t.Fatalf("lo was touched for a dnsdir address: %d adds, %d dels", lo.adds, lo.dels)
	}
}

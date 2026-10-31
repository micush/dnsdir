package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The DNS over TLS/HTTPS certificate is the GUI's until one is set; it then has its own, from files, from an install
// or from the cluster, and the GUI's is never touched.
func TestDNSCertFallsBackToGUIThenOwnThenReverts(t *testing.T) {
	gui, d := newTestCertMgr(t)
	conf := filepath.Join(d, "etc", "dnsdir.conf")
	files := WebConfig{}
	dm := NewDNSCertManager(filepath.Join(d, "state"), conf, func() WebConfig { return files }, gui)

	g := gui.Status()
	s := dm.Status()
	if s.Source != certSourceGUI || s.Fingerprint != g.Fingerprint || s.Error != "" {
		t.Fatalf("with nothing set the GUI's certificate is served: %+v", s)
	}
	if w := dm.ExpiryWarning(); w != "" {
		t.Fatalf("the GUI's certificate is not reported twice: %q", w)
	}
	if _, err := dm.Regenerate("t"); err == nil {
		t.Fatal("there is no automatic DNS certificate to regenerate")
	}

	ca := newTestCA(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, _, err := dm.Install(ca.issue(t, &k.PublicKey, time.Now().Add(72*time.Hour), "dns.test"), ecKeyPEM(k), "alice", certSourceInstalled); err != nil {
		t.Fatal(err)
	}
	s = dm.Status()
	if s.Source != certSourceInstalled || s.Fingerprint == g.Fingerprint {
		t.Fatalf("installed: %+v", s)
	}
	if gui.Status().Fingerprint != g.Fingerprint || gui.Status().Source != certSourceSelfSigned {
		t.Fatal("installing the DNS certificate must leave the GUI's alone")
	}
	c, err := dm.GetCertificate(nil)
	if err != nil || fingerprint(*c) != s.Fingerprint {
		t.Fatalf("handshake gets the DNS certificate: %v", err)
	}

	// files named in the config win over the installed one, and a renewal is picked up
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	crt, key := filepath.Join(d, "c.pem"), filepath.Join(d, "k.pem")
	os.WriteFile(crt, ca.issue(t, &k2.PublicKey, time.Now().Add(96*time.Hour), "files.test"), 0o644)
	os.WriteFile(key, ecKeyPEM(k2), 0o600)
	files = WebConfig{CertFile: crt, KeyFile: key}
	dm.Refresh()
	if f := dm.Status(); f.Source != certSourceFiles || f.Fingerprint == s.Fingerprint {
		t.Fatalf("files: %+v", f)
	}
	files = WebConfig{}
	dm.Refresh()
	if dm.Status().Source != certSourceInstalled {
		t.Fatal("without files the installed certificate is back")
	}

	if _, err := dm.Revert("alice"); err != nil {
		t.Fatal(err)
	}
	if s := dm.Status(); s.Source != certSourceGUI || s.Fingerprint != g.Fingerprint {
		t.Fatalf("reverted: %+v", s)
	}
	// the GUI's certificate changing is followed
	if _, _, err := gui.Install(ca.issue(t, &k.PublicKey, time.Now().Add(72*time.Hour), "gui.test"), ecKeyPEM(k), "bob", certSourceInstalled); err != nil {
		t.Fatal(err)
	}
	dm.Refresh()
	if dm.Status().Fingerprint != gui.Status().Fingerprint {
		t.Fatal("while it has none of its own, DNS follows the GUI's certificate")
	}
}

func TestDNSCertExpiryWarning(t *testing.T) {
	gui, d := newTestCertMgr(t)
	dm := NewDNSCertManager(filepath.Join(d, "state"), filepath.Join(d, "etc", "dnsdir.conf"), func() WebConfig { return WebConfig{} }, gui)
	ca := newTestCA(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, _, err := dm.Install(ca.issue(t, &k.PublicKey, time.Now().Add(5*24*time.Hour), "dns.test"), ecKeyPEM(k), "t", certSourceInstalled); err != nil {
		t.Fatal(err)
	}
	if w := dm.ExpiryWarning(); w == "" || w[:len("the DNS over TLS/HTTPS certificate")] != "the DNS over TLS/HTTPS certificate" {
		t.Fatalf("warning: %q", w)
	}
}

func TestDNSCertFilesGoTogether(t *testing.T) {
	d := defaultDNS()
	d.TLSCertFile = "/x.pem"
	if err := d.Validate(); err == nil {
		t.Fatal("a certificate file without its key must be refused")
	}
	d.TLSKeyFile = "/x.key"
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestClusterDNSCertificateReplication(t *testing.T) {
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	b.sync()
	ca := newTestCA(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chain := string(ca.issue(t, &k.PublicKey, time.Now().Add(72*time.Hour), "dns.test"))
	if _, _, err := a.mg.DNSTLSInstall(chain, string(ecKeyPEM(k)), "alice"); err != nil {
		t.Fatal(err)
	}
	b.sync()
	if s := b.mg.dnscerts.Status(); s.Source != certSourceCluster || s.Fingerprint != a.mg.dnscerts.Status().Fingerprint {
		t.Fatalf("B must present A's DNS certificate: %+v", s)
	}
	if b.mg.certs.Status().Source != certSourceSelfSigned {
		t.Fatal("the GUI certificate is not touched")
	}
	// from the replica, through the primary
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chain2 := string(ca.issue(t, &k2.PublicKey, time.Now().Add(96*time.Hour), "dns2.test"))
	if _, _, err := b.mg.DNSTLSInstall(chain2, string(ecKeyPEM(k2)), "bob"); err != nil {
		t.Fatal(err)
	}
	if a.mg.dnscerts.Status().Fingerprint != b.mg.dnscerts.Status().Fingerprint {
		t.Fatal("replica install must end up on both nodes")
	}
	if _, err := b.mg.DNSTLSRevert("bob"); err != nil {
		t.Fatal(err)
	}
	if a.mg.dnscerts.Status().Source != certSourceGUI || b.mg.dnscerts.Status().Source != certSourceGUI {
		t.Fatal("revert must reach both nodes")
	}
}

// A gateway with its own DNS pool follows the shared DNS over TLS/HTTPS ports (they are set on the Settings page).
func TestGroupPoolFollowsSharedDoTAndDoHPorts(t *testing.T) {
	dc := newDaemonConfig()
	own := defaultDNS()
	dc.Groups[0].DNS = &own
	dc.DNS.DoTPort, dc.DNS.DoHPort = 853, 443
	_, c := dc.poolFor(&dc.Groups[0])
	if c.DoTPort != 853 || c.DoHPort != 443 {
		t.Fatalf("the gateway's pool has dot %d, doh %d; want 853 and 443", c.DoTPort, c.DoHPort)
	}
}

// A gateway with its own DNS pool follows the Settings page's other pool-wide settings too (the certificate check of each
// server is the gateway's own, servertls_test.go).
func TestGroupPoolFollowsSharedSettings(t *testing.T) {
	dc := newDaemonConfig()
	own := defaultDNS()
	own.Servers = []string{"tls://86.54.11.1:853"}
	own.ECS = true
	dc.Groups[0].DNS = &own
	dc.DNS.Bootstrap = []string{"9.9.9.9:53"}
	dc.DNS.ProbeIntervalMS, dc.DNS.ProbeTimeoutMS, dc.DNS.QueryTimeoutMS = 7000, 1500, 2500
	dc.DNS.ECSPrefix4, dc.DNS.ECSPrefix6 = 22, 48
	dc.DNS.ForwardUpdates, dc.DNS.RegisterKeyName, dc.DNS.RegisterKey, dc.DNS.RegisterTTL = true, "k1", "c2VjcmV0", 120
	_, c := dc.poolFor(&dc.Groups[0])
	if len(c.Bootstrap) != 1 || c.ProbeIntervalMS != 7000 || c.ProbeTimeoutMS != 1500 || c.QueryTimeoutMS != 2500 || c.ECSPrefix4 != 22 || c.ECSPrefix6 != 48 ||
		!c.ForwardUpdates || c.RegisterKeyName != "k1" || c.RegisterKey != "c2VjcmV0" || c.RegisterTTL != 120 {
		t.Fatalf("not followed: %+v", c)
	}
	// what is the gateway's own stays its own
	if len(c.Servers) != 1 || c.Servers[0] != "tls://86.54.11.1:853" || !c.ECS {
		t.Fatalf("the gateway's own settings were overwritten: servers %v ecs %v", c.Servers, c.ECS)
	}
}

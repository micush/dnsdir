package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestMetricsIsForTheACLOnly(t *testing.T) {
	dc := newDaemonConfig()
	dc.Groups = nil
	s := NewSupervisor(context.Background(), dc)
	w := &WebServer{status: &StatusServer{sup: s}}
	set := func(acl ...string) {
		d := newDaemonConfig()
		d.Groups = nil
		d.DNS.MetricsACL = acl
		if err := d.DNS.Validate(); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		s.dc = d.effective()
		s.mu.Unlock()
	}
	get := func(from string) (int, string) {
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.RemoteAddr = from
		rw := httptest.NewRecorder()
		w.handleMetrics(rw, r)
		return rw.Code, rw.Body.String()
	}
	set() // nobody listed: nobody may read it
	if c, _ := get("192.0.2.7:5000"); c != http.StatusForbidden {
		t.Fatalf("empty list: %d, want 403", c)
	}
	set("192.0.2.7", "10.1.0.0/24", "2001:db8::/32")
	for from, want := range map[string]int{"192.0.2.7:1": 200, "10.1.0.99:1": 200, "[2001:db8::5]:1": 200, "[::ffff:192.0.2.7]:1": 200, "192.0.2.8:1": 403, "10.2.0.1:1": 403, "[2001:db9::1]:1": 403} {
		if c, _ := get(from); c != want {
			t.Errorf("%s: %d, want %d", from, c, want)
		}
	}
	_, body := get("192.0.2.7:1")
	if !strings.Contains(body, "# TYPE dnsdir_info gauge") || !strings.Contains(body, `dnsdir_info{version="`) {
		t.Fatalf("no info line in:\n%s", body)
	}
}

func TestMetricsTextHasNoBlankLinesAndEscapes(t *testing.T) {
	if got := promLabel("a", "x\"y\\z\n"); got != `a="x\"y\\z\n"` {
		t.Fatal(got)
	}
	dc := newDaemonConfig()
	dc.Groups = nil
	s := &StatusServer{sup: NewSupervisor(context.Background(), dc)}
	for _, l := range strings.Split(strings.TrimSpace(s.metricsText()), "\n") {
		if l == "" {
			t.Fatal("blank line in the page")
		}
	}
}

func TestSNMPAccessListRestrictsSources(t *testing.T) {
	c := SNMPConfig{Communities: []string{"public"}, ACL: []string{"10.0.0.0/8", " 192.0.2.5 ", "2001:db8::/32", "192.0.2.5"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.ACL, ","); got != "10.0.0.0/8,192.0.2.5,2001:db8::/32" {
		t.Fatalf("ACL %s", got)
	}
	body := snmpdConfBody(c)
	for _, want := range []string{"rocommunity public 10.0.0.0/8\n", "rocommunity public 192.0.2.5\n", "rocommunity6 public 2001:db8::/32\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	if strings.Contains(body, "rocommunity public\n") || strings.Contains(body, "rocommunity6 public\n") {
		t.Errorf("an open community is left in\n%s", body)
	}
	none := snmpdConfBody(SNMPConfig{Communities: []string{"public"}})
	if strings.Contains(none, "rocommunity") {
		t.Errorf("no list must allow nobody:\n%s", none)
	}
	bad := SNMPConfig{Communities: []string{"x"}, ACL: []string{"not-an-address"}}
	if bad.Validate() == nil {
		t.Fatal("a bad source was accepted")
	}
}

func TestACLTakesAddressesNetworksAndNames(t *testing.T) {
	got, err := normACL("x", []string{"10.1.1.1", "10.1.1.1/32", "10.1.1.1/24", "2620::/128", "2620::", "2620::/64", "Prom.Example.COM.", "prom.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(got, " "); s != "10.1.1.1 10.1.1.0/24 2620:: 2620::/64 prom.example.com" {
		t.Fatalf("got %s", s)
	}
	for _, bad := range []string{"fqdn", "a b.example.com", "-x.example.com", "10.1.1.1/33", "http://x.example.com"} {
		if _, err := normACL("x", []string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	old := aclLookup
	t.Cleanup(func() { aclLookup = old })
	aclLookup = func(n string) []netip.Addr {
		if n == "prom.example.com" {
			return []netip.Addr{netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")}
		}
		return nil
	}
	nets := expandACL(got)
	for _, a := range []string{"10.1.1.1", "10.1.1.77", "2620::", "2620::1:2", "192.0.2.9", "2001:db8::9"} {
		if !inNets(nets, netip.MustParseAddr(a)) {
			t.Errorf("%s is not in %v", a, nets)
		}
	}
	for _, a := range []string{"10.1.2.1", "2620:0:0:1::1", "192.0.2.10"} {
		if inNets(nets, netip.MustParseAddr(a)) {
			t.Errorf("%s is in %v", a, nets)
		}
	}
	// a name that cannot be looked up allows nobody, and SNMP then writes no open community
	body := snmpdConfBody(SNMPConfig{Communities: []string{"c"}, ACL: []string{"gone.example.com"}})
	if strings.Contains(body, "rocommunity c\n") || strings.Contains(body, "rocommunity c ") {
		t.Fatalf("an unresolved name opened the community:\n%s", body)
	}
	body = snmpdConfBody(SNMPConfig{Communities: []string{"c"}, ACL: []string{"prom.example.com"}})
	if !strings.Contains(body, "rocommunity c 192.0.2.9\n") || !strings.Contains(body, "rocommunity6 c 2001:db8::9\n") {
		t.Fatalf("name not written as addresses:\n%s", body)
	}
}

func TestMetricsExampleFilesUseOnlyExportedMetrics(t *testing.T) {
	src, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatal(err)
	}
	dash, err := webFS.ReadFile("webui/grafana-dashboard.json")
	if err != nil || !json.Valid(dash) {
		t.Fatalf("the dashboard is missing or not JSON: %v", err)
	}
	rules, err := webFS.ReadFile("webui/prometheus-alerts.yml")
	if err != nil || len(rules) == 0 {
		t.Fatalf("the alert rules are missing: %v", err)
	}
	re := regexp.MustCompile(`dnsdir_[a-z_]+`)
	for _, f := range [][]byte{dash, rules} {
		for _, n := range re.FindAll(f, -1) {
			if !strings.Contains(string(src), `"`+string(n)+`"`) {
				t.Errorf("%s is used in an example file but metrics.go does not write it", n)
			}
		}
	}
}

func TestMetricsCertificateExpiry(t *testing.T) {
	cm, _ := newTestCertMgr(t)
	m := &metricsOut{seen: map[string]bool{}}
	m.cert("x_not_after", "x_left", "web", cm)
	m.cert("x_not_after", "x_left", "none", nil) // no manager: nothing written
	out := m.b.String()
	if !strings.Contains(out, `x_not_after{certificate="web"} `) || !strings.Contains(out, `x_left{certificate="web"} `) || strings.Contains(out, "none") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, `x_left{`) {
			var v float64
			if _, err := fmt.Sscanf(l[strings.LastIndex(l, " ")+1:], "%g", &v); err != nil || v < 86400 {
				t.Fatalf("a new certificate should have days left: %q", l)
			}
		}
	}
}

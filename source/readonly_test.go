package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// roAuth: alice is in the login group, bob only in the read-only group "view".
type roAuth struct{ fakeAuth }

func (a *roAuth) InGroup(user, group string) (bool, error) {
	switch group {
	case "dnsdir,dnsdir-users":
		return user == "alice", nil
	case "view":
		return user == "bob", nil
	}
	return false, nil
}

func TestReadOnlyGroup(t *testing.T) {
	e := newWebEnv(t)
	e.ws.auth = &roAuth{}
	with := func(r *http.Request) {
		r.Header.Set("Cookie", cookie)
		if r.Method != "GET" {
			r.Header.Set("X-CSRF-Token", e.csrf)
		}
	}
	if r := e.login("bob", "pw"); r.code != 401 {
		t.Fatalf("a member of no group must not sign in: %d", r.code)
	}
	pol := *e.ws.policy.Load()
	pol.ReadGroup = "view"
	e.ws.policy.Store(&pol)

	if r := e.login("bob", "pw"); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("read-only login: %d %v", r.code, r.body)
	}
	if r := e.do("GET", "/api/session", nil, with); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("session: %d %v", r.code, r.body)
	}
	for _, p := range []string{"/api/gateways", "/api/config", "/api/qstats", "/api/log", "/api/users"} {
		if r := e.do("GET", p, nil, with); r.code == 403 || r.code == 401 {
			t.Errorf("GET %s was refused for a read-only account: %d %s", p, r.code, r.raw)
		}
	}
	for _, c := range []struct{ m, p string }{
		{"PUT", "/api/config"}, {"POST", "/api/cache/clear"}, {"POST", "/api/qstats/clear"}, {"POST", "/api/users/add"},
		{"POST", "/api/nettool"}, {"POST", "/api/power"}, {"POST", "/api/update/apply"}, {"POST", "/api/bgp/operate"},
	} {
		r := e.do(c.m, c.p, map[string]any{}, with)
		if r.code != 403 || !strings.Contains(string(r.raw), "read-only") {
			t.Errorf("%s %s as read-only: %d %s (want 403)", c.m, c.p, r.code, r.raw)
		}
	}
	for _, p := range []string{"/api/versions/get?id=x", "/api/versions/diff?a=x&b=y", "/api/versions/download"} {
		if r := e.do("GET", p, nil, with); r.code != 403 {
			t.Errorf("GET %s as read-only: %d (the whole configuration file must stay back)", p, r.code)
		}
	}
	if r := e.do("POST", "/api/logout", nil, with); r.code != 200 {
		t.Fatalf("a read-only account can sign out: %d", r.code)
	}

	// a member of a login group is not read-only and still changes things
	if r := e.login("alice", "pw"); r.code != 200 || r.body["read_only"] == true {
		t.Fatalf("alice: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/cache/clear", map[string]any{}, with); r.code == 403 {
		t.Fatalf("a full account was refused: %s", r.raw)
	}
}

func TestRedactSecrets(t *testing.T) {
	dc := newDaemonConfig()
	dc.DNS.RegisterKeyName = "k."
	dc.DNS.RegisterKey = "c2VjcmV0"
	out := redactSecrets(dc)
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "c2VjcmV0") || !strings.Contains(string(b), "(hidden)") || !strings.Contains(string(b), `"register_key_name":"k."`) {
		t.Fatalf("redacted: %s", b)
	}
	if dc.DNS.RegisterKey != "c2VjcmV0" {
		t.Fatal("the real config was changed")
	}
}

// A read-only account sees the BGP and OSPF pages but not the passwords in them: the status the pages read (also when it
// comes through the node picker, which runs the same handler) has them hidden, a full account still sees them, and the
// secrets FRR can echo in the result of an apply are taken out of the text.
func TestReadOnlyDoesNotSeeRoutingPasswords(t *testing.T) {
	e := bgpEnv(t)
	e.ws.auth = &roAuth{}
	pol := *e.ws.policy.Load()
	pol.ReadGroup = "view"
	e.ws.policy.Store(&pol)
	if err := e.mg.BGPSet(BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500, Password: "bgp-sekrit-1"}}}, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.mg.OSPFSet(OSPFConfig{RouterID: "192.0.2.10", Interfaces: []OSPFInterface{{Name: "eth0", Password: "ospfpw1"}}}, "t"); err != nil {
		t.Fatal(err)
	}
	if r := e.login("alice", "pw"); r.code != 200 {
		t.Fatalf("alice: %d", r.code)
	}
	full := withAuth(e, false)
	if r := e.do("GET", "/api/bgp", nil, full); r.code != 200 || !strings.Contains(string(r.raw), "bgp-sekrit-1") {
		t.Fatalf("a full account must see the BGP settings as they are (the form needs them): %d %s", r.code, r.raw)
	}
	if r := e.do("GET", "/api/ospf", nil, full); r.code != 200 || !strings.Contains(string(r.raw), "ospfpw1") {
		t.Fatalf("a full account must see the OSPF settings as they are: %d %s", r.code, r.raw)
	}
	if r := e.login("bob", "pw"); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("bob: %d %v", r.code, r.body)
	}
	ro := withAuth(e, false)
	for _, c := range []struct{ path, secret string }{{"/api/bgp", "bgp-sekrit-1"}, {"/api/ospf", "ospfpw1"}} {
		r := e.do("GET", c.path, nil, ro)
		if r.code != 200 {
			t.Fatalf("GET %s as read-only: %d %s (the page must still load)", c.path, r.code, r.raw)
		}
		if strings.Contains(string(r.raw), c.secret) || !strings.Contains(string(r.raw), `"password":"(hidden)"`) {
			t.Errorf("GET %s as read-only shows the password: %s", c.path, r.raw)
		}
	}
	if r := e.do("GET", "/api/bgp", nil, ro); !strings.Contains(string(r.raw), `"peer":"192.0.2.1"`) || !strings.Contains(string(r.raw), `"remote_as":64500`) {
		t.Errorf("the rest of the BGP settings must still be there: %s", r.raw)
	}
}

func TestRedactRoutingTakesSecretsOutOfTheApplyText(t *testing.T) {
	st := BGPStatus{Config: BGPConfig{ASN: 64512, Neighbors: []BGPNeighbor{{Peer: "192.0.2.1", RemoteAS: 64500, Password: "bgp-sekrit-1"}}},
		Applied: BGPApplied{OK: false, Detail: "reloading FRR failed: exit status 1  neighbor 192.0.2.1 password bgp-sekrit-1\n ip ospf message-digest-key 1 md5 ospfpw1"}}
	b, _ := json.Marshal(redactRouting(st))
	for _, s := range []string{"bgp-sekrit-1", "ospfpw1"} {
		if strings.Contains(string(b), s) {
			t.Errorf("%q is still in %s", s, b)
		}
	}
	if !strings.Contains(string(b), "reloading FRR failed") || !strings.Contains(string(b), `"peer":"192.0.2.1"`) {
		t.Errorf("the rest must stay: %s", b)
	}
	if st.Config.Neighbors[0].Password != "bgp-sekrit-1" {
		t.Error("the status itself must not be changed")
	}
}

func TestReadOnlyDoesNotSeeTheRepositoryPath(t *testing.T) {
	e := bgpEnv(t)
	e.ws.auth = &roAuth{}
	pol := *e.ws.policy.Load()
	pol.ReadGroup = "view"
	e.ws.policy.Store(&pol)
	if err := e.mg.UpdateRepo("https://github.com/someone/secretrepo", "t"); err != nil {
		t.Fatal(err)
	}
	if r := e.login("alice", "pw"); r.code != 200 {
		t.Fatalf("alice: %d", r.code)
	}
	full := withAuth(e, false)
	for _, p := range []string{"/api/update", "/api/update/history"} {
		if r := e.do("GET", p, nil, full); r.code != 200 || !strings.Contains(string(r.raw), "someone/secretrepo") {
			t.Fatalf("a full account must see the repository on %s: %d %s", p, r.code, r.raw)
		}
	}
	if r := e.login("bob", "pw"); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("bob: %d %v", r.code, r.body)
	}
	ro := withAuth(e, false)
	for _, p := range []string{"/api/update", "/api/update/history"} {
		r := e.do("GET", p, nil, ro)
		if r.code != 200 {
			t.Fatalf("GET %s as read-only: %d %s (the page must still load)", p, r.code, r.raw)
		}
		if strings.Contains(string(r.raw), "someone") || strings.Contains(string(r.raw), "secretrepo") {
			t.Errorf("GET %s as read-only shows the repository: %s", p, r.raw)
		}
	}
	if r := e.do("GET", "/api/update", nil, ro); !strings.Contains(string(r.raw), `"repo":"(hidden)"`) {
		t.Errorf("the repository must read (hidden): %s", r.raw)
	}
}

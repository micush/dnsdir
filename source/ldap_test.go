package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// A small directory server that speaks enough LDAP for the client: simple bind, search (and, or, not, equality and the
// nested-group matching rule), StartTLS and unbind.

type fakeUser struct {
	dn, sam, upn, pw string
	disabled         bool
	computer         bool
	groups           map[string]bool // lower-case DNs of every group it is in, nested ones included
}

type fakeLDAP struct {
	t              *testing.T
	ln             net.Listener
	cfg            *tls.Config
	mu             sync.Mutex
	users          []*fakeUser
	groups         map[string]string // sAMAccountName -> DN
	svcDN, svcPW   string
	svcBinds       int
	userBinds      int
	refuseStartTLS bool
	tlsFirst       bool
}

const (
	fakeRW = "CN=dns-admins,OU=Groups,DC=example,DC=lan"
	fakeRO = "CN=dns-readers,OU=Groups,DC=example,DC=lan"
)

func newFakeLDAP(t *testing.T, tlsFirst bool) *fakeLDAP {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc1"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	f := &fakeLDAP{t: t, tlsFirst: tlsFirst, svcDN: "CN=svc,OU=Service,DC=example,DC=lan", svcPW: "svcpw",
		groups: map[string]string{"dns-admins": fakeRW, "dns-readers": fakeRO},
		cfg:    &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	add := func(sam, pw string, groups ...string) *fakeUser {
		u := &fakeUser{dn: "CN=" + sam + ",OU=People,DC=example,DC=lan", sam: sam, upn: sam + "@example.lan", pw: pw, groups: map[string]bool{}}
		for _, g := range groups {
			u.groups[strings.ToLower(g)] = true
		}
		f.users = append(f.users, u)
		return u
	}
	add("alice", "alicepw", fakeRW)
	add("bob", "bobpw", fakeRO)
	add("carol", "carolpw")
	add("dave", "davepw", fakeRW).disabled = true
	add("erin", "erinpw", fakeRW) // in the group through another group
	add("pc1$", "pcpw", fakeRW).computer = true
	add("twin", "twinpw", fakeRW)
	add("twin", "twinpw", fakeRW).dn = "CN=twin2,OU=People,DC=example,DC=lan"
	add("dora", "dorapw", fakeRW)
	add("rob", "robpw", fakeRO)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	t.Cleanup(f.stop)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeLDAP) stop() { f.ln.Close() }

func (f *fakeLDAP) addr() string {
	s := "ldap://"
	if f.tlsFirst {
		s = "ldaps://"
	}
	return s + f.ln.Addr().String()
}

func (f *fakeLDAP) config() LDAPConfig {
	return LDAPConfig{LDAPServers: []string{f.addr()}, LDAPSkipVerify: true, LDAPBindDN: f.svcDN, LDAPBindPassword: f.svcPW,
		LDAPBaseDN: "DC=example,DC=lan", LDAPRWGroup: fakeRW, LDAPROGroup: "dns-readers"}
}

func lresult(tag byte, code int, diag string) []byte {
	return tlv(tag, berInt(0x0a, code), berOctet(""), berOctet(diag))
}

type fakeEntry struct {
	dn      string
	classes []string
	sam     string
	upn     string
	uac     string
	chain   map[string]bool
}

func (f *fakeLDAP) entries() []*fakeEntry {
	var out []*fakeEntry
	for _, u := range f.users {
		e := &fakeEntry{dn: u.dn, classes: []string{"top", "person", "user"}, sam: u.sam, upn: u.upn, uac: "512", chain: u.groups}
		if u.computer {
			e.classes = append(e.classes, "computer")
		}
		if u.disabled {
			e.uac = "514"
		}
		out = append(out, e)
	}
	for sam, dn := range f.groups {
		out = append(out, &fakeEntry{dn: dn, classes: []string{"top", "group"}, sam: sam})
	}
	return out
}

func evalFilter(n *berNode, e *fakeEntry) bool {
	switch n.tag {
	case 0xA0:
		for _, k := range n.kids {
			if !evalFilter(k, e) {
				return false
			}
		}
		return true
	case 0xA1:
		for _, k := range n.kids {
			if evalFilter(k, e) {
				return true
			}
		}
		return false
	case 0xA2:
		return !evalFilter(n.kids[0], e)
	case 0xA3:
		attr, val := strings.ToLower(string(n.kids[0].val)), string(n.kids[1].val)
		switch attr {
		case "objectclass":
			for _, c := range e.classes {
				if strings.EqualFold(c, val) {
					return true
				}
			}
		case "samaccountname":
			return strings.EqualFold(e.sam, val)
		case "userprincipalname":
			return e.upn != "" && strings.EqualFold(e.upn, val)
		}
		return false
	case 0xA9:
		var rule, attr, val string
		for _, k := range n.kids {
			switch k.tag {
			case 0x81:
				rule = string(k.val)
			case 0x82:
				attr = string(k.val)
			case 0x83:
				val = string(k.val)
			}
		}
		return rule == "1.2.840.113556.1.4.1941" && strings.EqualFold(attr, "memberOf") && e.chain[strings.ToLower(val)]
	}
	return false
}

func (f *fakeLDAP) serve(raw net.Conn) {
	var c net.Conn = raw
	defer func() { c.Close() }()
	if f.tlsFirst {
		c = tls.Server(raw, f.cfg)
	}
	br := bufio.NewReader(c)
	bound := false
	send := func(id int, op []byte) { c.Write(tlv(0x30, berInt(0x02, id), op)) }
	for {
		id, op, err := readMessage(br)
		if err != nil {
			return
		}
		f.mu.Lock()
		switch op.tag {
		case 0x77: // StartTLS
			f.mu.Unlock()
			if f.refuseStartTLS {
				send(id, lresult(0x78, 2, "no"))
				continue
			}
			send(id, lresult(0x78, 0, ""))
			c = tls.Server(raw, f.cfg)
			br = bufio.NewReader(c)
			continue
		case 0x60: // bind
			dn, pw := string(op.kids[1].val), string(op.kids[2].val)
			ok := false
			if dn == f.svcDN {
				f.svcBinds++
				ok = pw == f.svcPW
				bound = ok
			} else {
				f.userBinds++
				for _, u := range f.users {
					who := strings.EqualFold(u.dn, dn) || strings.EqualFold(u.upn, dn) || strings.EqualFold("EXAMPLE\\"+u.sam, dn)
					if !who && strings.EqualFold(u.sam+"@example.lan", dn) { // account name @ domain, only when no account has it as its UPN (as Active Directory does)
						who = true
						for _, o := range f.users {
							if strings.EqualFold(o.upn, dn) {
								who = false
							}
						}
					}
					if who && u.pw == pw && pw != "" && !u.disabled {
						ok = true
					}
				}
			}
			if ok {
				if dn != f.svcDN {
					bound = true // a person who bound may read the directory too
				}
				send(id, lresult(0x61, 0, ""))
			} else {
				send(id, lresult(0x61, 49, "invalid credentials"))
			}
		case 0x63: // search
			if !bound {
				send(id, lresult(0x65, 50, "bind first"))
				break
			}
			base, scope, limit, filter, attrs := string(op.kids[0].val), berToInt(op.kids[1]), berToInt(op.kids[3]), op.kids[6], op.kids[7]
			var hits []*fakeEntry
			for _, e := range f.entries() {
				if scope == ldapScopeBase && !strings.EqualFold(e.dn, base) {
					continue
				}
				if evalFilter(filter, e) {
					hits = append(hits, e)
				}
			}
			code := 0
			if limit > 0 && len(hits) > limit {
				hits, code = hits[:limit], 4
			}
			for _, e := range hits {
				var as [][]byte
				for _, a := range attrs.kids {
					if strings.EqualFold(string(a.val), "sAMAccountName") && e.sam != "" {
						as = append(as, tlv(0x30, berOctet("sAMAccountName"), tlv(0x31, berOctet(e.sam))))
					}
					if strings.EqualFold(string(a.val), "userPrincipalName") && e.upn != "" {
						as = append(as, tlv(0x30, berOctet("userPrincipalName"), tlv(0x31, berOctet(e.upn))))
					}
					if strings.EqualFold(string(a.val), "userAccountControl") && e.uac != "" && e.sam != "" && !strings.Contains(strings.Join(e.classes, ","), "group") {
						as = append(as, tlv(0x30, berOctet("userAccountControl"), tlv(0x31, berOctet(e.uac))))
					}
				}
				send(id, tlv(0x64, berOctet(e.dn), tlv(0x30, as...)))
			}
			send(id, lresult(0x65, code, ""))
		case 0x42:
			f.mu.Unlock()
			return
		}
		f.mu.Unlock()
	}
}

func TestLDAPFind(t *testing.T) {
	f := newFakeLDAP(t, true)
	// erin is in the group through another group, which the chain rule sees (the fake keeps the flattened set)
	cfg := f.config()
	for _, c := range []struct {
		user, pw string
		ok, ro   bool
	}{
		{"alice", "alicepw", true, false},
		{"EXAMPLE\\alice", "alicepw", true, false}, // DOMAIN\name
		{"alice@example.lan", "alicepw", true, false},
		{"ALICE", "alicepw", true, false},
		{"bob", "bobpw", true, true},
		{"erin", "erinpw", true, false},
		{"alice", "wrong", false, false},
		{"carol", "carolpw", false, false},      // in no group
		{"dave", "davepw", false, false},        // disabled
		{"pc1$", "pcpw", false, false},          // a computer account is not a person
		{"twin", "twinpw", false, false},        // two accounts with the name
		{"nobody", "x", false, false},           // no such account
		{"*)(objectClass=*", "x", false, false}, // filter characters are only a name that does not exist
		{"alice", "", false, false},             // an empty password is never a login
	} {
		before := f.userBinds
		o := cfg.ldapFind(c.user, c.pw, true)
		if o.OK != c.ok || (c.ok && o.ReadOnly != c.ro) {
			t.Errorf("%q: ok=%v ro=%v, want ok=%v ro=%v (%v)", c.user, o.OK, o.ReadOnly, c.ok, c.ro, o.Steps)
		}
		if o.Failed {
			t.Errorf("%q: reported as a directory failure: %v", c.user, o.Steps)
		}
		if c.pw == "" && f.userBinds != before {
			t.Errorf("an empty password was sent to the server")
		}
	}
	// the recheck of a session asks without a password
	if o := cfg.ldapFind("bob", "", false); !o.OK || !o.ReadOnly {
		t.Errorf("recheck: %v", o.Steps)
	}
	// a disabled account is refused by the lookup itself (a recheck has no password to fail)
	if o := cfg.ldapFind("dave", "", false); o.OK {
		t.Errorf("a disabled account passed the recheck: %v", o.Steps)
	}
	// a wrong service account is a settings problem, not an answer about a person
	bad := cfg
	bad.LDAPBindPassword = "nope"
	if o := bad.ldapFind("alice", "alicepw", true); o.OK || !o.Failed {
		t.Errorf("wrong bind password: %v", o.Steps)
	}
	// a server that is gone is a failure too (the session stays)
	f.stop()
	if o := cfg.ldapFind("alice", "", false); o.OK || !o.Failed {
		t.Errorf("server down: %v", o.Steps)
	}
}

func TestLDAPStartTLSAndCertificates(t *testing.T) {
	// ldap:// with StartTLS
	f := newFakeLDAP(t, false)
	cfg := f.config()
	if o := cfg.ldapFind("alice", "alicepw", true); !o.OK {
		t.Fatalf("StartTLS: %v", o.Steps)
	}
	// a server that will not start TLS is not given the password, or the service account's
	g := newFakeLDAP(t, false)
	g.refuseStartTLS = true
	c2 := g.config()
	if o := c2.ldapFind("alice", "alicepw", true); o.OK || g.svcBinds != 0 || g.userBinds != 0 {
		t.Fatalf("StartTLS refused: ok=%v binds=%d/%d %v", o.OK, g.svcBinds, g.userBinds, o.Steps)
	}
	// certificate checking: a self-signed certificate is refused unless the checkbox is on
	h := newFakeLDAP(t, true)
	c3 := h.config()
	c3.LDAPSkipVerify = false
	if o := c3.ldapFind("alice", "alicepw", true); o.OK || !o.Failed || h.svcBinds != 0 {
		t.Fatalf("self-signed certificate was accepted: %v", o.Steps)
	}
	c3.LDAPSkipVerify = true
	if o := c3.ldapFind("alice", "alicepw", true); !o.OK {
		t.Fatalf("with the checkbox on: %v", o.Steps)
	}
	// the first server is down: the second answers
	c4 := h.config()
	c4.LDAPServers = []string{"ldaps://127.0.0.1:1", h.addr()}
	if o := c4.ldapFind("alice", "alicepw", true); !o.OK {
		t.Fatalf("fallback server: %v", o.Steps)
	}
}

func TestLDAPWebLogin(t *testing.T) {
	f := newFakeLDAP(t, true)
	e := newWebEnv(t)
	p := defaultWeb()
	p.MaxFailedLogins = 50
	p.LDAPConfig = f.config()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	e.ws.policy.Store(&p)
	// a directory account that the host does not know
	if r := e.login("dora", "dorapw"); r.code != 200 || r.body["read_only"] != false {
		t.Fatalf("dora: %d %v", r.code, r.body)
	}
	session := func() resp { return e.do("GET", "/api/session", nil, withAuth(e, false)) }
	if r := session(); r.code != 200 || r.body["user"] != "dora" {
		t.Fatalf("session: %d %v", r.code, r.body)
	}
	age := func() {
		e.ws.mu.Lock()
		for _, s := range e.ws.sessions {
			s.checked = time.Now().Add(-time.Hour)
		}
		e.ws.mu.Unlock()
	}
	// the read-only group gives a read-only session
	if r := e.login("rob", "robpw"); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("rob: %d %v", r.code, r.body)
	}
	// a wrong password, and a host account, still behave as before
	if r := e.login("dora", "wrong"); r.code != 401 {
		t.Fatalf("wrong password: %d", r.code)
	}
	binds := f.svcBinds
	if r := e.login("alice", "pw"); r.code != 200 {
		t.Fatalf("host account: %d", r.code)
	}
	if f.svcBinds != binds {
		t.Fatal("the directory was asked about a host account")
	}
	// removed from the group: the session ends at the next check; the directory unreachable: it stays
	e.login("dora", "dorapw")
	f.mu.Lock()
	for _, u := range f.users {
		if u.sam == "dora" {
			u.groups = map[string]bool{}
		}
	}
	f.mu.Unlock()
	age()
	if r := session(); r.code != 401 {
		t.Fatalf("after removal: %d", r.code)
	}
	e.login("rob", "robpw")
	f.stop()
	age()
	if r := session(); r.code != 200 {
		t.Fatalf("directory down: %d", r.code)
	}
	// the Test button: needs a full-access session, says what happened
	e.login("alice", "pw")
	f2 := newFakeLDAP(t, true)
	q := *e.ws.policy.Load()
	q.LDAPConfig = f2.config()
	e.ws.policy.Store(&q)
	r := e.do("POST", "/api/ldap/test", map[string]string{"username": "bob", "password": "bobpw"}, withAuth(e, true))
	d, _ := r.body["data"].(map[string]any)
	if r.code != 200 || d["ok"] != true || d["read_only"] != true || len(d["steps"].([]any)) < 3 {
		t.Fatalf("test: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/ldap/test", map[string]string{}, withAuth(e, true)); r.code != 200 || r.body["data"].(map[string]any)["ok"] != true {
		t.Fatalf("test without a user: %d %v", r.code, r.body)
	}
	if r := e.do("POST", "/api/ldap/test", map[string]string{"username": "bob"}, func(r *http.Request) {}); r.code != 401 {
		t.Fatalf("test without a session: %d", r.code)
	}
}

func TestLDAPConfigRules(t *testing.T) {
	c := LDAPConfig{LDAPServers: []string{"ldaps://dc1.example.lan, ldap://dc2.example.lan:389/"}, LDAPBindDN: " CN=svc,DC=x ", LDAPBindPassword: "p"}
	if err := c.validateLDAP(); err != nil || strings.Join(c.LDAPServers, "|") != "ldaps://dc1.example.lan|ldap://dc2.example.lan:389" || c.LDAPBindDN != "CN=svc,DC=x" {
		t.Fatalf("%v %+v", err, c)
	}
	for _, bad := range []LDAPConfig{
		{LDAPServers: []string{"http://dc1"}}, {LDAPServers: []string{"dc1.example.lan"}}, {LDAPServers: []string{"ldaps://u:p@dc1"}},
		{LDAPServers: []string{"ldaps://dc1/base"}}, {LDAPBaseDN: "DC=x\nDC=y"}, {LDAPRWGroup: strings.Repeat("x", 600)},
		{LDAPServers: strings.Fields("ldap://a ldap://b ldap://c ldap://d ldap://e ldap://f ldap://g ldap://h ldap://i")},
	} {
		if err := bad.validateLDAP(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	// half set up is not an error and is not enabled
	h := LDAPConfig{LDAPServers: []string{"ldaps://dc1"}, LDAPBindDN: "x"}
	if err := h.validateLDAP(); err != nil || h.enabled() {
		t.Fatalf("half set up: %v", err)
	}
	// shared by the cluster only when set; read-only accounts are not shown the password
	dc := newDaemonConfig()
	if sharedOf(dc).LDAP != nil {
		t.Fatal("an empty LDAP block appears in the shared document")
	}
	dc.Web.LDAPConfig = LDAPConfig{LDAPServers: []string{"ldaps://dc1"}, LDAPBindDN: "svc", LDAPBindPassword: "hunter2", LDAPBaseDN: "DC=x", LDAPRWGroup: "g"}
	sc := sharedOf(dc)
	if sc.LDAP == nil || sc.LDAP.LDAPBindDN != "svc" {
		t.Fatal("not shared")
	}
	b, _ := json.Marshal(dc)
	var back DaemonConfig
	if err := json.Unmarshal(b, &back); err != nil || back.Web.LDAPBindPassword != "hunter2" || !back.Web.LDAPConfig.enabled() {
		t.Fatalf("round trip: %v %+v", err, back.Web.LDAPConfig)
	}
	red, _ := json.Marshal(redactSecrets(dc.Web))
	if strings.Contains(string(red), "hunter2") {
		t.Fatalf("the bind password is shown: %s", red)
	}
	_ = fmt.Sprint
}

// Without a service account each person binds as themselves.
func TestLDAPNoServiceAccount(t *testing.T) {
	f := newFakeLDAP(t, true)
	cfg := f.config()
	cfg.LDAPBindDN, cfg.LDAPBindPassword = "", ""
	if !cfg.enabled() || cfg.hasBind() {
		t.Fatal("a configuration without a bind account is not enabled")
	}
	for _, c := range []struct {
		user, pw string
		ok, ro   bool
	}{
		{"alice", "alicepw", true, false},
		{"EXAMPLE\\alice", "alicepw", true, false},
		{"alice@example.lan", "alicepw", true, false},
		{"bob", "bobpw", true, true},
		{"erin", "erinpw", true, false},
		{"alice", "wrong", false, false},
		{"carol", "carolpw", false, false}, // in no group
		{"dave", "davepw", false, false},   // disabled: the directory refuses the bind
		{"pc1$", "pcpw", false, false},     // a computer account
		{"twin", "twinpw", false, false},   // two accounts with the name
		{"nobody", "x", false, false},
		{"alice", "", false, false},
	} {
		before := f.userBinds
		o := cfg.ldapFind(c.user, c.pw, true)
		if o.OK != c.ok || (c.ok && o.ReadOnly != c.ro) {
			t.Errorf("%q: ok=%v ro=%v, want ok=%v ro=%v (%v)", c.user, o.OK, o.ReadOnly, c.ok, c.ro, o.Steps)
		}
		if o.Failed {
			t.Errorf("%q: reported as a directory failure: %v", c.user, o.Steps)
		}
		if c.pw == "" && f.userBinds != before {
			t.Errorf("an empty password was sent to the server")
		}
	}
	if f.svcBinds != 0 {
		t.Errorf("the service account was used %d times", f.svcBinds)
	}
	// a session cannot be rechecked: asking without a password is refused, and says why
	if o := cfg.ldapFind("alice", "", false); o.OK || !o.Failed {
		t.Errorf("recheck without a service account: %v", o.Steps)
	}
	// a service account without its password (or the reverse) is half set up, so off
	half := cfg
	half.LDAPBindDN = "CN=svc,DC=x"
	if half.enabled() {
		t.Error("a bind account without a password is enabled")
	}
	// the entry read back must be the account that signed in: twin2 shares a name but not the bind identity
	tw := newFakeLDAP(t, true)
	for _, u := range tw.users {
		if u.dn == "CN=twin2,OU=People,DC=example,DC=lan" {
			u.sam, u.upn = "other", "other@example.lan"
		}
	}
	tc := tw.config()
	tc.LDAPBindDN, tc.LDAPBindPassword = "", ""
	if o := tc.ldapFind("twin", "twinpw", true); !o.OK {
		t.Errorf("a unique twin should sign in: %v", o.Steps)
	}
	// somebody else's password must not sign in as the account the name finds: "alice" binds as alice@example.lan, which
	// here belongs to another account (ally) than the one whose account name is alice
	for _, u := range tw.users {
		if u.sam == "alice" {
			u.upn = "alice2@example.lan"
		}
	}
	tw.users = append(tw.users, &fakeUser{dn: "CN=ally,OU=People,DC=example,DC=lan", sam: "ally", upn: "alice@example.lan", pw: "allypw",
		groups: map[string]bool{strings.ToLower(fakeRW): true}})
	if o := tc.ldapFind("alice", "allypw", true); o.OK {
		t.Errorf("a different account signed in under alice's name: %v", o.Steps)
	}
}

// An account whose user principal name is not name@domain still signs in by its account name (mcc -> mcc@example.lan) when no
// other account has that UPN; when one has, it is the one that signed in and the entry found is refused.
func TestLDAPAccountNameWithDifferentUPN(t *testing.T) {
	f := newFakeLDAP(t, true)
	f.users = append(f.users, &fakeUser{dn: "CN=Michael,OU=People,DC=example,DC=lan", sam: "mcc", upn: "michael.cushard@example.com", pw: "mccpw",
		groups: map[string]bool{strings.ToLower(fakeRW): true}})
	cfg := f.config()
	cfg.LDAPBindDN, cfg.LDAPBindPassword = "", ""
	for _, user := range []string{"mcc", "EXAMPLE\\mcc"} {
		if o := cfg.ldapFind(user, "mccpw", true); !o.OK || o.Failed {
			t.Errorf("%q should sign in: %v", user, o.Steps)
		}
	}
	if o := cfg.ldapFind("mcc", "wrong", true); o.OK {
		t.Errorf("a wrong password signed in: %v", o.Steps)
	}
	// another account owns mcc@example.lan as its UPN: the server signs that one in, not the account named mcc
	f.users = append(f.users, &fakeUser{dn: "CN=Other,OU=People,DC=example,DC=lan", sam: "other", upn: "mcc@example.lan", pw: "otherpw",
		groups: map[string]bool{strings.ToLower(fakeRW): true}})
	if o := cfg.ldapFind("mcc", "otherpw", true); o.OK {
		t.Errorf("a different account signed in under mcc's name: %v", o.Steps)
	}
	if o := cfg.ldapFind("mcc", "mccpw", true); o.OK {
		t.Errorf("mcc's own password cannot sign in while another account owns the UPN: %v", o.Steps)
	}
}

func TestLDAPBindName(t *testing.T) {
	c := LDAPConfig{LDAPBaseDN: "OU=x,DC=example,DC=lan"}
	for in, want := range map[string]string{"alice": "alice@example.lan", "a@b.c": "a@b.c", `EX\a`: `EX\a`} {
		if got := c.ldapBindName(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := (LDAPConfig{LDAPBaseDN: "O=x"}).ldapBindName("alice"); got != "alice" {
		t.Errorf("no DC parts: %q", got)
	}
}

func TestLDAPWebNoServiceAccount(t *testing.T) {
	f := newFakeLDAP(t, true)
	e := newWebEnv(t)
	p := defaultWeb()
	p.MaxFailedLogins = 50
	p.LDAPConfig = f.config()
	p.LDAPBindDN, p.LDAPBindPassword = "", ""
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	e.ws.policy.Store(&p)
	if r := e.login("dora", "dorapw"); r.code != 200 || r.body["read_only"] != false {
		t.Fatalf("dora: %d %v", r.code, r.body)
	}
	if r := e.login("rob", "robpw"); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("rob: %d %v", r.code, r.body)
	}
	// a session cannot be rechecked, so it stays even when the directory would now refuse it
	for _, u := range f.users {
		if u.sam == "dora" {
			u.disabled = true
		}
	}
	e.ws.mu.Lock()
	for _, s := range e.ws.sessions {
		s.checked = time.Now().Add(-time.Hour)
	}
	e.ws.mu.Unlock()
	if r := e.do("GET", "/api/session", nil, withAuth(e, false)); r.code != 200 {
		t.Fatalf("session was ended without a service account: %d", r.code)
	}
	if f.svcBinds != 0 {
		t.Fatalf("service account used %d times", f.svcBinds)
	}
	// the Test button needs a password in this mode
	e.login("alice", "pw")
	r := e.do("POST", "/api/ldap/test", map[string]any{"username": "rob"}, withAuth(e, true))
	d, _ := r.body["data"].(map[string]any)
	if r.code != 200 || d["ok"] != false || !strings.Contains(fmt.Sprint(d["steps"]), "password") {
		t.Fatalf("test without a password: %d %v", r.code, r.body)
	}
	r = e.do("POST", "/api/ldap/test", map[string]any{"username": "rob", "password": "robpw"}, withAuth(e, true))
	if d, _ = r.body["data"].(map[string]any); r.code != 200 || d["ok"] != true || d["read_only"] != true {
		t.Fatalf("test with a password: %d %v", r.code, r.body)
	}
}

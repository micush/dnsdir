package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	cryptoRandPkg "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCA is just enough of an ACME server (RFC 8555) and of an acme-dns server to run the whole flow; it checks the JWS
// signatures and the dns-01 proof the way a real CA would.
type fakeCA struct {
	t   *testing.T
	ca  *testCA
	srv *httptest.Server
	mu  sync.Mutex

	nonces  map[string]bool
	acctKey *ecdsa.PublicKey
	needEAB bool
	eabKey  []byte
	eabSeen bool

	orders []*fakeOrder
	authz  []*fakeAuthz

	// acme-dns
	regs  map[string][2]string // subdomain -> user, password
	txt   map[string][]string  // fulldomain -> the newest values (two kept)
	cname map[string]string    // base domain -> where its _acme-challenge points (the test's "DNS")
	nreg  int
}

type fakeOrder struct {
	names []string
	authz []int
	chain []byte
	done  bool
}
type fakeAuthz struct {
	base, token, status string
	wildcard            bool
}

func newFakeCA(t *testing.T) *fakeCA {
	f := &fakeCA{t: t, ca: newTestCA(t), nonces: map[string]bool{}, regs: map[string][2]string{}, txt: map[string][]string{}, cname: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCA) dir() string     { return f.srv.URL + "/dir" }
func (f *fakeCA) acmeDNS() string { return f.srv.URL + "/acmedns" }
func (f *fakeCA) nonce() string {
	n := fmt.Sprint(time.Now().UnixNano(), len(f.nonces))
	f.nonces[n] = true
	return n
}

func (f *fakeCA) reply(w http.ResponseWriter, code int, v any, hdr map[string]string) {
	w.Header().Set("Replay-Nonce", f.nonce())
	for k, x := range hdr {
		w.Header().Set(k, x)
	}
	if s, ok := v.([]byte); ok {
		w.WriteHeader(code)
		w.Write(s)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func (f *fakeCA) problem(w http.ResponseWriter, code int, typ, detail string) {
	f.reply(w, code, map[string]string{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail}, nil)
}

func de(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

// jws verifies a request and returns its payload.  A request with a jwk creates the account; one with a kid is the account.
func (f *fakeCA) jws(w http.ResponseWriter, r *http.Request) (payload []byte, isJWK bool, ok bool) {
	var body struct{ Protected, Payload, Signature string }
	b, _ := io.ReadAll(r.Body)
	if json.Unmarshal(b, &body) != nil {
		f.problem(w, 400, "malformed", "bad JWS")
		return
	}
	var prot struct {
		Alg, Nonce, URL, Kid string
		Jwk                  map[string]string
	}
	json.Unmarshal(de(body.Protected), &prot)
	if prot.Alg != "ES256" || prot.URL != "http://"+r.Host+r.URL.Path {
		f.problem(w, 400, "malformed", "wrong alg or url "+prot.URL)
		return
	}
	if !f.nonces[prot.Nonce] {
		f.problem(w, 400, "badNonce", "bad nonce")
		return
	}
	delete(f.nonces, prot.Nonce)
	var pub *ecdsa.PublicKey
	if prot.Jwk != nil {
		pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(de(prot.Jwk["x"])), Y: new(big.Int).SetBytes(de(prot.Jwk["y"]))}
		isJWK = true
	} else {
		if prot.Kid != f.srv.URL+"/acct/1" || f.acctKey == nil {
			f.problem(w, 401, "unauthorized", "unknown account")
			return
		}
		pub = f.acctKey
	}
	sig := de(body.Signature)
	h := sha256.Sum256([]byte(body.Protected + "." + body.Payload))
	if len(sig) != 64 || !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		f.problem(w, 400, "malformed", "bad signature")
		return
	}
	if isJWK {
		f.acctKey = pub
	}
	return de(body.Payload), isJWK, true
}

func (f *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.srv.URL
	switch p := r.URL.Path; {
	case p == "/dir":
		d := map[string]any{"newNonce": u + "/nonce", "newAccount": u + "/acct", "newOrder": u + "/order"}
		if f.needEAB {
			d["meta"] = map[string]any{"externalAccountRequired": true}
		}
		f.reply(w, 200, d, nil)
	case p == "/nonce":
		f.reply(w, 200, nil, nil)
	case p == "/acct":
		pl, _, ok := f.jws(w, r)
		if !ok {
			return
		}
		var req struct {
			TermsOfServiceAgreed   bool
			Contact                []string
			ExternalAccountBinding *struct{ Protected, Payload, Signature string }
		}
		json.Unmarshal(pl, &req)
		if !req.TermsOfServiceAgreed {
			f.problem(w, 400, "malformed", "terms not agreed")
			return
		}
		if f.needEAB {
			e := req.ExternalAccountBinding
			if e == nil {
				f.problem(w, 400, "externalAccountRequired", "needs EAB")
				return
			}
			m := hmac.New(sha256.New, f.eabKey)
			m.Write([]byte(e.Protected + "." + e.Payload))
			if !hmac.Equal(m.Sum(nil), de(e.Signature)) {
				f.problem(w, 400, "unauthorized", "bad EAB mac")
				return
			}
			f.eabSeen = true
		}
		f.reply(w, 201, map[string]string{"status": "valid"}, map[string]string{"Location": u + "/acct/1"})
	case p == "/order":
		pl, _, ok := f.jws(w, r)
		if !ok {
			return
		}
		var req struct {
			Identifiers []acmeIdentifier
		}
		json.Unmarshal(pl, &req)
		o := &fakeOrder{}
		var az []string
		for _, id := range req.Identifiers {
			o.names = append(o.names, id.Value)
			a := &fakeAuthz{base: strings.TrimPrefix(id.Value, "*."), wildcard: strings.HasPrefix(id.Value, "*."), token: fmt.Sprintf("tok%d", len(f.authz)), status: "pending"}
			f.authz = append(f.authz, a)
			o.authz = append(o.authz, len(f.authz)-1)
			az = append(az, fmt.Sprintf("%s/authz/%d", u, len(f.authz)-1))
		}
		f.orders = append(f.orders, o)
		n := len(f.orders) - 1
		f.reply(w, 201, map[string]any{"status": "pending", "authorizations": az, "finalize": fmt.Sprintf("%s/final/%d", u, n)}, map[string]string{"Location": fmt.Sprintf("%s/order/%d", u, n)})
	case strings.HasPrefix(p, "/authz/"):
		if _, _, ok := f.jws(w, r); !ok {
			return
		}
		var i int
		fmt.Sscan(strings.TrimPrefix(p, "/authz/"), &i)
		a := f.authz[i]
		ch := map[string]any{"type": "dns-01", "url": fmt.Sprintf("%s/chall/%d", u, i), "token": a.token, "status": "pending"}
		if a.status == "invalid" {
			ch["error"] = map[string]string{"type": "urn:ietf:params:acme:error:dns", "detail": "no TXT record found for " + a.base}
		}
		f.reply(w, 200, map[string]any{"status": a.status, "identifier": acmeIdentifier{"dns", a.base}, "wildcard": a.wildcard,
			"challenges": []any{map[string]any{"type": "http-01", "url": u + "/nope", "token": "x"}, ch}}, nil)
	case strings.HasPrefix(p, "/chall/"):
		if _, _, ok := f.jws(w, r); !ok {
			return
		}
		var i int
		fmt.Sscan(strings.TrimPrefix(p, "/chall/"), &i)
		a := f.authz[i]
		want := acmeKeyAuthTXT(a.token, f.acctKey)
		a.status = "invalid"
		if full := f.cname[a.base]; full != "" {
			for _, v := range f.txt[full] {
				if v == want {
					a.status = "valid"
				}
			}
		}
		f.reply(w, 200, map[string]string{"status": "processing"}, nil)
	case strings.HasPrefix(p, "/final/"):
		pl, _, ok := f.jws(w, r)
		if !ok {
			return
		}
		var i int
		fmt.Sscan(strings.TrimPrefix(p, "/final/"), &i)
		o := f.orders[i]
		var req struct{ CSR string }
		json.Unmarshal(pl, &req)
		csr, err := x509.ParseCertificateRequest(de(req.CSR))
		if err != nil || csr.CheckSignature() != nil {
			f.problem(w, 400, "badCSR", "bad csr")
			return
		}
		o.chain = f.ca.issue(f.t, csr.PublicKey.(*ecdsa.PublicKey), time.Now().Add(90*24*time.Hour), csr.DNSNames...)
		o.done = true
		f.reply(w, 200, map[string]string{"status": "valid"}, nil)
	case strings.HasPrefix(p, "/order/"):
		if _, _, ok := f.jws(w, r); !ok {
			return
		}
		var i int
		fmt.Sscan(strings.TrimPrefix(p, "/order/"), &i)
		o := f.orders[i]
		st := map[string]any{"status": "pending"}
		if o.done {
			st = map[string]any{"status": "valid", "certificate": fmt.Sprintf("%s/cert/%d", u, i)}
		}
		f.reply(w, 200, st, nil)
	case strings.HasPrefix(p, "/cert/"):
		if _, _, ok := f.jws(w, r); !ok {
			return
		}
		var i int
		fmt.Sscan(strings.TrimPrefix(p, "/cert/"), &i)
		f.reply(w, 200, f.orders[i].chain, map[string]string{"Content-Type": "application/pem-certificate-chain"})
	case p == "/acmedns/register":
		f.nreg++
		sub := fmt.Sprintf("sub%d", f.nreg)
		f.regs[sub] = [2]string{"user" + sub, "pass" + sub}
		f.reply(w, 201, map[string]string{"username": "user" + sub, "password": "pass" + sub, "subdomain": sub, "fulldomain": sub + ".auth.test"}, nil)
	case p == "/acmedns/update":
		var body struct{ Subdomain, Txt string }
		json.NewDecoder(r.Body).Decode(&body)
		c, ok := f.regs[body.Subdomain]
		if !ok || r.Header.Get("X-Api-User") != c[0] || r.Header.Get("X-Api-Key") != c[1] || len(body.Txt) != 43 {
			f.reply(w, 401, map[string]string{"error": "bad"}, nil)
			return
		}
		full := body.Subdomain + ".auth.test"
		f.txt[full] = append(f.txt[full], body.Txt)
		if len(f.txt[full]) > 2 {
			f.txt[full] = f.txt[full][len(f.txt[full])-2:]
		}
		f.reply(w, 200, map[string]string{"txt": body.Txt}, nil)
	default:
		http.NotFound(w, r)
	}
}

// acmeTestMgr sets a node's ACME manager up against the fake.
func acmeTestMgr(t *testing.T, f *fakeCA, n *tnode) *ACMEManager {
	m := n.mg.acme
	m.hc = f.srv.Client()
	m.settle, m.jitter = 0, 0
	m.lookupCNAME = func(_ context.Context, host string) (string, error) {
		b := strings.TrimPrefix(host, "_acme-challenge.")
		f.mu.Lock()
		defer f.mu.Unlock()
		if full := f.cname[b]; full != "" {
			return full + ".", nil
		}
		return host + ".", nil
	}
	return m
}

func ctxTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func waitACME(t *testing.T, m *ACMEManager) ACMEView {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		v := m.Status()
		if !v.Running {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatal("the order did not finish")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (f *fakeCA) point(m *ACMEManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	for b, r := range m.st.Regs {
		f.cname[b] = r.FullDomain
	}
}

func TestACMEEndToEnd(t *testing.T) {
	f := newFakeCA(t)
	n := newTNode(t, "A")
	m := acmeTestMgr(t, f, n)
	if err := m.Set(ACMESettings{Enabled: true, Directory: f.dir(), Email: "a@example.com", Names: []string{"DNS.example.com", "example.com", "*.example.com"}, Target: "dns", DNSServer: f.acmeDNS()}, "t"); err != nil {
		t.Fatal(err)
	}
	if !m.hasTask() {
		t.Fatal("turning it on must add the renewal task to the Scheduler")
	}
	if err := m.Request("t"); err == nil || !strings.Contains(err.Error(), "Set up DNS records") {
		t.Fatalf("an order before the records are set up must say so: %v", err)
	}
	ctx, cancel := ctxTimeout(10 * time.Second)
	defer cancel()
	if err := m.Register(ctx); err != nil {
		t.Fatal(err)
	}
	v := m.Status()
	if len(v.Records) != 2 || v.Records[0].Name != "_acme-challenge.dns.example.com" || v.Records[1].Name != "_acme-challenge.example.com" || v.Records[1].Target == "" {
		t.Fatalf("example.com and *.example.com share one record: %+v", v.Records)
	}
	// before the CNAME exists the order is refused with a clear reason, and nothing is installed
	if err := m.Request("t"); err != nil {
		t.Fatal(err)
	}
	if v := waitACME(t, m); !strings.Contains(v.LastError, "not a CNAME yet") || v.Issued != nil {
		t.Fatalf("missing CNAME: %+v", v)
	}
	if n.mg.dnscerts.Status().Source != certSourceGUI {
		t.Fatal("a failed order must change nothing")
	}
	f.point(m)
	m.Check(ctx)
	for _, r := range m.Status().Records {
		if !r.Checked || !r.OK {
			t.Fatalf("check: %+v", r)
		}
	}
	if err := m.Request("t"); err != nil {
		t.Fatal(err)
	}
	v = waitACME(t, m)
	if v.LastError != "" || v.Issued == nil {
		t.Fatalf("order: %+v progress %v", v, v.Progress)
	}
	s := n.mg.dnscerts.Status()
	if s.Source != certSourceInstalled || s.Fingerprint != v.Issued.Fingerprint || s.InstalledBy != "acme" {
		t.Fatalf("installed: %+v", s)
	}
	if got := strings.Join(s.DNSNames, ","); !strings.Contains(got, "dns.example.com") || !strings.Contains(got, "*.example.com") {
		t.Fatalf("names: %v", s.DNSNames)
	}
	if n.mg.certs.Status().Source != certSourceSelfSigned {
		t.Fatal("the GUI certificate must not change for target dns")
	}
	// not due yet
	out, err := m.RunScheduled("sched")
	if err != nil || !strings.HasPrefix(out, "nothing to do") {
		t.Fatalf("not due: %q %v", out, err)
	}
	// near expiry: the scheduled run renews
	m.mu.Lock()
	m.st.Issued.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	m.mu.Unlock()
	old := v.Issued.Fingerprint
	if out, err = m.RunScheduled("sched"); err != nil || out != "certificate renewed" {
		t.Fatalf("renew: %q %v", out, err)
	}
	if v = m.Status(); v.Issued.Fingerprint == old || n.mg.dnscerts.Status().Fingerprint != v.Issued.Fingerprint {
		t.Fatalf("renewed: %+v", v.Issued)
	}
	// a certificate installed by hand pauses the automatic renewal
	m.mu.Lock()
	m.st.Issued.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	m.mu.Unlock()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), cryptoRandPkg.Reader)
	if _, _, err := n.mg.dnscerts.Install(f.ca.issue(t, &k.PublicKey, time.Now().Add(72*time.Hour), "hand.test"), ecKeyPEM(k), "bob", certSourceInstalled); err != nil {
		t.Fatal(err)
	}
	if out, _ = m.RunScheduled("sched"); !strings.Contains(out, "by hand") {
		t.Fatalf("a hand-installed certificate must pause renewal: %q", out)
	}
	// the account key and the acme-dns password never leave through the view
	b, _ := json.Marshal(m.Status())
	if strings.Contains(string(b), "PRIVATE KEY") || strings.Contains(string(b), "passsub") {
		t.Fatalf("secrets in the view: %s", b)
	}
}

func TestACMEExternalAccountBinding(t *testing.T) {
	f := newFakeCA(t)
	f.needEAB, f.eabKey = true, []byte("secret-eab-key-1234")
	n := newTNode(t, "A")
	m := acmeTestMgr(t, f, n)
	set := ACMESettings{Enabled: true, Directory: f.dir(), Names: []string{"dns.example.com"}, DNSServer: f.acmeDNS()}
	if err := m.Set(set, "t"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := ctxTimeout(10 * time.Second)
	defer cancel()
	m.Register(ctx)
	f.point(m)
	m.Request("t")
	if v := waitACME(t, m); !strings.Contains(v.LastError, "EAB") {
		t.Fatalf("a CA that needs EAB must be told so: %q", v.LastError)
	}
	set.EABKid, set.EABKey = "kid-1", base64.RawURLEncoding.EncodeToString(f.eabKey)
	if err := m.Set(set, "t"); err != nil {
		t.Fatal(err)
	}
	m.Request("t")
	if v := waitACME(t, m); v.LastError != "" || !f.eabSeen {
		t.Fatalf("with EAB: %q seen=%v", v.LastError, f.eabSeen)
	}
	// saving again with the key box empty keeps the key
	set.EABKey = ""
	if err := m.Set(set, "t"); err != nil || !m.Status().EABKeySet {
		t.Fatalf("the key must be kept: %v", err)
	}
}

func TestACMESettingsChecks(t *testing.T) {
	n := newTNode(t, "A")
	m := n.mg.acme
	bad := []ACMESettings{
		{Names: []string{"10.0.0.1"}},
		{Names: []string{"localhost"}},
		{Names: []string{"a b.example.com"}},
		{Names: []string{"x.example.com"}, Directory: "http://ca.example.com/dir"},
		{Names: []string{"x.example.com"}, DNSServer: "ftp://x"},
		{Names: []string{"x.example.com"}, Target: "everywhere"},
		{Names: []string{"x.example.com"}, Email: "nobody"},
		{Enabled: true},
	}
	for i, s := range bad {
		if err := m.Set(s, "t"); err == nil {
			t.Fatalf("case %d must be refused: %+v", i, s)
		}
	}
	if err := m.Set(ACMESettings{Names: []string{"X.Example.com", "x.example.com", "*.example.com"}}, "t"); err != nil {
		t.Fatal(err)
	}
	if v := m.Status(); strings.Join(v.Settings.Names, ",") != "x.example.com,*.example.com" || v.Settings.Directory != acmeLetsEncrypt || v.Settings.DNSServer != defaultACMEDNS {
		t.Fatalf("normalised: %+v", v.Settings)
	}
	if m.hasTask() {
		t.Fatal("no task is added while it is off")
	}
}

func TestACMEClusterReplication(t *testing.T) {
	f := newFakeCA(t)
	a, b := newTNode(t, "A"), newTNode(t, "B")
	b.join(a)
	b.sync()
	ma, mb := acmeTestMgr(t, f, a), acmeTestMgr(t, f, b)
	if err := ma.Set(ACMESettings{Enabled: true, Directory: f.dir(), Names: []string{"dns.example.com"}, DNSServer: f.acmeDNS()}, "t"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := ctxTimeout(10 * time.Second)
	defer cancel()
	if err := ma.Register(ctx); err != nil {
		t.Fatal(err)
	}
	f.point(ma)
	ma.Request("t")
	if v := waitACME(t, ma); v.LastError != "" {
		t.Fatalf("order: %+v", v)
	}
	b.sync()
	v := mb.Status()
	if !v.Settings.Enabled || v.Issued == nil || len(v.Records) != 1 || v.Records[0].Target == "" || v.Primary {
		t.Fatalf("B must carry the primary's state: %+v", v)
	}
	if b.mg.dnscerts.Status().Fingerprint != v.Issued.Fingerprint {
		t.Fatal("B serves the certificate A ordered")
	}
	// a replica does not renew; its scheduled run says so
	mb.mu.Lock()
	mb.st.Issued.NotAfter = time.Now().Add(time.Hour)
	mb.mu.Unlock()
	if out, err := mb.RunScheduled("sched"); err != nil || !strings.Contains(out, "not the primary") {
		t.Fatalf("replica: %q %v", out, err)
	}
	// a change on the replica goes through the primary
	if _, err := b.mg.ACMESet(ACMESettings{Enabled: true, Directory: f.dir(), Names: []string{"dns.example.com", "dns2.example.com"}, DNSServer: f.acmeDNS()}, "bob"); err != nil {
		t.Fatal(err)
	}
	if len(ma.Status().Settings.Names) != 2 {
		t.Fatal("the primary must have taken the change")
	}
	b.sync()
	if len(mb.Status().Settings.Names) != 2 {
		t.Fatal("the replica must see it after a sync")
	}
}

func TestACMEShareCredentialsBetweenClusters(t *testing.T) {
	f := newFakeCA(t)
	a, b := newTNode(t, "A"), newTNode(t, "B")
	ma, mb := acmeTestMgr(t, f, a), acmeTestMgr(t, f, b)
	set := ACMESettings{Enabled: true, Directory: f.dir(), Names: []string{"dns.example.com"}, DNSServer: f.acmeDNS()}
	if err := ma.Set(set, "t"); err != nil {
		t.Fatal(err)
	}
	if err := mb.Set(set, "t"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := ctxTimeout(10 * time.Second)
	defer cancel()
	if err := ma.Register(ctx); err != nil {
		t.Fatal(err)
	}
	regs := ma.ExportRegs()
	if err := mb.ImportRegs(map[string]acmeDNSReg{"other.example.com": regs["dns.example.com"]}, "t"); err == nil {
		t.Fatal("credentials for a name that is not set here must be refused")
	}
	bad := regs["dns.example.com"]
	bad.Server = "https://elsewhere.example.com"
	if err := mb.ImportRegs(map[string]acmeDNSReg{"dns.example.com": bad}, "t"); err == nil {
		t.Fatal("credentials for another acme-dns server must be refused")
	}
	if err := mb.ImportRegs(regs, "t"); err != nil {
		t.Fatal(err)
	}
	f.point(ma)
	for _, m := range []*ACMEManager{ma, mb} {
		m.Request("t")
		if v := waitACME(t, m); v.LastError != "" || v.Issued == nil {
			t.Fatalf("both clusters order with the same CNAME: %+v", v)
		}
	}
	if len(f.regs) != 1 {
		t.Fatalf("one acme-dns entry for both: %d", len(f.regs))
	}
}

func TestACMESaveRegistersTheNames(t *testing.T) {
	f := newFakeCA(t)
	n := newTNode(t, "A")
	m := acmeTestMgr(t, f, n)
	v, err := n.mg.ACMESet(ACMESettings{Enabled: true, Directory: f.dir(), Names: []string{"dns.example.com"}, DNSServer: f.acmeDNS()}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Records) != 1 || !v.Records[0].Registered || v.Records[0].Target == "" || v.RegisterError != "" {
		t.Fatalf("saving must leave the CNAME target ready to copy: %+v", v)
	}
	// a server that cannot be reached is reported on the page, and the settings stay saved
	f.srv.Close()
	m.mu.Lock()
	m.st.Regs = map[string]acmeDNSReg{}
	m.mu.Unlock()
	v, err = n.mg.ACMESet(ACMESettings{Enabled: true, Directory: f.dir(), Names: []string{"dns.example.com"}, DNSServer: f.acmeDNS()}, "t")
	if err != nil || v.RegisterError == "" || len(v.Settings.Names) != 1 {
		t.Fatalf("unreachable acme-dns: %+v %v", v, err)
	}
}

func TestACMEGoWaitsForTheCNAMEsAndThenOrders(t *testing.T) {
	f := newFakeCA(t)
	n := newTNode(t, "A")
	m := acmeTestMgr(t, f, n)
	m.pollEvery = 20 * time.Millisecond
	set := ACMESettings{Directory: f.dir(), Names: []string{"dns.example.com"}, DNSServer: f.acmeDNS()}
	v, err := n.mg.ACMEGo(set, "t")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Settings.Enabled || !v.Waiting || len(v.Records) != 1 || v.Records[0].Target == "" {
		t.Fatalf("with no CNAME yet it waits and shows what to add: %+v", v)
	}
	time.Sleep(100 * time.Millisecond)
	if m.Status().Issued != nil {
		t.Fatal("nothing may be ordered before the CNAME exists")
	}
	f.point(m) // the person adds the CNAME
	deadline := time.Now().Add(10 * time.Second)
	for m.Status().Issued == nil {
		if time.Now().After(deadline) {
			t.Fatalf("the watcher never ordered: %+v", m.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if v := waitACME(t, m); v.LastError != "" || v.Waiting || n.mg.dnscerts.Status().Source != certSourceInstalled {
		t.Fatalf("after: %+v", v)
	}
	// with the CNAME already there, pressing the button orders at once
	if v, err = n.mg.ACMEGo(set, "t"); err != nil || v.Waiting {
		t.Fatalf("immediate: %+v %v", v, err)
	}
	waitACME(t, m)
}

func TestACMEClientPrefersIPv4(t *testing.T) {
	hc := acmeHTTPClient()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close()
	// "localhost" has both ::1 and 127.0.0.1; the server listens on IPv4 only, so this works only if IPv4 is tried first
	u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := hc.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestSameNameSetIgnoresOrder(t *testing.T) {
	if !sameNameSet([]string{"b.example.com", "a.example.com"}, []string{"a.example.com", "b.example.com"}) {
		t.Fatal("the same names in another order are the same set")
	}
	if sameNameSet([]string{"a.example.com"}, []string{"a.example.com", "b.example.com"}) {
		t.Fatal("different names are not the same set")
	}
}

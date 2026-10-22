package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeIdP struct {
	t        *testing.T
	srv      *httptest.Server
	key      *rsa.PrivateKey
	other    *rsa.PrivateKey
	secret   string
	nonce    string
	challnge string
	redirect string
	mut      func(claims map[string]any, hdr map[string]any)
	badSig   bool
	tokens   int
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newFakeIdP(t *testing.T) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	o, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{t: t, key: k, other: o, secret: "s3cret"}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	disc := func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/keys"})
	}
	mux.HandleFunc("/.well-known/openid-configuration", disc)
	mux.HandleFunc("/{tenant}/v2.0/.well-known/openid-configuration", disc)
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64(f.key.N.Bytes()), "e": b64(big.NewInt(int64(f.key.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.tokens++
		ch := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("client_secret") != f.secret || r.Form.Get("code") != "good-code" || b64(ch[:]) != f.challnge || r.Form.Get("redirect_uri") != f.redirect {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "no"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.token(r.Form.Get("client_id")), "access_token": "x"})
	})
	return f
}

func (f *fakeIdP) token(aud string) string {
	claims := map[string]any{"iss": f.srv.URL, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(), "nonce": f.nonce,
		"email": "alice@example.com", "email_verified": true, "tid": "11111111-2222-3333-4444-555555555555"}
	hdr := map[string]any{"alg": "RS256", "kid": "k1"}
	if f.mut != nil {
		f.mut(claims, hdr)
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signed := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(signed))
	key := f.key
	if f.badSig {
		key = f.other
	}
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return signed + "." + b64(sig)
}

// signIn runs the browser's part: start, (the provider), callback.  It returns the callback response and the session cookie, if any.
func (f *fakeIdP) signIn(e *webEnv, provider string, mut func(claims, hdr map[string]any)) (*http.Response, string) {
	f.t.Helper()
	f.mut = mut
	get := func(path, cookie string) *http.Response {
		req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		res, err := e.client.Do(req)
		if err != nil {
			f.t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	res := get("/api/sso/start?p="+provider, "")
	if res.StatusCode != 302 {
		f.t.Fatalf("start: %d", res.StatusCode)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("state") == "" || q.Get("nonce") == "" {
		f.t.Fatalf("authorization request: %v", q)
	}
	f.nonce, f.challnge, f.redirect = q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")
	if !strings.HasSuffix(f.redirect, "/api/sso/callback") {
		f.t.Fatalf("redirect %q", f.redirect)
	}
	var ck string
	for _, c := range res.Cookies() {
		if c.Name == ssoCookie {
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
				f.t.Fatalf("sso cookie flags: %+v", c)
			}
			ck = c.Name + "=" + c.Value
		}
	}
	back := get("/api/sso/callback?code=good-code&state="+url.QueryEscape(q.Get("state")), ck)
	for _, c := range back.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return back, c.Name + "=" + c.Value
		}
	}
	return back, ""
}

func ssoEnv(t *testing.T, users ...string) (*webEnv, *fakeIdP) {
	f := newFakeIdP(t)
	ssoInsecure, ssoGoogleIssuer, ssoEntraBase = true, f.srv.URL, f.srv.URL
	t.Cleanup(func() {
		ssoInsecure, ssoGoogleIssuer, ssoEntraBase = false, "https://accounts.google.com", "https://login.microsoftonline.com"
	})
	e := newWebEnv(t)
	p := defaultWeb()
	p.GoogleClientID, p.GoogleClientSecret = "gid", f.secret
	p.EntraTenant, p.EntraClientID, p.EntraClientSecret = "11111111-2222-3333-4444-555555555555", "eid", f.secret
	p.Users = users
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	e.ws.policy.Store(&p)
	return e, f
}

func sessionOf(e *webEnv, cookie string) resp {
	return e.do("GET", "/api/session", nil, func(r *http.Request) { r.Header.Set("Cookie", cookie) })
}

func TestSSOSignIn(t *testing.T) {
	e, f := ssoEnv(t, "alice@example.com rw", "Bob@Example.com")
	// the login page learns which buttons to show
	if r := e.do("GET", "/api/login/state", nil); len(r.body["sso"].([]any)) != 2 {
		t.Fatalf("login state: %v", r.body)
	}
	for _, prov := range []string{"google", "entra"} {
		back, ck := f.signIn(e, prov, nil)
		if back.StatusCode != 302 || back.Header.Get("Location") != "/" || ck == "" {
			t.Fatalf("%s: %d %q %q", prov, back.StatusCode, back.Header.Get("Location"), ck)
		}
		if r := sessionOf(e, ck); r.code != 200 || r.body["user"] != "alice@example.com" || r.body["read_only"] != false || r.body["sso"] != true {
			t.Fatalf("%s session: %d %v", prov, r.code, r.body)
		}
	}
	// no level written: read-only
	_, ck := f.signIn(e, "google", func(c, h map[string]any) { c["email"] = "BOB@example.com" })
	if r := sessionOf(e, ck); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("bob: %d %v", r.code, r.body)
	}
	// Entra without an e-mail claim: the user name is used
	_, ck = f.signIn(e, "entra", func(c, h map[string]any) { delete(c, "email"); c["preferred_username"] = "alice@example.com" })
	if ck == "" {
		t.Fatal("entra preferred_username was not used")
	}
}

func TestSSORefusals(t *testing.T) {
	e, f := ssoEnv(t, "alice@example.com rw")
	now := time.Now()
	for name, c := range map[string]struct {
		prov string
		mut  func(c, h map[string]any)
		bad  bool
	}{
		"not on the list":         {"google", func(c, h map[string]any) { c["email"] = "mallory@example.com" }, false},
		"unverified google email": {"google", func(c, h map[string]any) { c["email_verified"] = false }, false},
		"other audience":          {"google", func(c, h map[string]any) { c["aud"] = "someone-else" }, false},
		"other issuer":            {"google", func(c, h map[string]any) { c["iss"] = "https://evil.example" }, false},
		"expired":                 {"google", func(c, h map[string]any) { c["exp"] = now.Add(-time.Hour).Unix() }, false},
		"wrong nonce":             {"google", func(c, h map[string]any) { c["nonce"] = "other" }, false},
		"alg none":                {"google", func(c, h map[string]any) { h["alg"] = "none" }, false},
		"alg HS256":               {"google", func(c, h map[string]any) { h["alg"] = "HS256" }, false},
		"unknown key id":          {"google", func(c, h map[string]any) { h["kid"] = "zzz" }, false},
		"bad signature":           {"google", nil, true},
		"other tenant":            {"entra", func(c, h map[string]any) { c["tid"] = "99999999-2222-3333-4444-555555555555" }, false},
	} {
		f.badSig = c.bad
		back, ck := f.signIn(e, c.prov, c.mut)
		f.badSig = false
		if ck != "" || !strings.HasPrefix(back.Header.Get("Location"), "/?sso_error=") {
			t.Errorf("%s: signed in (%q) or no error redirect (%q)", name, ck, back.Header.Get("Location"))
		}
	}
	// a callback from a browser that did not start the sign-in
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/sso/callback?code=good-code&state=made-up", nil)
	res, _ := e.client.Do(req)
	res.Body.Close()
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			t.Fatal("a forged callback signed someone in")
		}
	}
	// a provider that is not set up
	req, _ = http.NewRequest("GET", e.ts.URL+"/api/sso/start?p=nope", nil)
	if res, _ = e.client.Do(req); res.StatusCode != 404 {
		t.Fatalf("unknown provider: %d", res.StatusCode)
	}
	// a state cannot be used twice
	f.mut = nil
	res0 := func() (string, string) {
		req, _ := http.NewRequest("GET", e.ts.URL+"/api/sso/start?p=google", nil)
		res, _ := e.client.Do(req)
		loc, _ := url.Parse(res.Header.Get("Location"))
		f.nonce, f.challnge, f.redirect = loc.Query().Get("nonce"), loc.Query().Get("code_challenge"), loc.Query().Get("redirect_uri")
		ck := ""
		for _, c := range res.Cookies() {
			if c.Name == ssoCookie {
				ck = c.Name + "=" + c.Value
			}
		}
		return loc.Query().Get("state"), ck
	}
	st, ck := res0()
	call := func() *http.Response {
		req, _ := http.NewRequest("GET", e.ts.URL+"/api/sso/callback?code=good-code&state="+url.QueryEscape(st), nil)
		req.Header.Set("Cookie", ck)
		res, _ := e.client.Do(req)
		return res
	}
	hasSession := func(r *http.Response) bool {
		for _, c := range r.Cookies() {
			if c.Name == sessionCookie && c.Value != "" {
				return true
			}
		}
		return false
	}
	if !hasSession(call()) || hasSession(call()) {
		t.Fatal("a state must work once")
	}
}

func TestSSOSessionFollowsTheList(t *testing.T) {
	e, f := ssoEnv(t, "alice@example.com rw")
	_, ck := f.signIn(e, "google", nil)
	if sessionOf(e, ck).code != 200 {
		t.Fatal("not signed in")
	}
	// demoted: the next check (a minute later) makes it read-only; removed: it ends
	age := func() {
		e.ws.mu.Lock()
		for _, s := range e.ws.sessions {
			s.checked = time.Now().Add(-time.Hour)
		}
		e.ws.mu.Unlock()
	}
	p := *e.ws.policy.Load()
	p.Users = []string{"alice@example.com ro"}
	e.ws.policy.Store(&p)
	age()
	if r := sessionOf(e, ck); r.code != 200 || r.body["read_only"] != true {
		t.Fatalf("after demotion: %d %v", r.code, r.body)
	}
	p.Users = nil
	e.ws.policy.Store(&p)
	age()
	if r := sessionOf(e, ck); r.code != 401 {
		t.Fatalf("after removal: %d", r.code)
	}
}

func TestSSOConfigRules(t *testing.T) {
	c := SSOConfig{Users: []string{"Alice@Example.com rw, bob@example.com", "carol@example.com read-only", "alice@example.com ro"}}
	if err := c.validateSSO(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Users, "|"); got != "alice@example.com ro|bob@example.com ro|carol@example.com ro" {
		t.Fatalf("users: %s", got)
	}
	for _, bad := range []SSOConfig{
		{Users: []string{"not-an-email"}}, {Users: []string{"a@b@c"}}, {EntraTenant: "contoso.com"},
		{BaseURL: "http://x.example"}, {BaseURL: "https://x.example/path"}, {GoogleClientID: "has space"},
	} {
		if err := bad.validateSSO(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	// half set up is not an error and is not a provider
	h := SSOConfig{GoogleClientID: "x"}
	if err := h.validateSSO(); err != nil || len(h.providers()) != 0 {
		t.Fatalf("half set up: %v %v", err, h.providers())
	}
	// the cluster's document is unchanged while nothing is set, and carries the settings when they are
	dc := newDaemonConfig()
	if sharedOf(dc).SSO != nil {
		t.Fatal("an empty SSO block appears in the shared document")
	}
	dc.Web.GoogleClientID, dc.Web.GoogleClientSecret, dc.Web.Users = "g", "s", []string{"a@b.co rw"}
	sc := sharedOf(dc)
	if sc.SSO == nil || sc.SSO.GoogleClientID != "g" {
		t.Fatal("not shared")
	}
	var back DaemonConfig
	b, _ := json.Marshal(dc)
	if err := json.Unmarshal(b, &back); err != nil || back.Web.GoogleClientSecret != "s" || len(back.Web.Users) != 1 {
		t.Fatalf("round trip: %v %+v", err, back.Web.SSOConfig)
	}
	// a read-only account is not shown the secrets
	red, _ := json.Marshal(redactSecrets(dc.Web))
	if strings.Contains(string(red), `"s"`) && strings.Contains(string(red), "sso_google_client_secret\":\"s") {
		t.Fatalf("secret shown: %s", red)
	}
}

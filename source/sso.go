package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Single sign-on with Google or Microsoft Entra ID (OpenID Connect, authorization code flow with PKCE).
//
// The login page shows a button for each provider that is set up.  The button sends the browser to the provider; the
// provider sends it back to /api/sso/callback with a one-time code; the daemon trades the code for an ID token at the
// provider's token endpoint, checks the token (signature against the provider's published keys, issuer, audience, expiry,
// nonce), and signs the person in when their e-mail address is on the list of allowed users (sso_users), with the access
// level written beside it: rw (may change settings) or ro (may only look).  Password login through PAM is unchanged and
// stays available.  An SSO session is checked against the list every minute, like a PAM session against its group, so
// removing an address ends its sessions.
//
// Who may sign in is only ever decided by the list: a Google account or a Microsoft account that is not on it gets nothing.
// For Entra ID the tenant is fixed (the token's issuer and tid must be that tenant), so only that organisation's accounts
// are looked at.

// SSOConfig is the single sign-on part of the web block (flat keys in the file), shared by the cluster.
type SSOConfig struct {
	GoogleClientID     string `json:"sso_google_client_id,omitempty"`
	GoogleClientSecret string `json:"sso_google_client_secret,omitempty"`
	EntraTenant        string `json:"sso_entra_tenant,omitempty"`
	EntraClientID      string `json:"sso_entra_client_id,omitempty"`
	EntraClientSecret  string `json:"sso_entra_client_secret,omitempty"`
	// OIDC is any other OpenID Connect provider (Authentik, Keycloak, Authelia, ...): its issuer address, a name for the
	// button, and the client ID and secret registered with it.
	OIDCName         string `json:"sso_oidc_name,omitempty"`
	OIDCIssuer       string `json:"sso_oidc_issuer,omitempty"`
	OIDCClientID     string `json:"sso_oidc_client_id,omitempty"`
	OIDCClientSecret string `json:"sso_oidc_client_secret,omitempty"`
	// OIDCSkipVerify accepts any certificate the provider presents (a self-signed one, say).  The connection is still
	// encrypted, but nothing proves who is on the other end.
	OIDCSkipVerify bool `json:"sso_oidc_skip_verify,omitempty"`
	// Users are the people who may sign in: "alice@example.com rw" or "bob@example.com ro" (no level means ro).
	Users []string `json:"sso_users,omitempty"`
	// BaseURL is the address the provider sends the browser back to ("https://dns1.example.com:53853"); empty uses the
	// address the browser used to reach this node.  It must be registered with the provider as BaseURL/api/sso/callback.
	BaseURL string `json:"sso_base_url,omitempty"`
}

func (c SSOConfig) empty() bool {
	return c.GoogleClientID == "" && c.GoogleClientSecret == "" && c.EntraTenant == "" && c.EntraClientID == "" &&
		c.EntraClientSecret == "" && c.OIDCName == "" && c.OIDCIssuer == "" && c.OIDCClientID == "" && c.OIDCClientSecret == "" && !c.OIDCSkipVerify &&
		len(c.Users) == 0 && c.BaseURL == ""
}

func (c SSOConfig) clone() *SSOConfig {
	if c.empty() {
		return nil
	}
	c.Users = append([]string(nil), c.Users...)
	return &c
}

var entraTenantRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

const ssoMaxUsers = 5000

// ssoProviderToken is the name a provider has in the users list: "google", "microsoft" (an Entra ID provider is "entra" inside) or "oidc".
func ssoProviderToken(id string) string {
	if id == "entra" {
		return "microsoft"
	}
	return id
}

// normalizeSSOUsers returns the list as "email level [provider]" lines, lower case, no repeats.  The provider (google or
// microsoft or oidc) is optional: without one the address may sign in with any provider that is set up.
func normalizeSSOUsers(in []string) ([]string, error) {
	var out []string
	seen := map[string]int{}
	for _, line := range in {
		f := strings.Fields(strings.ReplaceAll(line, ",", " "))
		for i := 0; i < len(f); i++ {
			email := strings.ToLower(f[i])
			if at := strings.IndexByte(email, '@'); at < 1 || at == len(email)-1 || strings.Count(email, "@") != 1 || len(email) > 254 || strings.ContainsAny(email, "<>\"'\\/") {
				return nil, fmt.Errorf("web: single sign-on user %q is not an e-mail address like alice@example.com", f[i])
			}
			level, prov := "ro", ""
			for i+1 < len(f) {
				switch strings.ToLower(f[i+1]) {
				case "rw", "read-write", "readwrite", "admin":
					level = "rw"
				case "ro", "read-only", "readonly", "read":
					level = "ro"
				case "google":
					prov = "google"
				case "microsoft", "entra", "azure", "ms":
					prov = "microsoft"
				case "oidc", "openid", "generic":
					prov = "oidc"
				case "any", "both":
					prov = ""
				default:
					goto done
				}
				i++
			}
		done:
			l := email + " " + level
			if prov != "" {
				l += " " + prov
			}
			if j, dup := seen[email]; dup {
				out[j] = l // the last one wins
				continue
			}
			seen[email] = len(out)
			out = append(out, l)
		}
	}
	if len(out) > ssoMaxUsers {
		return nil, fmt.Errorf("web: at most %d single sign-on users", ssoMaxUsers)
	}
	return out, nil
}

// validateSSO checks and tidies the single sign-on settings.  A provider counts as set up only when all its values are
// given; a half-filled one is not an error (the page saves as you type).
func (c *SSOConfig) validateSSO() error {
	c.GoogleClientID, c.GoogleClientSecret = strings.TrimSpace(c.GoogleClientID), strings.TrimSpace(c.GoogleClientSecret)
	c.EntraTenant, c.EntraClientID, c.EntraClientSecret = strings.ToLower(strings.TrimSpace(c.EntraTenant)), strings.TrimSpace(c.EntraClientID), strings.TrimSpace(c.EntraClientSecret)
	if c.EntraTenant != "" && !entraTenantRE.MatchString(c.EntraTenant) {
		return errors.New("web: sso_entra_tenant must be the Directory (tenant) ID, a GUID like 11111111-2222-3333-4444-555555555555")
	}
	c.OIDCName, c.OIDCIssuer = strings.TrimSpace(c.OIDCName), strings.TrimRight(strings.TrimSpace(c.OIDCIssuer), "/")
	c.OIDCClientID, c.OIDCClientSecret = strings.TrimSpace(c.OIDCClientID), strings.TrimSpace(c.OIDCClientSecret)
	if len(c.OIDCName) > 40 || strings.ContainsAny(c.OIDCName, "\r\n\t<>&\"'") {
		return errors.New("web: sso_oidc_name is the text of the button: up to 40 characters, without < > & or quotes")
	}
	if c.OIDCIssuer != "" {
		u, err := url.Parse(c.OIDCIssuer)
		if err != nil || (u.Scheme != "https" && !(ssoInsecure && u.Scheme == "http")) || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(c.OIDCIssuer, " \t\r\n") {
			return errors.New("web: sso_oidc_issuer must be the provider's issuer address, like https://auth.example.lan/realms/main (https)")
		}
	}
	for _, v := range []string{c.GoogleClientID, c.GoogleClientSecret, c.EntraClientID, c.EntraClientSecret, c.OIDCClientID, c.OIDCClientSecret} {
		if len(v) > 600 || strings.ContainsAny(v, " \t\r\n") {
			return errors.New("web: a single sign-on client ID or secret is too long or has spaces in it")
		}
	}
	if c.BaseURL != "" {
		c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
		u, err := url.Parse(c.BaseURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("web: sso_base_url must be an address like https://dns1.example.com:53853 (https, no path)")
		}
	}
	us, err := normalizeSSOUsers(c.Users)
	if err != nil {
		return err
	}
	c.Users = us
	return nil
}

// ssoLevel looks an address up in the list: whether it may sign in with the provider (its id, google or entra), and whether
// read-only.  An entry that names a provider admits the address only through that one.
func (c SSOConfig) ssoLevel(email, provider string) (ok, readOnly bool) {
	email = strings.ToLower(email)
	for _, l := range c.Users {
		f := strings.Fields(l)
		if len(f) < 1 || f[0] != email {
			continue
		}
		if len(f) >= 3 && f[2] != ssoProviderToken(provider) {
			return false, false
		}
		return true, len(f) < 2 || f[1] != "rw"
	}
	return false, false
}

// ---- providers ----

// The providers' own addresses (variables so the tests can point them at a fake provider).
var (
	ssoGoogleIssuer = "https://accounts.google.com"
	ssoEntraBase    = "https://login.microsoftonline.com"
	ssoInsecure     = false // tests: allow http:// provider addresses
	ssoHTTP         = &http.Client{Timeout: 15 * time.Second}
)

type ssoProvider struct {
	id, title        string
	issuer           string // oidc: the issuer the discovery document must name
	skipVerify       bool   // oidc: do not check the provider's certificate
	clientID, secret string
	tenant           string
	disc             string // discovery document address
	extra            url.Values
	scope            string
}

func (c SSOConfig) providers() []ssoProvider {
	var out []ssoProvider
	if c.GoogleClientID != "" && c.GoogleClientSecret != "" {
		out = append(out, ssoProvider{id: "google", title: "Google", clientID: c.GoogleClientID, secret: c.GoogleClientSecret,
			disc: ssoGoogleIssuer + "/.well-known/openid-configuration", scope: "openid email", extra: url.Values{"prompt": {"select_account"}}})
	}
	if c.EntraTenant != "" && c.EntraClientID != "" && c.EntraClientSecret != "" {
		out = append(out, ssoProvider{id: "entra", title: "Microsoft", clientID: c.EntraClientID, secret: c.EntraClientSecret, tenant: c.EntraTenant,
			disc: ssoEntraBase + "/" + c.EntraTenant + "/v2.0/.well-known/openid-configuration", scope: "openid email profile", extra: url.Values{"prompt": {"select_account"}}})
	}
	if c.OIDCIssuer != "" && c.OIDCClientID != "" && c.OIDCClientSecret != "" {
		title := c.OIDCName
		if title == "" {
			title = "SSO"
		}
		out = append(out, ssoProvider{id: "oidc", title: title, clientID: c.OIDCClientID, secret: c.OIDCClientSecret, issuer: c.OIDCIssuer,
			disc: c.OIDCIssuer + "/.well-known/openid-configuration", scope: "openid email profile", skipVerify: c.OIDCSkipVerify})
	}
	return out
}

func (c SSOConfig) provider(id string) *ssoProvider {
	for _, p := range c.providers() {
		if p.id == id {
			p := p
			return &p
		}
	}
	return nil
}

type ssoDisc struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURI  string `json:"jwks_uri"`
	at       time.Time
}

type ssoKey struct {
	kid string
	pub *rsa.PublicKey
}

type ssoJWKS struct {
	keys    []ssoKey
	fetched time.Time
}

type ssoPending struct {
	provider, nonce, verifier, redirect string
	created                             time.Time
}

type ssoState struct {
	mu      sync.Mutex
	pending map[string]*ssoPending
	disc    map[string]*ssoDisc
	jwks    map[string]*ssoJWKS
}

func newSSOState() *ssoState {
	return &ssoState{pending: map[string]*ssoPending{}, disc: map[string]*ssoDisc{}, jwks: map[string]*ssoJWKS{}}
}

func ssoURLOK(u string) bool {
	if ssoInsecure {
		return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
	}
	return strings.HasPrefix(u, "https://")
}

// client is the HTTP client for talking to the provider: the ordinary one, or one that accepts any certificate when the
// administrator turned certificate checking off for this provider.
func (p *ssoProvider) client() *http.Client {
	if !p.skipVerify {
		return ssoHTTP
	}
	warnNoCertCheck(p.title)
	ssoInsecureClient.Do.Lock()
	defer ssoInsecureClient.Do.Unlock()
	if ssoInsecureClient.c == nil {
		ssoInsecureClient.c = &http.Client{Timeout: ssoHTTP.Timeout, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // Do not check the provider's certificate is on
		}}
	}
	return ssoInsecureClient.c
}

var ssoInsecureClient = struct {
	Do sync.Mutex
	c  *http.Client
}{}

func ssoGetJSON(hc *http.Client, req *http.Request, v any) error {
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	return json.Unmarshal(body, v)
}

func (s *ssoState) discovery(p *ssoProvider) (*ssoDisc, error) {
	s.mu.Lock()
	d := s.disc[p.disc]
	s.mu.Unlock()
	if d != nil && time.Since(d.at) < time.Hour {
		return d, nil
	}
	req, _ := http.NewRequest(http.MethodGet, p.disc, nil)
	nd := &ssoDisc{}
	if err := ssoGetJSON(p.client(), req, nd); err != nil {
		if d != nil {
			return d, nil // the provider is briefly unreachable: the last document still holds
		}
		return nil, err
	}
	if p.issuer != "" && strings.TrimRight(nd.Issuer, "/") != p.issuer { // a discovery document must name the issuer it was fetched from
		return nil, errors.New("the provider's discovery document names another issuer")
	}
	if nd.Issuer == "" || !ssoURLOK(nd.AuthURL) || !ssoURLOK(nd.TokenURL) || !ssoURLOK(nd.JWKSURI) {
		return nil, errors.New("the provider's discovery document is not usable")
	}
	nd.at = time.Now()
	s.mu.Lock()
	s.disc[p.disc] = nd
	s.mu.Unlock()
	return nd, nil
}

func b64Int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// key finds the provider's signing key for kid, fetching the key set when it is old or the key is not in it.
func (s *ssoState) key(hc *http.Client, d *ssoDisc, kid string) (*rsa.PublicKey, error) {
	find := func(j *ssoJWKS) *rsa.PublicKey {
		if j == nil {
			return nil
		}
		for _, k := range j.keys {
			if k.kid == kid {
				return k.pub
			}
		}
		return nil
	}
	s.mu.Lock()
	j := s.jwks[d.JWKSURI]
	s.mu.Unlock()
	if k := find(j); k != nil && time.Since(j.fetched) < 6*time.Hour {
		return k, nil
	}
	if j != nil && time.Since(j.fetched) < time.Minute {
		return nil, errors.New("the token is signed with a key the provider does not publish")
	}
	req, _ := http.NewRequest(http.MethodGet, d.JWKSURI, nil)
	var doc struct {
		Keys []struct {
			Kty, Kid, N, E, Use, Alg string
		} `json:"keys"`
	}
	if err := ssoGetJSON(hc, req, &doc); err != nil {
		return nil, err
	}
	nj := &ssoJWKS{fetched: time.Now()}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err1 := b64Int(k.N)
		e, err2 := b64Int(k.E)
		if err1 != nil || err2 != nil || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 || n.BitLen() < 2048 {
			continue
		}
		nj.keys = append(nj.keys, ssoKey{k.Kid, &rsa.PublicKey{N: n, E: int(e.Int64())}})
	}
	s.mu.Lock()
	s.jwks[d.JWKSURI] = nj
	s.mu.Unlock()
	if k := find(nj); k != nil {
		return k, nil
	}
	return nil, errors.New("the token is signed with a key the provider does not publish")
}

type ssoClaims struct {
	Iss           string          `json:"iss"`
	Aud           json.RawMessage `json:"aud"`
	Exp           float64         `json:"exp"`
	Nbf           float64         `json:"nbf"`
	Nonce         string          `json:"nonce"`
	Email         string          `json:"email"`
	EmailVerified any             `json:"email_verified"`
	Preferred     string          `json:"preferred_username"`
	Tid           string          `json:"tid"`
}

func (c ssoClaims) audHas(id string) bool {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return one == id
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		for _, a := range many {
			if a == id {
				return true
			}
		}
	}
	return false
}

// verifyIDToken checks an ID token and returns the e-mail address it vouches for.
func (s *ssoState) verifyIDToken(p *ssoProvider, d *ssoDisc, tok, nonce string, now time.Time) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", errors.New("the ID token is malformed")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", errors.New("the ID token is malformed")
	}
	var hdr struct{ Alg, Kid string }
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "RS256" { // never "none", never a key-confusion HMAC
		return "", errors.New("the ID token is not signed with RS256")
	}
	pub, err := s.key(p.client(), d, hdr.Kid)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return "", errors.New("the ID token's signature is wrong")
	}
	var c ssoClaims
	if json.Unmarshal(cb, &c) != nil {
		return "", errors.New("the ID token is malformed")
	}
	issOK := c.Iss == d.Issuer
	if p.id == "google" && (c.Iss == "https://accounts.google.com" || c.Iss == "accounts.google.com") {
		issOK = true
	}
	if !issOK {
		return "", errors.New("the ID token comes from another issuer")
	}
	if !c.audHas(p.clientID) {
		return "", errors.New("the ID token is for another application")
	}
	if c.Exp == 0 || now.After(time.Unix(int64(c.Exp), 0).Add(time.Minute)) {
		return "", errors.New("the ID token has expired")
	}
	if c.Nbf != 0 && now.Before(time.Unix(int64(c.Nbf), 0).Add(-time.Minute)) {
		return "", errors.New("the ID token is not valid yet")
	}
	if c.Nonce == "" || c.Nonce != nonce {
		return "", errors.New("the ID token answers another sign-in")
	}
	email := c.Email
	switch p.id {
	case "google":
		if v, ok := c.EmailVerified.(bool); !(ok && v) {
			if sv, ok := c.EmailVerified.(string); !(ok && sv == "true") {
				return "", errors.New("Google has not verified this address")
			}
		}
	case "oidc":
		if v, ok := c.EmailVerified.(bool); !(ok && v) {
			if sv, ok := c.EmailVerified.(string); !(ok && sv == "true") {
				return "", errors.New("the provider has not verified this address")
			}
		}
	case "entra":
		if !strings.EqualFold(c.Tid, p.tenant) {
			return "", errors.New("the account is from another tenant")
		}
		if email == "" {
			email = c.Preferred
		}
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if strings.Count(email, "@") != 1 {
		return "", errors.New("the provider sent no e-mail address")
	}
	return email, nil
}

// ---- web handlers ----

func (w *WebServer) ssoCfg() SSOConfig { return w.policy.Load().SSOConfig }

func ssoBase(c SSOConfig, r *http.Request) string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return "https://" + r.Host
}

const ssoCookie = "__Host-dnsdir_sso"

func ssoFail(rw http.ResponseWriter, r *http.Request, msg string) {
	http.SetCookie(rw, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(rw, r, "/?sso_error="+url.QueryEscape(msg), http.StatusFound)
}

// handleSSOStart sends the browser to the provider.
func (w *WebServer) handleSSOStart(rw http.ResponseWriter, r *http.Request) {
	cfg := w.ssoCfg()
	p := cfg.provider(r.URL.Query().Get("p"))
	if p == nil {
		http.NotFound(rw, r)
		return
	}
	d, err := w.sso.discovery(p)
	if err != nil {
		warnf("web: single sign-on: %s: %v", p.title, err)
		ssoFail(rw, r, "Could not reach "+p.title+" to sign in.")
		return
	}
	state, nonce, verifier := randToken(), randToken(), randToken()
	redirect := ssoBase(cfg, r) + "/api/sso/callback"
	now := time.Now()
	w.sso.mu.Lock()
	for k, v := range w.sso.pending {
		if now.Sub(v.created) > 10*time.Minute {
			delete(w.sso.pending, k)
		}
	}
	if len(w.sso.pending) >= 2000 {
		w.sso.mu.Unlock()
		jsonError(rw, http.StatusServiceUnavailable, "Too many sign-ins at once; try again in a moment.")
		return
	}
	w.sso.pending[sessKey(state)] = &ssoPending{provider: p.id, nonce: nonce, verifier: verifier, redirect: redirect, created: now}
	w.sso.mu.Unlock()
	ch := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {p.clientID}, "redirect_uri": {redirect}, "scope": {p.scope},
		"state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(ch[:])}, "code_challenge_method": {"S256"},
	}
	for k, v := range p.extra {
		q[k] = v
	}
	// the cookie ties the callback to this browser (a forged callback link cannot sign someone in as the attacker)
	http.SetCookie(rw, &http.Cookie{Name: ssoCookie, Value: state, Path: "/", MaxAge: 600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	sep := "?"
	if strings.Contains(d.AuthURL, "?") {
		sep = "&"
	}
	http.Redirect(rw, r, d.AuthURL+sep+q.Encode(), http.StatusFound)
}

// handleSSOCallback finishes a sign-in.
func (w *WebServer) handleSSOCallback(rw http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	q := r.URL.Query()
	c, err := r.Cookie(ssoCookie)
	state := q.Get("state")
	if err != nil || state == "" || c.Value != state {
		warnf("web: single sign-on refused from %s: the sign-in was not started in this browser", ip)
		ssoFail(rw, r, "That sign-in expired or was not started here. Try again.")
		return
	}
	w.sso.mu.Lock()
	pd := w.sso.pending[sessKey(state)]
	delete(w.sso.pending, sessKey(state))
	w.sso.mu.Unlock()
	if pd == nil || time.Since(pd.created) > 10*time.Minute {
		ssoFail(rw, r, "That sign-in expired. Try again.")
		return
	}
	cfg := w.ssoCfg()
	p := cfg.provider(pd.provider)
	if p == nil {
		ssoFail(rw, r, "Single sign-on is no longer set up.")
		return
	}
	if e := q.Get("error"); e != "" {
		warnf("web: single sign-on with %s from %s: the provider answered %q", p.title, ip, e)
		ssoFail(rw, r, "The sign-in was cancelled or refused by "+p.title+".")
		return
	}
	code := q.Get("code")
	if code == "" {
		ssoFail(rw, r, "The provider sent no code. Try again.")
		return
	}
	select {
	case w.loginQ <- struct{}{}:
		defer func() { <-w.loginQ }()
	default:
		ssoFail(rw, r, "Too many sign-ins at once; try again in a moment.")
		return
	}
	d, err := w.sso.discovery(p)
	if err != nil {
		warnf("web: single sign-on: %s: %v", p.title, err)
		ssoFail(rw, r, "Could not reach "+p.title+" to sign in.")
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {pd.redirect},
		"client_id": {p.clientID}, "client_secret": {p.secret}, "code_verifier": {pd.verifier}}
	req, _ := http.NewRequest(http.MethodPost, d.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var tr struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	resp, err := p.client().Do(req)
	if err == nil {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if jerr := json.Unmarshal(b, &tr); jerr != nil || resp.StatusCode != http.StatusOK {
			if tr.Error != "" {
				err = fmt.Errorf("%s: %s", tr.Error, strings.SplitN(tr.Desc, "\n", 2)[0])
			} else {
				err = fmt.Errorf("the token endpoint answered %s", resp.Status)
			}
		}
	}
	if err != nil {
		warnf("web: single sign-on with %s from %s: %v", p.title, ip, err)
		ssoFail(rw, r, "Could not finish signing in with "+p.title+". Check the client ID and secret under Configure ▸ Users ▸ SSO.")
		return
	}
	email, err := w.sso.verifyIDToken(p, d, tr.IDToken, pd.nonce, time.Now())
	if err != nil {
		warnf("web: single sign-on with %s from %s refused: %v", p.title, ip, err)
		ssoFail(rw, r, "The sign-in could not be verified.")
		return
	}
	ok, readOnly := cfg.ssoLevel(email, p.id)
	if !ok {
		warnf("web: single sign-on with %s: %q from %s is not on the list of users", p.title, email, ip)
		ssoFail(rw, r, email+" is not allowed to use this console.")
		return
	}
	now := time.Now()
	s := &session{user: email, csrf: randToken(), created: now, last: now, checked: now, readOnly: readOnly, ip: ip, sso: true, ssoProv: p.id}
	tok := randToken()
	w.mu.Lock()
	w.sessions[sessKey(tok)] = s
	w.mu.Unlock()
	w.saveSessions()
	http.SetCookie(rw, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMaxAge.Seconds()),
	})
	infof("web: login: %q signed in with %s from %s (%s)", email, p.title, ip, accessWord(readOnly))
	http.Redirect(rw, r, "/", http.StatusFound)
}

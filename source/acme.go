package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// A small ACME client (RFC 8555), standard library only, for the one thing dnsdir needs it for: ordering a
// certificate for a list of names, proving control of them with the dns-01 challenge, and downloading the chain.
// The proof is published by an acme-dns service (acmedns.go) that the names' _acme-challenge records point to
// with a CNAME, so no DNS server of the person's ever has to accept an update.

const (
	acmeLetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	acmeLetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeMaxBody            = 1 << 20
	acmePollEvery          = 2 * time.Second
	acmePollFor            = 3 * time.Minute
)

// acmeError is a problem document the CA sent.
type acmeError struct {
	Status int
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

func (e *acmeError) Error() string {
	t := strings.TrimPrefix(e.Type, "urn:ietf:params:acme:error:")
	if e.Detail == "" {
		return fmt.Sprintf("the CA refused (HTTP %d, %s)", e.Status, t)
	}
	return fmt.Sprintf("the CA refused (%s): %s", t, e.Detail)
}

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	Meta       struct {
		TermsOfService          string `json:"termsOfService"`
		ExternalAccountRequired bool   `json:"externalAccountRequired"`
	} `json:"meta"`
}

type acmeClient struct {
	hc     *http.Client
	dirURL string
	dir    acmeDirectory
	key    *ecdsa.PrivateKey
	kid    string
	nonce  string
	say    func(string, ...any) // progress lines
}

func acmeB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func padTo32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

// acmeJWK is the public half of the account key as a JSON Web Key.
func acmeJWK(k *ecdsa.PublicKey) map[string]string {
	return map[string]string{"crv": "P-256", "kty": "EC", "x": acmeB64(padTo32(k.X)), "y": acmeB64(padTo32(k.Y))}
}

// acmeThumbprint is the RFC 7638 thumbprint of the account key (members in alphabetical order, no spaces).
func acmeThumbprint(k *ecdsa.PublicKey) string {
	j := acmeJWK(k)
	s := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, j["crv"], j["kty"], j["x"], j["y"])
	h := sha256.Sum256([]byte(s))
	return acmeB64(h[:])
}

// acmeKeyAuthTXT is the value the _acme-challenge TXT record must hold for a challenge token.
func acmeKeyAuthTXT(token string, k *ecdsa.PublicKey) string {
	h := sha256.Sum256([]byte(token + "." + acmeThumbprint(k)))
	return acmeB64(h[:])
}

func newACMEClient(hc *http.Client, dirURL string, key *ecdsa.PrivateKey, say func(string, ...any)) *acmeClient {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	if say == nil {
		say = func(string, ...any) {}
	}
	return &acmeClient{hc: hc, dirURL: dirURL, key: key, say: say}
}

func (c *acmeClient) do(ctx context.Context, method, url string, body []byte, accept string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/jose+json")
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "dnsdir/"+version())
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, acmeMaxBody))
	if err != nil {
		return nil, nil, err
	}
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
	if resp.StatusCode >= 400 {
		ae := &acmeError{Status: resp.StatusCode}
		json.Unmarshal(b, ae)
		return resp, b, ae
	}
	return resp, b, nil
}

func (c *acmeClient) loadDirectory(ctx context.Context) error {
	if c.dir.NewOrder != "" {
		return nil
	}
	_, b, err := c.do(ctx, "GET", c.dirURL, nil, "application/json")
	if err != nil {
		return fmt.Errorf("could not read the CA's directory %s: %w", c.dirURL, err)
	}
	if err := json.Unmarshal(b, &c.dir); err != nil || c.dir.NewOrder == "" || c.dir.NewAccount == "" || c.dir.NewNonce == "" {
		return fmt.Errorf("%s is not an ACME directory", c.dirURL)
	}
	return nil
}

func (c *acmeClient) freshNonce(ctx context.Context) error {
	resp, _, err := c.do(ctx, "HEAD", c.dir.NewNonce, nil, "")
	if err != nil {
		return err
	}
	if resp.Header.Get("Replay-Nonce") == "" {
		return errors.New("the CA sent no nonce")
	}
	return nil
}

// sign makes a flattened JWS.  payload nil is a POST-as-GET (empty payload).  With a kid it is signed as the account;
// without one it carries the key (account creation).
func (c *acmeClient) sign(url string, payload []byte, useKID bool) ([]byte, error) {
	prot := map[string]any{"alg": "ES256", "nonce": c.nonce, "url": url}
	if useKID {
		prot["kid"] = c.kid
	} else {
		prot["jwk"] = acmeJWK(&c.key.PublicKey)
	}
	pj, _ := json.Marshal(prot)
	p64 := acmeB64(pj)
	pl := ""
	if payload != nil {
		pl = acmeB64(payload)
	}
	h := sha256.Sum256([]byte(p64 + "." + pl))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, h[:])
	if err != nil {
		return nil, err
	}
	sig := append(padTo32(r), padTo32(s)...)
	return json.Marshal(map[string]string{"protected": p64, "payload": pl, "signature": acmeB64(sig)})
}

// post sends a signed request, getting a nonce first when it has none and trying once more on badNonce.
func (c *acmeClient) post(ctx context.Context, url string, payload any, useKID bool, accept string) (*http.Response, []byte, error) {
	var pb []byte
	if payload != nil {
		var err error
		if pb, err = json.Marshal(payload); err != nil {
			return nil, nil, err
		}
	}
	for try := 0; ; try++ {
		if c.nonce == "" {
			if err := c.freshNonce(ctx); err != nil {
				return nil, nil, err
			}
		}
		body, err := c.sign(url, pb, useKID)
		if err != nil {
			return nil, nil, err
		}
		c.nonce = "" // a nonce is used once
		resp, b, err := c.do(ctx, "POST", url, body, accept)
		var ae *acmeError
		if errors.As(err, &ae) && strings.HasSuffix(ae.Type, ":badNonce") && try < 2 {
			continue
		}
		return resp, b, err
	}
}

// eab builds the externalAccountBinding some CAs (Google, ZeroSSL) require to tie the account to a customer.
func (c *acmeClient) eab(kid, hmacKey string) (map[string]string, error) {
	mk, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(hmacKey), "="))
	if err != nil {
		return nil, errors.New("the external account key is not base64url text")
	}
	jwk, _ := json.Marshal(acmeJWK(&c.key.PublicKey))
	pj, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": kid, "url": c.dir.NewAccount})
	p64, pl := acmeB64(pj), acmeB64(jwk)
	m := hmac.New(sha256.New, mk)
	m.Write([]byte(p64 + "." + pl))
	return map[string]string{"protected": p64, "payload": pl, "signature": acmeB64(m.Sum(nil))}, nil
}

// Account registers the key with the CA, or finds the account it already has.
func (c *acmeClient) Account(ctx context.Context, email, eabKid, eabKey string) error {
	if err := c.loadDirectory(ctx); err != nil {
		return err
	}
	req := map[string]any{"termsOfServiceAgreed": true}
	if email != "" {
		req["contact"] = []string{"mailto:" + email}
	}
	if c.dir.Meta.ExternalAccountRequired && (eabKid == "" || eabKey == "") {
		return errors.New("this CA needs an external account key id and key (EAB); get them from the CA and fill them in")
	}
	if eabKid != "" && eabKey != "" {
		e, err := c.eab(eabKid, eabKey)
		if err != nil {
			return err
		}
		req["externalAccountBinding"] = e
	}
	resp, _, err := c.post(ctx, c.dir.NewAccount, req, false, "")
	if err != nil {
		return err
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		return errors.New("the CA did not say where the account is")
	}
	return nil
}

type acmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type acmeOrder struct {
	Status         string           `json:"status"`
	Identifiers    []acmeIdentifier `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate"`
	Error          *acmeError       `json:"error"`
	url            string
}

type acmeChallenge struct {
	Type   string     `json:"type"`
	URL    string     `json:"url"`
	Token  string     `json:"token"`
	Status string     `json:"status"`
	Error  *acmeError `json:"error"`
}

type acmeAuthz struct {
	Status     string         `json:"status"`
	Identifier acmeIdentifier `json:"identifier"`
	Wildcard   bool           `json:"wildcard"`
	Challenges []acmeChallenge
	url        string
}

// acmeSolver publishes and (afterwards) forgets the dns-01 proof for a domain (a name without "*.").
type acmeSolver interface {
	Present(ctx context.Context, domain, txt string) error
}

func (c *acmeClient) poll(ctx context.Context, url string, done func([]byte) (bool, error)) error {
	deadline := time.Now().Add(acmePollFor)
	for {
		_, b, err := c.post(ctx, url, nil, true, "")
		if err != nil {
			return err
		}
		ok, err := done(b)
		if err != nil || ok {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("the CA took too long to answer")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(acmePollEvery):
		}
	}
}

// Obtain orders a certificate for names (a "*." name is a wildcard), proves them through solver and returns the
// certificate chain (leaf first) and its new private key, both PEM.
func (c *acmeClient) Obtain(ctx context.Context, names []string, solver acmeSolver, settle time.Duration) (chainPEM, keyPEM []byte, err error) {
	ids := make([]acmeIdentifier, len(names))
	for i, n := range names {
		ids[i] = acmeIdentifier{"dns", n}
	}
	c.say("placing the order for %s", strings.Join(names, ", "))
	resp, b, err := c.post(ctx, c.dir.NewOrder, map[string]any{"identifiers": ids}, true, "")
	if err != nil {
		return nil, nil, err
	}
	var order acmeOrder
	if err := json.Unmarshal(b, &order); err != nil {
		return nil, nil, fmt.Errorf("the CA's order answer was not understood: %w", err)
	}
	order.url = resp.Header.Get("Location")

	// every proof is published first (names that share a domain, such as example.com and *.example.com, share its record),
	// then the CA is told to look
	type pending struct {
		authz acmeAuthz
		ch    acmeChallenge
	}
	var todo []pending
	for _, au := range order.Authorizations {
		_, ab, err := c.post(ctx, au, nil, true, "")
		if err != nil {
			return nil, nil, err
		}
		var az acmeAuthz
		if err := json.Unmarshal(ab, &az); err != nil {
			return nil, nil, fmt.Errorf("an authorization was not understood: %w", err)
		}
		az.url = au
		if az.Status == "valid" {
			continue
		}
		var ch *acmeChallenge
		for i := range az.Challenges {
			if az.Challenges[i].Type == "dns-01" {
				ch = &az.Challenges[i]
			}
		}
		if ch == nil {
			return nil, nil, fmt.Errorf("the CA offers no dns-01 challenge for %s", az.Identifier.Value)
		}
		todo = append(todo, pending{az, *ch})
	}
	for _, p := range todo {
		dom := strings.ToLower(p.authz.Identifier.Value)
		c.say("publishing the proof for %s", dom)
		if err := solver.Present(ctx, dom, acmeKeyAuthTXT(p.ch.Token, &c.key.PublicKey)); err != nil {
			return nil, nil, fmt.Errorf("could not publish the proof for %s: %w", dom, err)
		}
	}
	if len(todo) > 0 && settle > 0 {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(settle):
		}
	}
	for _, p := range todo {
		c.say("asking the CA to check %s", p.authz.Identifier.Value)
		if _, _, err := c.post(ctx, p.ch.URL, struct{}{}, true, ""); err != nil {
			return nil, nil, err
		}
	}
	for _, p := range todo {
		name := p.authz.Identifier.Value
		err := c.poll(ctx, p.authz.url, func(b []byte) (bool, error) {
			var az acmeAuthz
			if err := json.Unmarshal(b, &az); err != nil {
				return false, err
			}
			switch az.Status {
			case "valid":
				return true, nil
			case "invalid", "deactivated", "expired", "revoked":
				for _, ch := range az.Challenges {
					if ch.Type == "dns-01" && ch.Error != nil {
						return false, fmt.Errorf("%s was not proven: %w (is the CNAME for _acme-challenge.%s in place?)", name, ch.Error, strings.TrimPrefix(name, "*."))
					}
				}
				return false, fmt.Errorf("%s was not proven (%s)", name, az.Status)
			}
			return false, nil
		})
		if err != nil {
			return nil, nil, err
		}
		c.say("%s proven", name)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: strings.TrimPrefix(names[0], "*.")}, DNSNames: names,
	}, key)
	if err != nil {
		return nil, nil, err
	}
	c.say("finishing the order")
	if _, _, err := c.post(ctx, order.Finalize, map[string]string{"csr": acmeB64(csr)}, true, ""); err != nil {
		return nil, nil, err
	}
	var certURL string
	err = c.poll(ctx, order.url, func(b []byte) (bool, error) {
		var o acmeOrder
		if err := json.Unmarshal(b, &o); err != nil {
			return false, err
		}
		switch o.Status {
		case "valid":
			certURL = o.Certificate
			return true, nil
		case "invalid":
			if o.Error != nil {
				return false, o.Error
			}
			return false, errors.New("the CA marked the order invalid")
		}
		return false, nil
	})
	if err != nil {
		return nil, nil, err
	}
	if certURL == "" {
		return nil, nil, errors.New("the CA gave no certificate")
	}
	_, chain, err := c.post(ctx, certURL, nil, true, "application/pem-certificate-chain")
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return chain, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

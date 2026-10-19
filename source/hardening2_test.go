package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ── minimum password length ──────────────────────────────────────────────────

func TestMinimumPasswordLength(t *testing.T) {
	m, _ := usersFixture(t, fxGroup, fxPasswd, "")
	// default: 8 characters
	for pw, ok := range map[string]bool{"1234567": false, "12345678": true, "пароль12": true, "пароль1": false, "": false} {
		err := m.checkPassword(pw)
		if (err == nil) != ok {
			t.Errorf("default policy, %q: err=%v, want ok=%v", pw, err, ok)
		}
	}
	if _, _, err := m.UserPassword("bob", "short", "alice"); err == nil || !strings.Contains(err.Error(), "at least 8") {
		t.Fatalf("a 5 character password with the default policy: %v", err)
	}
	// configured
	m.webPolicy.Store(&WebConfig{Group: "ntpdir", MinPasswordLength: 12})
	if err := m.checkPassword("eleven-char"); err == nil {
		t.Error("11 characters accepted with a minimum of 12")
	}
	if err := m.checkPassword("twelve-chars"); err != nil {
		t.Errorf("12 characters refused with a minimum of 12: %v", err)
	}
	m.webPolicy.Store(&WebConfig{Group: "ntpdir", MinPasswordLength: 1})
	if err := m.checkPassword("x"); err != nil {
		t.Errorf("a minimum of 1 refused one character: %v", err)
	}
}

func TestMinPasswordLengthConfig(t *testing.T) {
	w := defaultWeb()
	if w.minPassword() != 8 || w.Validate() != nil {
		t.Fatalf("default: %d %v", w.minPassword(), w.Validate())
	}
	for _, bad := range []int{-1, 129, 100000} {
		w.MinPasswordLength = bad
		if w.Validate() == nil {
			t.Errorf("min_password_length %d accepted", bad)
		}
	}
	for _, good := range []int{0, 1, 8, 128} {
		w.MinPasswordLength = good
		if err := w.Validate(); err != nil {
			t.Errorf("min_password_length %d refused: %v", good, err)
		}
	}
	// an unset value is not written, so an older version can still read the file
	b, _ := json.Marshal(defaultWeb())
	if strings.Contains(string(b), "min_password_length") {
		t.Fatalf("the default is written to the config: %s", b)
	}
	var back WebConfig
	if err := json.Unmarshal([]byte(`{"min_password_length": 10}`), &back); err != nil || back.minPassword() != 10 {
		t.Fatalf("reading it back: %v %d", err, back.minPassword())
	}
}

// ── sessions end with the account ────────────────────────────────────────────

func TestSessionsEndWhenTheAccountChanges(t *testing.T) {
	failDelay = 0
	m, _ := usersFixture(t, fxGroup, fxPasswd, "")
	ws := NewWebServer(m, nil, &fakeAuth{})
	now := time.Now()
	add := func(tok, user string) {
		ws.mu.Lock()
		ws.sessions[sessKey(tok)] = &session{user: user, csrf: "c", created: now, last: now, checked: now}
		ws.mu.Unlock()
	}
	has := func(tok string) bool {
		ws.mu.Lock()
		defer ws.mu.Unlock()
		return ws.sessions[sessKey(tok)] != nil
	}
	reset := func() {
		add("bob1", "bob")
		add("bob2", "bob")
		add("alice1", "alice")
	}

	reset()
	if _, _, err := m.UserPassword("bob", "newpw-12345", "alice"); err != nil {
		t.Fatal(err)
	}
	if has("bob1") || has("bob2") || !has("alice1") {
		t.Fatal("a password change must end that user's sessions, and only theirs")
	}

	reset()
	if _, _, err := m.UserExpiry("bob", time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), "alice"); err != nil {
		t.Fatal(err)
	}
	if !has("bob1") {
		t.Fatal("a future expiry date must not end a session")
	}
	if _, _, err := m.UserExpiry("bob", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix(), "alice"); err != nil {
		t.Fatal(err)
	}
	if has("bob1") || !has("alice1") {
		t.Fatal("an expiry date in the past must end that user's sessions")
	}

	reset()
	if _, _, err := m.UserDelete("bob", "alice"); err != nil {
		t.Fatal(err)
	}
	if has("bob1") || has("bob2") || !has("alice1") {
		t.Fatal("deleting an account must end its sessions")
	}

	// the same changes arriving from another cluster node
	m2, _ := usersFixture(t, fxGroup, fxPasswd, "")
	ws2 := NewWebServer(m2, nil, &fakeAuth{})
	ws2.mu.Lock()
	ws2.sessions[sessKey("b")] = &session{user: "bob", csrf: "c", created: now, last: now, checked: now}
	ws2.mu.Unlock()
	if err := m2.usersPeer(usersMsg{Op: "apply", Name: "bob", Hash: testHash}, "node2"); err != nil {
		t.Fatal(err)
	}
	ws2.mu.Lock()
	left := len(ws2.sessions)
	ws2.mu.Unlock()
	if left != 0 {
		t.Fatal("a password change from another node left the session open")
	}
}

func TestSessionCookieHasHostPrefix(t *testing.T) {
	e := newWebEnv(t)
	r := e.login("alice", "pw")
	if r.code != 200 {
		t.Fatalf("login: %d", r.code)
	}
	var sc string
	for _, v := range r.hdr["Set-Cookie"] {
		if strings.Contains(v, "session") {
			sc = v
		}
	}
	if !strings.HasPrefix(sc, "__Host-") || !strings.Contains(sc, "Secure") || !strings.Contains(sc, "Path=/") ||
		strings.Contains(strings.ToLower(sc), "domain") || !strings.Contains(sc, "HttpOnly") {
		t.Fatalf("the session cookie does not meet the __Host- rules: %q", sc)
	}
	e.do("POST", "/api/logout", map[string]string{}, withAuth(e, true))
}

// ── TCP and DoT ──────────────────────────────────────────────────────────────

// ── cluster: the signature is checked before the body is read ────────────────

// rawPeerReq sends a request to a node's cluster listener signed with secret.  withHash adds X-Ntpdir-Body (the
// form v194 sends); without it the request is the legacy form.  signedBody is the body the signature is made
// over, body what is really sent (they differ in the mismatch test).
func rawPeerReq(t *testing.T, secret []byte, to *tnode, claim ClusterPeer, me *tls.Certificate, method, path string, signedBody, body []byte, withHash bool) (int, string) {
	t.Helper()
	pj, _ := json.Marshal(claim)
	peerHdr := base64.StdEncoding.EncodeToString(pj)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := randHex(12)
	req, err := http.NewRequest(method, peerURL(path), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Ntpdir-Peer", peerHdr)
	req.Header.Set("X-Ntpdir-Ts", ts)
	req.Header.Set("X-Ntpdir-Nonce", nonce)
	if withHash {
		sum := sha256.Sum256(signedBody)
		h := hex.EncodeToString(sum[:])
		req.Header.Set("X-Ntpdir-Body", h)
		req.Header.Set("X-Ntpdir-Sig", signMessageHash(secret, peerHdr, ts, nonce, method, path, h))
	} else {
		req.Header.Set("X-Ntpdir-Sig", signMessage(secret, peerHdr, ts, nonce, method, path, signedBody))
	}
	res, err := pinnedClientAs(to.addr, to.mg.cl.node.Fingerprint(), 5*time.Second, me).Do(req)
	if err != nil {
		// A server that refuses a body that is too large may answer and close before the client has finished
		// sending it; the client then sees a reset instead of the 413. That is the refusal, only seen from the other
		// side, so a body over the limit that ends this way counts as one.
		if len(body) > legacyPreAuthBody && (errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || strings.Contains(err.Error(), "connection reset") || strings.Contains(err.Error(), "broken pipe")) {
			return http.StatusRequestEntityTooLarge, "closed while the body was being sent"
		}
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var e struct {
		Error string `json:"error"`
	}
	json.Unmarshal(b, &e)
	return res.StatusCode, e.Error
}

func TestClusterBodyIsHeldToItsSignedHash(t *testing.T) {
	a, b := twoNodeCluster(t)
	bc, _ := b.mg.cl.node.Identity()
	secret := a.mg.cl.node.Secret()
	self := b.mg.cl.node.Self()
	body := []byte(`{"epoch":1,"primary_addr":"` + a.addr + `"}`)

	if code, msg := rawPeerReq(t, secret, a, self, &bc, "POST", "/cluster/announce", body, body, true); code != http.StatusOK {
		t.Fatalf("a correctly signed request with a body hash: %d %s", code, msg)
	}
	other := []byte(`{"epoch":99,"primary_addr":"` + b.addr + `"}`)
	if code, msg := rawPeerReq(t, secret, a, self, &bc, "POST", "/cluster/announce", body, other, true); code != http.StatusUnauthorized {
		t.Fatalf("a body other than the one signed was accepted: %d %s", code, msg)
	}
	if a.mg.cl.node.Snapshot().Epoch == 99 {
		t.Fatal("the substituted body took effect")
	}
	// a wrong signature is refused with the hash form, too
	if code, _ := rawPeerReq(t, []byte("not-the-secret-0123456789"), a, self, &bc, "POST", "/cluster/announce", body, body, true); code != http.StatusUnauthorized {
		t.Fatalf("a wrong secret was accepted: %d", code)
	}
}

func TestClusterLegacyRequestsAreLimitedBeforeTheSignature(t *testing.T) {
	a, b := twoNodeCluster(t)
	bc, _ := b.mg.cl.node.Identity()
	secret := a.mg.cl.node.Secret()
	self := b.mg.cl.node.Self()
	big := bytes.Repeat([]byte("x"), legacyPreAuthBody+1000)

	// a caller with no certificate (a stranger as far as we can tell) may not make us read more than the small limit
	if code, _ := rawPeerReq(t, secret, a, self, nil, "GET", "/cluster/status", big, big, false); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a large body from a caller without a certificate: %d", code)
	}
	// a member known by its certificate may send a large one (the node picker relays uploads)
	if code, msg := rawPeerReq(t, secret, a, self, &bc, "GET", "/cluster/status", big, big, false); code != http.StatusOK {
		t.Fatalf("a large legacy body from a known member: %d %s", code, msg)
	}
	// and the v194 form has no such limit below maxPeerBody
	if code, msg := rawPeerReq(t, secret, a, self, &bc, "GET", "/cluster/status", big, big, true); code != http.StatusOK {
		t.Fatalf("a large body with the hash: %d %s", code, msg)
	}
}

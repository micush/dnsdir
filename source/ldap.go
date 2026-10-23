package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sign-in with an LDAP directory (Active Directory, including Samba 4).
//
// The password form on the login page tries the host's own accounts first (PAM); when those do not accept the name and
// password and LDAP is set up here, the directory is asked: the daemon connects to a server over TLS (ldaps://, or ldap://
// with StartTLS - the password is never sent unprotected), binds with a read-only service account, finds the person by
// sAMAccountName or userPrincipalName, checks that the account is enabled, that it is a member (directly or through
// nested groups) of the full-access group or the read-only group, and finally checks the password by binding as that
// person.  A session started this way is checked against the directory every minute, like a PAM session against its group.
//
// There is no LDAP client in Go's standard library, so the small part of the protocol needed (bind, search, StartTLS) is
// written here on top of BER.  Search filters are built from values, never parsed from text, so a user name cannot change
// the shape of a filter.

// LDAPConfig is the LDAP part of the web block (flat keys in the file), shared by the cluster.
type LDAPConfig struct {
	// Servers are tried in order: "ldaps://dc1.example.lan:636" or "ldap://dc1.example.lan:389" (StartTLS is then required).
	LDAPServers []string `json:"ldap_servers,omitempty"`
	// LDAPSkipVerify accepts any certificate the server presents (a self-signed one, say).  The connection is still
	// encrypted, but nothing proves who is on the other end.
	LDAPSkipVerify bool `json:"ldap_skip_verify,omitempty"`
	// LDAPBindDN is the read-only service account used to look people up: a DN or a user principal name.  Leave the account
	// and its password empty and each person binds as themselves instead (see ldapFindAsUser).
	LDAPBindDN       string `json:"ldap_bind_dn,omitempty"`
	LDAPBindPassword string `json:"ldap_bind_password,omitempty"`
	// LDAPBaseDN is where people and groups are searched, like DC=example,DC=lan.
	LDAPBaseDN string `json:"ldap_base_dn,omitempty"`
	// LDAPRWGroup and LDAPROGroup are groups (a DN, or just the group's name): members of the first may change settings,
	// members of the second may only look.
	LDAPRWGroup string `json:"ldap_rw_group,omitempty"`
	LDAPROGroup string `json:"ldap_ro_group,omitempty"`
}

func (c LDAPConfig) empty() bool {
	return len(c.LDAPServers) == 0 && !c.LDAPSkipVerify && c.LDAPBindDN == "" && c.LDAPBindPassword == "" && c.LDAPBaseDN == "" &&
		c.LDAPRWGroup == "" && c.LDAPROGroup == ""
}

func (c LDAPConfig) clone() *LDAPConfig {
	if c.empty() {
		return nil
	}
	c.LDAPServers = append([]string(nil), c.LDAPServers...)
	return &c
}

// enabled is true when everything needed to sign people in is given; a half-filled form is simply off.
func (c LDAPConfig) enabled() bool {
	both, neither := c.LDAPBindDN != "" && c.LDAPBindPassword != "", c.LDAPBindDN == "" && c.LDAPBindPassword == ""
	return len(c.LDAPServers) > 0 && (both || neither) && c.LDAPBaseDN != "" && (c.LDAPRWGroup != "" || c.LDAPROGroup != "")
}

// hasBind is true when a service account is set; without one each person binds as themselves and sessions cannot be rechecked.
func (c LDAPConfig) hasBind() bool { return c.LDAPBindDN != "" && c.LDAPBindPassword != "" }

const ldapMaxServers = 8

func ldapServerURL(s string) (host, port string, tlsFirst bool, err error) {
	u, e := url.Parse(s)
	if e != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return "", "", false, fmt.Errorf("%q is not an LDAP server address like ldaps://dc1.example.lan:636", s)
	}
	port = u.Port()
	if port == "" {
		port = "389"
		if u.Scheme == "ldaps" {
			port = "636"
		}
	}
	return u.Hostname(), port, u.Scheme == "ldaps", nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validateLDAP checks and tidies the settings.
func (c *LDAPConfig) validateLDAP() error {
	var servers []string
	for _, l := range c.LDAPServers {
		for _, s := range strings.Fields(strings.ReplaceAll(l, ",", " ")) {
			if _, _, _, err := ldapServerURL(s); err != nil {
				return errors.New("web: ldap_servers: " + err.Error())
			}
			servers = append(servers, strings.TrimRight(s, "/"))
		}
	}
	if len(servers) > ldapMaxServers {
		return fmt.Errorf("web: at most %d LDAP servers", ldapMaxServers)
	}
	c.LDAPServers = servers
	c.LDAPBindDN, c.LDAPBindPassword, c.LDAPBaseDN = strings.TrimSpace(c.LDAPBindDN), strings.TrimSpace(c.LDAPBindPassword), strings.TrimSpace(c.LDAPBaseDN)
	c.LDAPRWGroup, c.LDAPROGroup = strings.TrimSpace(c.LDAPRWGroup), strings.TrimSpace(c.LDAPROGroup)
	for _, v := range []string{c.LDAPBindDN, c.LDAPBaseDN, c.LDAPRWGroup, c.LDAPROGroup} {
		if len(v) > 512 || hasControl(v) {
			return errors.New("web: an LDAP name (bind account, search base or group) is too long or has control characters in it")
		}
	}
	if len(c.LDAPBindPassword) > 512 || hasControl(c.LDAPBindPassword) {
		return errors.New("web: the LDAP bind password is too long or has control characters in it")
	}
	return nil
}

// ---- BER ----

func berLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for x := n; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func tlv(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := append([]byte{tag}, berLen(n)...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func berInt(tag byte, n int) []byte {
	var b []byte
	for x := n; ; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
		if x>>8 == 0 {
			break
		}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return tlv(tag, b)
}

func berOctet(s string) []byte { return tlv(0x04, []byte(s)) }

type berNode struct {
	tag  byte
	val  []byte
	kids []*berNode
}

const (
	berMaxMessage = 4 << 20
	berMaxDepth   = 12
)

func readTLV(r *bufio.Reader) (byte, []byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	if tag&0x1f == 0x1f {
		return 0, nil, errors.New("ldap: a tag this client does not know")
	}
	l, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n := int(l)
	if l >= 0x80 {
		k := int(l & 0x7f)
		if k == 0 || k > 4 {
			return 0, nil, errors.New("ldap: a length this client does not accept")
		}
		n = 0
		for i := 0; i < k; i++ {
			b, err := r.ReadByte()
			if err != nil {
				return 0, nil, err
			}
			n = n<<8 | int(b)
		}
	}
	if n < 0 || n > berMaxMessage {
		return 0, nil, errors.New("ldap: a message that is too large")
	}
	val := make([]byte, n)
	if _, err := io.ReadFull(r, val); err != nil {
		return 0, nil, err
	}
	return tag, val, nil
}

func decodeBER(tag byte, val []byte, depth int) (*berNode, error) {
	n := &berNode{tag: tag, val: val}
	if tag&0x20 == 0 {
		return n, nil
	}
	if depth > berMaxDepth {
		return nil, errors.New("ldap: a message nested too deeply")
	}
	r := bufio.NewReader(bytes.NewReader(val))
	for {
		t, v, err := readTLV(r)
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return nil, err
		}
		k, err := decodeBER(t, v, depth+1)
		if err != nil {
			return nil, err
		}
		n.kids = append(n.kids, k)
	}
}

func readMessage(r *bufio.Reader) (id int, op *berNode, err error) {
	tag, val, err := readTLV(r)
	if err != nil {
		return 0, nil, err
	}
	if tag != 0x30 {
		return 0, nil, errors.New("ldap: not an LDAP message")
	}
	n, err := decodeBER(tag, val, 0)
	if err != nil {
		return 0, nil, err
	}
	if len(n.kids) < 2 || n.kids[0].tag != 0x02 {
		return 0, nil, errors.New("ldap: a malformed message")
	}
	for _, b := range n.kids[0].val {
		id = id<<8 | int(b)
	}
	return id, n.kids[1], nil
}

func berToInt(n *berNode) int {
	v := 0
	for _, b := range n.val {
		v = v<<8 | int(b)
	}
	return v
}

// ldapResultOf reads an LDAPResult: the result code and the server's diagnostic text.
func ldapResultOf(n *berNode) (code int, diag string) {
	if len(n.kids) < 3 {
		return -1, "a malformed answer"
	}
	return berToInt(n.kids[0]), string(n.kids[2].val)
}

// ---- filters (built from values, never parsed) ----

func fAnd(subs ...[]byte) []byte { return tlv(0xA0, subs...) }
func fOr(subs ...[]byte) []byte  { return tlv(0xA1, subs...) }
func fNot(sub []byte) []byte     { return tlv(0xA2, sub) }
func fEq(attr, val string) []byte {
	return tlv(0xA3, berOctet(attr), berOctet(val))
}

// fChain matches entries whose attr names value directly or through nested groups (LDAP_MATCHING_RULE_IN_CHAIN).
func fChain(attr, val string) []byte {
	return tlv(0xA9, tlv(0x81, []byte("1.2.840.113556.1.4.1941")), tlv(0x82, []byte(attr)), tlv(0x83, []byte(val)))
}

// ---- connection ----

type ldapEntry struct {
	dn    string
	attrs map[string][]string
}

type ldapConn struct {
	c     net.Conn
	br    *bufio.Reader
	id    int
	where string
}

const ldapOpTimeout = 15 * time.Second

var ldapSkipWarned = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

func ldapTLSConfig(host string, skip bool) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if skip {
		cfg.InsecureSkipVerify = true // the administrator turned certificate checking off (Do not check the server's certificate)
		warnNoCertCheck(host)
	}
	return cfg
}

// warnNoCertCheck writes a warning to the log, at most once an hour for each name, that a certificate is not being checked.
func warnNoCertCheck(name string) {
	ldapSkipWarned.Lock()
	defer ldapSkipWarned.Unlock()
	if time.Since(ldapSkipWarned.at[name]) > time.Hour {
		ldapSkipWarned.at[name] = time.Now()
		warnf("web: the certificate of %s is not being checked (\"Do not check ... certificate\" is on)", name)
	}
}

// ldapDial connects to one server and has TLS running before it returns.
func ldapDial(server string, skip bool) (*ldapConn, error) {
	host, port, tlsFirst, err := ldapServerURL(server)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	raw, err := d.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	lc := &ldapConn{where: net.JoinHostPort(host, port)}
	raw.SetDeadline(time.Now().Add(ldapOpTimeout))
	if tlsFirst {
		tc := tls.Client(raw, ldapTLSConfig(host, skip))
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS: %w", err)
		}
		lc.c, lc.br = tc, bufio.NewReader(tc)
		return lc, nil
	}
	lc.c, lc.br = raw, bufio.NewReader(raw)
	// ldap://: StartTLS must work before anything secret is sent
	lc.id++
	req := tlv(0x30, berInt(0x02, lc.id), tlv(0x77, tlv(0x80, []byte("1.3.6.1.4.1.1466.20037"))))
	if _, err := raw.Write(req); err != nil {
		raw.Close()
		return nil, err
	}
	_, op, err := readMessage(lc.br)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if code, diag := ldapResultOf(op); op.tag != 0x78 || code != 0 {
		raw.Close()
		return nil, fmt.Errorf("the server did not start TLS (result %d %s); an ldap:// server must offer StartTLS", code, diag)
	}
	tc := tls.Client(raw, ldapTLSConfig(host, skip))
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS: %w", err)
	}
	lc.c, lc.br = tc, bufio.NewReader(tc)
	return lc, nil
}

func (lc *ldapConn) close() {
	lc.id++
	lc.c.SetDeadline(time.Now().Add(2 * time.Second))
	lc.c.Write(tlv(0x30, berInt(0x02, lc.id), tlv(0x42)))
	lc.c.Close()
}

func (lc *ldapConn) send(op []byte) (int, error) {
	lc.id++
	lc.c.SetDeadline(time.Now().Add(ldapOpTimeout))
	_, err := lc.c.Write(tlv(0x30, berInt(0x02, lc.id), op))
	return lc.id, err
}

// bind does a simple bind and returns the server's result code (0 is success) and its diagnostic text.
func (lc *ldapConn) bind(dn, password string) (int, string, error) {
	id, err := lc.send(tlv(0x60, berInt(0x02, 3), berOctet(dn), tlv(0x80, []byte(password))))
	if err != nil {
		return 0, "", err
	}
	for {
		rid, op, err := readMessage(lc.br)
		if err != nil {
			return 0, "", err
		}
		if rid != id {
			continue
		}
		if op.tag != 0x61 {
			return 0, "", errors.New("ldap: an unexpected answer to a bind")
		}
		code, diag := ldapResultOf(op)
		return code, diag, nil
	}
}

const (
	ldapScopeBase = 0
	ldapScopeSub  = 2
)

// search runs one search; at most limit entries are asked for.
func (lc *ldapConn) search(base string, scope int, filter []byte, attrs []string, limit int) ([]ldapEntry, error) {
	var as [][]byte
	for _, a := range attrs {
		as = append(as, berOctet(a))
	}
	id, err := lc.send(tlv(0x63, berOctet(base), berInt(0x0a, scope), berInt(0x0a, 0), berInt(0x02, limit), berInt(0x02, 30),
		tlv(0x01, []byte{0}), filter, tlv(0x30, as...)))
	if err != nil {
		return nil, err
	}
	var out []ldapEntry
	for {
		rid, op, err := readMessage(lc.br)
		if err != nil {
			return nil, err
		}
		if rid != id {
			continue
		}
		switch op.tag {
		case 0x64:
			if len(op.kids) < 2 {
				return nil, errors.New("ldap: a malformed entry")
			}
			e := ldapEntry{dn: string(op.kids[0].val), attrs: map[string][]string{}}
			for _, a := range op.kids[1].kids {
				if len(a.kids) < 2 {
					continue
				}
				k := strings.ToLower(string(a.kids[0].val))
				for _, v := range a.kids[1].kids {
					e.attrs[k] = append(e.attrs[k], string(v.val))
				}
			}
			if len(out) < 1000 {
				out = append(out, e)
			}
		case 0x73: // a referral to another server: not followed
		case 0x65:
			code, diag := ldapResultOf(op)
			if code != 0 && code != 4 { // 4: more matches than asked for; the entries so far are what was wanted
				return out, fmt.Errorf("the search was refused (result %d %s)", code, diag)
			}
			return out, nil
		default:
			return nil, errors.New("ldap: an unexpected answer to a search")
		}
	}
}

// ---- looking people up ----

// ldapOutcome is what asking the directory about one person found.
type ldapOutcome struct {
	OK       bool     // may sign in
	ReadOnly bool     // only to look
	DN       string   // the person's distinguished name
	Steps    []string // what happened, in order (shown by the Test button, and the reason in the log)
	Failed   bool     // the directory could not be asked (a server problem, not an answer about the person)
}

func (o *ldapOutcome) step(f string, a ...any) { o.Steps = append(o.Steps, fmt.Sprintf(f, a...)) }

func (o *ldapOutcome) reason() string {
	if len(o.Steps) == 0 {
		return "no answer"
	}
	return o.Steps[len(o.Steps)-1]
}

// ldapLoginName is what a person typed, as the directory knows it: DOMAIN\name becomes name.
func ldapLoginName(u string) string {
	if i := strings.LastIndexByte(u, '\\'); i >= 0 {
		u = u[i+1:]
	}
	return u
}

// ldapConnect connects to the first server that answers and binds the service account.
func (c LDAPConfig) ldapConnect(o *ldapOutcome) *ldapConn {
	var lastErr error
	for _, s := range c.LDAPServers {
		lc, err := ldapDial(s, c.LDAPSkipVerify)
		if err != nil {
			o.step("could not connect to %s: %v", s, err)
			lastErr = err
			continue
		}
		o.step("connected to %s over TLS", lc.where)
		if !c.hasBind() {
			return lc // no service account: the caller binds as the person
		}
		code, diag, err := lc.bind(c.LDAPBindDN, c.LDAPBindPassword)
		if err != nil {
			o.step("the bind account could not be checked on %s: %v", lc.where, err)
			lc.close()
			lastErr = err
			continue
		}
		if code != 0 {
			o.step("the server refused the bind account %q (result %d %s)", c.LDAPBindDN, code, diag)
			lc.close()
			o.Failed = true // a wrong service account is a settings problem, not an answer about the person
			return nil
		}
		o.step("bound as %s", c.LDAPBindDN)
		return lc
	}
	o.Failed = true
	if lastErr == nil {
		o.step("no LDAP server is set")
	}
	return nil
}

// groupDN turns a group's name into its DN (a value that already looks like a DN is used as it is).
func (c LDAPConfig) groupDN(lc *ldapConn, v string) (string, error) {
	if strings.Contains(v, "=") {
		return v, nil
	}
	es, err := lc.search(c.LDAPBaseDN, ldapScopeSub, fAnd(fEq("objectClass", "group"), fEq("sAMAccountName", v)), []string{"1.1"}, 2)
	if err != nil {
		return "", err
	}
	if len(es) != 1 {
		return "", fmt.Errorf("the group %q was not found (or is not unique)", v)
	}
	return es[0].dn, nil
}

// ldapFind looks a person up and works out their access.  When password is not empty it is checked last, by binding as the
// person; with no password only the lookup is done (the once-a-minute recheck of a session).
func (c LDAPConfig) ldapFind(user, password string, checkPassword bool) *ldapOutcome {
	o := &ldapOutcome{}
	if !c.enabled() {
		o.step("LDAP is not set up")
		return o
	}
	name := ldapLoginName(user)
	if name == "" || len(name) > 256 || hasControl(name) {
		o.step("the user name is not usable")
		return o
	}
	if checkPassword && password == "" {
		o.step("an empty password is never accepted")
		return o
	}
	if !c.hasBind() && !checkPassword {
		o.step("without a service account a person can only be checked together with their password")
		o.Failed = true
		return o
	}
	lc := c.ldapConnect(o)
	if lc == nil {
		return o
	}
	defer lc.close()
	ident, passwordDone := "", false
	if !c.hasBind() { // no service account: the person binds as themselves, then reads their own entry
		ident = c.ldapBindName(user)
		code, diag, err := lc.bind(ident, password)
		if err != nil {
			o.Failed = true
			o.step("the password could not be checked: %v", err)
			return o
		}
		if code != 0 {
			o.step("the server refused %q (result %d %s)", ident, code, diag)
			return o
		}
		o.step("the server accepted the password for %s", ident)
		passwordDone = true
	}
	es, err := lc.search(c.LDAPBaseDN, ldapScopeSub,
		fAnd(fEq("objectClass", "user"), fNot(fEq("objectClass", "computer")), fOr(fEq("sAMAccountName", name), fEq("userPrincipalName", name))),
		[]string{"userAccountControl", "sAMAccountName", "userPrincipalName"}, 3)
	if err != nil {
		o.Failed = true
		o.step("looking %q up failed: %v", name, err)
		return o
	}
	switch len(es) {
	case 0:
		o.step("no account %q under %s", name, c.LDAPBaseDN)
		return o
	case 1:
	default:
		o.step("%q matches more than one account; nobody is signed in on an ambiguous name", name)
		return o
	}
	if passwordDone && !ldapSameAccount(es[0], ident, name) { // the entry found must be the one that signed in
		o.step("the account found (%s) is not the one that signed in as %q", es[0].dn, ident)
		return o
	}
	o.DN = es[0].dn
	o.step("found %s", o.DN)
	if uac, _ := strconv.Atoi(strings.Join(es[0].attrs["useraccountcontrol"], "")); uac&2 != 0 {
		o.step("the account is disabled")
		return o
	}
	level := func(group string) (bool, error) {
		gdn, err := c.groupDN(lc, group)
		if err != nil {
			return false, err
		}
		in, err := lc.search(o.DN, ldapScopeBase, fChain("memberOf", gdn), []string{"1.1"}, 1)
		return len(in) > 0, err
	}
	rw, ro := false, false
	if c.LDAPRWGroup != "" {
		if rw, err = level(c.LDAPRWGroup); err != nil {
			o.Failed = true
			o.step("checking the full-access group failed: %v", err)
			return o
		}
		o.step("member of the full-access group: %v", rw)
	}
	if !rw && c.LDAPROGroup != "" {
		if ro, err = level(c.LDAPROGroup); err != nil {
			o.Failed = true
			o.step("checking the read-only group failed: %v", err)
			return o
		}
		o.step("member of the read-only group: %v", ro)
	}
	if !rw && !ro {
		o.step("the account is in neither group")
		return o
	}
	if checkPassword && !passwordDone {
		code, diag, err := lc.bind(o.DN, password)
		if err != nil {
			o.Failed = true
			o.step("the password could not be checked: %v", err)
			return o
		}
		if code != 0 {
			o.step("the password was refused (result %d %s)", code, diag)
			return o
		}
		o.step("the password is right")
	}
	o.OK, o.ReadOnly = true, !rw
	return o
}

// ldapBindName is how a person who typed "alice" is named to the directory when there is no service account to look them
// up with: alice@example.lan, the domain taken from the search base.  Names already written as a user principal name or as
// DOMAIN\name are used as typed.
func (c LDAPConfig) ldapBindName(typed string) string {
	if strings.ContainsAny(typed, `@\`) {
		return typed
	}
	var parts []string
	for _, rdn := range strings.Split(c.LDAPBaseDN, ",") {
		rdn = strings.TrimSpace(rdn)
		if len(rdn) > 3 && strings.EqualFold(rdn[:3], "dc=") {
			parts = append(parts, rdn[3:])
		}
	}
	if len(parts) == 0 {
		return typed
	}
	return typed + "@" + strings.Join(parts, ".")
}

// ldapSameAccount says whether the entry read back is the account that bound: by user principal name when the bind name is
// one, by account name when it was written DOMAIN\name.
func ldapSameAccount(e ldapEntry, ident, name string) bool {
	if strings.Contains(ident, "@") {
		for _, u := range e.attrs["userprincipalname"] {
			if strings.EqualFold(u, ident) {
				return true
			}
		}
		return false
	}
	for _, s := range e.attrs["samaccountname"] {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

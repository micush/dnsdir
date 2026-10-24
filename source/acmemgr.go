package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Automatic certificates (ACME, dns-01 through acme-dns): the person lists the names, adds one CNAME per name, and the
// primary orders the certificate and installs it as the DNS over TLS/HTTPS certificate and/or the GUI's, then renews it
// by itself.  Renewal is a task of the Scheduler (action certificate_renew) that does nothing on a node that is not the
// primary and nothing while the certificate is not yet due, so it can stay on every node and survives a change of primary.
//
// Everything (settings, the account key, the acme-dns credentials, what was issued) is one small state file that the
// primary copies to the other nodes the way it copies the certificates, so a new primary carries on from where the old
// one was.  The file holds secrets: mode 0600, and the API never shows them.

const (
	acmeRenewBefore = 30 * 24 * time.Hour
	acmeRetryAfter  = 6 * time.Hour
	acmeRenewTaskID = "acme-renew"
	acmeMaxNames    = 20
)

type ACMESettings struct {
	Enabled   bool     `json:"enabled"`
	Directory string   `json:"directory"` // the CA's ACME directory URL
	Email     string   `json:"email"`
	Names     []string `json:"names"`      // "example.com", "*.example.com"
	Target    string   `json:"target"`     // dns (DoT and DoH), gui, or both
	DNSServer string   `json:"dns_server"` // the acme-dns server the CNAMEs point into
	EABKid    string   `json:"eab_kid,omitempty"`
	EABKey    string   `json:"eab_key,omitempty"` // never shown; empty on a save keeps the one set
}

type acmeIssued struct {
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
	Names       []string  `json:"names"`
	At          time.Time `json:"at"`
	Directory   string    `json:"directory"`
}

// ACMEState is the file (and what the primary copies to the other nodes).
type ACMEState struct {
	Settings   ACMESettings          `json:"settings"`
	AccountKey string                `json:"account_key,omitempty"`
	Regs       map[string]acmeDNSReg `json:"regs,omitempty"` // by base domain
	Issued     *acmeIssued           `json:"issued,omitempty"`
	LastTry    time.Time             `json:"last_try,omitempty"`
	LastError  string                `json:"last_error,omitempty"`
	LastBy     string                `json:"last_by,omitempty"`
}

type acmeCheck struct {
	OK   bool
	Seen string
	At   time.Time
}

type ACMEManager struct {
	mg   *Mgmt
	path string

	// replaced by tests
	hc          *http.Client
	lookupCNAME func(ctx context.Context, host string) (string, error)
	settle      time.Duration // after publishing the proofs, before the CA is told to look
	pollEvery   time.Duration // how often the watcher looks for the CNAMEs (30 s)
	jitter      time.Duration // an automatic run waits up to this long first, so clusters sharing a name do not collide

	mu       sync.Mutex
	st       ACMEState
	running  bool
	progress []string
	checks   map[string]acmeCheck
	regErr   string // why the last automatic registration with acme-dns failed
	waitGen  int    // the watcher that waits for the CNAMEs (a new one replaces the old)
	waiting  bool
}

func newACMEManager(mg *Mgmt, stateDir string) *ACMEManager {
	m := &ACMEManager{
		mg: mg, path: filepath.Join(stateDir, "acme", "state.json"),
		hc:          acmeHTTPClient(),
		lookupCNAME: func(ctx context.Context, h string) (string, error) { return net.DefaultResolver.LookupCNAME(ctx, h) },
		settle:      5 * time.Second, jitter: 30 * time.Second,
		checks: map[string]acmeCheck{},
	}
	if b, err := os.ReadFile(m.path); err == nil {
		if err := json.Unmarshal(b, &m.st); err != nil {
			warnf("acme: the saved state could not be read (%v) — starting without it", err)
			m.st = ACMEState{}
		}
	}
	m.fill()
	return m
}

// acmeHTTPClient reaches the CA and the acme-dns server over IPv4 when it can and over IPv6 only when there is no IPv4
// way (a host whose IPv6 route is broken otherwise stalls until the handshake times out).
func acmeHTTPClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == "tcp" {
				if c, err := d.DialContext(ctx, "tcp4", addr); err == nil {
					return c, nil
				}
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
	}}
}

func (m *ACMEManager) fill() {
	s := &m.st.Settings
	if s.Directory == "" {
		s.Directory = acmeLetsEncrypt
	}
	if s.DNSServer == "" {
		s.DNSServer = defaultACMEDNS
	}
	if s.Target == "" {
		s.Target = "dns"
	}
	if s.Names == nil {
		s.Names = []string{}
	}
	if m.st.Regs == nil {
		m.st.Regs = map[string]acmeDNSReg{}
	}
}

func (m *ACMEManager) saveLocked() error {
	b, err := json.MarshalIndent(m.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	return writeAtomic(m.path, b, 0o600)
}

var acmeLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// acmeNames checks and normalises a list of names.
func acmeNames(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, n := range in {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		host := strings.TrimPrefix(n, "*.")
		if net.ParseIP(host) != nil {
			return nil, fmt.Errorf("%q is an address: a certificate from an ACME CA needs a name", n)
		}
		labels := strings.Split(host, ".")
		if len(host) > 253 || len(labels) < 2 {
			return nil, fmt.Errorf("%q is not a full domain name such as dns.example.com", n)
		}
		for _, l := range labels {
			if !acmeLabel.MatchString(l) {
				return nil, fmt.Errorf("%q is not a valid domain name", n)
			}
		}
		out = append(out, n)
	}
	if len(out) > acmeMaxNames {
		return nil, fmt.Errorf("at most %d names", acmeMaxNames)
	}
	return out, nil
}

func acmeBase(n string) string { return strings.TrimPrefix(n, "*.") }

func (m *ACMEManager) say(f string, a ...any) {
	line := time.Now().UTC().Format("15:04:05") + " " + fmt.Sprintf(f, a...)
	infof("acme: %s", fmt.Sprintf(f, a...))
	m.mu.Lock()
	m.progress = append(m.progress, line)
	if len(m.progress) > 40 {
		m.progress = m.progress[len(m.progress)-40:]
	}
	m.mu.Unlock()
}

// ── views ────────────────────────────────────────────────────────────────────

type ACMERecord struct {
	Name       string `json:"name"`       // _acme-challenge.example.com
	Target     string `json:"target"`     // what the CNAME must point to
	Registered bool   `json:"registered"` // acme-dns has handed out a name for it
	Checked    bool   `json:"checked"`
	OK         bool   `json:"ok"`
	Seen       string `json:"seen,omitempty"`
}

type ACMEView struct {
	Settings      ACMESettings `json:"settings"`
	EABKeySet     bool         `json:"eab_key_set"`
	Records       []ACMERecord `json:"records"`
	Issued        *acmeIssued  `json:"issued,omitempty"`
	LastTry       time.Time    `json:"last_try,omitempty"`
	LastError     string       `json:"last_error,omitempty"`
	Running       bool         `json:"running"`
	Progress      []string     `json:"progress"`
	Due           bool         `json:"due"`
	Note          string       `json:"note,omitempty"` // why nothing happens, or when it renews
	Primary       bool         `json:"primary"`
	TaskExists    bool         `json:"task_exists"`
	RegisterError string       `json:"register_error,omitempty"`
	Waiting       bool         `json:"waiting"` // the CNAMEs are not all in place yet: the primary keeps checking and orders when they are
}

func (m *ACMEManager) isPrimary() bool {
	return m.mg.cl == nil || !m.mg.cl.Enabled() || m.mg.cl.Snapshot().Role == RolePrimary
}

func (m *ACMEManager) hasTask() bool {
	if m.mg.sched == nil {
		return false
	}
	for _, t := range m.mg.sched.Status().Tasks {
		if t.Action == "certificate_renew" {
			return true
		}
	}
	return false
}

func (m *ACMEManager) Status() ACMEView {
	task := m.hasTask()
	m.mu.Lock()
	defer m.mu.Unlock()
	v := ACMEView{Settings: m.st.Settings, Issued: m.st.Issued, LastTry: m.st.LastTry, LastError: m.st.LastError,
		Running: m.running, Progress: append([]string{}, m.progress...), Records: []ACMERecord{}, Primary: m.isPrimary(), TaskExists: task}
	v.RegisterError = m.regErr
	v.Waiting = m.waiting
	v.EABKeySet = v.Settings.EABKey != ""
	v.Settings.EABKey = ""
	seen := map[string]bool{}
	for _, n := range v.Settings.Names {
		b := acmeBase(n)
		if seen[b] {
			continue
		}
		seen[b] = true
		r := ACMERecord{Name: "_acme-challenge." + b}
		if reg, ok := m.st.Regs[b]; ok {
			r.Registered, r.Target = true, reg.FullDomain
			if c, ok := m.checks[b]; ok {
				r.Checked, r.OK, r.Seen = true, c.OK && c.Seen == reg.FullDomain, c.Seen
			}
		}
		v.Records = append(v.Records, r)
	}
	due, note := m.dueLocked(time.Now())
	v.Due, v.Note = due, note
	return v
}

// currentFP is the fingerprint of the certificate now served for the target.
func (m *ACMEManager) currentFP(target string) string {
	if target == "gui" {
		return m.mg.certs.Status().Fingerprint
	}
	return m.mg.dnscerts.Status().Fingerprint
}

// dueLocked says whether the automatic run should order a certificate now, and why not when it should not.
func (m *ACMEManager) dueLocked(now time.Time) (bool, string) {
	s, is := m.st.Settings, m.st.Issued
	if !s.Enabled {
		return false, "automatic certificates are off"
	}
	if len(s.Names) == 0 {
		return false, "no names are set"
	}
	if is == nil {
		return true, "no certificate has been ordered yet"
	}
	if !sameNameSet(is.Names, s.Names) {
		return true, "the names changed"
	}
	if is.Directory != s.Directory {
		return true, "the CA changed"
	}
	if fp := m.currentFP(s.Target); fp != is.Fingerprint {
		return false, "a different certificate was installed by hand since: automatic renewal is paused. Press Get certificate now to take over again"
	}
	left := is.NotAfter.Sub(now)
	if left < acmeRenewBefore {
		return true, fmt.Sprintf("the certificate expires in %d day(s)", int(left.Hours()/24))
	}
	return false, fmt.Sprintf("renews about %s (the certificate runs until %s)", is.NotAfter.Add(-acmeRenewBefore).Format("2006-01-02"), is.NotAfter.Format("2006-01-02"))
}

// ── settings ─────────────────────────────────────────────────────────────────

// Set saves the settings.  Run on the primary.
func (m *ACMEManager) Set(in ACMESettings, by string) error {
	names, err := acmeNames(in.Names)
	if err != nil {
		return err
	}
	in.Names = names
	if in.Directory = strings.TrimSpace(in.Directory); in.Directory == "" {
		in.Directory = acmeLetsEncrypt
	}
	if in.Directory, err = checkServerURL(in.Directory, "the CA's directory address"); err != nil {
		return err
	}
	if in.DNSServer = strings.TrimSpace(in.DNSServer); in.DNSServer == "" {
		in.DNSServer = defaultACMEDNS
	}
	if in.DNSServer, err = checkServerURL(in.DNSServer, "the acme-dns server address"); err != nil {
		return err
	}
	if in.Email = strings.TrimSpace(in.Email); in.Email != "" && (strings.ContainsAny(in.Email, " \t\r\n<>,;") || !strings.Contains(in.Email, "@") || len(in.Email) > 254) {
		return errors.New("that is not an email address")
	}
	switch in.Target {
	case "":
		in.Target = "dns"
	case "dns", "gui", "both":
	default:
		return errors.New("the certificate is for dns, gui or both")
	}
	in.EABKid, in.EABKey = strings.TrimSpace(in.EABKid), strings.TrimSpace(in.EABKey)
	if in.Enabled && len(in.Names) == 0 {
		return errors.New("give at least one name before turning automatic certificates on")
	}
	m.mu.Lock()
	if in.EABKey == "" && in.EABKid != "" {
		in.EABKey = m.st.Settings.EABKey // the key is never shown, so an empty box keeps it
	}
	if in.EABKid == "" {
		in.EABKey = ""
	}
	old := m.st.Settings
	m.st.Settings = in
	if old.DNSServer != in.DNSServer { // the registrations belong to one server
		m.st.Regs = map[string]acmeDNSReg{}
		m.checks = map[string]acmeCheck{}
	}
	keep := map[string]bool{}
	for _, n := range in.Names {
		keep[acmeBase(n)] = true
	}
	for b := range m.st.Regs {
		if !keep[b] {
			delete(m.st.Regs, b)
			delete(m.checks, b)
		}
	}
	err = m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	infof("acme: settings saved by %s (%d name(s), %s)", by, len(in.Names), map[bool]string{true: "on", false: "off"}[in.Enabled])
	if in.Enabled {
		m.ensureTask(by)
	}
	return nil
}

// ensureTask adds the daily renewal task to the Scheduler when there is none, so turning the feature on is all it takes.
func (m *ACMEManager) ensureTask(by string) {
	if m.hasTask() {
		return
	}
	t := SchedTask{ID: acmeRenewTaskID, Name: "Renew the automatic certificate", Action: "certificate_renew", Freq: "daily", At: "10:17"}
	if _, err := m.mg.SchedSet(t, by); err != nil {
		warnf("acme: could not add the renewal task to the Scheduler (%v) — add a daily \"Renew the certificate\" task yourself", err)
		return
	}
	infof("acme: added a daily task to the Scheduler to renew it")
}

// Register asks the acme-dns server for a name for every domain that has none yet.
func (m *ACMEManager) Register(ctx context.Context) (err error) {
	defer func() {
		m.mu.Lock()
		m.regErr = ""
		if err != nil {
			m.regErr = err.Error()
		}
		m.mu.Unlock()
	}()
	m.mu.Lock()
	s := m.st.Settings
	var need []string
	seen := map[string]bool{}
	for _, n := range s.Names {
		b := acmeBase(n)
		if _, ok := m.st.Regs[b]; !ok && !seen[b] {
			need = append(need, b)
		}
		seen[b] = true
	}
	m.mu.Unlock()
	if len(s.Names) == 0 {
		return errors.New("give at least one name first")
	}
	for _, b := range need {
		reg, err := acmeDNSRegister(ctx, m.hc, s.DNSServer)
		if err != nil {
			return fmt.Errorf("acme-dns (%s) did not register %s: %w", s.DNSServer, b, err)
		}
		m.mu.Lock()
		m.st.Regs[b] = reg
		err = m.saveLocked()
		m.mu.Unlock()
		if err != nil {
			return err
		}
		infof("acme: registered %s with %s", b, s.DNSServer)
	}
	return nil
}

// ExportRegs returns the acme-dns credentials, to be pasted into another cluster that uses the same names.
func (m *ACMEManager) ExportRegs() map[string]acmeDNSReg {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]acmeDNSReg{}
	for k, v := range m.st.Regs {
		out[k] = v
	}
	return out
}

// ImportRegs takes credentials made elsewhere for the names this cluster has: the CNAMEs already in DNS then serve both.
func (m *ACMEManager) ImportRegs(in map[string]acmeDNSReg, by string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]bool{}
	for _, n := range m.st.Settings.Names {
		want[acmeBase(n)] = true
	}
	if len(in) == 0 {
		return errors.New("nothing to import")
	}
	for d, r := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if !want[d] {
			return fmt.Errorf("%s is not one of the names set here: save the names first", d)
		}
		srv, err := checkServerURL(r.Server, "the acme-dns server in the credentials")
		if err != nil {
			return err
		}
		r.Server = srv
		r.FullDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.FullDomain), "."))
		if r.Username == "" || r.Password == "" || r.Subdomain == "" || r.FullDomain == "" {
			return fmt.Errorf("the credentials for %s are incomplete", d)
		}
		if srv != m.st.Settings.DNSServer {
			return fmt.Errorf("the credentials for %s are for %s, but this cluster uses %s: change the acme-dns server first", d, srv, m.st.Settings.DNSServer)
		}
		m.st.Regs[d] = r
		delete(m.checks, d)
	}
	infof("acme: acme-dns credentials for %d name(s) imported by %s", len(in), by)
	return m.saveLocked()
}

// allInPlace says whether every name's CNAME was found pointing at its acme-dns entry by the last Check.
func (m *ACMEManager) allInPlace() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.st.Settings.Names) == 0 {
		return false
	}
	for _, n := range m.st.Settings.Names {
		b := acmeBase(n)
		reg, ok := m.st.Regs[b]
		c, checked := m.checks[b]
		if !ok || !checked || !c.OK || c.Seen != strings.ToLower(reg.FullDomain) {
			return false
		}
	}
	return true
}

const (
	acmeWatchEvery = 30 * time.Second
	acmeWatchFor   = 24 * time.Hour
)

// Go is the one button: the names have been saved and registered; order the certificate now when every CNAME is in
// place, otherwise keep looking every 30 seconds (for a day) and order as soon as they are.  Nothing more to press.
func (m *ACMEManager) Go(by string) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("an order is already in progress")
	}
	m.waitGen++
	gen := m.waitGen
	m.waiting = false
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	m.Check(ctx)
	cancel()
	if m.allInPlace() {
		return m.Request(by)
	}
	m.mu.Lock()
	m.waiting = true
	m.mu.Unlock()
	go m.watch(by, gen)
	return nil
}

func (m *ACMEManager) watch(by string, gen int) {
	end := time.Now().Add(acmeWatchFor)
	for time.Now().Before(end) {
		time.Sleep(m.watchEvery())
		m.mu.Lock()
		if gen != m.waitGen || !m.st.Settings.Enabled {
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		if !m.isPrimary() {
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		m.Check(ctx)
		cancel()
		if m.allInPlace() {
			m.mu.Lock()
			if gen == m.waitGen {
				m.waiting = false
			}
			m.mu.Unlock()
			if err := m.Request(by); err != nil {
				warnf("acme: %v", err)
			}
			return
		}
	}
	m.mu.Lock()
	if gen == m.waitGen {
		m.waiting = false
	}
	m.mu.Unlock()
}

func (m *ACMEManager) watchEvery() time.Duration {
	if m.pollEvery > 0 {
		return m.pollEvery
	}
	return acmeWatchEvery
}

// Check looks up every CNAME and remembers whether it points where it should.
func (m *ACMEManager) Check(ctx context.Context) {
	m.mu.Lock()
	regs := map[string]acmeDNSReg{}
	for k, v := range m.st.Regs {
		regs[k] = v
	}
	m.mu.Unlock()
	for b, reg := range regs {
		got, err := m.cname(ctx, b)
		c := acmeCheck{At: time.Now()}
		if err == nil {
			c.Seen = got
			c.OK = got == strings.ToLower(reg.FullDomain)
		}
		m.mu.Lock()
		m.checks[b] = c
		m.mu.Unlock()
	}
}

// cname returns where _acme-challenge.<base> points ("" when it is not a CNAME).
func (m *ACMEManager) cname(ctx context.Context, base string) (string, error) {
	host := "_acme-challenge." + base
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	got, err := m.lookupCNAME(cctx, host)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return "", nil
		}
		return "", err
	}
	got = strings.ToLower(strings.TrimSuffix(got, "."))
	if got == host {
		return "", nil
	}
	return got, nil
}

// ── ordering ─────────────────────────────────────────────────────────────────

func (m *ACMEManager) accountKey() (*ecdsa.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if blk, _ := pem.Decode([]byte(m.st.AccountKey)); blk != nil {
		if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil && k.Curve == elliptic.P256() {
			return k, nil
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	m.st.AccountKey = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	return k, m.saveLocked()
}

type acmeDNSSolver struct{ m *ACMEManager }

func (s acmeDNSSolver) Present(ctx context.Context, domain, txt string) error {
	m := s.m
	base := acmeBase(domain)
	m.mu.Lock()
	reg, ok := m.st.Regs[base]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("%s has no acme-dns name yet: press Set up DNS records first", base)
	}
	got, err := m.cname(ctx, base)
	switch {
	case err != nil: // the lookup itself failed here: let the CA be the judge
	case got == "":
		return fmt.Errorf("_acme-challenge.%s is not a CNAME yet: add a CNAME to %s", base, reg.FullDomain)
	case got != strings.ToLower(reg.FullDomain):
		return fmt.Errorf("_acme-challenge.%s points to %s, not to %s", base, got, reg.FullDomain)
	}
	var last error
	for try := 0; try < 3; try++ {
		if last = reg.Update(ctx, m.hc, txt); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return last
}

// Request orders the certificate now, in the background (the page watches the progress).
func (m *ACMEManager) Request(by string) error {
	m.mu.Lock()
	s := m.st.Settings
	if m.running {
		m.mu.Unlock()
		return errors.New("an order is already in progress")
	}
	if len(s.Names) == 0 {
		m.mu.Unlock()
		return errors.New("give at least one name first")
	}
	for _, n := range s.Names {
		if _, ok := m.st.Regs[acmeBase(n)]; !ok {
			m.mu.Unlock()
			return fmt.Errorf("%s has no acme-dns name yet: press Set up DNS records first", acmeBase(n))
		}
	}
	m.running = true
	m.progress = nil
	m.mu.Unlock()
	go func() {
		err := m.run(by, false)
		if err != nil {
			warnf("acme: %v", err)
		}
	}()
	return nil
}

// RunScheduled is the Scheduler action: order a certificate if one is due, on the primary only.
func (m *ACMEManager) RunScheduled(by string) (string, error) {
	if !m.isPrimary() {
		return "not the primary: the primary renews the certificate", nil
	}
	m.mu.Lock()
	due, note := m.dueLocked(time.Now())
	retry := m.st.LastError != "" && time.Since(m.st.LastTry) < acmeRetryAfter
	if m.running {
		m.mu.Unlock()
		return "an order is already in progress", nil
	}
	if !due {
		m.mu.Unlock()
		return "nothing to do: " + note, nil
	}
	if retry {
		m.mu.Unlock()
		return "waiting to try again after the last failure (" + m.st.LastError + ")", nil
	}
	m.running = true
	m.progress = nil
	m.mu.Unlock()
	if err := m.run(by, true); err != nil {
		return "", err
	}
	return "certificate renewed", nil
}

func (m *ACMEManager) run(by string, auto bool) (err error) {
	defer func() {
		m.mu.Lock()
		m.running = false
		m.st.LastTry, m.st.LastBy = time.Now().UTC(), by
		if err != nil {
			m.st.LastError = err.Error()
		} else {
			m.st.LastError = ""
		}
		m.saveLocked()
		m.mu.Unlock()
		if err != nil {
			m.say("failed: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	m.mu.Lock()
	s := m.st.Settings
	m.mu.Unlock()
	for _, t := range targetsOf(s.Target) {
		if cm := m.mg.certFor(t); cm.Status().Source == certSourceFiles {
			return fmt.Errorf("the %s certificate comes from files named in the configuration file, which take precedence: remove them first", t)
		}
	}
	key, err := m.accountKey()
	if err != nil {
		return err
	}
	c := newACMEClient(m.hc, s.Directory, key, m.say)
	m.say("contacting the CA at %s", s.Directory)
	if err := c.Account(ctx, s.Email, s.EABKid, s.EABKey); err != nil {
		return err
	}
	if auto && m.jitter > 0 {
		d := time.Duration(mrand.Int63n(int64(m.jitter)))
		m.say("waiting %s so that clusters sharing a name do not collide", d.Round(time.Second))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	chain, keyPEM, err := c.Obtain(ctx, s.Names, acmeDNSSolver{m}, m.settle)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return fmt.Errorf("the certificate the CA gave does not fit its key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	for _, t := range targetsOf(s.Target) {
		if _, _, err := m.mg.certFor(t).Install(chain, keyPEM, "acme", certSourceInstalled); err != nil {
			return fmt.Errorf("the certificate was issued but could not be installed as the %s certificate: %w", t, err)
		}
		m.say("installed as the %s certificate", map[string]string{"dns": "DNS over TLS/HTTPS", "gui": "GUI"}[t])
	}
	m.mu.Lock()
	m.st.Issued = &acmeIssued{Fingerprint: fingerprint(pair), NotAfter: leaf.NotAfter.UTC(), Names: append([]string{}, s.Names...), At: time.Now().UTC(), Directory: s.Directory}
	m.mu.Unlock()
	m.say("done: valid until %s", leaf.NotAfter.UTC().Format("2006-01-02"))
	return nil
}

func targetsOf(t string) []string {
	switch t {
	case "gui":
		return []string{"gui"}
	case "both":
		return []string{"dns", "gui"}
	}
	return []string{"dns"}
}

func (m *Mgmt) certFor(target string) *CertManager {
	if target == "gui" {
		return m.certs
	}
	return m.dnscerts
}

// ── cluster ──────────────────────────────────────────────────────────────────

// Export is the state the primary copies to the other nodes (nil when nothing was ever set).
func (m *ACMEManager) Export() *ACMEState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.st.Settings.Enabled && len(m.st.Settings.Names) == 0 && m.st.Issued == nil && m.st.AccountKey == "" {
		return nil
	}
	b, _ := json.Marshal(m.st)
	var cp ACMEState
	json.Unmarshal(b, &cp)
	return &cp
}

// ApplyCluster makes this node's state the primary's.
func (m *ACMEManager) ApplyCluster(st *ACMEState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st == nil {
		st = &ACMEState{}
	}
	nb, _ := json.Marshal(st)
	ob, _ := json.Marshal(m.st)
	if string(nb) == string(ob) {
		return nil
	}
	m.st = *st
	m.fill()
	return m.saveLocked()
}

// sameNameSet says whether two name lists hold the same names, whatever their order.
func sameNameSet(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, ",") == strings.Join(y, ",")
}

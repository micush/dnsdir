package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// chrony answers the clients; ntpdir decides which upstream servers chrony takes its time from.
//
// Every node runs chrony.  ntpdir probes the servers that are defined (the shared list and the gateways' own), and the
// ones that pass are written to a file chrony reads as a source directory (`sourcedir`), then chrony is told to read
// it again (`chronyc reload sources`).  A server that stops passing (it does not answer, is too far out of step with
// the others, is too slow, has too high a stratum or root distance) is left out of the file at the next look, so
// chrony stops using it.  The installer adds `sourcedir` and `confdir` to chrony's configuration; see install.sh.
//
// Clients reach chrony on the gateway addresses (chrony listens on every address, so the address on lo or on the
// macvlan is served as soon as it is there).  The allowed-clients list and the rate limit are written for chrony as a
// second small file in its confdir (allow, ratelimit, port); chrony has to be restarted to read that one, which
// happens only when its content changes.

const chronyHeader = "# Written by ntpdir. Changes made here are overwritten.\n"

// Where the files go; the installer creates both directories and points chrony at them.  Replaceable for tests.
var (
	chronySourceDir = envOr("NTPDIR_CHRONY_SOURCEDIR", "/etc/chrony/ntpdir.sources.d")
	chronyConfDir   = envOr("NTPDIR_CHRONY_CONFDIR", "/etc/chrony/ntpdir.conf.d")
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// chronyc runs the chrony control program (replaceable in tests).  NTPDIR_CHRONYC_ARGS can add arguments in front, such
// as "-h /run/chrony/chronyd.sock".
var chronyc = func(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bin := envOr("NTPDIR_CHRONYC", "chronyc")
	full := append(strings.Fields(os.Getenv("NTPDIR_CHRONYC_ARGS")), args...)
	cmd := exec.CommandContext(ctx, bin, full...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if msg != "" {
			return out.Bytes(), fmt.Errorf("%s: %s", bin, firstLine(msg))
		}
		return out.Bytes(), fmt.Errorf("%s: %w", bin, err)
	}
	return out.Bytes(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// chronyRestart restarts the chrony service (replaceable in tests): the unit is chrony on Debian and Ubuntu and chronyd
// elsewhere.
var chronyRestart = func() error {
	var last error
	for _, u := range []string{"chrony.service", "chronyd.service"} {
		if out, err := exec.Command(envOr("NTPDIR_SYSTEMCTL", "systemctl"), "restart", u).CombinedOutput(); err == nil {
			return nil
		} else {
			last = fmt.Errorf("systemctl restart %s: %s", u, firstLine(strings.TrimSpace(string(out))))
		}
	}
	return last
}

// ── Sources ──────────────────────────────────────────────────────────────────

func validChronyHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == "" // an address; a zone is not accepted
	}
	for _, r := range h { // a host name: letters, digits, dots, hyphens and underscores
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// chronyServerLine is the `server` line for an upstream as written in the configuration: "10.0.0.1", "10.0.0.1:1123",
// "[2001:db8::1]:123", "ntp.example.com".
func chronyServerLine(addr string) (string, error) {
	host, port := addr, ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		host = addr[1 : len(addr)-1]
	}
	if !validChronyHost(host) {
		return "", fmt.Errorf("%q is not a server chrony can use", addr)
	}
	line := "server " + host
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("%q: bad port", addr)
		}
		if n != 123 {
			line += " port " + port
		}
	}
	return line + " iburst", nil
}

// chronySourcesFile is the content of the source file for a set of servers (sorted, once each).
func chronySourcesFile(servers []string) (string, error) { return chronySourcesFileAuth(servers, nil) }

// chronySourcesFileAuth is the same with each server's options (auth, by server address) on its line.
func chronySourcesFileAuth(servers []string, auth map[string]string) (string, error) {
	seen := map[string]bool{}
	var lines []string
	for _, s := range servers {
		l, err := chronyServerLine(s)
		if err != nil {
			return "", err
		}
		if n, err := normalizeServer(s); err == nil {
			l += auth[n]
		}
		if !seen[l] {
			seen[l] = true
			lines = append(lines, l)
		}
	}
	sort.Strings(lines)
	return chronyHeader + strings.Join(lines, "\n") + "\n", nil
}

// writeIfChanged writes the file atomically unless it already has this content; it says whether it changed.
func writeIfChanged(dir, name, content string) (bool, error) {
	path := dir + "/" + name
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}

// ── The manager ──────────────────────────────────────────────────────────────

// ChronyState is what chrony says about itself (chronyc tracking).
type ChronyState struct {
	Running   bool         `json:"running"`
	Synced    bool         `json:"synced"`
	Stratum   int          `json:"stratum"`
	Ref       string       `json:"ref,omitempty"`      // the server it is synchronised to, or its reference ID
	OffsetMS  float64      `json:"offset_ms"`          // the system clock's offset from the time chrony believes
	RootDelay float64      `json:"root_delay_ms"`      // ms
	RootDisp  float64      `json:"root_dispersion_ms"` // ms
	Leap      string       `json:"leap,omitempty"`     // Normal, Insert second, Delete second, Not synchronised
	Err       string       `json:"error,omitempty"`    // why it could not be read
	At        int64        `json:"at,omitempty"`       // unix seconds of the reading
	Sources   []ChronySrc  `json:"sources"`            // the sources chrony has
	Auth      []ChronyAuth `json:"auth,omitempty"`     // what chrony says about the authentication of its sources (chronyc authdata)
}

// ChronySrc is one source chrony has: State is chronyc's mark (* selected, + combined, - not combined, ? unreachable,
// x falseticker, ~ too variable).
type ChronySrc struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Reach int    `json:"reach"` // how many of its last 8 polls were answered
}

// stateOf is chrony's mark for a server written as in the configuration ("10.0.0.1", "10.0.0.1:1123", "[::1]:123",
// "ntp.example.com"), or "" when chrony does not have it.
func (s ChronyState) stateOf(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	} else if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		host = addr[1 : len(addr)-1]
	}
	for _, c := range s.Sources {
		if strings.EqualFold(c.Name, host) {
			return c.State
		}
	}
	return ""
}

type chronyMgr struct {
	mu       sync.Mutex
	last     []string // the servers last written (sorted lines)
	pending  bool     // the file was written but chrony has not yet taken it
	state    ChronyState
	confBody string                  // the client file as last written, "" before the first look
	offLimit int                     // how far the clock may be off and still serve, ms (0: no limit)
	offOver  bool                    // the clock is beyond that now
	muted    bool                    // no server is in service: chrony is told to answer nobody
	auth     map[string]string       // per-server options (" nts", " key 7") by server address
	allowed  bool                    // the allow rules were put into the running chrony at least once
	keyFile  string                  // where the port and rate limit chrony runs with are remembered ("": not kept)
	seen     map[string]chronyClient // chrony's totals per client at the last look (nil before the first)
	warned   map[string]time.Time
}

var chrony = &chronyMgr{warned: map[string]time.Time{}}

// warnEvery logs a message once a minute at most for a key.
func (m *chronyMgr) warnEvery(key, msg string) {
	m.mu.Lock()
	t := m.warned[key]
	if time.Since(t) < time.Minute {
		m.mu.Unlock()
		return
	}
	m.warned[key] = time.Now()
	m.mu.Unlock()
	warnf("%s", msg)
}

// applySources makes chrony use exactly these servers.  An empty list changes nothing unless empty is set (no server
// is defined at all, or every one is paused): with servers defined but none passing, chrony keeps the ones it has.
func (m *chronyMgr) applySources(servers []string, empty bool) error {
	if len(servers) == 0 && !empty {
		return nil
	}
	m.mu.Lock()
	auth := m.auth
	m.mu.Unlock()
	if len(auth) > 0 && !m.authApplied() {
		// the keys or NTS settings are not in the running chrony yet (a restart is due): a server that is to be
		// authenticated stays out rather than being used without it
		var plain []string
		for _, s := range servers {
			if n, err := normalizeServer(s); err == nil {
				if _, need := auth[n]; need {
					continue
				}
			}
			plain = append(plain, s)
		}
		if len(plain) == 0 && len(servers) > 0 {
			return nil
		}
		servers = plain
	}
	body, err := chronySourcesFileAuth(servers, auth)
	if err != nil {
		return err
	}
	changed, err := writeIfChanged(chronySourceDir, "ntpdir.sources", body)
	if err != nil {
		return fmt.Errorf("chrony sources: %w", err)
	}
	m.mu.Lock()
	if changed {
		m.pending = true
	}
	need := m.pending
	m.mu.Unlock()
	if !need {
		return nil
	}
	if out, err := chronyc("reload", "sources"); err != nil {
		return fmt.Errorf("chrony sources: %w", err)
	} else if !strings.Contains(string(out), "200 OK") && len(bytes.TrimSpace(out)) > 0 {
		return fmt.Errorf("chrony sources: %s", firstLine(strings.TrimSpace(string(out))))
	}
	m.mu.Lock()
	m.pending = false
	m.last = append(m.last[:0], strings.Split(strings.TrimSpace(body), "\n")[1:]...)
	m.mu.Unlock()
	infof("chrony: sources now %s", strings.Join(serverNames(body), ", "))
	return nil
}

func serverNames(body string) []string {
	var out []string
	for _, l := range strings.Split(body, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "server" {
			out = append(out, f[1])
		}
	}
	return out
}

// chronyConfBody is the file for chrony's confdir: the port, who may ask and how often.
func chronyConfBody(d NTPConfig) (string, error) { return chronyConfBodyMuted(d, false) }

// chronyConfBodyMuted is the file with no keys, NTS or leap-second settings written out (tests, and chrony before the
// files for them exist); chronyConfBodyAuth adds them.
func chronyConfBodyMuted(d NTPConfig, muted bool) (string, error) {
	return chronyConfBodyAuth(d, muted, authFiles{})
}

// chronyConfBodyAuth is the file; muted leaves out every allow line, so chrony answers nobody, also after a restart.
func chronyConfBodyAuth(d NTPConfig, muted bool, af authFiles) (string, error) {
	var b strings.Builder
	b.WriteString(chronyHeader)
	port := d.ListenPort
	if port == 0 {
		port = 123
	}
	fmt.Fprintf(&b, "port %d\n", port)
	if !muted {
		b.WriteString("allow 127.0.0.0/8\nallow ::1\n")
		if len(d.AllowedClients) == 0 {
			b.WriteString("allow all\n")
		} else {
			nets, err := parseClientNets(d.AllowedClients)
			if err != nil {
				return "", err
			}
			for _, n := range nets {
				fmt.Fprintf(&b, "allow %s\n", n.String())
			}
		}
		// blocked clients come after every allow, and `deny all` also drops any more specific allow inside the block
		blocked, err := parseClientNets(d.BlockedClients)
		if err != nil {
			return "", err
		}
		for _, n := range blocked {
			fmt.Fprintf(&b, "deny all %s\n", n.String())
		}
	}
	if d.ClientRate > 0 {
		interval := int(math.Round(-math.Log2(float64(d.ClientRate))))
		if interval < -19 {
			interval = -19
		}
		if interval > 12 {
			interval = 12
		}
		burst := int(effectiveBurst(d.ClientRate, d.ClientBurst))
		if burst < 1 {
			burst = 1
		}
		if burst > 255 {
			burst = 255
		}
		leak := 4 // a limited client mostly gets nothing
		if d.ClientAction == actKoD {
			leak = 2 // and more often a kiss-o'-death RATE, which tells it to slow down
		}
		fmt.Fprintf(&b, "ratelimit interval %d burst %d leak %d\n", interval, burst, leak)
	}
	b.WriteString(authConf(d, af))
	return b.String(), nil
}

// restartKey is the part of the client file that chrony can only read at start: the port, the rate limit, the keys, NTS and
// the leap-second settings.
func restartKey(body string) string {
	var k []string
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "port ") || strings.HasPrefix(l, "ratelimit ") || strings.HasPrefix(l, "keyfile ") ||
			strings.HasPrefix(l, "ntsserver") || strings.HasPrefix(l, "leapsec") || strings.HasPrefix(l, "smoothtime ") ||
			strings.HasPrefix(l, "# authsum ") {
			k = append(k, l)
		}
	}
	return strings.Join(k, "\n")
}

// allowLive puts the allow rules into the running chrony: who may ask can change without a restart.
func allowLive(d NTPConfig) error { return allowLiveMuted(d, false) }

func allowLiveMuted(d NTPConfig, muted bool) error {
	if _, err := chronyc("deny", "all"); err != nil { // forgets every earlier rule, whatever its family
		return err
	}
	if muted {
		return nil
	}
	rules := []string{"127.0.0.0/8", "::1"}
	if len(d.AllowedClients) == 0 {
		rules = append(rules, "")
	} else {
		nets, err := parseClientNets(d.AllowedClients)
		if err != nil {
			return err
		}
		for _, n := range nets {
			rules = append(rules, n.String())
		}
	}
	for _, r := range rules {
		args := []string{"allow", "all"}
		if r != "" {
			args = append(args, r)
		}
		if _, err := chronyc(args...); err != nil {
			return err
		}
	}
	blocked, err := parseClientNets(d.BlockedClients)
	if err != nil {
		return err
	}
	for _, n := range blocked {
		if _, err := chronyc("deny", "all", n.String()); err != nil {
			return err
		}
	}
	return nil
}

// defaultRestartKey is what chrony runs with when it has read no file of ours.
const defaultRestartKey = "port 123"

// appliedKey is the port and rate limit the running chrony was started with, as far as ntpdir knows.
func (m *chronyMgr) appliedKey() string {
	m.mu.Lock()
	f := m.keyFile
	m.mu.Unlock()
	if f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return defaultRestartKey
}

// setAuth gives the per-server options chrony's source lines carry (" nts", " key 7"), by server address.
func (m *chronyMgr) setAuth(auth map[string]string) {
	m.mu.Lock()
	m.auth = auth
	m.mu.Unlock()
}

// authApplied says the running chrony has the keys and NTS settings the client file now holds (the "# authsum" line of the
// file equals the one it was started with).
func (m *chronyMgr) authApplied() bool {
	m.mu.Lock()
	body := m.confBody
	m.mu.Unlock()
	return authSumOf(body) == authSumOf(m.appliedKey())
}

func (m *chronyMgr) allowedOK() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allowed
}

// markApplied records that chrony was (re)started with the settings now in the file.
func (m *chronyMgr) markApplied() {
	m.mu.Lock()
	f, body := m.keyFile, m.confBody
	m.mu.Unlock()
	if f != "" {
		_ = os.WriteFile(f, []byte(restartKey(body)+"\n"), 0o600)
	}
}

// needsRestart says the file holds a port or rate limit that the running chrony does not have yet.
func (m *chronyMgr) needsRestart() bool {
	m.mu.Lock()
	body := m.confBody
	m.mu.Unlock()
	return body != "" && restartKey(body) != m.appliedKey()
}

// applyClients writes chrony's client file and puts a new allow list into the running chrony.  It never restarts
// chrony: the port and the rate limit are read only at start, so a change of either is left for the rolling restart
// (chronyroll.go), which takes the nodes one at a time and out of service while chrony starts.
func (m *chronyMgr) applyClients(d NTPConfig) error {
	m.mu.Lock()
	muted := m.muted
	m.mu.Unlock()
	af, warns := prepareAuth(d)
	for i, w := range warns {
		m.warnEvery(fmt.Sprintf("auth%d", i), "chrony: "+w)
	}
	if d.LeapTZ != "" && !leapTZExists(d.LeapTZ) {
		m.warnEvery("leaptz", "chrony: the leap-second table "+d.LeapTZ+" is not in "+zoneinfoDir+" on this node (install tzdata), so it is left out")
	}
	body, err := chronyConfBodyAuth(d, muted, af)
	if err != nil {
		return err
	}
	changed, err := writeIfChanged(chronyConfDir, "ntpdir.conf", body)
	if err != nil {
		return fmt.Errorf("chrony clients: %w", err)
	}
	m.mu.Lock()
	m.confBody = body
	first := !m.allowed
	m.mu.Unlock()
	if !changed && !first {
		return nil
	}
	if err := allowLiveMuted(d, muted); err != nil {
		// chrony is not running: it reads the file when it starts
		m.warnEvery("allow", "chrony: could not apply the allowed clients now ("+err.Error()+"); chrony reads them when it starts")
		return nil
	}
	m.mu.Lock()
	m.allowed = true
	m.mu.Unlock()
	if changed {
		infof("chrony: allowed clients applied without a restart")
	}
	return nil
}

// setServing says whether any server is in service.  With none, chrony is told to answer nobody (the gateway is red: clients
// are not to get a time from a source that is gone), and the allowed clients come back as soon as one is.  Reports a change.
func (m *chronyMgr) setServing(serve bool, d NTPConfig) bool {
	m.mu.Lock()
	if m.muted == !serve {
		m.mu.Unlock()
		return false
	}
	m.muted = !serve
	m.mu.Unlock()
	if serve {
		infof("chrony: a server is in service again; answering clients")
	} else {
		warnf("chrony: no server is in service; not answering clients until one is")
	}
	_ = m.applyClients(d)
	return true
}

// ── Reading chrony ───────────────────────────────────────────────────────────

func csvFields(line string) []string { return strings.Split(strings.TrimSpace(line), ",") }

func atof(s string) float64 { f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64); return f }

// parseTracking reads `chronyc -c tracking`.
func parseTracking(out []byte) (ChronyState, error) {
	f := csvFields(firstLine(string(out)))
	if len(f) < 14 {
		return ChronyState{}, errors.New("unexpected answer from chronyc tracking")
	}
	st := ChronyState{Running: true, Leap: f[13], At: time.Now().Unix()}
	st.Stratum, _ = strconv.Atoi(f[2])
	st.Ref = f[1]
	if st.Ref == "" {
		st.Ref = f[0]
	}
	st.OffsetMS = atof(f[4]) * 1000
	st.RootDelay = atof(f[10]) * 1000
	st.RootDisp = atof(f[11]) * 1000
	st.Synced = f[13] != "Not synchronised" && st.Stratum > 0 && st.Stratum < 16
	return st, nil
}

// chronySource is one line of `chronyc -n -c sources`.
type chronySource struct {
	Mode  string // ^ server, = peer, # local clock
	State string // * selected, + combined, - not combined, ? unreachable, x falseticker, ~ too variable
	Name  string
	Reach int // octal reachability register as a number of recent good replies (0-8)
}

func parseSources(out []byte) []chronySource {
	var res []chronySource
	for _, l := range strings.Split(string(out), "\n") {
		f := csvFields(l)
		if len(f) < 7 || len(f[0]) != 1 {
			continue
		}
		reach, _ := strconv.ParseUint(f[5], 8, 16)
		n := 0
		for r := reach; r > 0; r >>= 1 {
			n += int(r & 1)
		}
		res = append(res, chronySource{Mode: f[0], State: f[1], Name: f[2], Reach: n})
	}
	return res
}

// readState asks chrony how it is doing and remembers the answer.  Tracking and the sources come from one chronyc
// run (`-m` takes several commands; `sources -n` keeps the sources numeric as before, while tracking still shows
// the reference by name): the daemon looks every two seconds, and each run is a fork and an exec.  Should the
// combined run fail, the two are asked for one at a time as they used to be, so a chrony that answers one and not
// the other is read as before.
func (m *chronyMgr) readState() ChronyState {
	out, err := chronyc("-c", "-m", "tracking", "sources -n")
	var so []byte
	haveSources := err == nil
	if haveSources {
		so = out
	} else {
		out, err = chronyc("-c", "tracking")
	}
	st := ChronyState{}
	if err == nil {
		st, err = parseTracking(out)
	}
	if err != nil {
		st = ChronyState{Err: err.Error(), At: time.Now().Unix()}
	} else {
		if !haveSources {
			so, err = chronyc("-n", "-c", "sources")
			haveSources = err == nil
		}
		if haveSources {
			for _, s := range parseSources(so) {
				st.Sources = append(st.Sources, ChronySrc{Name: s.Name, State: s.State, Reach: s.Reach})
			}
		}
		m.mu.Lock()
		wantAuth := len(m.auth) > 0
		m.mu.Unlock()
		if wantAuth { // only when a server is set to be authenticated
			if ao, err := chronyc("-n", "-c", "authdata"); err == nil {
				st.Auth = parseAuthdata(ao)
			}
		}
	}
	m.mu.Lock()
	m.state = st
	m.mu.Unlock()
	return st
}

// State is the last reading.
func (m *chronyMgr) State() ChronyState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// chronyServing says whether chrony is up and keeping time (replaceable in tests): it answers clients while it is.
var chronyServingFn = func() bool { s := chrony.State(); return s.Running && s.Synced && !chrony.tooFar(s) }

// setOffsetLimit sets how far the clock may be off (ms; 0 = no limit) and still serve.
func (m *chronyMgr) setOffsetLimit(ms int) {
	m.mu.Lock()
	m.offLimit = ms
	m.mu.Unlock()
}

// tooFar says whether the clock is further from what chrony measures than the limit.  Once over, it takes a reading
// within 80% of the limit to be trusted again, so a clock at the edge does not flap.
func (m *chronyMgr) tooFar(s ChronyState) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.offLimit <= 0 || !s.Running || !s.Synced {
		m.offOver = false
		return false
	}
	off := math.Abs(s.OffsetMS)
	if m.offOver {
		m.offOver = off > 0.8*float64(m.offLimit)
	} else {
		m.offOver = off > float64(m.offLimit)
	}
	return m.offOver
}

// ServerStats is chrony's own count of the NTP packets it has handled.
type ServerStats struct {
	Received uint64 `json:"received"`
	Dropped  uint64 `json:"dropped"`
	Err      string `json:"error,omitempty"`
}

func readServerStats() ServerStats {
	out, err := chronyc("-c", "serverstats")
	if err != nil {
		return ServerStats{Err: err.Error()}
	}
	f := csvFields(firstLine(string(out)))
	if len(f) < 2 {
		return ServerStats{Err: "unexpected answer from chronyc serverstats"}
	}
	r, _ := strconv.ParseUint(f[0], 10, 64)
	d, _ := strconv.ParseUint(f[1], 10, 64)
	return ServerStats{Received: r, Dropped: d}
}

// chronyClient is one line of `chronyc -c clients`: a client chrony has answered, with its totals since chrony started.
type chronyClient struct {
	Addr    string
	Packets uint64
	Drops   uint64
}

func parseClients(out []byte) []chronyClient {
	var res []chronyClient
	for _, l := range strings.Split(string(out), "\n") {
		f := csvFields(l)
		if len(f) < 3 || f[0] == "" || strings.EqualFold(f[0], "Hostname") {
			continue
		}
		p, e1 := strconv.ParseUint(f[1], 10, 64)
		d, e2 := strconv.ParseUint(f[2], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		res = append(res, chronyClient{Addr: f[0], Packets: p, Drops: d})
	}
	return res
}

func readClients() ([]chronyClient, error) {
	out, err := chronyc("-n", "-c", "clients")
	if err != nil {
		return nil, err
	}
	return parseClients(out), nil
}

// qsServerName is what the statistics call the thing that answered: this node, by its host name (chrony answers on every
// node, so the name is what tells the nodes apart in Top servers, and the cluster view adds up the same name).  A node
// with no host name falls back to "chrony".
func qsServerName() string {
	if h := strings.TrimSpace(hostCurrent()); h != "" {
		return h
	}
	return "chrony"
}

// sampleClients folds what chrony reports per client into the statistics: the requests each client has made since the
// last look.  The first look only learns the totals (chrony has been counting since before ntpdir started).
func (m *chronyMgr) sampleClients(rec *QStats) {
	cl, err := readClients()
	if err != nil {
		return
	}
	m.mu.Lock()
	first := m.seen == nil
	prev := m.seen
	m.seen = make(map[string]chronyClient, len(cl))
	for _, c := range cl {
		m.seen[c.Addr] = c
	}
	m.mu.Unlock()
	if first {
		return
	}
	node := qsServerName()
	for _, c := range cl {
		ip, err := netip.ParseAddr(c.Addr)
		if err != nil {
			continue
		}
		dp, dd := c.Packets, c.Drops
		if p, ok := prev[c.Addr]; ok {
			if c.Packets >= p.Packets {
				dp -= p.Packets
			}
			if c.Drops >= p.Drops {
				dd -= p.Drops
			}
		}
		if dd > dp {
			dd = dp
		}
		rec.RecordN(ip.Unmap(), node, 0, outAnswered, uint32(min(dp-dd, 1<<30)))
		rec.RecordN(ip.Unmap(), node, 0, outRefused, uint32(min(dd, 1<<30)))
	}
}

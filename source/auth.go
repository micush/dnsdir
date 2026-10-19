package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Authentication and leap seconds for chrony (Configure ▸ NTP ▸ Security and Leap seconds).
//
//	keys            symmetric keys, one per line as chrony's keyfile has them: "ID HASH KEY".  Written to a keyfile chrony reads
//	                (`keyfile`); a client that signs its request with one of them gets a signed answer.
//	server_auth     how chrony reaches an upstream server: "ntp.example.com nts" (Network Time Security) or "10.0.0.5 key 7".
//	nts_server      chrony also serves NTS to clients (NTS-KE on TCP 4460) with this node's web GUI certificate.
//	leap_tz         the tz database leap-second table chrony reads (`leapsectz`, normally right/UTC)
//	leap_mode       how the clock handles a leap second (`leapsecmode`): system (default), step, slew, ignore
//	leap_smear      serve time smeared across a leap second (`smoothtime 400 0.001 leaponly`)
//
// All of it is shared by the cluster and goes into the file chrony reads from its confdir (chronysrc.go); chrony reads it only
// at start, so a change rolls a chrony restart through the nodes, one at a time, like a new port does.  The key file and the
// NTS certificate copy are written to chronyAuthDir, readable by root and chrony's group only.

const maxNTPKeys = 64

var (
	chronyAuthDir = envOr("NTPDIR_CHRONY_AUTHDIR", "/etc/chrony/ntpdir.auth.d")
	zoneinfoDir   = envOr("NTPDIR_ZONEINFO", "/usr/share/zoneinfo")
	// ntsCertSource says where the certificate and key of the web GUI are (set when the manager exists).
	ntsCertSource = func() (cert, key string) { return "", "" }
	// chronyHasNTS says whether the installed chronyd was built with NTS (replaced in tests).
	chronyHasNTS = chronyBuiltWithNTS
	leapTZRe     = regexp.MustCompile(`^[A-Za-z0-9_+\-]+(/[A-Za-z0-9_+\-]+)*$`)
	keyHashes    = map[string]bool{"MD5": true, "SHA1": true, "SHA256": true, "SHA384": true, "SHA512": true,
		"SHA3-224": true, "SHA3-256": true, "SHA3-384": true, "SHA3-512": true, "RMD160": true}
)

var (
	ntsOnce sync.Once
	ntsOK   = true
)

// chronyBuiltWithNTS reads `chronyd -v`; when it cannot be asked, NTS is assumed to be there.
func chronyBuiltWithNTS() bool {
	ntsOnce.Do(func() {
		for _, bin := range []string{envOr("NTPDIR_CHRONYD", "chronyd"), "/usr/sbin/chronyd"} {
			out, err := exec.Command(bin, "-v").CombinedOutput()
			if err != nil && len(out) == 0 {
				continue
			}
			s := string(out)
			switch {
			case strings.Contains(s, "-NTS"):
				ntsOK = false
			case strings.Contains(s, "+NTS"):
				ntsOK = true
			}
			return
		}
	})
	return ntsOK
}

// validateAuth checks the keys, the per-server authentication and the leap-second settings, and tidies them in place.
func (d *NTPConfig) validateAuth() error {
	// keys
	ids := map[uint32]bool{}
	var keys []string
	for _, l := range d.Keys {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return fmt.Errorf("ntp: keys: a key is written as ID HASH KEY (for example 7 SHA256 HEX:00ff…), not %q", "…")
		}
		id, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil || id < 1 {
			return fmt.Errorf("ntp: keys: the key number %q must be a whole number from 1 to 4294967295", f[0])
		}
		if ids[uint32(id)] {
			return fmt.Errorf("ntp: keys: key %d is listed twice", id)
		}
		hash := strings.ToUpper(f[1])
		if !keyHashes[hash] {
			return fmt.Errorf("ntp: keys: key %d: hash %q is not one of MD5, SHA1, SHA256, SHA384, SHA512, SHA3-224, SHA3-256, SHA3-384, SHA3-512, RMD160", id, f[1])
		}
		secret := f[2]
		switch {
		case strings.HasPrefix(secret, "HEX:"):
			h := secret[4:]
			if _, err := hex.DecodeString(h); err != nil || len(h) < 2 || len(h) > 256 {
				return fmt.Errorf("ntp: keys: key %d: HEX: needs an even number of hex digits (up to 256)", id)
			}
		default:
			s := strings.TrimPrefix(secret, "ASCII:")
			if len(s) < 1 || len(s) > 64 {
				return fmt.Errorf("ntp: keys: key %d: the key is 1 to 64 characters (or HEX: and hex digits)", id)
			}
			for _, r := range s {
				if r <= ' ' || r > '~' || r == '#' {
					return fmt.Errorf("ntp: keys: key %d: the key has printable characters only (no #); use HEX: for anything else", id)
				}
			}
		}
		ids[uint32(id)] = true
		keys = append(keys, fmt.Sprintf("%d %s %s", id, hash, secret))
	}
	if len(keys) > maxNTPKeys {
		return fmt.Errorf("ntp: keys: at most %d keys", maxNTPKeys)
	}
	d.Keys = keys
	// per-server authentication
	auth, err := parseServerAuth(d.ServerAuth, ids)
	if err != nil {
		return err
	}
	var lines []string
	for a, opt := range auth {
		lines = append(lines, a+opt)
	}
	sort.Strings(lines)
	d.ServerAuth = lines
	// leap seconds
	switch d.LeapMode {
	case "", "system":
		d.LeapMode = ""
	case "step", "slew", "ignore":
	default:
		return fmt.Errorf("ntp: leap_mode %q must be system, step, slew or ignore", d.LeapMode)
	}
	d.LeapTZ = strings.TrimSpace(d.LeapTZ)
	if d.LeapTZ != "" && (len(d.LeapTZ) > 64 || !leapTZRe.MatchString(d.LeapTZ)) {
		return fmt.Errorf("ntp: leap_tz %q is not a time zone name such as right/UTC", d.LeapTZ)
	}
	return nil
}

// parseServerAuth reads "ntp.example.com nts" and "10.0.0.5 key 7" lines.  The result maps the server (as normalizeServer
// writes it) to the options for its chrony line, " nts" or " key 7".  ids are the keys that exist (nil: not checked).
func parseServerAuth(lines []string, ids map[uint32]bool) (map[string]string, error) {
	out := map[string]string{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		bad := fmt.Errorf("ntp: server_auth: %q must be a server and then nts, or key and a key number", l)
		if len(f) < 2 {
			return nil, bad
		}
		addr, err := normalizeServer(f[0])
		if err != nil {
			return nil, fmt.Errorf("ntp: server_auth: %w", err)
		}
		var opt string
		switch strings.ToLower(f[1]) {
		case "nts":
			if len(f) != 2 {
				return nil, bad
			}
			opt = " nts"
		case "key":
			if len(f) != 3 {
				return nil, bad
			}
			n, err := strconv.ParseUint(f[2], 10, 32)
			if err != nil || n < 1 {
				return nil, bad
			}
			if ids != nil && !ids[uint32(n)] {
				return nil, fmt.Errorf("ntp: server_auth: %s uses key %d, which is not in the list of keys", f[0], n)
			}
			opt = " key " + strconv.FormatUint(n, 10)
		default:
			return nil, bad
		}
		if _, dup := out[addr]; dup {
			return nil, fmt.Errorf("ntp: server_auth: %s is listed twice", f[0])
		}
		out[addr] = opt
	}
	return out, nil
}

// authFiles is what prepareAuth put on disk for chrony.
type authFiles struct {
	keyfile string // the key file, or ""
	ntsCert string // the NTS server certificate and key, or ""
	ntsKey  string
	sum     string // changes whenever anything chrony reads at start from these files or from server_auth changes
}

var chronyGIDOnce sync.Once
var chronyGID = -1

// chronyGroup finds the group chrony runs as (_chrony on Debian and Ubuntu, chrony elsewhere).
func chronyGroupID() int {
	chronyGIDOnce.Do(func() {
		for _, n := range []string{"_chrony", "chrony"} {
			if g, err := user.LookupGroup(n); err == nil {
				if id, err := strconv.Atoi(g.Gid); err == nil {
					chronyGID = id
					return
				}
			}
		}
	})
	return chronyGID
}

// writeSecretFile writes a file only root and chrony's group may read, unless it already has this content.
func writeSecretFile(path string, content []byte) error {
	if old, err := os.ReadFile(path); err == nil && string(old) == string(content) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if gid := chronyGroupID(); gid >= 0 {
		_ = os.Chown(filepath.Dir(path), 0, gid)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o640); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o640)
	if gid := chronyGroupID(); gid >= 0 {
		_ = os.Chown(tmp, 0, gid)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// prepareAuth writes the key file and the NTS certificate copy for the settings and says where they are.  A problem (no
// certificate, chrony without NTS) leaves that part out and is returned as a message.
func prepareAuth(d NTPConfig) (authFiles, []string) {
	var af authFiles
	var warns []string
	h := sha256.New()
	keyPath := filepath.Join(chronyAuthDir, "ntpdir.keys")
	if len(d.Keys) > 0 {
		content := chronyHeader + strings.Join(d.Keys, "\n") + "\n"
		if err := writeSecretFile(keyPath, []byte(content)); err != nil {
			warns = append(warns, "chrony keys: "+err.Error())
		} else {
			af.keyfile = keyPath
			h.Write([]byte(content))
		}
	} else {
		_ = os.Remove(keyPath)
	}
	crtPath, keyOut := filepath.Join(chronyAuthDir, "nts.crt"), filepath.Join(chronyAuthDir, "nts.key")
	wantNTS := d.NTSServer || len(authServersNTS(d)) > 0
	if wantNTS && !chronyHasNTS() {
		warns = append(warns, "NTS is set but this chrony was built without NTS: install a chrony with NTS (4.0 or newer, built with gnutls); the NTS settings are ignored here")
		wantNTS = false
	}
	if d.NTSServer && wantNTS {
		cf, kf := ntsCertSource()
		cb, err1 := os.ReadFile(cf)
		kb, err2 := os.ReadFile(kf)
		switch {
		case cf == "" || kf == "" || err1 != nil || err2 != nil:
			warns = append(warns, "NTS server: the web GUI certificate could not be read, so NTS is not served yet")
		default:
			if err := writeSecretFile(crtPath, cb); err != nil {
				warns = append(warns, "NTS certificate: "+err.Error())
			} else if err := writeSecretFile(keyOut, kb); err != nil {
				warns = append(warns, "NTS key: "+err.Error())
			} else {
				af.ntsCert, af.ntsKey = crtPath, keyOut
				h.Write(cb)
				h.Write(kb)
			}
		}
	}
	if af.ntsCert == "" {
		_ = os.Remove(crtPath)
		_ = os.Remove(keyOut)
	}
	if wantNTS || len(d.ServerAuth) > 0 || af.keyfile != "" {
		h.Write([]byte("|" + strings.Join(d.ServerAuth, "\n")))
		af.sum = hex.EncodeToString(h.Sum(nil))[:16]
	}
	return af, warns
}

// authServersNTS lists the servers set to use NTS.
func authServersNTS(d NTPConfig) []string {
	var out []string
	for _, l := range d.ServerAuth {
		if strings.HasSuffix(l, " nts") {
			out = append(out, l)
		}
	}
	return out
}

// leapTZExists says whether the leap-second table is on this node (chrony will not start with a name it cannot find).
func leapTZExists(tz string) bool {
	st, err := os.Stat(filepath.Join(zoneinfoDir, tz))
	return err == nil && !st.IsDir()
}

// authConf is the part of chrony's client file about keys, NTS and leap seconds.
func authConf(d NTPConfig, af authFiles) string {
	var b strings.Builder
	if af.keyfile != "" {
		fmt.Fprintf(&b, "keyfile %s\n", af.keyfile)
	}
	if af.ntsCert != "" {
		fmt.Fprintf(&b, "ntsservercert %s\nntsserverkey %s\n", af.ntsCert, af.ntsKey)
	}
	if d.LeapTZ != "" && leapTZExists(d.LeapTZ) {
		fmt.Fprintf(&b, "leapsectz %s\n", d.LeapTZ)
	}
	if d.LeapMode != "" {
		fmt.Fprintf(&b, "leapsecmode %s\n", d.LeapMode)
	}
	if d.LeapSmear {
		b.WriteString("smoothtime 400 0.001 leaponly\n")
	}
	if af.sum != "" {
		fmt.Fprintf(&b, "# authsum %s\n", af.sum)
	}
	return b.String()
}

// authSumOf is the "# authsum" line of a client file or restart key, or "".
func authSumOf(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "# authsum ") {
			return l
		}
	}
	return ""
}

// ChronyAuth is one line of `chronyc authdata`: how a source is authenticated.
type ChronyAuth struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"` // "nts", "key" or "none"
	KeyID    int    `json:"key_id,omitempty"`
	Attempts int    `json:"attempts"` // NTS key establishments tried since the last success
	NAK      int    `json:"nak"`
	Cookies  int    `json:"cookies"` // NTS cookies in hand; -1 when chrony did not say
}

// parseAuthdata reads `chronyc -n -c authdata`: name, mode, key id, key type, key length, seconds since the last key
// establishment, attempts, NAKs, cookies, cookie length.
func parseAuthdata(out []byte) []ChronyAuth {
	var res []ChronyAuth
	for _, l := range strings.Split(string(out), "\n") {
		f := csvFields(l)
		if len(f) < 3 || f[0] == "" {
			continue
		}
		a := ChronyAuth{Name: f[0], Cookies: -1}
		switch m := strings.ToUpper(f[1]); {
		case strings.Contains(m, "NTS"):
			a.Mode = "nts"
		case m == "SK" || strings.Contains(m, "KEY") || strings.Contains(m, "SYM"):
			a.Mode = "key"
		default:
			a.Mode = "none"
		}
		a.KeyID, _ = strconv.Atoi(f[2])
		if len(f) >= 9 {
			a.Attempts, _ = strconv.Atoi(f[6])
			a.NAK, _ = strconv.Atoi(f[7])
			a.Cookies, _ = strconv.Atoi(f[8])
		}
		res = append(res, a)
	}
	return res
}

// AuthStat is what the server table says about a server that is set to be authenticated.
type AuthStat struct {
	Mode   string `json:"mode"`   // "nts" or "key"
	Status string `json:"status"` // ok, pending (chrony has not started with the setting yet) or failing
	Detail string `json:"detail"`
}

// authStatus says how the authentication of a server is going, or nil when it is not set to be authenticated.  chrony says
// it does not use authentication for a source with mode none, so a setting chrony did not take is told apart from one that
// does not work.
func (m *chronyMgr) authStatus(addr string, st ChronyState) *AuthStat {
	m.mu.Lock()
	opt, ok := "", false
	if n, err := normalizeServer(addr); err == nil {
		opt, ok = m.auth[n]
	}
	m.mu.Unlock()
	if !ok {
		return nil
	}
	mode := "nts"
	if strings.HasPrefix(strings.TrimSpace(opt), "key") {
		mode = "key"
	}
	label := map[string]string{"nts": "NTS", "key": "the key" + strings.TrimPrefix(strings.TrimSpace(opt), "key")}[mode]
	if !m.authApplied() {
		return &AuthStat{Mode: mode, Status: "pending", Detail: "waiting for chrony to restart with this setting; the server is not used until then"}
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	var a *ChronyAuth
	for i := range st.Auth {
		if strings.EqualFold(st.Auth[i].Name, host) {
			a = &st.Auth[i]
		}
	}
	var src *ChronySrc
	for i := range st.Sources {
		if strings.EqualFold(st.Sources[i].Name, host) {
			src = &st.Sources[i]
		}
	}
	switch {
	case a == nil && src == nil:
		return &AuthStat{Mode: mode, Status: "pending", Detail: "not one of chrony's sources yet"}
	case a == nil || a.Mode != mode:
		return &AuthStat{Mode: mode, Status: "failing", Detail: "chrony uses this server without " + label}
	case mode == "nts" && a.Cookies == 0:
		d := "no NTS cookies yet: key establishment with the server has not succeeded"
		if a.Attempts > 0 {
			d += fmt.Sprintf(" (%d attempt(s))", a.Attempts)
		}
		return &AuthStat{Mode: mode, Status: "failing", Detail: d}
	case mode == "key" && (src == nil || src.Reach == 0):
		return &AuthStat{Mode: mode, Status: "failing", Detail: "the server does not answer with " + label + " (wrong key, or it does not have it)"}
	}
	d := "authenticated with " + label
	if mode == "nts" && a.Cookies > 0 {
		d += fmt.Sprintf(" (%d cookies)", a.Cookies)
	}
	return &AuthStat{Mode: mode, Status: "ok", Detail: d}
}

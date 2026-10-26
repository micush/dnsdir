package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// SNMP.  dnsdir runs net-snmp's snmpd on this node when, and only when, a community string is set (Configure ▸ SNMP):
//
//	communities  read-only community strings, any number of them; none = snmpd is switched off
//	location     what snmpd reports as sysLocation
//	contact      what snmpd reports as sysContact
//
// The communities and the contact are cluster settings (DNSConfig.SNMPCommunities/SNMPContact, replicated); the location is
// local to the node (DaemonConfig.SNMP) because it differs from node to node.  dnsdir owns
// /etc/snmp/snmpd.conf while it is in use: the file it writes starts with snmpHeader, an snmpd.conf that was there before
// is kept once as snmpd.conf.dnsdir-orig and put back when the communities are emptied.  An snmpd that dnsdir never took
// over (no header) is left alone when the communities are empty.

// SNMPConfig is the snmp block of the configuration.
type SNMPConfig struct {
	Communities []string `json:"communities,omitempty"`
	Location    string   `json:"location,omitempty"`
	Contact     string   `json:"contact,omitempty"`
	ACL         []string `json:"acl,omitempty"` // sources snmpd answers to; empty = nobody
}

const (
	maxSNMPCommunities   = 16
	maxSNMPCommunityLen  = 64
	maxSNMPTextLen       = 255
	snmpHeader           = "# Managed by dnsdir (Configure ▸ SNMP). Changes made here are overwritten; change them there.\n"
	snmpUnit             = "snmpd"
	snmpBackupSuffix     = ".dnsdir-orig"
	snmpRestartThrottle  = 5 * time.Second
	snmpNotInstalledWarn = "snmpd is not installed, so SNMP cannot answer: install the snmpd package (net-snmp on Fedora/RHEL/Arch) or run the installer again"
)

var (
	snmpConfPath = "/etc/snmp/snmpd.conf"
	// snmpRun runs systemctl; replaced in tests.
	snmpRun = func(args ...string) ([]byte, error) {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		return out, err
	}
	snmpInstalled = func() bool {
		if _, err := exec.LookPath("snmpd"); err == nil {
			return true
		}
		_, err := os.Stat("/usr/sbin/snmpd")
		return err == nil
	}
)

// aclHostName says whether s is written like a fully qualified host name (letters, digits, "-" and "_", at least two labels).
func aclHostName(s string) bool {
	if len(s) > 253 || strings.Count(s, ".") < 1 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// aclLookup turns a host name into its addresses; replaced in tests.
var aclLookup = func(name string) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	return ips
}

// expandACL is the networks an access list stands for: addresses and networks as written, a host name as the addresses it
// has now (none when it cannot be looked up).  A list that was written but expands to nothing allows nobody.
func expandACL(list []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range list {
		if nets, err := parseClientNets([]string{s}); err == nil {
			out = append(out, nets...)
			continue
		}
		for _, a := range aclLookup(s) {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// normACL checks a list of sources ("10.1.1.50", "10.1.0.0/24", "2001:db8::/32") and writes each one the same way:
// a single address without a length, a network with it.  At most 64, no repeats.
func normACL(what string, list []string) ([]string, error) {
	if len(list) > 64 {
		return nil, fmt.Errorf("%s: at most 64 entries in the access list", what)
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var t string
		if nets, err := parseClientNets([]string{s}); err == nil {
			p := nets[0]
			t = p.String()
			if p.Bits() == p.Addr().BitLen() {
				t = p.Addr().String()
			}
		} else if n := strings.ToLower(strings.TrimSuffix(s, ".")); aclHostName(n) {
			t = n
		} else {
			return nil, fmt.Errorf("%s: access list: %q is not an address, a network like 10.0.0.0/8 or a host name like host.example.com", what, s)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func (c SNMPConfig) enabled() bool { return len(c.Communities) > 0 }

func (c SNMPConfig) empty() bool {
	return len(c.Communities) == 0 && c.Location == "" && c.Contact == ""
}

// Validate checks the settings and tidies them in place: surrounding blanks go, repeated communities are dropped.
func (c *SNMPConfig) Validate() error {
	seen := map[string]bool{}
	var out []string
	for _, s := range c.Communities {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		if len(s) > maxSNMPCommunityLen {
			return fmt.Errorf("snmp: a community string is at most %d characters", maxSNMPCommunityLen)
		}
		for _, r := range s {
			if r <= ' ' || r > '~' || r == '#' || r == '"' || r == '\'' || r == '\\' {
				return fmt.Errorf("snmp: a community string has letters, digits and punctuation only (no spaces, quotes, backslash or #, no accents)")
			}
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) > maxSNMPCommunities {
		return fmt.Errorf("snmp: at most %d community strings", maxSNMPCommunities)
	}
	c.Communities = out
	acl, err := normACL("snmp", c.ACL)
	if err != nil {
		return err
	}
	c.ACL = acl
	for _, f := range []struct {
		name string
		v    *string
	}{{"location", &c.Location}, {"contact", &c.Contact}} {
		*f.v = strings.TrimSpace(*f.v)
		if len(*f.v) > maxSNMPTextLen {
			return fmt.Errorf("snmp: the %s is at most %d characters", f.name, maxSNMPTextLen)
		}
		for _, r := range *f.v {
			if r < ' ' || r == 0x7f {
				return fmt.Errorf("snmp: the %s must be one line of text", f.name)
			}
		}
	}
	return nil
}

// snmpdConfBody is the snmpd.conf for the settings: read-only access for each community over IPv4 and IPv6, on every address.
func snmpdConfBody(c SNMPConfig) string {
	var b strings.Builder
	b.WriteString(snmpHeader)
	b.WriteString("agentaddress udp:161,udp6:161\n")
	for _, s := range c.Communities {
		for _, p := range expandACL(c.ACL) { // only from these sources: the IPv4 ones for rocommunity, the IPv6 ones for rocommunity6
			src := p.String()
			if p.Bits() == p.Addr().BitLen() {
				src = p.Addr().String()
			}
			if p.Addr().Is6() {
				fmt.Fprintf(&b, "rocommunity6 %s %s\n", s, src)
			} else {
				fmt.Fprintf(&b, "rocommunity %s %s\n", s, src)
			}
		}
	}
	if c.Location != "" {
		fmt.Fprintf(&b, "sysLocation %s\n", c.Location)
	}
	if c.Contact != "" {
		fmt.Fprintf(&b, "sysContact %s\n", c.Contact)
	}
	return b.String()
}

// snmpRefresh writes snmpd.conf again every few minutes while the access list has a host name in it, so a name that
// gets another address is followed.  It does nothing otherwise.
func snmpRefresh(ctx context.Context, sup *Supervisor) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sup.mu.Lock()
			var c SNMPConfig
			if sup.dc != nil {
				c = sup.dc.snmpSettings()
			}
			sup.mu.Unlock()
			for _, s := range c.ACL {
				if _, err := netip.ParseAddr(s); err != nil && !strings.Contains(s, "/") {
					applySNMP(c)
					break
				}
			}
		}
	}
}

var snmpMu sync.Mutex
var snmpWarned time.Time

// applySNMP makes snmpd match the settings: written, enabled and (re)started when a community is set; switched off, and the
// file it replaced put back, when the communities are emptied after dnsdir had taken it over.  It is cheap when nothing
// changed, so it runs at start and after every configuration change.
func applySNMP(cfg SNMPConfig) {
	snmpMu.Lock()
	defer snmpMu.Unlock()
	curB, readErr := os.ReadFile(snmpConfPath)
	cur := string(curB)
	managed := strings.HasPrefix(cur, snmpHeader)
	if !cfg.enabled() {
		if !managed {
			return // never taken over: whatever is there is not ours to stop
		}
		_, _ = snmpRun("disable", "--now", snmpUnit)
		if _, err := os.Stat(snmpConfPath + snmpBackupSuffix); err == nil {
			if err := os.Rename(snmpConfPath+snmpBackupSuffix, snmpConfPath); err != nil {
				warnf("snmp: could not put back the original %s: %v", snmpConfPath, err)
			}
		} else {
			_ = os.Remove(snmpConfPath)
		}
		infof("snmp: no community string is set — snmpd is switched off")
		return
	}
	if !snmpInstalled() {
		if time.Since(snmpWarned) > time.Hour {
			snmpWarned = time.Now()
			warnf("snmp: %s", snmpNotInstalledWarn)
		}
		return
	}
	body := snmpdConfBody(cfg)
	changed := cur != body
	if changed {
		if readErr == nil && !managed {
			if _, err := os.Stat(snmpConfPath + snmpBackupSuffix); err != nil {
				if err := os.WriteFile(snmpConfPath+snmpBackupSuffix, curB, 0o600); err != nil {
					warnf("snmp: could not keep a copy of %s: %v", snmpConfPath, err)
				}
			}
		}
		if err := os.MkdirAll(snmpConfPath[:strings.LastIndex(snmpConfPath, "/")], 0o755); err != nil {
			warnf("snmp: %v", err)
			return
		}
		tmp := snmpConfPath + ".dnsdir.tmp"
		if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
			warnf("snmp: could not write %s: %v", snmpConfPath, err)
			return
		}
		if err := os.Rename(tmp, snmpConfPath); err != nil {
			_ = os.Remove(tmp)
			warnf("snmp: could not write %s: %v", snmpConfPath, err)
			return
		}
	}
	if out, err := snmpRun("enable", snmpUnit); err != nil {
		warnf("snmp: could not enable snmpd: %v %s", err, strings.TrimSpace(string(out)))
	}
	verb := "start" // a running snmpd with the same file keeps running
	if changed {
		verb = "restart"
	}
	if verb == "start" {
		if _, err := snmpRun("is-active", "--quiet", snmpUnit); err == nil {
			return
		}
	}
	if out, err := snmpRun(verb, snmpUnit); err != nil {
		warnf("snmp: could not %s snmpd: %v %s", verb, err, strings.TrimSpace(string(out)))
		return
	}
	if changed {
		infof("snmp: snmpd configured with %d community string(s) and %s", len(cfg.Communities), map[bool]string{true: "restarted", false: "started"}[true])
	}
}

// snmpStatus is what Configure ▸ SNMP shows under the form.
func snmpStatus(cfg SNMPConfig) map[string]any {
	st := map[string]any{"enabled": cfg.enabled(), "installed": snmpInstalled(), "running": false}
	if _, err := snmpRun("is-active", "--quiet", snmpUnit); err == nil {
		st["running"] = true
	}
	cur, _ := os.ReadFile(snmpConfPath)
	st["managed"] = strings.HasPrefix(string(cur), snmpHeader)
	return st
}

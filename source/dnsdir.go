package main

import (
	"encoding/json"
	"os"
	"sort"
)

// The Anyname DNS Director (dnsdir) can live on the same host.  The two products cannot share BGP (each owns
// /etc/frr/frr.conf, see bgp.go), so while dnsdir is installed ntpdir does no BGP of its own; instead a gateway may
// answer NTP on chosen anycast addresses that dnsdir holds on lo and announces (GroupConfig.DNSDirVIPs).  ntpdir only
// listens on them: it never adds or removes them on lo and never announces them.

// dnsdirMarkers are what an installed dnsdir leaves behind (a variable for the tests).  The state directory is not
// one of them: it stays after an uninstall without --purge.
var dnsdirMarkers = []string{"/usr/local/sbin/dnsdir", "/usr/local/share/dnsdir", "/etc/systemd/system/dnsdir.service"}

// dnsdirConfPath is dnsdir's configuration, where its anycast addresses are listed (a variable for the tests).
var dnsdirConfPath = "/var/lib/dnsdir/dnsdir.conf"

// dnsdirPresent says whether dnsdir is installed on this host.
func dnsdirPresent() bool {
	for _, p := range dnsdirMarkers {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// dnsdirOffered lists the anycast addresses dnsdir is set up to announce (the extra_vips of its gateways), sorted.
// Nothing when dnsdir is not installed or its configuration cannot be read.
func dnsdirOffered() []string {
	out := []string{}
	if !dnsdirPresent() {
		return out
	}
	b, err := os.ReadFile(dnsdirConfPath)
	if err != nil {
		return out
	}
	var c struct {
		Groups []struct {
			ExtraVIPs []string `json:"extra_vips"`
		} `json:"groups"`
	}
	if json.Unmarshal(b, &c) != nil {
		return out
	}
	seen := map[string]bool{}
	for _, g := range c.Groups {
		for _, a := range g.ExtraVIPs {
			if n, err := normalizeAnycast(a); err == nil && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// DNSDirInfo is what the GUI needs to offer dnsdir's addresses.
type DNSDirInfo struct {
	Present bool     `json:"present"`
	Offered []string `json:"offered"`
}

func dnsdirInfo() DNSDirInfo { return DNSDirInfo{Present: dnsdirPresent(), Offered: dnsdirOffered()} }

// checkDNSDirAdded refuses a dnsdir address that was not on the gateway before unless dnsdir is installed here and
// announces it.  Addresses already in the configuration are not re-checked, so a config stays loadable (and its
// settings are kept) while dnsdir is away.
func checkDNSDirAdded(cur, next *DaemonConfig) error {
	had := map[string]bool{}
	for _, g := range cur.Groups {
		for _, a := range g.DNSDirVIPs {
			had[a] = true
		}
	}
	var offered map[string]bool
	for _, g := range next.Groups {
		for _, a := range g.DNSDirVIPs {
			if had[a] {
				continue
			}
			if !dnsdirPresent() {
				return errDNSDir("the Anyname DNS Director (dnsdir) is not installed on this host")
			}
			if offered == nil {
				offered = map[string]bool{}
				for _, o := range dnsdirOffered() {
					offered[o] = true
				}
			}
			if !offered[a] {
				return errDNSDir(a + " is not an anycast address of dnsdir")
			}
		}
	}
	return nil
}

type errDNSDir string

func (e errDNSDir) Error() string { return "dnsdir address: " + string(e) }

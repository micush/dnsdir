package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// tlsMigrateLog says once per run that tls_insecure was turned into per-server settings.
var tlsMigrateLog sync.Once

// Certificate checks of tls:// and https:// servers, one server at a time.
//
// By default the certificate a DNS-over-TLS or DNS-over-HTTPS server presents is checked as any TLS client does: a
// trusted chain, in date, for the host the server is written with.  A server given by IP address (tls://86.54.11.1)
// fails that check when its certificate names only the host ("doesn't contain any IP SANs"), so a server can instead be
// checked against a host name of its own (still connecting to the address written), or, as a last resort, not checked
// at all.  This replaced the pool-wide "tls_insecure" switch, which turned the check off for every server at once: on
// loading, a pool that had it on gives each of its tls:// and https:// servers "insecure" instead (migrateTLSInsecure).

// ServerTLS is how one tls:// or https:// server's certificate is checked; the zero value is the normal check.
type ServerTLS struct {
	// Name checks the certificate against this host name instead of the host in the server's address (and is the name
	// sent in the TLS handshake and, for https://, the Host of the request).
	Name string `json:"name,omitempty"`
	// Insecure accepts any certificate: the traffic is still encrypted, but the server is not authenticated.
	Insecure bool `json:"insecure,omitempty"`
}

// upTLS is what the exchange functions need to know about a server's certificate check.
type upTLS struct {
	name     string // check against this name ("" = the host of the address)
	insecure bool   // do not check
}

// tlsFor is the certificate check of server addr (as written in Servers or FallbackServers).
func (d *DNSConfig) tlsFor(addr string) upTLS {
	t := d.ServerTLS[addr]
	return upTLS{name: t.Name, insecure: t.Insecure}
}

// isTLSServer says whether a (normalised) server is spoken to over TLS: tls:// or https://.
func isTLSServer(addr string) bool {
	return strings.HasPrefix(addr, dotScheme) || strings.HasPrefix(addr, dohScheme)
}

// normServerTLS checks the entries of d.ServerTLS against the pool's servers (Servers and FallbackServers, already
// normalised): the keys are written the same way, an entry for a server that is not there (deleted, or renamed on the
// Topology page) or that is not tls:// or https:// is dropped, and an entry that says nothing is dropped too.
func (d *DNSConfig) normServerTLS() error {
	if len(d.ServerTLS) == 0 {
		d.ServerTLS = nil
		return nil
	}
	have := map[string]bool{}
	for _, s := range d.Servers {
		have[s] = true
	}
	for _, s := range d.FallbackServers {
		have[s] = true
	}
	out := map[string]ServerTLS{}
	for k, t := range d.ServerTLS {
		n, err := normalizeServer(k)
		if err != nil || !have[n] || !isTLSServer(n) {
			continue
		}
		t.Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(t.Name), "."))
		if t.Name != "" {
			if _, err := netip.ParseAddr(t.Name); err == nil || !validHostname(t.Name) {
				return fmt.Errorf("dns: server %s: the certificate name %q must be a host name (the name the certificate is for)", n, t.Name)
			}
			if t.Insecure {
				return fmt.Errorf("dns: server %s: either check its certificate against a name or do not check it, not both", n)
			}
		}
		if t.Name == "" && !t.Insecure {
			continue
		}
		out[n] = t
	}
	d.ServerTLS = out
	if len(out) == 0 {
		d.ServerTLS = nil
	}
	return nil
}

// uncheckAll gives every tls:// and https:// server of d (normal and fallback) that has no setting of its own "do not
// check the certificate".
func (d *DNSConfig) uncheckAll() {
	for _, list := range [][]string{d.Servers, d.FallbackServers} {
		for _, s := range list {
			n, err := normalizeServer(s)
			if err != nil || !isTLSServer(n) {
				continue
			}
			if _, ok := d.ServerTLS[n]; ok {
				continue
			}
			if d.ServerTLS == nil {
				d.ServerTLS = map[string]ServerTLS{}
			}
			d.ServerTLS[n] = ServerTLS{Insecure: true}
		}
	}
}

// migrateTLSInsecure turns the old pool-wide switch into per-server settings, so nothing that worked stops working: a pool
// with tls_insecure on, and every gateway's own pool while the shared one had it on (they followed it, v618 to v623),
// gives each of its tls:// and https:// servers "do not check".  The switch itself is then off and no longer written.
func migrateTLSInsecure(dc *DaemonConfig) (changed []string) {
	all := dc.DNS.TLSInsecure
	for i := range dc.Groups {
		g := &dc.Groups[i]
		if g.DNS != nil && (all || g.DNS.TLSInsecure) {
			g.DNS.uncheckAll()
			g.DNS.TLSInsecure = false
			changed = append(changed, fmt.Sprintf("gateway %d", g.GroupID))
		}
	}
	if all {
		dc.DNS.uncheckAll()
		dc.DNS.TLSInsecure = false
		changed = append(changed, "the shared servers")
	}
	if len(changed) > 0 {
		// once: the file keeps the old switch until the next save, and the configuration is read often
		tlsMigrateLog.Do(func() {
			infof("dns: tls_insecure (no certificate checks for the whole pool) was on for %s: each of their tls:// and https:// servers now has \"Don't check\" of its own instead; check them again one at a time on the Topology page (Edit server ▸ Certificate)", strings.Join(changed, ", "))
		})
	}
	return changed
}

// uncheckedServers lists the servers of d whose certificate is not checked, sorted (for the log and --show-dns).
func (d *DNSConfig) uncheckedServers() []string {
	var out []string
	for k, t := range d.ServerTLS {
		if t.Insecure {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// setServerCert sets how server addr of d (a normal or fallback server) has its certificate checked: "check", "none" or a
// host name (canvas edits, --canvas-set server|fallback ... --cert).
func setServerCert(d *DNSConfig, addr, how string) (string, error) {
	if !isTLSServer(addr) {
		return "", fmt.Errorf("%s is not a tls:// or https:// server: it has no certificate to check", addr)
	}
	how = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(how), "."))
	t := ServerTLS{}
	switch how {
	case "check", "default", "on":
	case "none", "off", "insecure", "no":
		t.Insecure = true
	default:
		if _, err := netip.ParseAddr(how); err == nil || !validHostname(how) {
			return "", fmt.Errorf("--cert: check, none, or the host name to check %s's certificate against", addr)
		}
		t.Name = how
	}
	if t == (ServerTLS{}) {
		delete(d.ServerTLS, addr)
		if len(d.ServerTLS) == 0 {
			d.ServerTLS = nil
		}
		return fmt.Sprintf("server %s: certificate checked (the normal check)", addr), nil
	}
	if d.ServerTLS == nil {
		d.ServerTLS = map[string]ServerTLS{}
	}
	d.ServerTLS[addr] = t
	if t.Insecure {
		return fmt.Sprintf("server %s: certificate NOT checked", addr), nil
	}
	return fmt.Sprintf("server %s: certificate checked against the name %s", addr, t.Name), nil
}

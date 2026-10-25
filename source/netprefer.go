package main

import (
	"context"
	"net"
	"net/http"
	"sort"
	"time"
)

// IPv4 before IPv6, for everything the daemon connects out to by name (upstream servers, the CA, block lists, releases,
// LDAP, syslog, whois, single sign-on, cluster peers).  A host whose IPv6 route is broken otherwise stalls on the IPv6
// address until the handshake times out.  IPv6 is still used when the target is an IPv6 address or has no IPv4 one.

// dialPrefer4 dials addr on network ("tcp" or "udp"), trying IPv4 first and then the network as given.
func dialPrefer4(ctx context.Context, d *net.Dialer, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "udp":
		if c, err := d.DialContext(ctx, network+"4", addr); err == nil {
			return c, nil
		} else if ctx.Err() != nil {
			return nil, err
		}
	}
	return d.DialContext(ctx, network, addr)
}

// ipv4FirstClient is an HTTP client for the downloads the daemon makes on its own: it dials IPv4 first and falls back
// to the other family, so a broken IPv6 route does not end in "TLS handshake timeout".
func ipv4FirstClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialPrefer4(ctx, d, network, addr)
		},
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
	}}
}

// ipv4First puts IPv4 addresses before IPv6 ones, keeping the order inside each family.
func ipv4First(ips []string) []string {
	out := append([]string(nil), ips...)
	is4 := func(s string) bool { a := net.ParseIP(s); return a != nil && a.To4() != nil }
	sort.SliceStable(out, func(i, j int) bool { return is4(out[i]) && !is4(out[j]) })
	return out
}

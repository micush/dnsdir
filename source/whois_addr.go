package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

const addrTimeout = 3 * time.Second

// whoisWithAddrs answers whois.get: the whois data of the name's registered domain, plus the first IPv4
// and IPv6 address found for the name itself.  A name with no whois record (an internal name, a
// registry that cannot be reached) still gets its addresses, with the reason in Note.
func whoisWithAddrs(name string) (*WhoisInfo, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" || len(name) > 255 {
		return nil, errors.New("no domain given")
	}
	if ip, err := netip.ParseAddr(name); err == nil {
		info, err := whois.LookupIP(ip) // an address: registry data of its block, no name to resolve
		if err != nil {
			return &WhoisInfo{Domain: ip.Unmap().String(), Kind: "ip", Note: err.Error()}, nil
		}
		return info, nil
	}
	type addrs struct{ v4, v6 string }
	ch := make(chan addrs, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), addrTimeout)
		defer cancel()
		var r addrs
		r.v4, r.v6 = systemAddrs(ctx, name, "", "")
		ch <- r
	}()
	info, err := whois.Lookup(name)
	var out WhoisInfo
	if err != nil {
		out = WhoisInfo{Domain: name, Note: err.Error()}
	} else {
		out = *info // the cached copy is shared: never changed
	}
	r := <-ch
	out.Name, out.IPv4, out.IPv6 = name, r.v4, r.v6
	return &out, nil
}

// systemAddrs fills in whichever of the two addresses is still empty from this machine's own resolver.
func systemAddrs(ctx context.Context, name, v4, v6 string) (string, string) {
	if v4 != "" && v6 != "" {
		return v4, v6
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return v4, v6
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() && v4 == "" {
			v4 = ip.String()
		} else if ip.Is6() && v6 == "" {
			v6 = ip.String()
		}
	}
	return v4, v6
}

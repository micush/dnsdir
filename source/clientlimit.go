package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The allowed-clients list and the client rate are written for chrony (chronysrc.go: allow, ratelimit).
//
//	allowed_clients  networks that may use the server; empty = everyone.
//	client_rate      requests per second one client may send; 0 = no limit.
//	client_burst     how many it may send at once before the rate applies; 0 = twice the rate, at least 10.
//	client_action    drop (default) or kod: what a client over its rate mostly gets (chrony's ratelimit leak).
//
// client_exempt and client_limits (a rate of its own for one client) are still read from older files and checked, but chrony
// has nothing like them, so they have no effect.

const (
	actDrop = "drop"
	actKoD  = "kod"
)

// limOverride is one client_limits line.
type limOverride struct {
	net         netip.Prefix
	rate, burst float64
}

// unmapPrefix turns ::ffff:a.b.c.d/N into a.b.c.d/(N-96) so it matches the unmapped client addresses.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p
}

// parseClientNets turns "10.0.0.0/8", "192.168.1.5" or "2001:db8::/32" into canonical prefixes.
func parseClientNets(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, unmapPrefix(p.Masked()))
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or a network like 10.0.0.0/8", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func effectiveBurst(rate, burst int) float64 {
	if burst > 0 {
		return float64(burst)
	}
	b := float64(rate) * 2
	if b < 10 {
		b = 10
	}
	return b
}

// parseClientLimits reads client_limits lines ("192.168.1.5 50", "10.2.0.0/16 200").
func parseClientLimits(list []string) ([]limOverride, error) {
	out := make([]limOverride, 0, len(list))
	for _, line := range list {
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("%q: write an address or network, then requests per second (192.168.1.5 50)", line)
		}
		nets, err := parseClientNets(f[:1])
		if err != nil {
			return nil, err
		}
		rate, err := strconv.Atoi(f[1])
		if err != nil || rate < 1 || rate > 10_000_000 {
			return nil, fmt.Errorf("%q: the rate must be 1-10000000 requests per second", line)
		}
		out = append(out, limOverride{net: nets[0], rate: float64(rate), burst: effectiveBurst(rate, 0)})
	}
	return out, nil
}

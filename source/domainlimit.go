package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rate limits per queried name (the dns block's "domain_limits", shared by every gateway): one line, "NAME RATE", caps
// the queries per second that ALL clients together may ask for the names it matches.  NAME is written like a source name
// of the policy table:
//
//	www.example.com    exactly that name
//	*.example.com      that name and every name below it
//	ad*.example.com    a pattern with * or ? inside its labels (nameglob.go)
//	*                  every name
//
// The lines are read from the top and the first that matches a query is the one that counts it.  Each line has one
// bucket for all the names it matches: *.example.com 100 is 100 queries per second for the whole zone, however many
// clients and names.  A query over the rate gets what a client over client_rate gets (client_action: drop, truncate or
// refused; over TCP, DoT and DoH always REFUSED).  The check runs before the cache, so cache hits count; the node itself
// (loopback) is never limited.  The counters are per node.

const (
	domainLimitsMax = 1000
	domLogInterval  = time.Minute
)

type domainRule struct {
	text     string // the pattern as written (lower case, no trailing dot)
	all      bool
	exact    string
	suffix   string // ".name" of a "*.name" line
	glob     *nameGlob
	rate     float64
	burst    float64
	mu       sync.Mutex
	tokens   float64
	last     time.Time
	limitedN uint64 // queries this line turned away (guarded by mu)
}

type domainLimits struct {
	rules  []*domainRule
	action string

	logMu   sync.Mutex
	lastLog time.Time
	pending int
	lastRow string
}

// parseDomainLimits reads domain_limits lines into rules (with full buckets); the error names the bad line.
func parseDomainLimits(list []string) ([]*domainRule, error) {
	if len(list) > domainLimitsMax {
		return nil, fmt.Errorf("at most %d lines", domainLimitsMax)
	}
	out := make([]*domainRule, 0, len(list))
	seen := map[string]bool{}
	for _, line := range list {
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("%q: write a name, then queries per second (*.example.com 100)", line)
		}
		rate, err := strconv.Atoi(f[1])
		if err != nil || rate < 1 || rate > 10_000_000 {
			return nil, fmt.Errorf("%q: the rate must be 1-10000000 queries per second", line)
		}
		pat := strings.ToLower(strings.TrimSuffix(f[0], "."))
		r := &domainRule{text: pat, rate: float64(rate), burst: effectiveBurst(rate, 0)}
		if g, is, err := parseGlob(pat); is {
			if err != nil {
				return nil, fmt.Errorf("%q: %w", line, err)
			}
			r.glob = g
		} else {
			exact, suffix, all, err := policyName(pat)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", line, err)
			}
			r.exact, r.suffix, r.all = exact, suffix, all
		}
		if seen[pat] {
			return nil, fmt.Errorf("%s is listed twice", pat)
		}
		seen[pat] = true
		r.tokens = r.burst
		out = append(out, r)
	}
	return out, nil
}

// newDomainLimits is nil when no line is configured, so the common case costs nothing.
func newDomainLimits(c DNSConfig) *domainLimits {
	if len(c.DomainLimits) == 0 {
		return nil
	}
	rules, _ := parseDomainLimits(c.DomainLimits) // validated when the config was loaded
	if len(rules) == 0 {
		return nil
	}
	d := &domainLimits{rules: rules, action: c.ClientAction}
	if d.action == "" {
		d.action = actDrop
	}
	return d
}

func (r *domainRule) matches(name string) bool {
	switch {
	case r.all:
		return true
	case r.glob != nil:
		return r.glob.match(name)
	case r.suffix != "":
		return name == r.suffix[1:] || strings.HasSuffix(name, r.suffix)
	}
	return name == r.exact
}

// check counts one query for name: admitLimited when the first line that matches it is out of tokens.
func (d *domainLimits) check(name string, now time.Time) (admitVerdict, string) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, r := range d.rules {
		if !r.matches(name) {
			continue
		}
		r.mu.Lock()
		r.tokens += now.Sub(r.last).Seconds() * r.rate
		if r.last.IsZero() || r.tokens > r.burst {
			r.tokens = r.burst
		}
		r.last = now
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return admitOK, ""
		}
		r.limitedN++
		r.mu.Unlock()
		return admitLimited, r.text
	}
	return admitOK, ""
}

// note logs the first refusal at once and then at most one line a minute.
func (d *domainLimits) note(row, name string, now time.Time) {
	d.logMu.Lock()
	d.pending++
	d.lastRow = row
	if !d.lastLog.IsZero() && now.Sub(d.lastLog) < domLogInterval {
		d.logMu.Unlock()
		return
	}
	n, r := d.pending, d.lastRow
	d.pending, d.lastLog = 0, now
	d.logMu.Unlock()
	warnf("dns: %d quer%s turned away for being over domain_limits (latest: %s, line %q); further ones are counted and logged at most once a minute", n, map[bool]string{true: "y", false: "ies"}[n == 1], name, r)
}

// admitDomain applies the pool's domain limits to one query for name; admitOK means go on.
func (p *Pool) admitDomain(name string, client netip.Addr) admitVerdict {
	if p.dlim == nil || client.Unmap().IsLoopback() {
		return admitOK
	}
	now := time.Now()
	v, row := p.dlim.check(name, now)
	if v == admitLimited {
		p.DomainLimited.Add(1)
		p.dlim.note(row, name, now)
	}
	return v
}

// turnedAwayDomain is the answer for a query over a domain limit: what client_action says for a client over its rate
// (drop = nil, truncate = a short answer with TC, refused), and REFUSED over a stream (TCP, DoT, DoH).
func (p *Pool) turnedAwayDomain(query []byte, tcp bool) []byte {
	if tcp {
		return errorResponse(query, rcodeRefused)
	}
	switch p.dlim.action {
	case actTruncate:
		r := errorResponse(query, rcodeNoError)
		if len(r) >= 4 {
			r[2] |= 0x02 // TC
		}
		return r
	case actRefused:
		return errorResponse(query, rcodeRefused)
	}
	return nil
}

// domainLimitRows is how many lines the pool has and how many queries each turned away, for the status page.
func (d *domainLimits) rows() []map[string]any {
	if d == nil {
		return nil
	}
	out := make([]map[string]any, 0, len(d.rules))
	for _, r := range d.rules {
		r.mu.Lock()
		out = append(out, map[string]any{"name": r.text, "rate": int(r.rate), "limited": r.limitedN})
		r.mu.Unlock()
	}
	return out
}

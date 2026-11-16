package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// Family filter (the dns block's "familyfilter", shared by every gateway): clients that get no IPv4 or no IPv6
// addresses.  Each entry is
//
//	client-network: no-ipv4
//	client-network: no-ipv6
//
// e.g. "10.1.0.0/16: no-ipv6".  "any" matches every client.  The first entry whose network holds the asking client is
// used.  A question for the filtered type (A for no-ipv4, AAAA for no-ipv6) is answered NOERROR with no records, as
// for a name that has none, so the client carries on with the other family; nothing is resolved or cached for it.
// Other types are untouched.

type familyRule struct {
	client netip.Prefix
	any    bool
	qtype  uint16 // the type that is answered empty: typeA or typeAAAA
}

func parseFamilyRule(s string) (familyRule, error) {
	var r familyRule
	i := strings.LastIndex(s, ":")
	if j := strings.Index(s, ": "); j >= 0 {
		i = j
	}
	if i < 0 {
		return r, fmt.Errorf("familyfilter %q: want client-network: no-ipv4 or client-network: no-ipv6", s)
	}
	cl, what := strings.TrimSpace(s[:i]), strings.ToLower(strings.TrimSpace(s[i+1:]))
	switch what {
	case "no-ipv4":
		r.qtype = typeA
	case "no-ipv6":
		r.qtype = typeAAAA
	default:
		return r, fmt.Errorf("familyfilter %q: after the colon say no-ipv4 or no-ipv6", s)
	}
	if strings.EqualFold(cl, "any") {
		r.any = true
		return r, nil
	}
	nets, err := parseClientNets([]string{cl})
	if err != nil {
		return r, fmt.Errorf("familyfilter %q: %w", s, err)
	}
	r.client = nets[0]
	return r, nil
}

func (r familyRule) String() string {
	cl := "any"
	if !r.any {
		cl = r.client.String()
	}
	if r.qtype == typeA {
		return cl + ": no-ipv4"
	}
	return cl + ": no-ipv6"
}

// normalizeFamilyFilter checks the entries and returns them in canonical form (nil for none).
func normalizeFamilyFilter(list []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		r, err := parseFamilyRule(s)
		if err != nil {
			return nil, fmt.Errorf("dns: %w", err)
		}
		if n := r.String(); !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > 1000 {
		return nil, fmt.Errorf("dns: familyfilter: at most 1000 entries")
	}
	return out, nil
}

func buildFamilyRules(list []string) []familyRule {
	var out []familyRule
	for _, s := range list {
		if r, err := parseFamilyRule(s); err == nil { // validated when the config was loaded
			out = append(out, r)
		}
	}
	return out
}

// familyDrops reports whether the client gets no answer records for a question of type qt.  The first rule that
// holds the client decides, and it filters one family only.
func (p *Pool) familyDrops(client netip.Addr, qt uint16) bool {
	if len(p.fams) == 0 || !client.IsValid() || (qt != typeA && qt != typeAAAA) {
		return false
	}
	client = client.Unmap()
	for i := range p.fams {
		if r := &p.fams[i]; r.any || r.client.Contains(client) {
			return r.qtype == qt
		}
	}
	return false
}

// familyDropFor is the type a client's rule leaves out (typeA, typeAAAA), or 0 for none.
func (p *Pool) familyDropFor(client netip.Addr) uint16 {
	if len(p.fams) == 0 || !client.IsValid() {
		return 0
	}
	client = client.Unmap()
	for i := range p.fams {
		if r := &p.fams[i]; r.any || r.client.Contains(client) {
			return r.qtype
		}
	}
	return 0
}

// dropFamily returns resp without its records of type drop (A or AAAA, and the RRSIGs that cover it) in the answer,
// authority and additional sections, so an ANY answer, or the glue of an MX answer, has none of the family the
// client does not get.  resp itself is never modified (it may be a cached message).  It is returned unchanged when
// there is nothing to remove, or when a name of a record that stays points into the removed area (which would break
// it).
func dropFamily(resp []byte, drop uint16) []byte {
	if drop == 0 || len(resp) < 12 || resp[2]&0x80 == 0 || resp[3]&0x0F != 0 {
		return resp
	}
	rrs, _, ok := recordsAfterQuestion(resp)
	if !ok {
		return resp
	}
	counts := [3]int{int(binary.BigEndian.Uint16(resp[6:])), int(binary.BigEndian.Uint16(resp[8:])), int(binary.BigEndian.Uint16(resp[10:]))}
	section := func(i int) int {
		if i < counts[0] {
			return 0
		}
		if i < counts[0]+counts[1] {
			return 1
		}
		return 2
	}
	remove := make([]bool, len(rrs))
	first, n := -1, 0
	var gone [3]int
	for i, rr := range rrs {
		covers := rr.typ == 46 && rr.rdlen >= 2 && binary.BigEndian.Uint16(resp[rr.rdataOff:]) == drop // RRSIG
		if (rr.typ == drop && rr.class == 1) || covers {
			remove[i] = true
			gone[section(i)]++
			n++
			if first < 0 {
				first = rr.start
			}
		}
	}
	if n == 0 {
		return resp
	}
	for i, rr := range rrs {
		if remove[i] || rr.start < first {
			continue
		}
		if ptrInto(resp, rr.start, first, len(resp)) {
			return resp
		}
		off := rr.rdataOff
		switch rr.typ {
		case 2, 5, 12, 39, 6: // NS CNAME PTR DNAME SOA: a name first
		case 15:
			off += 2 // MX
		case 33:
			off += 6 // SRV
		default:
			continue
		}
		if ptrInto(resp, off, first, len(resp)) {
			return resp
		}
		if rr.typ == 6 { // SOA: a second name
			if o, k := skipName(resp, off); k && ptrInto(resp, o, first, len(resp)) {
				return resp
			}
		}
	}
	out := make([]byte, 0, len(resp))
	out = append(out, resp[:first]...)
	for i, rr := range rrs {
		if rr.start >= first && !remove[i] {
			out = append(out, resp[rr.start:rr.end]...)
		}
	}
	for s := 0; s < 3; s++ {
		binary.BigEndian.PutUint16(out[6+2*s:], uint16(counts[s]-gone[s]))
	}
	return out
}

package main

import (
	"bytes"
	"context"
	"math/rand/v2"
	"strings"
	"sync/atomic"
	"time"
)

// Name case randomisation ("0x20", draft-vixie-dnsext-dns0x20).  A query to an upstream server over plain UDP carries the name
// with each letter in a random case (ExAmPlE.cOm).  A server keeps the spelling of the question in its answer, so the answer
// has to come back spelled the same way: an attacker who cannot see the query has to guess the case of every letter as well
// as the ID and the port to get a forged answer accepted.  The client's own spelling is put back before the answer goes on
// (and into the cache).
//
// Some servers write the name in one case.  Such an answer is not accepted: the query is sent again with the name as it was,
// and a server that did so five times in a row is left alone (asked the usual way) for half an hour, then tried again.  The
// setting is Randomize the case of names (randomize_case); it applies to plain UDP only: TCP, TLS and HTTPS are not forged
// that way.

const (
	case0x20Strikes = 5
	case0x20Pause   = 30 * time.Minute
)

// Case0x20Sent and Case0x20Mismatch count the queries sent that way and the answers that came back in another case.
var case0x20Sent, case0x20Mismatch atomic.Uint64

// randomCaseName returns a copy of the query q whose question name has its letters in random case, and the offsets of the
// name in it (the name runs from 12 to end).  ok is false for a query this does not apply to (not exactly one question, a
// name with no letter, a name that is compressed).
func randomCaseName(q []byte) (out []byte, end int, ok bool) {
	if len(q) < 17 || q[4] != 0 || q[5] != 1 || (q[2]>>3)&0x0F != 0 {
		return nil, 0, false
	}
	out = append([]byte(nil), q...)
	letters := 0
	var bits uint64
	left := 0
	i := 12
	for i < len(out) && out[i] != 0 {
		l := int(out[i])
		if l&0xC0 != 0 || i+1+l > len(out) {
			return nil, 0, false
		}
		for j := i + 1; j < i+1+l; j++ {
			c := out[j]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				continue
			}
			letters++
			if left == 0 {
				bits, left = rand.Uint64(), 64
			}
			if bits&1 == 1 {
				out[j] ^= 0x20
			}
			bits >>= 1
			left--
		}
		i += 1 + l
	}
	if i >= len(out) || letters == 0 {
		return nil, 0, false
	}
	return out, i + 1, true
}

// case0x20Check looks at the question of an answer: ok when it is spelled as sent (or cannot be checked: no question in it),
// bad when it is the same name in other case.  A different name is left to the usual checks.
func case0x20Check(resp, sent []byte, end int) (ok bool) {
	if len(resp) < 12 || len(resp) < end {
		return true
	}
	if resp[4] != 0 || resp[5] != 0 {
		if resp[5] != 1 {
			return true
		}
		got := resp[12:end]
		want := sent[12:end]
		if bytes.Equal(got, want) {
			return true
		}
		return !asciiEqualFold(got, want)
	}
	return true // an answer without the question (some servers do that to FORMERR): nothing to compare
}

// asciiEqualFold says whether a and b are the same bytes, upper and lower case letters (ASCII only) not told apart.
func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 0x20
		}
		if y >= 'A' && y <= 'Z' {
			y += 0x20
		}
		if x != y {
			return false
		}
	}
	return true
}

// exchangeQ is exchangeOpt for a client's query sent to server s, with the case of the name randomised when the pool's
// settings say so and the server allows it.
func (p *Pool) exchangeQ(ctx context.Context, s *Server, q []byte, tcp bool) ([]byte, time.Duration, error) {
	if !p.cfg.RandomizeCase || tcp || strings.HasPrefix(s.Addr, dohScheme) || strings.HasPrefix(s.Addr, dotScheme) {
		return exchangeOpt(ctx, s.Addr, q, tcp, p.cfg.queryTimeout(), p.cfg.TLSInsecure)
	}
	if until := s.case0x20Off.Load(); until != 0 {
		if time.Now().UnixNano() < until {
			return exchangeOpt(ctx, s.Addr, q, tcp, p.cfg.queryTimeout(), p.cfg.TLSInsecure)
		}
		s.case0x20Off.Store(0) // the pause is over: try it again
		s.case0x20Miss.Store(case0x20Strikes - 1)
	}
	rq, end, ok := randomCaseName(q)
	if !ok {
		return exchangeOpt(ctx, s.Addr, q, tcp, p.cfg.queryTimeout(), p.cfg.TLSInsecure)
	}
	case0x20Sent.Add(1)
	resp, rtt, err := exchangeOpt(ctx, s.Addr, rq, tcp, p.cfg.queryTimeout(), p.cfg.TLSInsecure)
	if err != nil {
		return resp, rtt, err
	}
	if case0x20Check(resp, rq, end) {
		s.case0x20Miss.Store(0)
		// the spelling the client used goes back into the answer: in the question and in any copy of the name
		if len(resp) >= end {
			orig := q[12:end]
			spelt := rq[12:end]
			copy(resp[12:end], orig)
			for off := end; off < len(resp); {
				i := bytes.Index(resp[off:], spelt)
				if i < 0 {
					break
				}
				copy(resp[off+i:], orig)
				off += i + len(spelt)
			}
		}
		return resp, rtt, nil
	}
	// the name came back in another case: not accepted
	case0x20Mismatch.Add(1)
	if s.case0x20Miss.Add(1) >= case0x20Strikes {
		s.case0x20Off.Store(time.Now().Add(case0x20Pause).UnixNano())
		warnf("dns: server %s does not keep the case of names (0x20): asking it the usual way for %v", s.Addr, case0x20Pause)
	}
	return exchangeOpt(ctx, s.Addr, q, tcp, p.cfg.queryTimeout(), p.cfg.TLSInsecure)
}

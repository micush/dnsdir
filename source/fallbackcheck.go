package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"time"
)

// Checking the fallback servers.  A fallback server is never probed with the pool's test domains (those may be names only
// the normal servers know) and always counts as up, so nothing used to say whether one would answer on the day it is
// needed.  Each probe round now also asks every fallback server one question any resolver can answer, the root zone's NS
// records, and counts any NOERROR or NXDOMAIN answer as "answering": the server is reachable and resolves for us.  REFUSED,
// SERVFAIL, a timeout or no connection count as not answering.  After fail_threshold rounds in a row without an answer the
// server is shown as not answering (Topology, Monitor ▸ DNS, --show-dns, get_dns) and the alert "Fallback server not
// answering" opens.
//
// The check only reports: a fallback server is still used when every normal server is down, whatever its check says, so a
// check that is wrong for some network can never take away the last resort.

// FallbackCheck is the latest check of one fallback server.
type FallbackCheck struct {
	Answering   bool    `json:"answering"`              // answered in the last rounds (fewer than fail_threshold misses in a row)
	LastOK      bool    `json:"last_ok"`                // the latest round answered
	MS          float64 `json:"ms,omitempty"`           // its round trip, when it answered
	Error       string  `json:"error,omitempty"`        // why the latest round did not answer
	ConsecFails int     `json:"consec_fails,omitempty"` // rounds in a row without an answer
	AgoS        float64 `json:"ago_s"`                  // seconds since that round
}

// buildRootNSQuery is ". IN NS" with recursion desired (buildQuery does not take the root name).
func buildRootNSQuery(id uint16) []byte {
	b := make([]byte, 12, 17)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(b[4:], 1)      // QDCOUNT
	return append(b, 0, 0, 2, 0, 1)           // the root name, type NS, class IN
}

// checkFallback asks s, a fallback server, for the root zone's NS records and keeps the result.  It never changes whether
// the pool may use s.
func (p *Pool) checkFallback(ctx context.Context, s *Server) {
	resp, rtt, err := exchangeOpt(ctx, s.Addr, buildRootNSQuery(uint16(rand.Uint32())), false, p.cfg.probeTimeout(), p.cfg.TLSInsecure)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		h, ok := parseHeader(resp)
		switch {
		case !ok || !h.qr:
			err = fmt.Errorf(". NS: not a DNS answer")
		case h.rcode != rcodeNoError && h.rcode != rcodeNXDomain:
			err = fmt.Errorf(". NS: %s", rcodeText(h.rcode))
		}
	} else {
		err = fmt.Errorf(". NS: %w", err)
	}
	if s.hist != nil { // the server's history (Monitor ▸ DNS ▸ a server) shows its checks like a normal server's probes
		if err == nil {
			s.hist.addPrOK()
			s.hist.lat(rtt)
		} else {
			s.hist.addPrFail()
		}
	}
	s.mu.Lock()
	was := !s.fbChecked || s.fbFails < p.failThreshold() // not checked yet counts as answering: no log line at start
	s.fbChecked, s.fbAt = true, time.Now()
	if err == nil {
		s.fbFails, s.fbErr, s.fbMS = 0, "", round2(float64(rtt)/float64(time.Millisecond))
	} else {
		s.fbFails++
		s.fbErr, s.fbMS = err.Error(), 0
	}
	now := s.fbFails < p.failThreshold()
	s.mu.Unlock()
	switch {
	case was && !now:
		warnf("dns: fallback server %s does not answer (%s)", s.Addr, err)
	case !was && now:
		infof("dns: fallback server %s answers again", s.Addr)
	}
}

func (p *Pool) failThreshold() int {
	if p.cfg.FailThreshold > 0 {
		return p.cfg.FailThreshold
	}
	return 1
}

// fallbackCheckOf is the snapshot of s's check (nil before the first one, or for a normal server); s.mu is held.
func (p *Pool) fallbackCheckOf(s *Server) *FallbackCheck {
	if !s.Fallback || !s.fbChecked {
		return nil
	}
	return &FallbackCheck{Answering: s.fbFails < p.failThreshold(), LastOK: s.fbFails == 0, MS: s.fbMS, Error: s.fbErr,
		ConsecFails: s.fbFails, AgoS: round2(time.Since(s.fbAt).Seconds())}
}

// fallbackCheckWords is a fallback server's check in a word or two, for the command line.
func fallbackCheckWords(c *FallbackCheck) string {
	switch {
	case c == nil:
		return "not checked yet"
	case !c.Answering:
		return "NOT ANSWERING"
	case !c.LastOK:
		return "answering (missed the last check)"
	}
	return "answering"
}

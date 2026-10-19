package main

// ClockReading is how a node's clock stands against the time chrony believes (chronyc tracking).  Every node measures against
// the same upstream servers, so the difference between two nodes' OffsetMS is how far apart their clocks are, to within the
// error of each measurement (chrony's own estimate, a fraction of a millisecond to a few milliseconds).
type ClockReading struct {
	OffsetMS float64 `json:"offset_ms"` // the system clock's offset from chrony's time; positive and negative as chrony reports it
	Synced   bool    `json:"synced"`
	Stratum  int     `json:"stratum,omitempty"`
	At       int64   `json:"at,omitempty"` // unix seconds of the reading
}

// ClockSpread is the largest difference between the clocks of the nodes that could be compared.
type ClockSpread struct {
	MS    float64 `json:"ms"`
	Nodes int     `json:"nodes"`           // how many nodes were compared
	Apart string  `json:"apart,omitempty"` // the two nodes furthest apart, "a ↔ b"
}

// clockReading is this node's reading, or nil while chrony is not running.
func clockReading() *ClockReading {
	st := chrony.State()
	if !st.Running {
		return nil
	}
	return &ClockReading{OffsetMS: st.OffsetMS, Synced: st.Synced, Stratum: st.Stratum, At: st.At}
}

// clockSpread compares the nodes that are reachable, say their clock and are synchronised.  nil with fewer than two.
func clockSpread(peers []PeerView) *ClockSpread {
	var lo, hi *PeerView
	n := 0
	for i := range peers {
		p := &peers[i]
		if !p.Reachable || p.Clock == nil || !p.Clock.Synced {
			continue
		}
		n++
		if lo == nil || p.Clock.OffsetMS < lo.Clock.OffsetMS {
			lo = p
		}
		if hi == nil || p.Clock.OffsetMS > hi.Clock.OffsetMS {
			hi = p
		}
	}
	if n < 2 {
		return nil
	}
	name := func(p *PeerView) string {
		if p.Hostname != "" {
			return p.Hostname
		}
		return p.Addr
	}
	d := hi.Clock.OffsetMS - lo.Clock.OffsetMS
	return &ClockSpread{MS: d, Nodes: n, Apart: name(lo) + " ↔ " + name(hi)}
}

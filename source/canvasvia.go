package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// A gateway this node does not serve (another subnet, removed from it, paused here) has nothing of its own to show: no
// servers probed, no domains tested.  The drawing is the gateway, not this node, so for such a gateway the picture is the
// one the nodes that serve it have: asked of one of them, over the cluster channel, and shown with the name of the node it
// came from.  The node's own entry among the cluster's nodes stays what this node says about itself.

// viaFetchTimeout bounds the ask: a slow node must not hold the Topology page up (it falls back to this node's own view).
var viaFetchTimeout = 4 * time.Second

// servingPeers lists the nodes that can say how the gateway is doing, best first: those serving it well, then those
// serving it degraded.  Empty when this node serves it itself or nobody does.
func servingPeers(g CanvasGateway) []CanvasNode {
	self := ""
	for _, n := range g.Nodes {
		if n.Self {
			self = n.Gw
		}
	}
	switch self {
	case "notserving", "paused", "removed":
	default:
		return nil // this node serves it (or is starting it): its own view is the picture
	}
	var ok, degraded []CanvasNode
	for _, n := range g.Nodes {
		if n.Self || !n.Reachable || n.Excluded {
			continue
		}
		switch n.Gw {
		case "ok":
			ok = append(ok, n)
		case "degraded":
			degraded = append(degraded, n)
		}
	}
	byAddr := func(l []CanvasNode) { sort.SliceStable(l, func(i, j int) bool { return l[i].Addr < l[j].Addr }) }
	byAddr(ok)
	byAddr(degraded)
	return append(ok, degraded...)
}

// takeFrom puts the serving node's picture of the gateway in place of this node's: its colour, servers, domains, anycast
// addresses, members and uptime; the cluster's nodes and everything about this node's own entry stay.
func (g *CanvasGateway) takeFrom(p CanvasGateway, from CanvasNode) {
	g.Status, g.Detail, g.Families, g.Servers, g.Fallback, g.UsingFallback, g.FallbackCheck = p.Status, p.Detail, p.Families, p.Servers, p.Fallback, p.UsingFallback, p.FallbackCheck
	g.Members, g.Anycast, g.Uptime, g.LB, g.LBOwn, g.ECS = p.Members, p.Anycast, p.Uptime, p.LB, p.LBOwn, p.ECS
	// the serving node's own entry is "local" to it, not to this node: nobody is this node here, or the
	// page would put the controller mark (and the star) on the node it is open on
	g.Members = make([]CanvasMember, len(p.Members))
	copy(g.Members, p.Members)
	for i := range g.Members {
		g.Members[i].ViaLocal = g.Members[i].Local
		g.Members[i].Local = false
	}
	g.Via, g.ViaAddr = from.Name, from.Addr
}

// viaServing replaces, in place, each gateway this node does not serve with the picture of a node that does.
func (s *StatusServer) viaServing(ctx context.Context, groups []CanvasGateway) {
	if s.mg == nil || s.mg.cl == nil {
		return
	}
	ask := func(n CanvasNode) []CanvasGateway {
		var out struct {
			Data []CanvasGateway `json:"data"`
		}
		if body := s.peerBody(n, "topology", "/api/canvas?own=1"); body == nil || json.Unmarshal(body, &out) != nil {
			return nil
		}
		return out.Data
	}
	for i := range groups {
	peers:
		for _, n := range servingPeers(groups[i]) {
			for _, p := range ask(n) {
				if p.GroupID == groups[i].GroupID {
					groups[i].takeFrom(p, n)
					break peers
				}
			}
		}
	}
}

// peerReplies keeps, per node and path, the last good answer of a node to a "?own=1" ask, so a poll asks no node that was asked a
// moment ago and a slow node never holds a page up: an older answer is used at once while a new one is fetched in the background,
// and a node that does not answer is waited for at most once (the very first ask), then only retried quietly in the background.
var (
	peerReplyMu sync.Mutex
	peerReplies = map[string]*peerReply{}
	// viaColdWait is how long a request waits for a node it has no answer from yet; then the page shows this node's own view.
	viaColdWait = 1500 * time.Millisecond
)

const peerReplyFor = 3 * time.Second

type peerReply struct {
	at       time.Time
	body     []byte
	fetching bool
	tried    bool // a fetch has ended (well or not): later requests do not wait for the next one
	done     chan struct{}
}

// askPeerBody asks a node, over the cluster channel, for GET path.
var askPeerBody = func(s *StatusServer, ctx context.Context, addr, user, path string) ([]byte, bool) {
	resp, err := s.mg.cl.Relay(ctx, addr, proxyReq{User: user, Method: http.MethodGet, Path: path})
	if err != nil || resp.Status != http.StatusOK {
		return nil, false
	}
	return resp.Body, true
}

// peerBody is the body of GET path on node n as last heard (nil: not heard, or too old to say how things are now).
func (s *StatusServer) peerBody(n CanvasNode, user, path string) []byte {
	key := n.Addr + "|" + path
	peerReplyMu.Lock()
	e := peerReplies[key]
	if e == nil {
		e = &peerReply{}
		peerReplies[key] = e
	}
	if time.Since(e.at) >= peerReplyFor && !e.fetching {
		e.fetching = true
		e.done = make(chan struct{})
		done := e.done
		go func() {
			t0 := time.Now()
			cctx, cancel := context.WithTimeout(context.Background(), viaFetchTimeout)
			defer cancel()
			body, good := askPeerBody(s, cctx, n.Addr, user, path)
			if took := time.Since(t0); took > time.Second {
				warnf("topology: node %s took %s to answer %s (answered: %v)", n.Addr, took.Round(100*time.Millisecond), path, good)
			}
			peerReplyMu.Lock()
			defer peerReplyMu.Unlock()
			e.fetching, e.tried = false, true
			close(done)
			if good {
				e.body, e.at = body, time.Now()
			} else {
				e.at = time.Now().Add(-(peerReplyFor - time.Second)) // counts as 2 s old: asked again in a second, not at once
			}
		}()
	}
	body, done, at, tried := e.body, e.done, e.at, e.tried
	peerReplyMu.Unlock()
	if body == nil && !tried && done != nil {
		select {
		case <-done:
		case <-time.After(viaColdWait):
		}
		peerReplyMu.Lock()
		body, at = e.body, e.at
		peerReplyMu.Unlock()
	}
	if time.Since(at) > time.Minute {
		return nil
	}
	return body
}

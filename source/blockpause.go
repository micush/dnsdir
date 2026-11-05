package main

import (
	"context"
	"errors"
	"time"
)

// Pausing the block lists: for a while no name is refused because a block list has it (policy rows that block are not
// touched).  The pause is held in memory on each node, so a restart puts blocking back, and it ends by itself.
// Starting and ending it empties the node's answer cache.

const (
	blockPauseDefault = time.Hour
	blockPauseMax     = 24 * time.Hour
)

// Paused says the lists are not blocking right now.
func (m *BlockManager) Paused() bool {
	u := m.pausedUntil.Load()
	return u != 0 && time.Now().Unix() < u
}

// PausedUntil is when blocking comes back, or the zero time when it is not paused.
func (m *BlockManager) PausedUntil() time.Time {
	if !m.Paused() {
		return time.Time{}
	}
	return time.Unix(m.pausedUntil.Load(), 0)
}

// Pause stops the lists blocking for d (a new pause replaces a running one) and calls onEnd when it runs out (not when Resume ends it).
func (m *BlockManager) Pause(d time.Duration, onEnd func()) time.Time {
	until := time.Now().Add(d).Truncate(time.Second)
	m.pauseMu.Lock()
	defer m.pauseMu.Unlock()
	if m.pauseTimer != nil {
		m.pauseTimer.Stop()
	}
	m.pausedUntil.Store(until.Unix())
	var t *time.Timer
	t = time.AfterFunc(time.Until(until), func() {
		m.pauseMu.Lock()
		current := m.pauseTimer == t
		if current {
			m.pauseTimer = nil
			m.pausedUntil.Store(0)
		}
		m.pauseMu.Unlock()
		if current && onEnd != nil {
			onEnd()
		}
	})
	m.pauseTimer = t
	return until
}

// Resume puts blocking back now, and says whether it was paused.
func (m *BlockManager) Resume() bool {
	m.pauseMu.Lock()
	defer m.pauseMu.Unlock()
	if m.pauseTimer != nil {
		m.pauseTimer.Stop()
		m.pauseTimer = nil
	}
	was := m.pausedUntil.Swap(0) != 0
	return was
}

// BlockPauseResult is what a node says after a pause or a resume.
type BlockPauseResult struct {
	PausedUntil int64 `json:"paused_until,omitempty"`
	Cleared     int   `json:"cleared"` // cached answers dropped on the node
}

// blockPauseNode pauses (or resumes) the block lists on this node and empties its answer cache.
func (m *Mgmt) blockPauseNode(pause bool, d time.Duration, actor string) (*BlockPauseResult, error) {
	bm := theBlocks.Load()
	if bm == nil {
		return nil, errors.New("block lists are not available on this node")
	}
	flush := func() int {
		if m.clearFn == nil {
			return 0
		}
		return m.clearFn()
	}
	r := &BlockPauseResult{}
	if pause {
		until := bm.Pause(d, func() {
			n := flush()
			infof("block lists: pause over, blocking again (%d cached answers dropped)", n)
		})
		r.PausedUntil = until.Unix()
		r.Cleared = flush()
		warnf("block lists: %q paused blocking on this node until %s (%d cached answers dropped)", actor, until.Format("15:04:05"), r.Cleared)
		return r, nil
	}
	if bm.Resume() {
		r.Cleared = flush()
		warnf("block lists: %q resumed blocking on this node (%d cached answers dropped)", actor, r.Cleared)
	}
	return r, nil
}

// blockPauseSeconds checks the length of a pause asked for (0: the default hour).
func blockPauseSeconds(sec int) (time.Duration, error) {
	if sec == 0 {
		return blockPauseDefault, nil
	}
	d := time.Duration(sec) * time.Second
	if d < 0 || d > blockPauseMax {
		return 0, errors.New("a pause is 1 second to 24 hours")
	}
	return d, nil
}

// blockPauseCluster does blockPauseNode on every node: this one asks the others, which are asked on the node route.
func (m *Mgmt) blockPauseCluster(pause bool, sec int, actor string) (any, error) {
	d, err := blockPauseSeconds(sec)
	if err != nil {
		return nil, err
	}
	body := `{"paused":false}`
	if pause {
		body = `{"paused":true,"seconds":` + itoa(int(d/time.Second)) + `}`
	}
	parts, infos := clusterGatherReq(context.Background(), m, proxyReq{User: actor, Method: "POST", Path: "/api/blocklists/pause-node", CT: "application/json", Body: []byte(body)}, clusterStatsTimeout,
		func() (*BlockPauseResult, error) { return m.blockPauseNode(pause, d, actor) })
	if len(parts) == 0 {
		return nil, errors.New("no node answered")
	}
	out := map[string]any{"paused": pause, "nodes": infos}
	total := 0
	var until int64
	for _, p := range parts {
		if p.R != nil {
			total += p.R.Cleared
			if p.R.PausedUntil > until {
				until = p.R.PausedUntil
			}
		}
	}
	out["cleared"] = total
	if pause {
		out["paused_until"] = until
	}
	return out, nil
}

// blockPauseText is a sentence for the command line.
func blockPauseText(until int64) string {
	if until == 0 {
		return "blocking is on"
	}
	return "blocking is paused until " + time.Unix(until, 0).Format("15:04:05")
}

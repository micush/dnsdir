package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func pausedTestManager() *BlockManager {
	m := NewBlockManager(".", "node")
	m.snap.Store(&blockSnap{names: map[string]uint8{"ads.example.com": 1}, keys: []string{"k"}, hits: []*atomic.Int64{new(atomic.Int64)}})
	return m
}

func TestBlockPauseStopsLookupAndResumeRestoresIt(t *testing.T) {
	m := pausedTestManager()
	if _, ok := m.Lookup("x.ads.example.com"); !ok {
		t.Fatal("a listed name is not blocked before a pause")
	}
	until := m.Pause(time.Hour, nil)
	if !m.Paused() || m.PausedUntil().IsZero() || time.Until(until) < 59*time.Minute {
		t.Fatalf("not paused for an hour: %v", until)
	}
	if _, ok := m.Lookup("ads.example.com"); ok {
		t.Error("a name is blocked while paused")
	}
	if m.Report().PausedUntil != until.Unix() {
		t.Error("the report does not say when the pause ends")
	}
	if !m.Resume() {
		t.Error("Resume said it was not paused")
	}
	if _, ok := m.Lookup("ads.example.com"); !ok || m.Paused() || m.Report().PausedUntil != 0 {
		t.Error("blocking did not come back on Resume")
	}
	if m.Resume() {
		t.Error("a second Resume said it was paused")
	}
}

func TestBlockPauseEndsByItselfAndCallsBack(t *testing.T) {
	m := pausedTestManager()
	done := make(chan struct{})
	m.Pause(50*time.Millisecond, func() { close(done) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the pause did not end")
	}
	if m.Paused() {
		t.Error("still paused after the end")
	}
}

func TestBlockPauseReplacedAndResumedDoNotCallBack(t *testing.T) {
	m := pausedTestManager()
	var ended atomic.Int32
	m.Pause(50*time.Millisecond, func() { ended.Add(1) })
	m.Pause(time.Hour, func() { ended.Add(1) }) // replaces the first: its end must not fire
	time.Sleep(200 * time.Millisecond)
	if ended.Load() != 0 || !m.Paused() {
		t.Fatalf("a replaced pause fired (%d) or ended the new one", ended.Load())
	}
	m.Resume()
	m.Pause(50*time.Millisecond, func() { ended.Add(1) })
	m.Resume()
	time.Sleep(200 * time.Millisecond)
	if ended.Load() != 0 {
		t.Errorf("Resume still called the end callback (%d)", ended.Load())
	}
}

func TestBlockPauseSeconds(t *testing.T) {
	if d, err := blockPauseSeconds(0); err != nil || d != time.Hour {
		t.Errorf("default = %v, %v", d, err)
	}
	if _, err := blockPauseSeconds(-1); err == nil {
		t.Error("negative accepted")
	}
	if _, err := blockPauseSeconds(86401); err == nil {
		t.Error("more than a day accepted")
	}
}

func TestBlockPauseNodeFlushesCacheOnPauseAndResume(t *testing.T) {
	m := &Mgmt{}
	cleared := 0
	m.clearFn = func() int { cleared++; return 7 }
	old := theBlocks.Swap(nil)
	defer theBlocks.Store(old)
	if _, err := m.blockPauseNode(true, time.Hour, "t"); err == nil {
		t.Fatal("no error without a block manager")
	}
	bm := pausedTestManager()
	theBlocks.Store(bm)
	r, err := m.blockPauseNode(true, time.Hour, "t")
	if err != nil || r.Cleared != 7 || cleared != 1 || r.PausedUntil == 0 || !bm.Paused() {
		t.Fatalf("pause: %+v %v flushes=%d", r, err, cleared)
	}
	r, err = m.blockPauseNode(false, 0, "t")
	if err != nil || r.Cleared != 7 || cleared != 2 || bm.Paused() {
		t.Fatalf("resume: %+v %v flushes=%d", r, err, cleared)
	}
	if _, err = m.blockPauseNode(false, 0, "t"); err != nil || cleared != 2 {
		t.Errorf("resuming when not paused flushed (%d) or failed: %v", cleared, err)
	}
}

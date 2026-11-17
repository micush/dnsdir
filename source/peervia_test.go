package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

func resetPeerReplies(t *testing.T) (restore func()) {
	t.Helper()
	peerReplyMu.Lock()
	peerReplies = map[string]*peerReply{}
	peerReplyMu.Unlock()
	oldAsk, oldWait := askPeerBody, viaColdWait
	return func() { askPeerBody, viaColdWait = oldAsk, oldWait }
}

// A node that does not answer is waited for once (the first look), then never again: every poll used to wait out the whole
// viaFetchTimeout for it.
func TestPeerBodyDoesNotWaitForADeadNodeTwice(t *testing.T) {
	t.Cleanup(resetPeerReplies(t))
	viaColdWait = 300 * time.Millisecond
	var mu sync.Mutex
	asks := 0
	askPeerBody = func(*StatusServer, context.Context, string, string, string) ([]byte, bool) {
		mu.Lock()
		asks++
		mu.Unlock()
		time.Sleep(600 * time.Millisecond) // slower than anyone waits
		return nil, false
	}
	s := &StatusServer{}
	n := CanvasNode{Addr: "10.9.9.9:1"}
	t0 := time.Now()
	if b := s.peerBody(n, "x", "/api/x?own=1"); b != nil {
		t.Fatalf("got %q from a node that did not answer", b)
	}
	if took := time.Since(t0); took < 250*time.Millisecond || took > 550*time.Millisecond {
		t.Fatalf("the first ask waited %s, want about the cold wait", took)
	}
	time.Sleep(450 * time.Millisecond) // the background ask has ended (failed)
	for i := 0; i < 5; i++ {
		t0 = time.Now()
		s.peerBody(n, "x", "/api/x?own=1")
		if took := time.Since(t0); took > 100*time.Millisecond {
			t.Fatalf("ask %d waited %s for a node already known not to answer", i+2, took)
		}
	}
	time.Sleep(peerReplyFor) // the retry window has passed: the next ask starts a new background fetch, and still does not wait for it
	t0 = time.Now()
	s.peerBody(n, "x", "/api/x?own=1")
	if took := time.Since(t0); took > 100*time.Millisecond {
		t.Fatalf("a retry of a dead node held the request %s", took)
	}
	for i := 0; i < 100; i++ { // the retry's background ask has started (it reads the stub): only then is it put back
		mu.Lock()
		n := asks
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A good answer is kept for a few seconds: polls in that time ask nobody.
func TestPeerBodyKeepsAGoodAnswer(t *testing.T) {
	t.Cleanup(resetPeerReplies(t))
	var mu sync.Mutex
	asks := 0
	askPeerBody = func(*StatusServer, context.Context, string, string, string) ([]byte, bool) {
		mu.Lock()
		asks++
		mu.Unlock()
		return []byte(`{"data":[]}`), true
	}
	s := &StatusServer{}
	n := CanvasNode{Addr: "10.9.9.8:1"}
	for i := 0; i < 6; i++ {
		if b := s.peerBody(n, "x", "/api/x?own=1"); string(b) != `{"data":[]}` {
			t.Fatalf("ask %d: %q", i+1, b)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if asks != 1 {
		t.Fatalf("%d asks for six polls within %s", asks, peerReplyFor)
	}
}

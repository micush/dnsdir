package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRandomCaseName(t *testing.T) {
	q := cacheQuery("www.example.com", 1, nil)
	mixed := 0
	for i := 0; i < 50; i++ {
		out, end, ok := randomCaseName(q)
		if !ok || end != 12+len("www.example.com")+2 {
			t.Fatalf("ok=%v end=%d", ok, end)
		}
		if !asciiEqualFold(out, q) || bytes.Equal(out[:12], q[:12]) == false || !bytes.Equal(out[end:], q[end:]) {
			t.Fatalf("only the letters of the name may change: %x vs %x", out, q)
		}
		if !bytes.Equal(out[12:end], q[12:end]) {
			mixed++
		}
	}
	if mixed < 40 {
		t.Fatalf("the case was changed in only %d of 50", mixed)
	}
	if _, _, ok := randomCaseName(cacheQuery("1.2.3", 1, nil)); ok {
		t.Fatal("a name with no letter has nothing to randomise")
	}
}

func case0x20Pool(t *testing.T, on bool) (*Pool, *fakeDNS) {
	up := newFakeDNS(t)
	cfg := testDNSCfg(up.addr)
	cfg.ECS = false
	cfg.RandomizeCase = on
	p := NewPool(cfg)
	p.ProbeNow(context.Background())
	return p, up
}

func TestCase0x20Randomises(t *testing.T) {
	p, up := case0x20Pool(t, true)
	sent := case0x20Sent.Load()
	differ := 0
	for i := 0; i < 12; i++ {
		q := cacheQuery("Mixed.Example", 1, nil)
		resp, err := p.Forward(context.Background(), q, false)
		if err != nil {
			t.Fatal(err)
		}
		if raw, _ := up.lastRaw.Load().(string); raw != string(q[12:12+len(raw)]) {
			differ++
		}
		// the client's spelling is what comes back
		if end, _ := questionEnd(q); !bytes.Equal(resp[12:end], q[12:end]) {
			t.Fatalf("the answer has the name as %q, not as asked %q", resp[12:end], q[12:end])
		}
	}
	if differ < 8 || case0x20Sent.Load()-sent < 12 {
		t.Fatalf("the upstream saw another spelling %d times of 12, sent %d", differ, case0x20Sent.Load()-sent)
	}
	// off: the upstream gets the name exactly as it came
	p2, up2 := case0x20Pool(t, false)
	q := cacheQuery("Mixed.Example", 1, nil)
	if _, err := p2.Forward(context.Background(), q, false); err != nil {
		t.Fatal(err)
	}
	if raw, _ := up2.lastRaw.Load().(string); raw != string(q[12:12+len(raw)]) {
		t.Fatal("randomised while switched off")
	}
	// TCP is not randomised
	p3, up3 := case0x20Pool(t, true)
	for i := 0; i < 6; i++ {
		if _, err := p3.Forward(context.Background(), q, true); err != nil {
			t.Fatal(err)
		}
		if raw, _ := up3.lastRaw.Load().(string); raw != string(q[12:12+len(raw)]) {
			t.Fatal("randomised over TCP")
		}
	}
}

func TestCase0x20ServerThatLowercases(t *testing.T) {
	p, up := case0x20Pool(t, true)
	up.lower.Store(true)
	mis := case0x20Mismatch.Load()
	q := cacheQuery("Mixed.Example", 1, nil)
	for i := 0; i < case0x20Strikes+2; i++ {
		resp, err := p.Forward(context.Background(), q, false)
		if err != nil {
			t.Fatalf("a server that lowercases must still be served (query %d): %v", i, err)
		}
		if h, _ := parseHeader(resp); h.rcode != 0 || h.ancount != 1 {
			t.Fatalf("answer %+v", h)
		}
	}
	s := p.servers[0]
	if s.case0x20Off.Load() == 0 {
		t.Fatalf("the server was not left alone after %d mismatches", case0x20Strikes)
	}
	if got := case0x20Mismatch.Load() - mis; got != uint64(case0x20Strikes) {
		t.Fatalf("mismatches %d, want %d (the rest went the usual way)", got, case0x20Strikes)
	}
	// paused: the name goes exactly as it came
	if _, err := p.Forward(context.Background(), q, false); err != nil {
		t.Fatal(err)
	}
	if raw, _ := up.lastRaw.Load().(string); raw != string(q[12:12+len(raw)]) {
		t.Fatalf("still randomised while paused: %q", raw)
	}
	_ = strings.ToLower
}

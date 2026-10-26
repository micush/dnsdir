package main

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func prefetchRig(t *testing.T, on bool) (*DNSFrontend, *Pool, *fakeDNS, *time.Time) {
	up := newFakeDNS(t)
	cfg := testDNSCfg(up.addr)
	cfg.ECS = false
	cfg.CachePrefetch = on
	p := NewPool(cfg)
	p.ProbeNow(context.Background())
	fe := NewDNSFrontend(mustAddr("127.0.0.2"), 0, func() *Pool { return p })
	fe.ctx, fe.cancel = context.WithCancel(context.Background())
	t.Cleanup(fe.cancel)
	clock := time.Now()
	p.cache.now = func() time.Time { return clock }
	return fe, p, up, &clock
}

// waitUntil polls until cond holds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

func TestPrefetchRefreshesAPopularAnswerBeforeItExpires(t *testing.T) {
	fe, p, up, clock := prefetchRig(t, true)
	cl := mustAddr("192.0.2.5")
	q := cacheQuery("pop.example", 1, nil) // the fake upstream answers with a 60 s TTL
	fe.resolve(q, false, cl)
	base := up.hits.Load()

	*clock = clock.Add(30 * time.Second) // half way: no refresh, whatever the hits
	fe.resolve(q, false, cl)
	fe.resolve(q, false, cl)
	time.Sleep(50 * time.Millisecond)
	if up.hits.Load() != base || p.cache.Prefetched.Load() != 0 {
		t.Fatalf("refreshed too early: upstream %d", up.hits.Load()-base)
	}

	*clock = clock.Add(25 * time.Second) // 5 s of 60 left (under 10 %), and it has been asked for more than twice
	r := fe.resolve(q, false, cl)
	if h, _ := parseHeader(r); h.ancount != 1 {
		t.Fatalf("the client still gets the cached answer: %+v", h)
	}
	waitUntil(t, "the refresh", func() bool { return p.cache.Prefetched.Load() == 1 })
	if up.hits.Load() != base+1 {
		t.Fatalf("one refresh upstream: %d", up.hits.Load()-base)
	}
	// the entry is new: a full TTL again, and no second refresh at the next hit
	r = fe.resolve(q, false, cl)
	var ttl uint32
	if end, _ := questionEnd(r); len(r) >= end+10 {
		ttl = binary.BigEndian.Uint32(r[end+6:])
	}
	if ttl < 58 {
		t.Fatalf("after the refresh the answer has %d s left", ttl)
	}
	time.Sleep(50 * time.Millisecond)
	if up.hits.Load() != base+1 {
		t.Fatal("refreshed twice")
	}
	// it is not a query: the counters of the clients are left alone
	if p.cache.PrefetchFailed.Load() != 0 {
		t.Fatal("no failure expected")
	}
}

func TestPrefetchNeedsHitsAndAFailedRefreshWaits(t *testing.T) {
	fe, p, up, clock := prefetchRig(t, true)
	cl := mustAddr("192.0.2.5")
	q := cacheQuery("rare.example", 1, nil)
	fe.resolve(q, false, cl)
	base := up.hits.Load()
	*clock = clock.Add(56 * time.Second)
	fe.resolve(q, false, cl) // the first hit: one is not enough (cache_prefetch_hits is 2)
	time.Sleep(50 * time.Millisecond)
	if up.hits.Load() != base {
		t.Fatal("an answer asked for once is not refreshed")
	}
	up.mode.Store(3) // the upstream fails now
	fe.resolve(q, false, cl)
	waitUntil(t, "the failed refresh", func() bool { return p.cache.PrefetchFailed.Load() == 1 })
	n := up.hits.Load()
	fe.resolve(q, false, cl) // within the pause: not tried again
	time.Sleep(50 * time.Millisecond)
	if up.hits.Load() != n {
		t.Fatal("a failed refresh was retried at once")
	}
	_ = p
}

// a failed refresh is tried again at a later hit, after the pause, while the entry is still there
func TestPrefetchRetryPause(t *testing.T) {
	c := newRespCache(1000, 3600)
	d := defaultDNS()
	d.CachePrefetch, d.CachePrefetchPercent, d.CachePrefetchHits = true, 40, 1
	c.setPrefetch(d)
	clock := time.Now()
	c.now = func() time.Time { return clock }
	q := cacheQuery("retry.example", 1, nil)
	var qi qinfo
	parseQuestion(q, &qi)
	kb, ok := c.keyBytes(nil, q, &qi, false, mustAddr("192.0.2.1"), false, 24, 56)
	if !ok {
		t.Fatal("not cacheable")
	}
	key := string(kb)
	c.put(key, reply(q, 0, 1)) // TTL 60
	end := qi.nameEnd + 4
	if r, pf := c.getBytesPF(kb, q, end, true); r == nil || pf {
		t.Fatalf("fresh: %v %v", r != nil, pf)
	}
	clock = clock.Add(40 * time.Second) // 20 s left of 60: under 40 %
	if _, pf := c.getBytesPF(kb, q, end, false); pf {
		t.Fatal("a query that cannot be refreshed was offered for it")
	}
	if _, pf := c.getBytesPF(kb, q, end, true); !pf {
		t.Fatal("should refresh now")
	}
	if _, pf := c.getBytesPF(kb, q, end, true); pf {
		t.Fatal("a refresh is on its way: not twice")
	}
	c.endPrefetch(key, false)
	clock = clock.Add(5 * time.Second)
	if _, pf := c.getBytesPF(kb, q, end, true); pf {
		t.Fatal("retried within the pause")
	}
	clock = clock.Add(6 * time.Second) // 11 s after the failure, the entry has 9 s left
	if _, pf := c.getBytesPF(kb, q, end, true); !pf {
		t.Fatal("not retried after the pause")
	}
}

func TestPrefetchOffByDefaultAndSettings(t *testing.T) {
	fe, p, up, clock := prefetchRig(t, false)
	cl := mustAddr("192.0.2.5")
	q := cacheQuery("off.example", 1, nil)
	fe.resolve(q, false, cl)
	base := up.hits.Load()
	*clock = clock.Add(57 * time.Second)
	for i := 0; i < 5; i++ {
		fe.resolve(q, false, cl)
	}
	time.Sleep(50 * time.Millisecond)
	if up.hits.Load() != base || p.cache.Prefetched.Load() != 0 {
		t.Fatal("prefetch ran while switched off")
	}
	d := defaultDNS()
	d.CachePrefetchPercent = 51
	if d.Validate() == nil {
		t.Fatal("percent 51")
	}
	d.CachePrefetchPercent, d.CachePrefetchHits = 50, 1001
	if d.Validate() == nil {
		t.Fatal("hits 1001")
	}
	d.CachePrefetchPercent, d.CachePrefetchHits = 25, 3
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.CachePrefetch = true
	c := newRespCache(1000, 3600)
	c.setPrefetch(d)
	if c.pfPct.Load() != 25 || c.pfHits.Load() != 3 {
		t.Fatal("settings not applied")
	}
	d.CachePrefetchPercent, d.CachePrefetchHits = 0, 0
	c.setPrefetch(d)
	if c.pfPct.Load() != cachePrefetchDefaultPercent || c.pfHits.Load() != cachePrefetchDefaultHits {
		t.Fatal("defaults not applied")
	}
	d.CachePrefetch = false
	c.setPrefetch(d)
	if c.pfPct.Load() != 0 {
		t.Fatal("not switched off")
	}
}

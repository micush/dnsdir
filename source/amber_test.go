package main

import "testing"

// failTest gives server i of p a failing probe domain, which makes it amber.
func failTest(p *Pool, i int) {
	s := p.servers[i]
	s.mu.Lock()
	s.tests = []TestStat{{Name: "a.example", Type: "A", OK: true}, {Name: "b.example", Type: "A", OK: false}}
	s.mu.Unlock()
	p.rankGen.Add(1)
}

// A server that is up with a probe domain failing (amber) is tried only after the green ones, even when it is faster,
// and takes no turn at the front of the spread band while a green server is up.
func TestAmberServerComesAfterGreen(t *testing.T) {
	cfg := testDNSCfg("127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3")
	cfg.Spread = false
	p := NewPool(cfg)
	setLatency(p, 5, 20, 30)
	failTest(p, 0)
	if c := p.Candidates(); names(c) != "127.0.0.1:2 127.0.0.1:3 127.0.0.1:1 " {
		t.Fatalf("amber server must be last: %s", names(c))
	}

	cfg.Spread = true
	p = NewPool(cfg)
	setLatency(p, 10, 11, 12)
	failTest(p, 0)
	first := map[string]int{}
	for i := 0; i < 20; i++ {
		c := p.Candidates()
		if len(c) != 3 || c[2].Addr != "127.0.0.1:1" {
			t.Fatalf("amber server must stay last: %s", names(c))
		}
		first[c[0].Addr]++
	}
	if first["127.0.0.1:2"] != 10 || first["127.0.0.1:3"] != 10 || first["127.0.0.1:1"] != 0 {
		t.Fatalf("turns = %v", first)
	}

	// with no green server up the amber one is used, in latency order
	p = NewPool(testDNSCfg("127.0.0.1:1", "127.0.0.1:2"))
	setLatency(p, 30, 10)
	failTest(p, 0)
	failTest(p, 1)
	if c := p.Candidates(); names(c) != "127.0.0.1:2 127.0.0.1:1 " {
		t.Fatalf("all amber: %s", names(c))
	}
}

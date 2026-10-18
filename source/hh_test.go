package main

import (
	"strings"
	"testing"
)

func TestHelloNotLargerThanHold(t *testing.T) {
	g := defaultGroup()
	if g.HelloMS != 150 || g.HoldMS != 750 {
		t.Fatalf("defaults %d/%d, want 150/750", g.HelloMS, g.HoldMS)
	}
	g.HelloMS, g.HoldMS = 800, 750
	dc := newDaemonConfig()
	dc.Groups = []GroupConfig{g}
	if err := dc.Validate(); err == nil || !strings.Contains(err.Error(), "hello_ms") {
		t.Fatalf("hello above hold accepted: %v", err)
	}
	dc.Groups[0].HelloMS = 750
	if err := dc.Validate(); err != nil {
		t.Fatalf("hello equal to hold refused: %v", err)
	}
}

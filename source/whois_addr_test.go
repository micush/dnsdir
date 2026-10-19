package main

import (
	"strings"
	"testing"
)

func TestWhoisWithAddrs(t *testing.T) {
	// a name with no whois record (it is not under a registered domain) still gets its addresses, from this machine's resolver
	w, err := whoisWithAddrs("localhost.")
	if err != nil {
		t.Fatal(err)
	}
	if w.Found || w.Name != "localhost" || w.IPv4 != "127.0.0.1" {
		t.Fatalf("%+v", w)
	}
	if txt := w.Text(); !strings.HasPrefix(txt, "localhost\nIPv4: 127.0.0.1\n") {
		t.Fatalf("text:\n%s", txt)
	}
	if _, err := whoisWithAddrs(" "); err == nil {
		t.Fatal("empty name accepted")
	}
}

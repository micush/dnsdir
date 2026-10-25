package main

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func tcpUp(port int) bool {
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// With listen_local on, the node answers on its own interface addresses (not on a gateway's); off closes them.
func TestListenLocalFollowsTheSettingAndTheInterfaces(t *testing.T) {
	port := freeUDPPort(t)
	old := localAddrsFn
	t.Cleanup(func() { localAddrsFn = old })
	addrs := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.5")}
	localAddrsFn = func() []netip.Addr { return addrs }

	dc := newDaemonConfig()
	dc.Groups = nil
	dc.DNS.ListenPort = port
	dc.DNS.ListenLocal = true
	s := NewSupervisor(context.Background(), dc)
	t.Cleanup(s.stopLocal)

	set := func() { s.mu.Lock(); s.dc = dc.effective(); s.mu.Unlock(); s.reconcileLocal() }
	set()
	if !tcpUp(port) {
		t.Fatal("not listening on the node's own address")
	}
	if n := len(s.localListenerNames()); n != 2 {
		t.Fatalf("listeners %v, want 2", s.localListenerNames())
	}

	// an address that belongs to a gateway is left to the gateway
	g := defaultGroup()
	g.VIP4 = "127.0.0.5/24"
	dc.Groups = []GroupConfig{g}
	set()
	if n := len(s.localListenerNames()); n != 1 {
		t.Fatalf("listeners %v, want only the address that is not a gateway's", s.localListenerNames())
	}

	// an address that goes away is closed
	addrs = nil
	set()
	if tcpUp(port) || len(s.localListenerNames()) != 0 {
		t.Fatal("still listening after the address went away")
	}

	// switched off
	addrs = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	set()
	if !tcpUp(port) {
		t.Fatal("not listening again")
	}
	dc.DNS.ListenLocal = false
	set()
	if tcpUp(port) {
		t.Fatal("still listening with the setting off")
	}
}

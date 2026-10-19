package main

import "testing"

func TestLearnPeerAddrs(t *testing.T) {
	p := ClusterPeer{Addr: "ns2:12381", Fp: "f", NodeID: "n", Alts: []string{"10.0.0.9:12381", "ns2.lan:12381"}}
	np, ok := learnPeerAddrs(p, []string{"192.168.5.55", "fdf5:168:5::55"})
	if !ok {
		t.Fatal("new addresses must be learned")
	}
	want := []string{"192.168.5.55:12381", "[fdf5:168:5::55]:12381", "ns2.lan:12381"}
	if len(np.Alts) != len(want) {
		t.Fatalf("got %v", np.Alts)
	}
	for i := range want {
		if np.Alts[i] != want[i] {
			t.Fatalf("got %v, want %v", np.Alts, want)
		}
	}
	if _, ok := learnPeerAddrs(np, []string{"192.168.5.55", "fdf5:168:5::55"}); ok {
		t.Fatal("nothing changed, nothing to save")
	}
	if _, ok := learnPeerAddrs(np, nil); ok {
		t.Fatal("no report, no change")
	}
}

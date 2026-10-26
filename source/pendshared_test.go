package main

import (
	"testing"
	"time"
)

// A replica whose change to the shared settings was accepted by the primary at revision N must not take an older state
// from the primary meanwhile: it would show the old values again until revision N arrives.
func TestReplicaIgnoresOlderSharedStateAfterItsOwnChange(t *testing.T) {
	e := newWebEnv(t)
	cur, _, err := e.mg.LiveConfig()
	if err != nil {
		t.Fatal(err)
	}
	sh := sharedOf(cur)
	sh.DNS.RandomizeCase = true // what the primary will have after the change
	old := sharedOf(cur)

	e.mg.pendShared.rev, e.mg.pendShared.until = 7, time.Now().Add(time.Minute)
	e.mg.applyClusterShared(old, nil, 6, "primary") // still the old state, one revision behind
	if got, _, _ := e.mg.LiveConfig(); got.DNS.RandomizeCase || e.mg.pendShared.rev != 7 {
		t.Fatal("an older state was applied, or the wait ended early")
	}
	e.mg.applyClusterShared(sh, nil, 7, "primary") // the state with the change
	if got, _, _ := e.mg.LiveConfig(); !got.DNS.RandomizeCase {
		t.Fatal("the new state was not applied")
	}
	if e.mg.pendShared.rev != 0 {
		t.Fatal("the wait did not end")
	}
	// the wait does not last for ever
	e.mg.pendShared.rev, e.mg.pendShared.until = 9, time.Now().Add(-time.Second)
	e.mg.applyClusterShared(old, nil, 8, "primary")
	if got, _, _ := e.mg.LiveConfig(); got.DNS.RandomizeCase {
		t.Fatal("after the wait an older state must apply again")
	}
}

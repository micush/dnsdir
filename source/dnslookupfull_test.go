package main

import "testing"

func TestLookupFullKinds(t *testing.T) {
	r, err := lookupFull("127.0.0.1")
	if err != nil || r.Kind != "address" || r.Text == "" {
		t.Fatalf("address: %+v %v", r, err)
	}
	r, err = lookupFull("localhost")
	if err != nil || r.Kind != "name" || r.Text == "" {
		t.Fatalf("name: %+v %v", r, err)
	}
	if _, err := lookupFull("not a name!"); err == nil {
		t.Fatal("a bad name was accepted")
	}
}

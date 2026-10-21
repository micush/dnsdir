package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fill adds pairs to the units first..last: three clients, five names, two answer kinds.
func fillPairs(p *pairStore, first, last int64) {
	for u := first; u <= last; u++ {
		t := u * 600
		for i := 0; i < 6; i++ {
			p.add(t+int64(i), i%2, fmt.Sprintf("10.0.0.%d", i%3), fmt.Sprintf("n%d.example", (int(u)+i)%5), uint32(1+i))
		}
	}
}

// the answer a plain scan of the unit files gives, which is what the roll-ups must reproduce
func scanLookup(p *pairStore, from, to int64, kind int, cset, dset map[string]bool) (map[string]uint64, map[string]uint64) {
	dom, cli := map[string]uint64{}, map[string]uint64{}
	p.scan(from, to, func(k int, c, name string, v uint32) {
		if kind >= 0 && k != kind {
			return
		}
		if cset[c] {
			dom[name] += uint64(v)
		}
		if dset[name] {
			cli[c] += uint64(v)
		}
	})
	return dom, cli
}

func TestPairRollupsAnswerTheSameAndAreFewer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pairs")
	p := newPairStore()
	p.setDir(dir)
	first := int64(20000) * pairDayUnits / 100 // a unit that is not on a day boundary
	first = (first/pairDayUnits)*pairDayUnits + 30
	last := first + 3*pairDayUnits + 11
	fillPairs(p, first, last)
	p.saveOpen()

	type q struct {
		from, to int64
		kind     int
		c, d     map[string]bool
	}
	cs, ds := map[string]bool{"10.0.0.1": true, "10.0.0.2": true}, map[string]bool{"n3.example": true}
	qs := []q{
		{first, last, -1, cs, ds},
		{first, last, 1, cs, nil},
		{(first/pairHourUnits + 2) * pairHourUnits, (last/pairHourUnits)*pairHourUnits - 1, 0, nil, ds}, // whole hours, as the hourly tier asks
		{(first/pairDayUnits + 1) * pairDayUnits, (first/pairDayUnits+2)*pairDayUnits - 1, -1, cs, ds},  // exactly one day
		{last - 3, last, -1, cs, ds},
		{last - 5, last - 5, -1, cs, ds}, // one recent unit: the 10-minute tier
		{last - 40, last - 2, 1, cs, ds},
	}
	want := make([][2]map[string]uint64, len(qs))
	for i, x := range qs {
		want[i][0], want[i][1] = scanLookup(p, x.from, x.to, x.kind, x.c, x.d)
		if len(want[i][0])+len(want[i][1]) == 0 {
			t.Fatalf("query %d finds nothing: the test is empty", i)
		}
	}
	units := func() (n int) {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".gz") {
				n++
			}
		}
		return
	}
	before := units()
	now := last + 1
	p.rollup(now)
	names := map[byte]int{}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if k, _, ok := parseAnyPairName(e.Name()); ok {
			names[k]++
		}
	}
	if names['h'] == 0 || names['d'] < 2 {
		t.Fatalf("roll-up made %v", names)
	}
	if after := units(); after >= before {
		t.Fatalf("files before %d, after %d", before, after)
	}
	// unit files of the last 26 hours are still there, older ones are gone
	if _, err := os.Stat(filepath.Join(dir, pairUnitName(last-3))); err != nil {
		t.Errorf("a recent unit file was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, pairUnitName(first+2))); err == nil {
		t.Errorf("an old unit file was kept")
	}
	for round := 0; round < 2; round++ { // the second round answers from the remembered results
		for i, x := range qs {
			d, c := p.lookup(x.from, x.to, now, x.kind, x.c, x.d)
			if !reflect.DeepEqual(d, want[i][0]) && !(len(d) == 0 && len(want[i][0]) == 0) || !reflect.DeepEqual(c, want[i][1]) && !(len(c) == 0 && len(want[i][1]) == 0) {
				t.Errorf("round %d query %d: got %v / %v, want %v / %v", round, i, d, c, want[i][0], want[i][1])
			}
		}
	}
	// a second roll-up changes nothing
	n1 := units()
	p.rollup(now)
	if n2 := units(); n2 != n1 {
		t.Errorf("a second roll-up changed the files: %d → %d", n1, n2)
	}
}

func TestPairLookupSeesTheOpenUnitAndForgetsOnClear(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pairs")
	p := newPairStore()
	p.setDir(dir)
	u := int64(50000)
	p.add(u*600, 0, "10.0.0.1", "a.example", 2)
	p.add((u+1)*600, 0, "10.0.0.1", "a.example", 3) // finishes unit u, opens u+1
	cs := map[string]bool{"10.0.0.1": true}
	d, _ := p.lookup(u, u+1, u+1, -1, cs, nil)
	if d["a.example"] != 5 {
		t.Fatalf("with the open unit: %v", d)
	}
	p.add((u+1)*600+1, 0, "10.0.0.1", "a.example", 4)
	d, _ = p.lookup(u, u+1, u+1, -1, cs, nil)
	if d["a.example"] != 9 {
		t.Fatalf("the open unit must not be remembered: %v", d)
	}
	if d, _ := p.lookup(u, u+1, u+10, 3, cs, nil); len(d) != 0 {
		t.Fatalf("another answer kind: %v", d)
	}
	p.clear()
	if d, _ := p.lookup(u, u+1, u+1, -1, cs, nil); len(d) != 0 {
		t.Fatalf("after clear: %v", d)
	}
}

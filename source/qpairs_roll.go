package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Reading the pairs fast.  Picking a client or a domain has to find its rows in every file of the range, and a file
// is a gzip stream with no way to jump to one client.  Three things keep that cheap:
//
//   - Roll-ups.  Once an hour is over, its six unit files are merged into one hour file (h<hour>.gz), and once a day
//     is over, its hour files into one day file (d<day>.gz).  Identical pairs add up, so the files are also smaller.
//     A range uses a day file for each whole day it covers, an hour file for each whole hour, and unit files only for
//     the rest.  The unit files of an hour that is merged are deleted after pairKeepUnits (the 10-minute tier of the
//     statistics reads 25 hours back); hour and day files are kept for the whole retention.
//   - A result per finished file.  What a file holds for one client or domain does not change once the file is
//     finished, so it is remembered (pairCacheMax entries at most); a refreshed page then reads only the unit still
//     being filled.
//   - One pass over a file that compares the raw bytes of its strings with what was picked (no string is made for the
//     rest), several files at once.
//
// A merged file keeps up to pairHourRows / pairDayRows pairs; a flood beyond that shows as "(others)" like before.

const (
	pairHourUnits = 6
	pairDayUnits  = 144
	pairKeepUnits = 26 * 6 // unit files kept after their hour is merged
	pairCacheMax  = 1 << 20
	rollHoursMax  = 240 // hours merged in one pass (a backlog is worked off over several passes)
	rollDaysMax   = 40
)

func pairUnitName(u int64) string { return "p" + strconv.FormatInt(u, 10) + ".gz" }
func pairHourName(h int64) string { return "h" + strconv.FormatInt(h, 10) + ".gz" }
func pairDayName(d int64) string  { return "d" + strconv.FormatInt(d, 10) + ".gz" }

// pairHit is what one file holds for the picked clients and domains.
type pairHit struct {
	dom, cli map[string]uint64 // what the picked clients asked for; who asked for the picked domains
}

func (h *pairHit) size() int { return len(h.dom) + len(h.cli) + 1 }

// pairRef is one file (or the open unit) a lookup reads.
type pairRef struct {
	name  string // file name; empty for the open unit
	unit  int64  // for a unit
	final bool   // finished: its result can be remembered
}

func (p *pairStore) dropCache() {
	p.cmu.Lock()
	p.cache, p.cacheN = nil, 0
	p.cmu.Unlock()
}

func (p *pairStore) listing() map[string]bool {
	out := map[string]bool{}
	if p.dir == "" {
		return out
	}
	ents, _ := os.ReadDir(p.dir)
	for _, e := range ents {
		out[e.Name()] = true
	}
	return out
}

// plan lists the files that cover units from..to: a day file for each whole day, an hour file for each whole hour,
// the unit files for the rest.  nowUnit is the unit the clock is in.
func (p *pairStore) plan(from, to, nowUnit int64, have map[string]bool, curUnit int64, curOK bool) []pairRef {
	var refs []pairRef
	for d := from / pairDayUnits; d <= to/pairDayUnits; d++ {
		ds, de := d*pairDayUnits, d*pairDayUnits+pairDayUnits-1
		if from <= ds && de <= to && have[pairDayName(d)] {
			refs = append(refs, pairRef{name: pairDayName(d), final: true})
			continue
		}
		for h := max(from, ds) / pairHourUnits; h <= min(to, de)/pairHourUnits; h++ {
			hs, he := h*pairHourUnits, h*pairHourUnits+pairHourUnits-1
			if from <= hs && he <= to && have[pairHourName(h)] {
				refs = append(refs, pairRef{name: pairHourName(h), final: true})
				continue
			}
			for u := max(from, hs); u <= min(to, he); u++ {
				if curOK && u == curUnit {
					refs = append(refs, pairRef{unit: u})
				} else if p.dir == "" || have[pairUnitName(u)] {
					refs = append(refs, pairRef{name: pairUnitName(u), unit: u, final: u < nowUnit-1})
				}
			}
		}
	}
	return refs
}

func setKey(m map[string]bool) string {
	if m == nil {
		return ""
	}
	l := make([]string, 0, len(m))
	for k := range m {
		l = append(l, k)
	}
	sort.Strings(l)
	return strings.Join(l, "\x00")
}

// lookup adds up, over units from..to, what the picked clients (cset) asked for and who asked for the picked
// domains (dset), limited to one answer kind (kind, -1 for all).
func (p *pairStore) lookup(from, to, nowUnit int64, kind int, cset, dset map[string]bool) (dom, cli map[string]uint64) {
	dom, cli = map[string]uint64{}, map[string]uint64{}
	have := p.listing()
	p.mu.Lock()
	curUnit, curOK := int64(0), false
	if p.cur != nil {
		curUnit, curOK = p.cur.unit, true
	}
	p.mu.Unlock()
	refs := p.plan(from, to, nowUnit, have, curUnit, curOK)
	sel := strconv.Itoa(kind) + "|" + setKey(cset) + "|" + setKey(dset)

	var mu sync.Mutex
	merge := func(h *pairHit) {
		mu.Lock()
		for k, v := range h.dom {
			dom[k] += v
		}
		for k, v := range h.cli {
			cli[k] += v
		}
		mu.Unlock()
	}
	one := func(r pairRef) {
		if r.name == "" { // the open unit, from memory
			h := &pairHit{dom: map[string]uint64{}, cli: map[string]uint64{}}
			p.mu.Lock()
			if p.cur != nil && p.cur.unit == r.unit {
				p.cur.each(func(k int, c, name string, v uint32) {
					if kind >= 0 && k != kind {
						return
					}
					if cset[c] {
						h.dom[name] += uint64(v)
					}
					if dset[name] {
						h.cli[c] += uint64(v)
					}
				})
			}
			p.mu.Unlock()
			merge(h)
			return
		}
		key := r.name + "|" + sel
		if r.final {
			p.cmu.Lock()
			h := p.cache[key]
			p.cmu.Unlock()
			if h != nil {
				merge(h)
				return
			}
		}
		var b []byte
		if p.dir == "" {
			p.mu.Lock()
			b = p.mem[r.unit]
			p.mu.Unlock()
		} else if bb, err := os.ReadFile(filepath.Join(p.dir, r.name)); err == nil {
			b = bb
		}
		if b == nil {
			return
		}
		h := filterPairs(b, kind, cset, dset)
		if r.final {
			p.cmu.Lock()
			if p.cache == nil || p.cacheN+h.size() > pairCacheMax {
				p.cache, p.cacheN = map[string]*pairHit{}, 0
			}
			p.cache[key] = h
			p.cacheN += h.size()
			p.cmu.Unlock()
		}
		merge(h)
	}
	workers := min(runtime.GOMAXPROCS(0), len(refs))
	if workers <= 1 {
		for _, r := range refs {
			one(r)
		}
		return dom, cli
	}
	ch := make(chan pairRef)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range ch {
				one(r)
			}
		}()
	}
	for _, r := range refs {
		ch <- r
	}
	close(ch)
	wg.Wait()
	return dom, cli
}

// filterPairs reads a file once and keeps what the picked clients asked for and who asked for the picked domains.  It
// compares the raw bytes of each string with the picked sets, so no string is made for the rest.  A damaged file gives
// what was read before the damage.
func filterPairs(b []byte, kind int, cset, dset map[string]bool) *pairHit {
	hit := &pairHit{dom: map[string]uint64{}, cli: map[string]uint64{}}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return hit
	}
	raw, _ := io.ReadAll(io.LimitReader(zr, pairMaxRead))
	if len(raw) < len(pairMagic) || string(raw[:len(pairMagic)]) != pairMagic {
		return hit
	}
	pos := len(pairMagic)
	uv := func() (uint64, bool) {
		v, n := binary.Uvarint(raw[pos:])
		if n <= 0 {
			return 0, false
		}
		pos += n
		return v, true
	}
	ns, ok := uv()
	if !ok || ns > pairRollStrs {
		return hit
	}
	off, ln := make([]uint32, ns), make([]uint32, ns)
	cwant, dwant := make([]bool, ns), make([]bool, ns)
	for i := range off {
		l, ok := uv()
		if !ok || l > 1024 || pos+int(l) > len(raw) {
			return hit
		}
		off[i], ln[i] = uint32(pos), uint32(l)
		s := raw[pos : pos+int(l)]
		cwant[i] = cset != nil && cset[string(s)] // a lookup with a converted slice makes no copy
		dwant[i] = dset != nil && dset[string(s)]
		pos += int(l)
	}
	str := func(i uint64) string { return string(raw[off[i] : off[i]+ln[i]]) }
	nr, ok := uv()
	if !ok || nr > pairDayRows {
		return hit
	}
	for i := uint64(0); i < nr; i++ {
		if pos >= len(raw) {
			break
		}
		k := int(raw[pos])
		pos++
		ci, ok1 := uv()
		ni, ok2 := uv()
		n, ok3 := uv()
		if !ok1 || !ok2 || !ok3 || ci >= ns || ni >= ns || k >= qcCount {
			break
		}
		if kind >= 0 && k != kind {
			continue
		}
		if cwant[ci] {
			hit.dom[str(ni)] += n
		}
		if dwant[ni] {
			hit.cli[str(ci)] += n
		}
	}
	return hit
}

// ── roll-ups ─────────────────────────────────────────────────────────────────

// mergeFiles adds up the files (by name) into one encoded file with room for maxRows pairs.
func (p *pairStore) mergeFiles(names []string, maxRows int) []byte {
	acc := newRollAcc(maxRows)
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(p.dir, n))
		if err != nil {
			continue
		}
		decodePairs(b, func(kind int, c, name string, v uint32) { acc.add(kind, c, name, v) })
	}
	if len(acc.rows) == 0 {
		return nil
	}
	return acc.encode()
}

// rollup merges finished hours and days into their files and deletes the unit files that are no longer read.  It
// runs in the background, one pass at a time; nowUnit is the unit the clock is in.  It is safe to call often.
func (p *pairStore) rollup(nowUnit int64) {
	if p.dir == "" || !p.rolling.CompareAndSwap(false, true) {
		return
	}
	defer p.rolling.Store(false)
	have := p.listing()
	units := map[int64][]string{} // hour → its unit files
	hours := map[int64]bool{}
	for n := range have {
		k, v, ok := parseAnyPairName(n)
		if !ok {
			continue
		}
		switch k {
		case 'p':
			units[v/pairHourUnits] = append(units[v/pairHourUnits], n)
		case 'h':
			hours[v] = true
		}
	}
	var todo []int64
	for h := range units {
		if (h+1)*pairHourUnits <= nowUnit-1 && !hours[h] {
			todo = append(todo, h)
		}
	}
	sort.Slice(todo, func(i, j int) bool { return todo[i] > todo[j] }) // the newest first: what is read most
	if len(todo) > rollHoursMax {
		todo = todo[:rollHoursMax]
	}
	for _, h := range todo {
		names := units[h]
		sort.Strings(names)
		if b := p.mergeFiles(names, pairHourRows); b != nil && p.putFile(pairHourName(h), b) {
			hours[h] = true
		}
	}
	// unit files of a merged hour that the 10-minute tier no longer reads
	for h, names := range units {
		if !hours[h] || (h+1)*pairHourUnits > nowUnit-pairKeepUnits {
			continue
		}
		for _, n := range names {
			os.Remove(filepath.Join(p.dir, n))
		}
	}
	// days
	days := map[int64][]string{}
	haveDay := map[int64]bool{}
	for n := range have {
		if k, v, ok := parseAnyPairName(n); ok && k == 'd' {
			haveDay[v] = true
		}
	}
	for h := range hours {
		d := h / (pairDayUnits / pairHourUnits)
		if !haveDay[d] && (d+1)*pairDayUnits <= nowUnit-1 {
			days[d] = append(days[d], pairHourName(h))
		}
	}
	for d := range days { // a day is merged only when none of its hours is still waiting for its own merge
		for h := d * (pairDayUnits / pairHourUnits); h < (d+1)*(pairDayUnits/pairHourUnits); h++ {
			if len(units[h]) > 0 && !hours[h] {
				delete(days, d)
				break
			}
		}
	}
	var dtodo []int64
	for d := range days {
		dtodo = append(dtodo, d)
	}
	sort.Slice(dtodo, func(i, j int) bool { return dtodo[i] > dtodo[j] })
	if len(dtodo) > rollDaysMax {
		dtodo = dtodo[:rollDaysMax]
	}
	for _, d := range dtodo {
		names := days[d]
		sort.Strings(names)
		if b := p.mergeFiles(names, pairDayRows); b != nil {
			p.putFile(pairDayName(d), b)
		}
	}
	if len(todo)+len(dtodo) > 0 {
		infof("statistics: merged %d hour(s) and %d day(s) of who-asked-what files", len(todo), len(dtodo))
	}
}

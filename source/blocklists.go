package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Block lists: well-known lists of domains to refuse (Configure ▸ DNS ▸ Resolution ▸ Block Lists), and a list of
// domains that are never refused (Always allow).
//
// Every node downloads the lists it is told to use, keeps the last good copy in its state directory (so a download that
// fails never empties a list, and a restart does not need the network), and holds the domains of all of them in one set
// in memory.  A listed domain blocks itself and every name below it.  The answer a blocked name gets is the one a
// policy row would give (null, nxdomain, nodata or refused).  The order for a query from a client is: the always-allow
// list, the policy rows (a row that answers or forwards decides, and a row that blocks is skipped for an allowed name),
// the block lists, then the servers.

const (
	blockDefaultHours = 24
	blockMaxLists     = 60
	blockMaxPerList   = 6_000_000  // domains in one list
	blockMaxTotal     = 10_000_000 // domains in all of them: the memory a node is willing to spend
	blockMaxBytes     = 512 << 20  // one download, after any compression the server applied
	blockMaxAllow     = 20000
)

// BlockListRef is one list in use: a list on offer (ID, and URL only to replace its address) or one of your own (Name and URL).
type BlockListRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

func (r BlockListRef) key() string {
	if r.ID != "" {
		return r.ID
	}
	h := sha1.Sum([]byte(r.URL))
	return "c-" + hex.EncodeToString(h[:5])
}

func (r BlockListRef) address() string {
	if r.URL != "" {
		return r.URL
	}
	if ci := catalogItem(r.ID); ci != nil {
		return ci.URL
	}
	return ""
}

func (r BlockListRef) title() string {
	if r.Name != "" {
		return r.Name
	}
	if ci := catalogItem(r.ID); ci != nil {
		return ci.Name
	}
	return r.key()
}

// validateBlocking checks and tidies the block list settings of a DNS block.
func (d *DNSConfig) validateBlocking() error {
	if len(d.BlockLists) > blockMaxLists {
		return fmt.Errorf("dns: at most %d block lists", blockMaxLists)
	}
	seen := map[string]bool{}
	for i := range d.BlockLists {
		r := &d.BlockLists[i]
		r.ID, r.Name, r.URL = strings.ToLower(strings.TrimSpace(r.ID)), strings.TrimSpace(r.Name), strings.TrimSpace(r.URL)
		if r.ID != "" {
			ci := catalogItem(r.ID)
			if ci == nil {
				return fmt.Errorf("dns: block list %q is not one of the lists on offer", r.ID)
			}
			r.Name = ""
			if r.URL == ci.URL {
				r.URL = ""
			}
		} else {
			if r.Name == "" || len([]rune(r.Name)) > 60 {
				return errors.New("dns: a block list of your own needs a name of at most 60 characters")
			}
			if r.URL == "" {
				return fmt.Errorf("dns: block list %q needs an address (URL)", r.Name)
			}
		}
		if r.URL != "" {
			u, err := url.Parse(r.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(r.URL) > 2000 {
				return fmt.Errorf("dns: block list address %q is not an http:// or https:// address", r.URL)
			}
		}
		if k := r.key(); seen[k] {
			return fmt.Errorf("dns: block list %q is listed twice", r.title())
		} else {
			seen[k] = true
		}
	}
	switch d.BlockAction {
	case "", polNull, polNXDomain, polNoData, polRefused:
	default:
		return fmt.Errorf("dns: block_action %q is not null, nxdomain, nodata or refused", d.BlockAction)
	}
	if d.BlockUpdateHours < 0 || d.BlockUpdateHours > 720 {
		return errors.New("dns: block_update_hours must be between 1 and 720 (0 = 24)")
	}
	al, err := normalizeAllow(d.AllowDomains)
	if err != nil {
		return err
	}
	d.AllowDomains = al
	return nil
}

// normalizeAllow turns the always-allow entries into plain lower case names (a leading "*." or "." is the same as none: a
// name covers everything below it), without duplicates.
func normalizeAllow(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		for _, f := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r' }) {
			n := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(f, "*"), "."), "."))
			if !validHostname(n) {
				return nil, fmt.Errorf("dns: always-allow entry %q is not a domain name like example.com", f)
			}
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	if len(out) > blockMaxAllow {
		return nil, fmt.Errorf("dns: at most %d always-allow entries", blockMaxAllow)
	}
	return out, nil
}

// nameSet is a set of domains; has says whether a name is one of them or below one.
type nameSet map[string]struct{}

func newNameSet(names []string) nameSet {
	if len(names) == 0 {
		return nil
	}
	s := make(nameSet, len(names))
	for _, n := range names {
		s[n] = struct{}{}
	}
	return s
}

func (s nameSet) has(name string) bool {
	if len(s) == 0 {
		return false
	}
	for {
		if _, ok := s[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}

// ---- reading a list ----

// blockLineNames calls emit for each domain a line of a block list names.  It reads hosts files ("0.0.0.0 example.com"),
// plain domain lists ("example.com", "*.example.com"), and the simple rules of ad-block lists ("||example.com^").  Comments
// and everything else are skipped, and so are single labels such as "localhost" (a list never blocks a whole top-level domain).
func blockLineNames(line string, emit func(string)) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	switch line[0] {
	case '#', '!', '[', ';', '-', '@':
		return
	}
	if i := strings.Index(line, " #"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	} else if i := strings.Index(line, "\t#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if strings.HasPrefix(line, "||") {
		rest := line[2:]
		end := strings.IndexAny(rest, "^$/|:?,")
		if end >= 0 && rest[end] != '^' {
			return // a rule about more than a domain
		}
		if end >= 0 {
			rest = rest[:end]
		}
		if strings.ContainsAny(rest, "*") {
			return
		}
		addBlockName(rest, emit)
		return
	}
	f := strings.Fields(line)
	switch {
	case len(f) == 1:
		addBlockName(f[0], emit)
	case len(f) >= 2:
		if _, err := netip.ParseAddr(f[0]); err != nil {
			return
		}
		for _, n := range f[1:] {
			if strings.HasPrefix(n, "#") {
				break
			}
			addBlockName(n, emit)
		}
	}
}

func addBlockName(n string, emit func(string)) {
	n = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(n, "*"), "."), ".")
	if n == "" || !strings.Contains(n, ".") {
		return
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return
	}
	n = strings.ToLower(n)
	if !validHostname(n) {
		return
	}
	emit(n)
}

// parseBlockList reads a whole list, calling emit for every domain; it stops with an error when there are more than limit.
func parseBlockList(r io.Reader, limit int, emit func(string)) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	n := 0
	var over bool
	for sc.Scan() {
		blockLineNames(sc.Text(), func(name string) {
			n++
			if n > limit {
				over = true
				return
			}
			emit(name)
		})
		if over {
			return n, fmt.Errorf("more than %d domains", limit)
		}
	}
	return n, sc.Err()
}

// ---- the manager ----

// blockSnap is what the forwarding path reads: every domain of every list in use, and the number (1-based) of the first
// list that has it.
type blockSnap struct {
	names map[string]uint8
	keys  []string
	hits  []*atomic.Int64
}

func (b *blockSnap) find(name string) int {
	for {
		if i, ok := b.names[name]; ok {
			return int(i) - 1
		}
		j := strings.IndexByte(name, '.')
		if j < 0 {
			return -1
		}
		name = name[j+1:]
	}
}

type blMeta struct {
	ETag     string `json:"etag,omitempty"`
	Modified string `json:"modified,omitempty"`
	OK       int64  `json:"ok,omitempty"`      // unix time of the last good download
	Tried    int64  `json:"tried,omitempty"`   // unix time of the last attempt
	Entries  int    `json:"entries,omitempty"` // domains in the copy on disk
	Err      string `json:"err,omitempty"`     // why the last attempt failed ("" if it did not)
	Fails    int    `json:"fails,omitempty"`   // failed attempts in a row
}

// BlockManager downloads, keeps and matches this node's block lists.
type BlockManager struct {
	dir    string
	client *http.Client
	jitter uint32 // spreads this node's updates in time, so the nodes do not all download together

	mu      sync.Mutex
	refs    []BlockListRef
	hours   int
	meta    map[string]*blMeta
	hitsOf  map[string]*atomic.Int64
	force   map[string]bool // lists to download now (Update now)
	loadErr string          // why the set in memory could not be built, "" if it could
	built   string          // the lists (and addresses) the set in memory was built from

	snap atomic.Pointer[blockSnap]
	kick chan struct{}
	stop chan struct{}
	once sync.Once
	done sync.WaitGroup
}

// theBlocks is this node's block list manager, read by the DNS pools.
var theBlocks atomic.Pointer[BlockManager]

// NewBlockManager makes a manager that keeps its files in dir.  Nothing runs until Apply is called.
func NewBlockManager(dir, nodeKey string) *BlockManager {
	h := fnv.New32a()
	h.Write([]byte(nodeKey))
	m := &BlockManager{
		dir: dir, jitter: h.Sum32(), meta: map[string]*blMeta{}, hitsOf: map[string]*atomic.Int64{}, force: map[string]bool{},
		kick: make(chan struct{}, 1), stop: make(chan struct{}),
		client: ipv4FirstClient(15 * time.Minute),
	}
	m.loadMeta()
	return m
}

func (m *BlockManager) metaPath() string { return filepath.Join(m.dir, "meta.json") }

func (m *BlockManager) loadMeta() {
	raw, err := os.ReadFile(m.metaPath())
	if err != nil {
		return
	}
	var mm map[string]*blMeta
	if json.Unmarshal(raw, &mm) == nil && mm != nil {
		m.meta = mm
	}
}

// saveMeta writes the notes about each list (m.mu held).
func (m *BlockManager) saveMeta() {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return
	}
	raw, _ := json.MarshalIndent(m.meta, "", " ")
	tmp := m.metaPath() + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		os.Rename(tmp, m.metaPath())
	}
}

func (m *BlockManager) filePath(key string) string { return filepath.Join(m.dir, key+".gz") }

// Apply tells the manager which lists to use and how often to refresh them.  It returns at once; the work is done in the background.
func (m *BlockManager) Apply(refs []BlockListRef, hours int) {
	if hours <= 0 {
		hours = blockDefaultHours
	}
	m.mu.Lock()
	m.refs = append([]BlockListRef(nil), refs...)
	m.hours = hours
	keep := map[string]bool{}
	for _, r := range refs {
		keep[r.key()] = true
		if m.hitsOf[r.key()] == nil {
			m.hitsOf[r.key()] = new(atomic.Int64)
		}
	}
	changed := false
	for k := range m.meta {
		if !keep[k] {
			delete(m.meta, k)
			os.Remove(m.filePath(k))
			changed = true
		}
	}
	for k := range m.hitsOf {
		if !keep[k] {
			delete(m.hitsOf, k)
		}
	}
	if changed {
		m.saveMeta()
	}
	m.mu.Unlock()
	m.once.Do(func() {
		m.done.Add(1)
		go m.loop()
	})
	m.poke()
}

func (m *BlockManager) poke() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// UpdateNow downloads one list (by its id) or, with "", every list now, in the background.
func (m *BlockManager) UpdateNow(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	for _, r := range m.refs {
		if id == "" || r.key() == id {
			m.force[r.key()] = true
			found = true
		}
	}
	if !found {
		if id == "" {
			return errors.New("no block list is switched on")
		}
		return fmt.Errorf("%q is not a block list in use", id)
	}
	m.poke()
	return nil
}

// Close stops the background work.
func (m *BlockManager) Close() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	m.done.Wait()
}

func (m *BlockManager) loop() {
	defer m.done.Done()
	defer recoverPanic("the block list updater")
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.cycle(context.Background())
		select {
		case <-m.stop:
			return
		case <-t.C:
		case <-m.kick:
		}
	}
}

// due says whether a list should be downloaded now (m.mu held).
func (m *BlockManager) due(r BlockListRef, hours int, now time.Time) bool {
	k := r.key()
	mt := m.meta[k]
	if m.force[k] {
		return true
	}
	if mt == nil {
		return true
	}
	if mt.Fails > 0 { // back off: 1, 2, 4, ... minutes, an hour at most
		wait := time.Minute << min(mt.Fails-1, 6)
		if wait > time.Hour {
			wait = time.Hour
		}
		return now.Sub(time.Unix(mt.Tried, 0)) >= wait
	}
	if mt.OK == 0 {
		return true
	}
	every := time.Duration(hours) * time.Hour
	every += time.Duration(int64(m.jitter%1000)) * every / 10000 // up to 10% later, differently on each node
	return now.Sub(time.Unix(mt.OK, 0)) >= every
}

// cycle does what is due: downloads, then (re)builds the set in memory if the lists changed.
func (m *BlockManager) cycle(ctx context.Context) {
	m.mu.Lock()
	refs := append([]BlockListRef(nil), m.refs...)
	hours := m.hours
	now := time.Now()
	var todo []BlockListRef
	for _, r := range refs {
		if m.due(r, hours, now) {
			todo = append(todo, r)
		}
	}
	m.mu.Unlock()
	for _, r := range todo {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-m.stop:
			return
		default:
		}
		m.fetch(ctx, r)
	}
	m.rebuildIfNeeded(refs)
}

// fetch downloads one list.  A failure leaves the copy on disk as it was.
func (m *BlockManager) fetch(ctx context.Context, r BlockListRef) {
	k := r.key()
	m.mu.Lock()
	delete(m.force, k)
	mt := m.meta[k]
	if mt == nil {
		mt = &blMeta{}
		m.meta[k] = mt
	}
	etag, mod := mt.ETag, mt.Modified
	have := false
	if _, err := os.Stat(m.filePath(k)); err == nil && mt.OK > 0 {
		have = true
	}
	m.mu.Unlock()

	entries, newTag, newMod, notModified, err := m.download(ctx, r, have, etag, mod)

	m.mu.Lock()
	defer m.mu.Unlock()
	mt = m.meta[k]
	if mt == nil { // dropped while it was downloading
		os.Remove(m.filePath(k))
		return
	}
	now := time.Now().Unix()
	mt.Tried = now
	switch {
	case err != nil:
		mt.Fails++
		mt.Err = err.Error()
		warnf("block lists: %s: %v", r.title(), err)
	case notModified:
		mt.Fails, mt.Err, mt.OK = 0, "", now
	default:
		mt.Fails, mt.Err, mt.OK, mt.Entries, mt.ETag, mt.Modified = 0, "", now, entries, newTag, newMod
		infof("block lists: %s: %d domains downloaded", r.title(), entries)
		m.built = "" // the set in memory is out of date
	}
	m.saveMeta()
}

func (m *BlockManager) download(ctx context.Context, r BlockListRef, have bool, etag, mod string) (entries int, newTag, newMod string, notModified bool, err error) {
	addr := r.address()
	if addr == "" {
		return 0, "", "", false, errors.New("no address")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return 0, "", "", false, err
	}
	req.Header.Set("User-Agent", "dnsdir block list updater")
	if have {
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		if mod != "" {
			req.Header.Set("If-Modified-Since", mod)
		}
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return 0, "", "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && have {
		return 0, etag, mod, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, "", "", false, fmt.Errorf("the server answered %s", resp.Status)
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return 0, "", "", false, err
	}
	tmp := m.filePath(r.key()) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, "", "", false, err
	}
	defer os.Remove(tmp)
	zw := gzip.NewWriter(f)
	bw := bufio.NewWriterSize(zw, 256<<10)
	n, perr := parseBlockList(io.LimitReader(resp.Body, blockMaxBytes), blockMaxPerList, func(name string) {
		bw.WriteString(name)
		bw.WriteByte('\n')
	})
	ferr := bw.Flush()
	if e := zw.Close(); ferr == nil {
		ferr = e
	}
	if e := f.Close(); ferr == nil {
		ferr = e
	}
	switch {
	case perr != nil:
		return 0, "", "", false, perr
	case ferr != nil:
		return 0, "", "", false, ferr
	case n == 0:
		return 0, "", "", false, errors.New("it holds no domains (is the address a list of domain names?)")
	}
	if err := os.Rename(tmp, m.filePath(r.key())); err != nil {
		return 0, "", "", false, err
	}
	return n, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), false, nil
}

// rebuildIfNeeded builds the set in memory from the copies on disk when the lists in use or a copy changed.
func (m *BlockManager) rebuildIfNeeded(refs []BlockListRef) {
	var sig strings.Builder
	m.mu.Lock()
	for _, r := range refs {
		mt := m.meta[r.key()]
		var ok int64
		if mt != nil {
			ok = mt.OK
		}
		fmt.Fprintf(&sig, "%s|%s|%d;", r.key(), r.address(), ok)
	}
	if m.built == sig.String() {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	names := map[string]uint8{}
	snap := &blockSnap{names: names}
	counts := map[string]int{}
	var loadErr string
	for _, r := range refs {
		k := r.key()
		f, err := os.Open(m.filePath(k))
		if err != nil {
			continue // not downloaded yet
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			os.Remove(m.filePath(k))
			continue
		}
		snap.keys = append(snap.keys, k)
		idx := uint8(len(snap.keys))
		n := 0
		sc := bufio.NewScanner(zr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			n++
			name := sc.Text()
			if _, ok := names[name]; !ok {
				if len(names) >= blockMaxTotal {
					loadErr = fmt.Sprintf("the lists hold more than %d domains in all: too many for this node's memory, switch some off", blockMaxTotal)
					break
				}
				names[name] = idx
			}
		}
		f.Close()
		counts[k] = n
		if loadErr != "" {
			break
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadErr = loadErr
	if loadErr != "" {
		warnf("block lists: %s", loadErr)
		return // keep what was in use
	}
	for _, k := range snap.keys {
		if h := m.hitsOf[k]; h != nil {
			snap.hits = append(snap.hits, h)
		} else {
			snap.hits = append(snap.hits, new(atomic.Int64))
		}
		if mt := m.meta[k]; mt != nil {
			mt.Entries = counts[k]
		}
	}
	m.snap.Store(snap)
	m.built = sig.String()
	if len(names) > 0 {
		infof("block lists: %d domains from %d lists in use", len(names), len(snap.keys))
	}
}

// Hit counts one blocked query for the list with this key.
func (m *BlockManager) Hit(key string) {
	m.mu.Lock()
	h := m.hitsOf[key]
	m.mu.Unlock()
	if h != nil {
		h.Add(1)
	}
}

// Lookup says which list (its key) has name, a lower case name without the final dot.
func (m *BlockManager) Lookup(name string) (string, bool) {
	s := m.snap.Load()
	if s == nil || len(s.names) == 0 {
		return "", false
	}
	if i := s.find(name); i >= 0 {
		return s.keys[i], true
	}
	return "", false
}

// BlockStatus is one list's state on this node.
type BlockStatus struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Custom  bool   `json:"custom,omitempty"`
	Entries int    `json:"entries"`
	Updated int64  `json:"updated,omitempty"` // unix time of the last good download
	Tried   int64  `json:"tried,omitempty"`
	Error   string `json:"error,omitempty"`
	Blocked int64  `json:"blocked"` // queries it has blocked since this node started
	Loaded  bool   `json:"loaded"`  // its domains are in use
}

// BlockReport is what the page and the command line show.
type BlockReport struct {
	Catalog []BlockCatalogItem `json:"catalog"`
	Lists   []BlockStatus      `json:"lists"`
	Domains int                `json:"domains"` // different domains in use, all lists together
	Error   string             `json:"error,omitempty"`
}

// Report is the state of every list in use.
func (m *BlockManager) Report() BlockReport {
	rep := BlockReport{Catalog: blockCatalog, Lists: []BlockStatus{}}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.snap.Load()
	loaded := map[string]bool{}
	if s != nil {
		rep.Domains = len(s.names)
		for _, k := range s.keys {
			loaded[k] = true
		}
	}
	rep.Error = m.loadErr
	for _, r := range m.refs {
		k := r.key()
		st := BlockStatus{ID: k, Name: r.title(), URL: r.address(), Custom: r.ID == "", Loaded: loaded[k]}
		if mt := m.meta[k]; mt != nil {
			st.Entries, st.Updated, st.Tried, st.Error = mt.Entries, mt.OK, mt.Tried, mt.Err
		}
		if h := m.hitsOf[k]; h != nil {
			st.Blocked = h.Load()
		}
		rep.Lists = append(rep.Lists, st)
	}
	return rep
}

// titleOf is the name of the list with this key, for the log.
func (m *BlockManager) titleOf(key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.refs {
		if r.key() == key {
			return r.title()
		}
	}
	return key
}

// BlockTest says what the block lists and the always-allow names do to a name.
type BlockTest struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"` // on the always-allow list
	List    string `json:"list,omitempty"`
	Title   string `json:"title,omitempty"`
	Action  string `json:"action"` // what a blocked name gets
}

// Text is the answer in a sentence.
func (t BlockTest) Text() string {
	switch {
	case t.Allowed && t.List != "":
		return fmt.Sprintf("%s is on the always-allow list, so %s does not block it", t.Name, t.Title)
	case t.Allowed:
		return fmt.Sprintf("%s is on the always-allow list; no block list has it", t.Name)
	case t.List != "":
		return fmt.Sprintf("%s is blocked by %s: it gets %s (a policy row for the name or the client is looked at first)", t.Name, t.Title, t.Action)
	}
	return fmt.Sprintf("%s is on no block list", t.Name)
}

// BlockTest checks a name against the always-allow names and the block lists in use on this node (policy rows are not looked at).
func (d DNSConfig) BlockTest(name string) BlockTest {
	t := BlockTest{Name: name, Allowed: newNameSet(d.AllowDomains).has(name), Action: d.BlockAction}
	if t.Action == "" {
		t.Action = polNull
	}
	if m := theBlocks.Load(); m != nil {
		if k, ok := m.Lookup(name); ok {
			t.List, t.Title = k, m.titleOf(k)
		}
	}
	return t
}

func printBlockReport(r BlockReport) {
	if len(r.Lists) == 0 {
		fmt.Println("no block list is switched on")
		return
	}
	for _, l := range r.Lists {
		st := "waiting for the first download"
		switch {
		case l.Error != "" && l.Entries > 0:
			st = "last download failed (" + l.Error + "); the older copy is in use"
		case l.Error != "":
			st = "download failed: " + l.Error
		case l.Updated > 0:
			st = "updated " + time.Unix(l.Updated, 0).Format("2006-01-02 15:04")
		}
		fmt.Printf("%-24s %-22s %9d domains  %8d blocked  %s\n", l.ID, l.Name, l.Entries, l.Blocked, st)
	}
	fmt.Printf("%d different domains in use\n", r.Domains)
	if r.Error != "" {
		fmt.Println("problem:", r.Error)
	}
}

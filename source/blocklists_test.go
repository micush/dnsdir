package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

func parsedNames(text string) []string {
	var out []string
	parseBlockList(strings.NewReader(text), 1000, func(n string) { out = append(out, n) })
	sort.Strings(out)
	return out
}

func TestBlockParseFormats(t *testing.T) {
	text := `# comment
! another
[Adblock Plus 2.0]
0.0.0.0 ads.example.com
127.0.0.1 localhost
0.0.0.0 a.example.net b.example.net # trailing
::1 ip6-localhost
plain.example.org
*.wild.example.org
||adblock.example.io^
||path.example.io/ads
||star*.example.io^
UPPER.Example.COM
192.168.1.1
tld
`
	got := strings.Join(parsedNames(text), " ")
	want := "a.example.net adblock.example.io ads.example.com b.example.net plain.example.org upper.example.com wild.example.org"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestBlockNameSetCoversSubdomains(t *testing.T) {
	s := newNameSet([]string{"example.com"})
	for n, want := range map[string]bool{"example.com": true, "a.b.example.com": true, "notexample.com": false, "com": false} {
		if s.has(n) != want {
			t.Errorf("has(%q) = %v", n, !want)
		}
	}
	if (nameSet)(nil).has("example.com") {
		t.Error("an empty set has a name")
	}
}

func TestBlockValidate(t *testing.T) {
	ok := DNSConfig{BlockLists: []BlockListRef{{ID: "HaGeZi-Pro"}, {Name: "mine", URL: "https://x.example/list.txt"}}, AllowDomains: []string{"*.Good.com", "good.com, other.org."}}
	if err := ok.validateBlocking(); err != nil {
		t.Fatal(err)
	}
	if ok.BlockLists[0].ID != "hagezi-pro" || strings.Join(ok.AllowDomains, " ") != "good.com other.org" {
		t.Fatalf("not tidied: %+v", ok)
	}
	for _, bad := range []DNSConfig{
		{BlockLists: []BlockListRef{{ID: "nope"}}},
		{BlockLists: []BlockListRef{{Name: "x"}}},
		{BlockLists: []BlockListRef{{Name: "x", URL: "ftp://x/y"}}},
		{BlockLists: []BlockListRef{{ID: "hagezi-pro"}, {ID: "hagezi-pro"}}},
		{BlockAction: "drop"},
		{BlockUpdateHours: 5000},
		{AllowDomains: []string{"bad name!"}},
	} {
		if err := bad.validateBlocking(); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

// listServer serves a list, and can be switched to fail.
func listServer(t *testing.T, body string) (*httptest.Server, *atomic.Bool, *atomic.Int64) {
	var fail atomic.Bool
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if fail.Load() {
			http.Error(w, "down", 503)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &fail, &hits
}

func testBlocks(t *testing.T, dir string, refs ...BlockListRef) *BlockManager {
	m := NewBlockManager(dir, "node")
	m.refs, m.hours = refs, 24
	for _, r := range refs {
		m.hitsOf[r.key()] = new(atomic.Int64)
	}
	return m
}

func TestBlockManagerKeepsLastGoodCopy(t *testing.T) {
	srv, fail, hits := listServer(t, "0.0.0.0 ads.example.com\ntrack.example.net\n")
	dir := t.TempDir()
	ref := BlockListRef{Name: "mine", URL: srv.URL + "/l.txt"}
	m := testBlocks(t, dir, ref)
	m.cycle(context.Background())
	if k, ok := m.Lookup("x.ads.example.com"); !ok || k != ref.key() {
		t.Fatalf("not loaded: %v %v", k, ok)
	}
	if r := m.Report(); len(r.Lists) != 1 || r.Lists[0].Entries != 2 || r.Domains != 2 || r.Lists[0].Error != "" {
		t.Fatalf("report %+v", r)
	}
	// an unchanged list answers 304: still good, nothing rewritten
	m.UpdateNow("")
	m.cycle(context.Background())
	if r := m.Report(); r.Lists[0].Error != "" || r.Lists[0].Entries != 2 {
		t.Fatalf("after 304: %+v", r.Lists[0])
	}
	// a failing server leaves the copy in use and says why
	fail.Store(true)
	m.UpdateNow("")
	m.cycle(context.Background())
	r := m.Report()
	if r.Lists[0].Error == "" || r.Lists[0].Entries != 2 || !r.Lists[0].Loaded {
		t.Fatalf("after failure: %+v", r.Lists[0])
	}
	if _, ok := m.Lookup("ads.example.com"); !ok {
		t.Fatal("the old copy was lost")
	}
	// a restart with the server gone loads the copy from disk
	n0 := hits.Load()
	m2 := testBlocks(t, dir, ref)
	m2.rebuildIfNeeded(m2.refs)
	if _, ok := m2.Lookup("track.example.net"); !ok {
		t.Fatal("not loaded from disk after a restart")
	}
	if hits.Load() != n0 {
		t.Fatal("a rebuild from disk went to the network")
	}
	// dropping a list from the settings drops its copy
	m2.Apply(nil, 24)
	m2.Close()
	m2.rebuildIfNeeded(nil)
	if _, ok := m2.Lookup("ads.example.com"); ok {
		t.Fatal("a list that is switched off still blocks")
	}
}

func TestBlockEmptyListIsRefused(t *testing.T) {
	srv, _, _ := listServer(t, "<html>not a list</html>\n")
	m := testBlocks(t, t.TempDir(), BlockListRef{Name: "x", URL: srv.URL})
	m.cycle(context.Background())
	if r := m.Report(); r.Lists[0].Error == "" || r.Lists[0].Loaded {
		t.Fatalf("%+v", r.Lists[0])
	}
}

func blockPool(t *testing.T, cfg DNSConfig, list string) *Pool {
	srv, _, _ := listServer(t, list)
	ref := BlockListRef{Name: "mine", URL: srv.URL}
	m := testBlocks(t, t.TempDir(), ref)
	m.cycle(context.Background())
	old := theBlocks.Swap(m)
	t.Cleanup(func() { theBlocks.Store(old) })
	cfg.BlockLists = []BlockListRef{ref}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return NewPool(cfg)
}

func TestBlockOrderAllowPolicyBlock(t *testing.T) {
	main := newFakeDNS(t)
	cfg := testDNSCfg(main.addr)
	cfg.AllowDomains = []string{"safe.ads.example"}
	cfg.Policy = []PolicyRule{
		{Client: "*", Name: "refuse.safe.ads.example", Servers: []string{"nxdomain"}},
		{Client: "*", Name: "dead.ads.example", Servers: []string{"nxdomain"}},
		{Client: "*", Name: "fwd.ads.example", Servers: []string{"192.0.2.53"}},
		{Client: "10.1.1.1", Name: "poolme.ads.example", Servers: []string{"pool"}},
	}
	p := blockPool(t, cfg, "ads.example\nother.example\n")
	cl := netip.MustParseAddr("10.9.9.9")
	look := func(c netip.Addr, name string) *policyRule {
		var qi qinfo
		parseQuestion(cacheQuery(name, 1, nil), &qi)
		return p.lookup(c, &qi)
	}
	if r := look(cl, "x.ads.example"); r == nil || !r.blockList || r.action != polNull {
		t.Fatalf("listed name: %+v", r)
	}
	if r := look(cl, "clean.example"); r != nil {
		t.Fatalf("unlisted name: %+v", r)
	}
	if r := look(cl, "www.safe.ads.example"); r != nil {
		t.Fatalf("allowed name was blocked: %+v", r)
	}
	if r := look(cl, "refuse.safe.ads.example"); r != nil {
		t.Fatalf("a blocking row beat the allow list: %+v", r)
	}
	if r := look(cl, "dead.ads.example"); r == nil || r.blockList || r.action != polNXDomain {
		t.Fatalf("a row for the name must come before the block list: %+v", r)
	}
	if r := look(cl, "fwd.ads.example"); r == nil || r.blockList || len(r.servers) == 0 {
		t.Fatalf("a forwarding row must beat the block list: %+v", r)
	}
	if r := look(netip.MustParseAddr("10.1.1.1"), "poolme.ads.example"); r == nil || r.action != polPool {
		t.Fatalf("a pool row must bypass the block list: %+v", r)
	}
	if r := look(netip.Addr{}, "x.ads.example"); r != nil {
		t.Fatal("a query the daemon makes itself was blocked")
	}
	if tr := cfg.BlockTest("www.safe.ads.example"); !tr.Allowed || tr.List == "" {
		t.Fatalf("test: %+v", tr)
	}
}

func TestBlockAnswersAndCounts(t *testing.T) {
	main := newFakeDNS(t)
	cfg := testDNSCfg(main.addr)
	cfg.ECS = false
	cfg.BlockAction = "nxdomain"
	cfg.AllowDomains = []string{"ok.ads.example"}
	p := blockPool(t, cfg, "ads.example\n")
	p.ProbeNow(context.Background())
	fe := NewDNSFrontend(mustAddr("127.0.0.2"), 0, func() *Pool { return p })
	fe.ctx, fe.cancel = context.WithCancel(context.Background())
	t.Cleanup(fe.cancel)
	m0 := main.hits.Load()
	resp := fe.resolve(cacheQuery("x.ads.example", 1, nil), false, mustAddr("10.9.9.9"))
	if h, _ := parseHeader(resp); h.rcode != rcodeNXDomain {
		t.Fatalf("rcode %d", h.rcode)
	}
	if main.hits.Load() != m0 {
		t.Fatal("a blocked name went to the servers")
	}
	if r := theBlocks.Load().Report(); r.Lists[0].Blocked != 1 {
		t.Fatalf("counted %d, want 1", r.Lists[0].Blocked)
	}
	fe.resolve(cacheQuery("ok.ads.example", 1, nil), false, mustAddr("10.9.9.9"))
	if main.hits.Load() == m0 {
		t.Fatal("an allowed name was not resolved")
	}
	if r := theBlocks.Load().Report(); r.Lists[0].Blocked != 1 {
		t.Fatalf("an allowed name was counted: %d", r.Lists[0].Blocked)
	}
}

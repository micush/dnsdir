package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeChrony replaces chronyc, the restart and the two directories for one test.
type fakeChrony struct {
	mu       sync.Mutex
	calls    [][]string
	restarts int
	reloadOK bool
	answers  map[string]string
}

func hookChrony(t *testing.T) *fakeChrony {
	t.Helper()
	f := &fakeChrony{reloadOK: true, answers: map[string]string{}}
	oc, or_, os_, oc2, om, ow := chronyc, chronyRestart, chronySourceDir, chronyConfDir, chrony, chronyServingFn
	chronySourceDir, chronyConfDir = t.TempDir(), t.TempDir()
	chrony = &chronyMgr{warned: map[string]time.Time{}}
	chronyc = func(args ...string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, args)
		key := strings.Join(args, " ")
		if key == "reload sources" {
			if !f.reloadOK {
				return nil, errors.New("chronyc: 506 Cannot talk to daemon")
			}
			return []byte("200 OK\n"), nil
		}
		if strings.HasPrefix(key, "deny ") || strings.HasPrefix(key, "allow ") {
			return []byte("200 OK\n"), nil
		}
		if a, ok := f.answers[key]; ok {
			return []byte(a), nil
		}
		return nil, errors.New("chronyc: no such answer: " + key)
	}
	chronyRestart = func() error { f.mu.Lock(); f.restarts++; f.mu.Unlock(); return nil }
	t.Cleanup(func() {
		chronyc, chronyRestart, chronySourceDir, chronyConfDir, chrony, chronyServingFn = oc, or_, os_, oc2, om, ow
	})
	return f
}

func (f *fakeChrony) reloads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Join(c, " ") == "reload sources" {
			n++
		}
	}
	return n
}

func TestChronyServerLine(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1":              "server 10.0.0.1 iburst",
		"10.0.0.1:123":          "server 10.0.0.1 iburst",
		"10.0.0.1:1123":         "server 10.0.0.1 port 1123 iburst",
		"[2001:db8::1]:123":     "server 2001:db8::1 iburst",
		"[2001:db8::1]:1123":    "server 2001:db8::1 port 1123 iburst",
		"2001:db8::1":           "server 2001:db8::1 iburst",
		"ntp.example.com:123":   "server ntp.example.com iburst",
		"time-1.example.org":    "server time-1.example.org iburst",
		"ntp.example.com:40000": "server ntp.example.com port 40000 iburst",
	} {
		got, err := chronyServerLine(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	// nothing that could add a second line or an option reaches chrony's file
	for _, bad := range []string{"", "a b", "a\nserver evil", "host;rm", "10.0.0.1:99999", "10.0.0.1:0", "x:y:z", "a#b", "[::1%eth0]:123"} {
		if got, err := chronyServerLine(bad); err == nil {
			t.Errorf("%q accepted: %q", bad, got)
		}
	}
}

func TestChronySourcesFileIsSortedAndDeduplicated(t *testing.T) {
	got, err := chronySourcesFile([]string{"10.0.0.2:123", "10.0.0.1", "10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	want := chronyHeader + "server 10.0.0.1 iburst\nserver 10.0.0.2 iburst\n"
	if got != want {
		t.Fatalf("got %q", got)
	}
	if _, err := chronySourcesFile([]string{"10.0.0.1", "bad host"}); err == nil {
		t.Fatal("a bad server was written")
	}
}

func readSources(t *testing.T) string {
	b, err := os.ReadFile(filepath.Join(chronySourceDir, "ntpdir.sources"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplySourcesWritesOnceAndReloads(t *testing.T) {
	f := hookChrony(t)
	m := chrony
	if err := m.applySources([]string{"10.0.0.2", "10.0.0.1"}, false); err != nil {
		t.Fatal(err)
	}
	if got := readSources(t); !strings.Contains(got, "server 10.0.0.1 iburst\nserver 10.0.0.2 iburst\n") {
		t.Fatalf("file: %q", got)
	}
	if f.reloads() != 1 {
		t.Fatalf("reloads = %d", f.reloads())
	}
	// the same set again: nothing written, chrony not asked again
	if err := m.applySources([]string{"10.0.0.1", "10.0.0.2"}, false); err != nil || f.reloads() != 1 {
		t.Fatalf("same set: %v, reloads %d", err, f.reloads())
	}
	// a server drops out: it leaves the file and chrony is told
	if err := m.applySources([]string{"10.0.0.1"}, false); err != nil || f.reloads() != 2 {
		t.Fatalf("one left: %v, reloads %d", err, f.reloads())
	}
	if strings.Contains(readSources(t), "10.0.0.2") {
		t.Fatal("a server that failed is still a source")
	}
	// none tests good: chrony keeps what it has
	before := readSources(t)
	if err := m.applySources(nil, false); err != nil || readSources(t) != before || f.reloads() != 2 {
		t.Fatalf("nothing good must change nothing: %v", err)
	}
	// nothing is defined (all paused): chrony is left without sources
	if err := m.applySources(nil, true); err != nil || f.reloads() != 3 {
		t.Fatalf("empty: %v reloads %d", err, f.reloads())
	}
	if strings.Contains(readSources(t), "server") {
		t.Fatalf("file: %q", readSources(t))
	}
}

func TestApplySourcesRetriesAfterChronyWasDown(t *testing.T) {
	f := hookChrony(t)
	f.reloadOK = false
	m := chrony
	if err := m.applySources([]string{"10.0.0.1"}, false); err == nil {
		t.Fatal("a failed reload must be reported")
	}
	// the file is already right, but chrony never read it: the next round asks again
	f.reloadOK = true
	if err := m.applySources([]string{"10.0.0.1"}, false); err != nil || f.reloads() != 2 {
		t.Fatalf("retry: %v reloads %d", err, f.reloads())
	}
	if err := m.applySources([]string{"10.0.0.1"}, false); err != nil || f.reloads() != 2 {
		t.Fatalf("after success: %v reloads %d", err, f.reloads())
	}
}

func TestChronyConfBody(t *testing.T) {
	d := defaultNTP()
	got, err := chronyConfBody(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"port 123\n", "allow 127.0.0.0/8\n", "allow ::1\n", "allow all\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in %q", w, got)
		}
	}
	if strings.Contains(got, "ratelimit") {
		t.Errorf("rate limit without a rate: %q", got)
	}
	d.ListenPort = 1123
	d.AllowedClients = []string{"10.0.0.0/8", "192.168.1.5"}
	d.ClientRate, d.ClientBurst, d.ClientAction = 8, 20, actKoD
	got, err = chronyConfBody(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"port 1123\n", "allow 10.0.0.0/8\n", "allow 192.168.1.5/32\n", "ratelimit interval -3 burst 20 leak 2\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in %q", w, got)
		}
	}
	if strings.Contains(got, "allow all") {
		t.Errorf("a listed client set must not also allow everyone: %q", got)
	}
	d.ClientRate, d.ClientBurst, d.ClientAction = 1, 0, ""
	got, _ = chronyConfBody(d)
	if !strings.Contains(got, "ratelimit interval 0 burst 10 leak 4\n") {
		t.Errorf("rate 1: %q", got)
	}
}

func TestParseTrackingSourcesStatsClients(t *testing.T) {
	st, err := parseTracking([]byte("A9FE0101,ntp1.example.com,2,1760000000.123,0.000012345,-0.000001,0.000020,1.234,0.001,0.050,0.012,0.003,64.0,Normal\n"))
	if err != nil || !st.Running || !st.Synced || st.Stratum != 2 || st.Ref != "ntp1.example.com" || st.Leap != "Normal" {
		t.Fatalf("%+v %v", st, err)
	}
	if st.OffsetMS < 0.012 || st.OffsetMS > 0.013 || st.RootDelay != 12 || st.RootDisp != 3 {
		t.Fatalf("numbers: %+v", st)
	}
	st, err = parseTracking([]byte("00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised\n"))
	if err != nil || st.Synced || !st.Running {
		t.Fatalf("not synchronised: %+v %v", st, err)
	}
	if _, err := parseTracking([]byte("506 Cannot talk to daemon")); err == nil {
		t.Fatal("garbage accepted")
	}

	src := parseSources([]byte("^,*,10.0.0.1,2,6,377,12,0.000001,0.000002,0.000003\n^,?,10.0.0.2,0,6,0,4294967295,0.0,0.0,0.0\n^,x,ntp.example.com,2,6,17,1,0.0,0.0,0.0\n"))
	if len(src) != 3 || src[0].State != "*" || src[0].Reach != 8 || src[1].Reach != 0 || src[2].Reach != 4 {
		t.Fatalf("%+v", src)
	}
	cs := ChronyState{Sources: []ChronySrc{{Name: "10.0.0.1", State: "*"}, {Name: "ntp.example.com", State: "x"}, {Name: "2001:db8::1", State: "+"}}}
	for addr, want := range map[string]string{"10.0.0.1:123": "*", "10.0.0.1": "*", "ntp.example.com:123": "x", "[2001:db8::1]:123": "+", "10.0.0.9:123": ""} {
		if got := cs.stateOf(addr); got != want {
			t.Errorf("stateOf(%s) = %q, want %q", addr, got, want)
		}
	}

	f := hookChrony(t)
	f.answers["-c serverstats"] = "3,1,10,0,0,0,0,0,0,0,0,0,3,3,0,0,0\n"
	if ss := readServerStats(); ss.Received != 3 || ss.Dropped != 1 || ss.Err != "" {
		t.Fatalf("%+v", ss)
	}
	f.answers["-n -c clients"] = "127.0.0.1,3,0,-5,127,0,0,0,127,4294967295\n2001:db8::7,10,2,1,2,3,0,0,127,4294967295\n"
	cl, err := readClients()
	if err != nil || len(cl) != 2 || cl[0].Addr != "127.0.0.1" || cl[0].Packets != 3 || cl[1].Drops != 2 {
		t.Fatalf("%+v %v", cl, err)
	}
}

func TestReadStateReportsChronyDown(t *testing.T) {
	f := hookChrony(t)
	st := chrony.readState()
	if st.Running || st.Err == "" {
		t.Fatalf("%+v", st)
	}
	if chronyServingFn() {
		t.Fatal("serving with chrony down")
	}
	f.answers["-c -m tracking sources -n"] = "A9FE0101,ntp1,2,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.01,0.01,64.0,Normal\n" +
		"^,*,10.0.0.1,2,6,377,12,0.0,0.0,0.0\n"
	st = chrony.readState()
	if !st.Running || !st.Synced || len(st.Sources) != 1 || st.Ref != "ntp1" || !chronyServingFn() {
		t.Fatalf("%+v", st)
	}
	// a combined run that fails is read as two separate ones
	delete(f.answers, "-c -m tracking sources -n")
	f.answers["-c tracking"] = "A9FE0101,ntp1,2,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.01,0.01,64.0,Normal\n"
	f.answers["-n -c sources"] = "^,*,10.0.0.1,2,6,377,12,0.0,0.0,0.0\n^,-,10.0.0.2,2,6,377,12,0.0,0.0,0.0\n"
	st = chrony.readState()
	if !st.Running || !st.Synced || len(st.Sources) != 2 {
		t.Fatalf("fallback: %+v", st)
	}
	_ = context.Background
}

// What chrony is told to use follows the servers' health across every pool.
func TestSupervisorChronySources(t *testing.T) {
	hookChrony(t)
	a, b, dead, fb := newFakeNTP(t), newFakeNTP(t), newFakeNTP(t), newFakeNTP(t)
	dead.mode.Store(fakeDrop)
	g1, g2 := defaultGroup(), defaultGroup()
	g2.GroupID = 2
	own := testNTPCfg(b.addr, dead.addr)
	g2.NTP = &own
	dc := newDaemonConfig()
	dc.NTP = testNTPCfg(a.addr)
	dc.NTP.FallbackServers = []string{fb.addr}
	dc.Groups = []GroupConfig{g1, g2}
	s := NewSupervisor(context.Background(), dc)
	t.Cleanup(s.StopAll)
	s.refreshPool(dc, true)
	got, empty := s.chronySources()
	want := []string{a.addr, b.addr}
	sortStrings(want)
	if !reflect.DeepEqual(got, want) || empty {
		t.Fatalf("got %v empty=%v, want %v (the dead one and the fallback left out)", got, empty, want)
	}
	// every ordinary server fails: the fallback takes over
	a.mode.Store(fakeDrop)
	b.mode.Store(fakeDrop)
	for _, p := range s.poolList() {
		p.Pool.ProbeNow(context.Background())
	}
	got, empty = s.chronySources()
	if !reflect.DeepEqual(got, []string{fb.addr}) || empty {
		t.Fatalf("fallback: got %v empty=%v", got, empty)
	}
	// and with no fallback either, nothing is proposed and nothing is "empty": chrony keeps its sources
	dc2 := newDaemonConfig()
	dc2.NTP = testNTPCfg(a.addr)
	dc2.Groups = []GroupConfig{g1}
	s.refreshPool(dc2, true)
	got, empty = s.chronySources()
	if len(got) != 0 || empty {
		t.Fatalf("all down: got %v empty=%v", got, empty)
	}
	// every server paused: that is what was asked for, so chrony is left with none
	dc3 := newDaemonConfig()
	dc3.NTP = testNTPCfg(a.addr)
	dc3.NTP.PausedServers = []string{a.addr}
	dc3.Groups = []GroupConfig{g1}
	s.refreshPool(dc3, true)
	got, empty = s.chronySources()
	if len(got) != 0 || !empty {
		t.Fatalf("all paused: got %v empty=%v", got, empty)
	}
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// chrony's per-client totals become statistics: only what is new since the last look counts, and a client chrony has
// not seen before shows up in full.
func TestSampleClientsCountsTheDifference(t *testing.T) {
	f := hookChrony(t)
	qs := NewQStats()
	m := chrony
	f.answers["-n -c clients"] = "10.0.0.1,100,10,-5,127,0,0,0,127,4294967295\n"
	m.sampleClients(qs) // the first look only learns the totals
	f.answers["-n -c clients"] = "10.0.0.1,150,12,-5,127,0,0,0,127,4294967295\n10.0.0.2,7,0,-5,127,0,0,0,127,4294967295\n"
	m.sampleClients(qs)
	qs.flush()
	r := qs.Query(time.Now().Add(-time.Hour), time.Now().Add(time.Minute), QFilter{})
	if r.Sums.Answered != 48+7 || r.Sums.Refused != 2 {
		t.Fatalf("answered %d refused %d, want 55 and 2", r.Sums.Answered, r.Sums.Refused)
	}
	if r.Sums.Clients != 2 {
		t.Fatalf("clients %d, want 2", r.Sums.Clients)
	}
	// chrony restarted: its totals start again, and are counted as they are
	f.answers["-n -c clients"] = "10.0.0.1,3,0,-5,127,0,0,0,127,4294967295\n"
	m.sampleClients(qs)
	qs.flush()
	r = qs.Query(time.Now().Add(-time.Hour), time.Now().Add(time.Minute), QFilter{})
	if r.Sums.Answered != 55+3 {
		t.Fatalf("answered %d, want 58", r.Sums.Answered)
	}
}

// Top servers names the node that answered, so the nodes of a cluster can be told apart.
func TestSampleClientsNamesTheNode(t *testing.T) {
	old := hostCurrent
	hostCurrent = func() string { return "ntp-b" }
	defer func() { hostCurrent = old }()
	f := hookChrony(t)
	qs := NewQStats()
	m := chrony
	f.answers["-n -c clients"] = "10.0.0.1,100,10,-5,127,0,0,0,127,4294967295\n"
	m.sampleClients(qs)
	f.answers["-n -c clients"] = "10.0.0.1,150,10,-5,127,0,0,0,127,4294967295\n"
	m.sampleClients(qs)
	qs.flush()
	r := qs.Query(time.Now().Add(-time.Hour), time.Now().Add(time.Minute), QFilter{})
	if len(r.Servers) != 1 || r.Servers[0].Name != "ntp-b" {
		t.Fatalf("servers %+v, want the one node ntp-b", r.Servers)
	}
}

func TestBlockedClientsAreDeniedAfterTheAllowRules(t *testing.T) {
	d := defaultNTP()
	d.BlockedClients = []string{"192.168.5.14", "10.9.0.0/16", "2001:db8::5"}
	if err := d.validateClients(); err != nil {
		t.Fatal(err)
	}
	body, err := chronyConfBody(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"deny all 192.168.5.14/32\n", "deny all 10.9.0.0/16\n", "deny all 2001:db8::5/128\n"} {
		if !strings.Contains(body, w) {
			t.Errorf("missing %q in %q", w, body)
		}
		if strings.Index(body, w) < strings.Index(body, "allow all\n") {
			t.Errorf("%q comes before the allow rules: %q", w, body)
		}
	}
	// a muted node answers nobody, so it needs no deny lines
	if muted, _ := chronyConfBodyMuted(d, true); strings.Contains(muted, "deny") {
		t.Errorf("muted file has deny lines: %q", muted)
	}
	// the running chrony gets the same rules, after the allows
	f := hookChrony(t)
	if err := allowLive(d); err != nil {
		t.Fatal(err)
	}
	var seq []string
	for _, c := range f.calls {
		seq = append(seq, strings.Join(c, " "))
	}
	got := strings.Join(seq, "|")
	if !strings.Contains(got, "allow all|deny all 192.168.5.14/32|deny all 10.9.0.0/16|deny all 2001:db8::5/128") {
		t.Errorf("live rules: %s", got)
	}
}

func TestBlockedClientsValidation(t *testing.T) {
	for _, bad := range []string{"127.0.0.0/8", "::1", "0.0.0.0/0", "::/0", "not-an-address"} {
		d := defaultNTP()
		d.BlockedClients = []string{bad}
		if err := d.validateClients(); err == nil {
			t.Errorf("%q should not be accepted", bad)
		}
	}
	d := defaultNTP()
	d.BlockedClients = []string{"10.0.0.7", "10.0.0.7/32", "10.1.2.3/8"}
	if err := d.validateClients(); err != nil || len(d.BlockedClients) != 2 || d.BlockedClients[0] != "10.0.0.7/32" || d.BlockedClients[1] != "10.0.0.0/8" {
		t.Fatalf("normalised: %v %v", d.BlockedClients, err)
	}
}

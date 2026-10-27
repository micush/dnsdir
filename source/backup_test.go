package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func init() { backupIter = 1000 }

func TestBackupSealRoundTripAndDamage(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 20000) // several pieces
	var buf bytes.Buffer
	w, err := newSealWriter(&buf, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sealed := buf.Bytes()
	if bytes.Contains(sealed, data[:64]) {
		t.Fatal("the data is in the clear")
	}
	read := func(b []byte, pw string) ([]byte, error) {
		r, err := newOpenReader(bytes.NewReader(b), pw)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(r)
	}
	if got, err := read(sealed, "correct horse"); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := read(sealed, "wrong"); err == nil {
		t.Fatal("a wrong password was accepted")
	}
	flip := append([]byte(nil), sealed...)
	flip[len(flip)/2] ^= 1
	if _, err := read(flip, "correct horse"); err == nil {
		t.Fatal("a damaged archive was accepted")
	}
	// cut at a piece boundary: the missing end must be noticed
	cut := sealed[:len(backupMagic)+4+16+5+backupChunk+16]
	if _, err := read(cut, "correct horse"); err == nil {
		t.Fatal("a truncated archive was accepted")
	}
	if _, err := read([]byte("not a backup at all, really not"), "x"); err == nil {
		t.Fatal("garbage was accepted")
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBackupArchiveHoldsTheStateAndLeavesOutTheRest(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "state")
	writeTree(t, state, map[string]string{
		"dnsdir.conf": "CONF", "webcert/dnsdir-web.key": "KEY", "versions/1.json": "V1", "cluster/id": "ID", "alerts.json": "AL",
		"backup/id_ed25519": "SSHKEY", "backup/known_hosts": "KH",
		"update/staged.tgz": "BIG", "blocklists/a.gz": "BL", "dnsdir.log": "LOG", "dnsdir.log.1": "LOG1", "sessions.json": "S", "stats.json.gz": "ST",
		"pairs/x": "P", "backup/work/x.part": "W", "backup/status.json": "S",
	})
	var buf bytes.Buffer
	n, err := writeBackupArchive(&buf, "pw-12345678", state, filepath.Join(state, "dnsdir.conf"), "ns1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("%d files packed", n)
	}
	out := filepath.Join(base, "out")
	man, err := readBackupArchive(bytes.NewReader(buf.Bytes()), "pw-12345678", out)
	if err != nil {
		t.Fatal(err)
	}
	if man.Node != "ns1" || man.Product != backupProduct || man.Conf != "dnsdir.conf" {
		t.Fatalf("manifest %+v", man)
	}
	var got []string
	filepath.WalkDir(out, func(p string, d os.DirEntry, _ error) error {
		if !d.IsDir() {
			r, _ := filepath.Rel(out, p)
			got = append(got, filepath.ToSlash(r))
		}
		return nil
	})
	sort.Strings(got)
	want := "alerts.json backup/id_ed25519 backup/known_hosts cluster/id dnsdir.conf versions/1.json webcert/dnsdir-web.key"
	if strings.Join(got, " ") != want {
		t.Fatalf("restored\n got %v\nwant %s", got, want)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "webcert/dnsdir-web.key")); string(b) != "KEY" {
		t.Fatal("content differs")
	}
}

func TestBackupRestoreReplacesAndKeepsWhatWasThere(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "state")
	writeTree(t, state, map[string]string{"dnsdir.conf": "NEW", "versions/1.json": "V1"})
	var buf bytes.Buffer
	if _, err := writeBackupArchive(&buf, "pw-12345678", state, filepath.Join(state, "dnsdir.conf"), "ns1", time.Now()); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "x"+backupExt)
	os.WriteFile(file, buf.Bytes(), 0o600)
	// the node now: another configuration, a log and a staged upgrade the backup does not hold
	os.RemoveAll(state)
	writeTree(t, state, map[string]string{"dnsdir.conf": "OLD", "versions/9.json": "V9", "update/s.tgz": "U", "dnsdir.log": "L"})
	if _, _, err := restoreBackup(file, "wrong-password", state, filepath.Join(state, "dnsdir.conf")); err == nil {
		t.Fatal("a wrong password restored something")
	}
	if b, _ := os.ReadFile(filepath.Join(state, "dnsdir.conf")); string(b) != "OLD" {
		t.Fatal("a failed restore changed the state")
	}
	_, aside, err := restoreBackup(file, "pw-12345678", state, filepath.Join(state, "dnsdir.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "dnsdir.conf")); string(b) != "NEW" {
		t.Fatalf("conf is %q", b)
	}
	if _, err := os.Stat(filepath.Join(state, "versions/9.json")); err == nil {
		t.Fatal("the old versions directory was merged in")
	}
	if b, _ := os.ReadFile(filepath.Join(aside, "dnsdir.conf")); string(b) != "OLD" {
		t.Fatal("the old configuration was not kept")
	}
	for _, keep := range []string{"update/s.tgz", "dnsdir.log"} {
		if _, err := os.Stat(filepath.Join(state, keep)); err != nil {
			t.Fatalf("%s was not left alone", keep)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(base, "state.restore-*")); len(m) != 0 {
		t.Fatalf("staging left behind: %v", m)
	}
}

func TestBackupRestoreRefusesBadPaths(t *testing.T) {
	for _, name := range []string{"../evil", "/etc/evil", "a/../../evil"} {
		var raw bytes.Buffer
		sw, _ := newSealWriter(&raw, "pw-12345678")
		gz := gzip.NewWriter(sw)
		tw := tar.NewWriter(gz)
		tarAdd(tw, backupManifestName, 0o600, []byte(`{"format":1,"product":"`+backupProduct+`","conf":"dnsdir.conf"}`), time.Now())
		tarAdd(tw, name, 0o600, []byte("x"), time.Now())
		tw.Close()
		gz.Close()
		sw.Close()
		dir := t.TempDir()
		if _, err := readBackupArchive(&raw, "pw-12345678", filepath.Join(dir, "o")); err == nil {
			t.Errorf("%q was accepted", name)
		}
		if _, err := os.Stat(filepath.Join(dir, "evil")); err == nil {
			t.Errorf("%q was written", name)
		}
	}
	// a link is not a file
	var raw bytes.Buffer
	sw, _ := newSealWriter(&raw, "pw-12345678")
	gz := gzip.NewWriter(sw)
	tw := tar.NewWriter(gz)
	tarAdd(tw, backupManifestName, 0o600, []byte(`{"format":1,"product":"`+backupProduct+`","conf":"c"}`), time.Now())
	tw.WriteHeader(&tar.Header{Name: "l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	tw.Close()
	gz.Close()
	sw.Close()
	if _, err := readBackupArchive(&raw, "pw-12345678", t.TempDir()); err == nil {
		t.Error("a symbolic link was accepted")
	}
}

// The archive password is the person's own choice: any length, any characters, or none; it is kept exactly as typed and
// opens the archive again.
func TestBackupPasswordHasNoLimits(t *testing.T) {
	long := strings.Repeat("ab ", 400)
	for _, pw := range []string{"", "x", " lead and trail ", "tab\there", long, "ünï©ødé"} {
		c := BackupConfig{Enabled: true, Targets: []BackupTarget{{Host: "h", User: "u"}}, Password: pw}
		if err := (&c).Validate(); err != nil {
			t.Fatalf("%q refused: %v", pw, err)
		}
		if c.Password != pw {
			t.Fatalf("%q was changed to %q", pw, c.Password)
		}
		state := t.TempDir()
		writeTree(t, state, map[string]string{"dnsdir.conf": "CONF"})
		var buf bytes.Buffer
		if _, err := writeBackupArchive(&buf, pw, state, filepath.Join(state, "dnsdir.conf"), "ns1", time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := readBackupArchive(bytes.NewReader(buf.Bytes()), pw, t.TempDir()); err != nil {
			t.Fatalf("%q: %v", pw, err)
		}
		if _, err := readBackupArchive(bytes.NewReader(buf.Bytes()), pw+"?", t.TempDir()); err == nil {
			t.Fatalf("%q: a wrong password opened it", pw)
		}
	}
}

func TestBackupConfigIsChecked(t *testing.T) {
	good := BackupConfig{Enabled: true, Host: "backup.example.com", User: "dnsdir", Dir: "backups/dns", Keep: 7, At: "03:15", Password: "longenough"}
	if err := (&good).Validate(); err != nil {
		t.Fatal(err)
	}
	for i, c := range []BackupConfig{
		{Enabled: true, User: "u", Password: "longenough"},     // no server
		{Enabled: true, Host: "h", Password: "longenough"},     // no user
		{Host: "-oProxyCommand=x"},                             // option as a host
		{Host: "a b"},                                          // space
		{User: "-x"},                                           // option as a user
		{Dir: "../x"}, {Dir: "a b"}, {Dir: `a"b`}, {Dir: "-r"}, // directories
		{Port: 70000}, {Keep: 500}, {Hours: 200}, {At: "25:00"}, {At: "9:00"}, // numbers
	} {
		if err := (&c).Validate(); err == nil {
			t.Errorf("case %d was accepted: %+v", i, c)
		}
	}
	var none *BackupConfig
	if !none.empty() || !(&BackupConfig{}).empty() || good.empty() {
		t.Fatal("empty()")
	}
}

// fakeServer is a backup server that keeps its files in a map.
type fakeServer struct {
	files   map[string]bool
	scripts []string
	fail    error
}

func (f *fakeServer) run(_ context.Context, c *BackupTarget, _ string, script, _ string) (string, error) {
	f.scripts = append(f.scripts, script)
	if f.fail != nil {
		return "", f.fail
	}
	var out strings.Builder
	for _, l := range strings.Split(script, "\n") {
		l = strings.TrimPrefix(l, "-")
		switch {
		case strings.HasPrefix(l, "ls -1"):
			names := make([]string, 0, len(f.files))
			for n := range f.files {
				names = append(names, n)
			}
			sort.Strings(names)
			out.WriteString("sftp> " + l + "\n")
			for _, n := range names {
				out.WriteString(c.Dir + "/" + n + "\n")
			}
		case strings.HasPrefix(l, "rename "):
			var a, b string
			parts := strings.Split(l, `" "`)
			a, b = strings.Trim(parts[0][len("rename "):], `"`), strings.Trim(parts[1], `"`)
			delete(f.files, filepath.Base(a))
			f.files[filepath.Base(b)] = true
		case strings.HasPrefix(l, "rm "):
			delete(f.files, filepath.Base(strings.Trim(l[3:], `"`)))
		case strings.HasPrefix(l, "put "):
			parts := strings.Split(l, `" "`)
			f.files[filepath.Base(strings.Trim(parts[1], `"`))] = true
		}
	}
	return out.String(), nil
}

func newBackupRig(t *testing.T, cfg *BackupConfig) (*BackupEngine, *fakeServer, *time.Time) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	writeTree(t, state, map[string]string{"dnsdir.conf": "C"})
	srv := &fakeServer{files: map[string]bool{}}
	oldS, oldK := backupSFTP, backupKeygen
	backupSFTP = srv.run
	backupKeygen = func(file, comment string) error {
		os.WriteFile(file, []byte("PRIVATE"), 0o600)
		return os.WriteFile(file+".pub", []byte("ssh-ed25519 AAAA "+comment+"\n"), 0o644)
	}
	t.Cleanup(func() { backupSFTP, backupKeygen = oldS, oldK })
	clock := time.Date(2026, 10, 25, 12, 0, 0, 0, time.Local)
	e := NewBackupEngine(state, filepath.Join(state, "dnsdir.conf"), "NS1.example", func() *BackupConfig { return cfg })
	e.now = func() time.Time { return clock }
	e.scheduled = func() bool { return true }
	return e, srv, &clock
}

func TestBackupUploadsAndKeepsTheNewestFew(t *testing.T) {
	cfg := &BackupConfig{Enabled: true, Targets: []BackupTarget{{Host: "h", User: "u", Dir: "/srv/bk", Keep: 3}}, Password: "longenough"}
	e, srv, clock := newBackupRig(t, cfg)
	srv.files["ns2-20260101-000000"+backupExt] = true // another node's: never touched
	srv.files["notes.txt"] = true
	for i := 0; i < 5; i++ {
		*clock = clock.Add(24 * time.Hour)
		if err := e.backup(cfg, cfg.Targets); err != nil {
			t.Fatal(err)
		}
	}
	var mine []string
	for n := range srv.files {
		if strings.HasPrefix(n, "ns1.example-") {
			mine = append(mine, n)
		}
	}
	sort.Strings(mine)
	if len(mine) != 3 || mine[0] != "ns1.example-20261028-120000"+backupExt || mine[2] != "ns1.example-20261030-120000"+backupExt {
		t.Fatalf("kept %v", mine)
	}
	if !srv.files["ns2-20260101-000000"+backupExt] || !srv.files["notes.txt"] {
		t.Fatal("something that is not this node's was removed")
	}
	if strings.Contains(strings.Join(mine, ""), ".part") {
		t.Fatal("a partial upload was left")
	}
	if !strings.Contains(srv.scripts[0], "-mkdir \"/srv\"\n-mkdir \"/srv/bk\"") || !strings.Contains(srv.scripts[0], "rename") {
		t.Fatalf("upload script:\n%s", srv.scripts[0])
	}
	if st := e.status.Targets[cfg.Targets[0].key()]; st == nil || st.Pruned != 1 || len(st.Remote) != 3 || st.LastFile != mine[2] {
		t.Fatalf("status %+v", e.status.Targets)
	}
	// the work file does not stay behind
	if m, _ := filepath.Glob(filepath.Join(e.dir, "work", "*")); len(m) != 0 {
		t.Fatalf("left %v", m)
	}
	// the key was made once, and its public half is shown
	if pub := e.Status()["public_key"].(string); !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatalf("public key %q", pub)
	}
}

func TestBackupFailureIsReportedAndRetried(t *testing.T) {
	cfg := &BackupConfig{Enabled: true, Targets: []BackupTarget{{Host: "h", User: "u", Keep: 3}}, Password: "longenough"}
	e, srv, clock := newBackupRig(t, cfg)
	srv.fail = os.ErrPermission
	done := make(chan struct{}, 1)
	e.onRunDone = func() { done <- struct{}{} }
	if err := e.start(false); err != nil {
		t.Fatal(err)
	}
	<-done
	failing, enabled, msg := e.Failing()
	if !failing || !enabled || !strings.Contains(msg, "uploading to h") {
		t.Fatalf("failing=%v enabled=%v %q", failing, enabled, msg)
	}
	if e.due() {
		t.Fatal("it retried at once")
	}
	*clock = clock.Add(backupRetry + time.Second)
	if !e.due() {
		t.Fatal("it did not retry after the pause")
	}
	srv.fail = nil
	if err := e.start(false); err != nil {
		t.Fatal(err)
	}
	<-done
	if failing, _, _ := e.Failing(); failing {
		t.Fatal("still failing after a good run")
	}
}

// Between the Scheduler's runs the engine only retries failed servers and serves new ones, and only while a backup task
// runs on the node.
func TestBackupRetriesOnlyWhileScheduled(t *testing.T) {
	cfg := &BackupConfig{Targets: []BackupTarget{{Host: "h", User: "u"}}, Password: "pw"}
	e, _, _ := newBackupRig(t, cfg)
	if !e.due() {
		t.Fatal("a server that never had a backup is not due")
	}
	e.scheduled = func() bool { return false }
	if e.due() {
		t.Fatal("due without a backup task")
	}
	if err := e.start(false); err == nil {
		t.Fatal("started without a backup task")
	}
	if on, _ := e.Status()["enabled"].(bool); on {
		t.Fatal("the page says scheduled")
	}
}

// The Scheduler's action waits for the backup and says how it went.
func TestBackupRunScheduled(t *testing.T) {
	cfg := &BackupConfig{Password: "pw", Targets: []BackupTarget{{Name: "A", Host: "a", User: "u"}, {Name: "B", Host: "b", User: "u"}}}
	e, _, _ := newBackupRig(t, cfg)
	servers := map[string]*fakeServer{"a": {files: map[string]bool{}}, "b": {files: map[string]bool{}, fail: os.ErrPermission}}
	backupSFTP = func(ctx context.Context, tg *BackupTarget, d, script, pw string) (string, error) {
		return servers[tg.Host].run(ctx, tg, d, script, pw)
	}
	out, err := e.RunScheduled("test")
	if err == nil || !strings.Contains(err.Error(), "B:") || strings.Contains(err.Error(), "A:") || !strings.Contains(out, "A (ns1.example-") {
		t.Fatalf("out %q err %v", out, err)
	}
	servers["b"].fail = nil
	if out, err := e.RunScheduled("test"); err != nil || !strings.Contains(out, "A (") || !strings.Contains(out, "B (") {
		t.Fatalf("out %q err %v", out, err)
	}
	if _, err := (&BackupEngine{cfg: func() *BackupConfig { return &BackupConfig{} }}).RunScheduled("x"); err == nil {
		t.Fatal("ran with no server")
	}
}

// A configuration file with the old schedule reads as the task, so a page that saves what it read keeps the backups on.
func TestBackupOldScheduleReadsAsATask(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(f, []byte(`{"groups":[],"dns":{"backup":{"enabled":true,"hours":6,"password":"p","targets":[{"host":"h","user":"u"}]}}}`), 0o600)
	dc, err := loadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(dc.DNS.Schedule) != 1 || dc.DNS.Schedule[0].Action != "backup" || dc.DNS.Backup.Enabled || dc.DNS.Backup.Hours != 0 {
		t.Fatalf("%+v %+v", dc.DNS.Schedule, dc.DNS.Backup)
	}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(dc.DNS.Schedule) != 1 {
		t.Fatalf("%+v", dc.DNS.Schedule)
	}
}

// The schedule of v583-v591 becomes a Scheduler task once, and the old fields are cleared.
func TestBackupScheduleMovesToTheScheduler(t *testing.T) {
	d := DNSConfig{Backup: &BackupConfig{Enabled: true, At: "03:15", Targets: []BackupTarget{{Host: "h", User: "u"}}}}
	migrateBackupSchedule(&d)
	if len(d.Schedule) != 1 || d.Schedule[0].Action != "backup" || d.Schedule[0].Freq != "daily" || d.Backup.Enabled || d.Backup.At != "" {
		t.Fatalf("%+v %+v", d.Schedule, d.Backup)
	}
	if err := validateSchedule(d.Schedule); err != nil {
		t.Fatal(err)
	}
	if !backupScheduled(d.Schedule, "any") {
		t.Fatal("not scheduled")
	}
	migrateBackupSchedule(&d) // nothing more
	if len(d.Schedule) != 1 {
		t.Fatalf("%+v", d.Schedule)
	}
	// local time becomes UTC
	tk := oldBackupTask(0, "03:15", time.FixedZone("x", -7*3600))
	if tk.At != "10:15" || tk.Until != "10:20" {
		t.Fatalf("%+v", tk)
	}
	h := oldBackupTask(6, "", time.UTC)
	if h.Freq != "hourly" || h.Every != 6 {
		t.Fatalf("%+v", h)
	}
	if err := validateSchedule([]SchedTask{h}); err != nil {
		t.Fatal(err)
	}
	// switched off: no task, the fields go
	off := DNSConfig{Backup: &BackupConfig{Hours: 4, Targets: []BackupTarget{{Host: "h", User: "u"}}}}
	migrateBackupSchedule(&off)
	if len(off.Schedule) != 0 || off.Backup.Hours != 0 {
		t.Fatalf("%+v", off)
	}
	// a disabled task, or one for other nodes, does not count
	if backupScheduled([]SchedTask{{Action: "backup", Disabled: true}}, "n1") || backupScheduled([]SchedTask{{Action: "backup", Nodes: []string{"n2"}}}, "n1") {
		t.Fatal("counted")
	}
}

func TestBackupConfigMigratesTheSingleServer(t *testing.T) {
	c := BackupConfig{Enabled: true, Host: "h1", User: "u", Dir: "d", Keep: 5, Password: "longenough",
		Targets: []BackupTarget{{Host: "h2", User: "u2"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Targets) != 2 || c.Targets[0].Host != "h1" || c.Targets[0].Keep != 5 || c.Targets[1].Host != "h2" || c.Host != "" || c.Keep != 0 {
		t.Fatalf("%+v", c)
	}
	d := BackupConfig{Targets: []BackupTarget{{Host: "h", User: "u"}, {Host: "h", User: "u"}}}
	if d.Validate() == nil {
		t.Fatal("the same server twice was accepted")
	}
	many := BackupConfig{}
	for i := 0; i < backupMaxTargets+1; i++ {
		many.Targets = append(many.Targets, BackupTarget{Host: fmt.Sprintf("h%d", i), User: "u"})
	}
	if many.Validate() == nil {
		t.Fatal("too many servers")
	}
}

func TestBackupGoesToEveryServerAndOneFailureDoesNotStopTheRest(t *testing.T) {
	cfg := &BackupConfig{Enabled: true, Password: "longenough", Targets: []BackupTarget{
		{Name: "A", Host: "a", User: "u", Dir: "/x", Keep: 2}, {Name: "B", Host: "b", User: "u", Dir: "/y", Keep: 2}, {Name: "C", Host: "c", User: "u", Dir: "/z", Keep: 2}}}
	e, _, clock := newBackupRig(t, cfg)
	servers := map[string]*fakeServer{"a": {files: map[string]bool{}}, "b": {files: map[string]bool{}, fail: os.ErrPermission}, "c": {files: map[string]bool{}}}
	backupSFTP = func(ctx context.Context, tg *BackupTarget, d, script, pw string) (string, error) {
		return servers[tg.Host].run(ctx, tg, d, script, pw)
	}
	done := make(chan struct{}, 1)
	e.onRunDone = func() { done <- struct{}{} }
	if err := e.start(false); err != nil {
		t.Fatal(err)
	}
	<-done
	if len(servers["a"].files) != 1 || len(servers["c"].files) != 1 || len(servers["b"].files) != 0 {
		t.Fatalf("a=%v b=%v c=%v", servers["a"].files, servers["b"].files, servers["c"].files)
	}
	failing, _, msg := e.Failing()
	if !failing || !strings.Contains(msg, "B:") || strings.Contains(msg, "A:") || strings.Contains(msg, "C:") {
		t.Fatalf("%v %q", failing, msg)
	}
	// after the pause only the one that failed is tried again
	*clock = clock.Add(backupRetry + time.Second)
	servers["b"].fail = nil
	servers["a"].scripts, servers["c"].scripts = nil, nil
	if err := e.start(false); err != nil {
		t.Fatal(err)
	}
	<-done
	if len(servers["b"].files) != 1 || len(servers["a"].scripts) != 0 || len(servers["c"].scripts) != 0 {
		t.Fatalf("retry: b=%v a=%d c=%d", servers["b"].files, len(servers["a"].scripts), len(servers["c"].scripts))
	}
	if failing, _, _ := e.Failing(); failing {
		t.Fatal("still failing")
	}
	// a server that is added later gets its first backup at once, without the others being touched
	cfg.Targets = append(cfg.Targets, BackupTarget{Name: "D", Host: "d", User: "u", Dir: "/w"})
	servers["d"] = &fakeServer{files: map[string]bool{}}
	if !e.due() {
		t.Fatal("a new server is not due")
	}
	if err := e.start(false); err != nil {
		t.Fatal(err)
	}
	<-done
	if len(servers["d"].files) != 1 || len(servers["a"].files) != 1 {
		t.Fatalf("d=%v a=%v", servers["d"].files, servers["a"].files)
	}
}

func TestAuthorizeKeys(t *testing.T) {
	const k1 = "ssh-ed25519 AAAAC3Nza1 a@x"
	out, n := authorizeKeys("ssh-rsa AAAB old@laptop", []string{k1, k1, "junk"})
	if n != 1 || !strings.Contains(out, "old@laptop\nrestrict "+k1+"\n") {
		t.Fatalf("%d %q", n, out)
	}
	if _, n := authorizeKeys(out, []string{k1}); n != 0 {
		t.Fatal("added twice")
	}
}

func TestPendingRestoreIsAppliedAtStart(t *testing.T) {
	old := backupIter
	backupIter = 1000
	defer func() { backupIter = old }()
	src := filepath.Join(t.TempDir(), "src")
	writeTree(t, src, map[string]string{"dnsdir.conf": "FROM-BACKUP", "webcert/k": "KEY"})
	var raw bytes.Buffer
	if _, err := writeBackupArchive(&raw, "pw-12345678", src, filepath.Join(src, "dnsdir.conf"), "ns1", time.Now()); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	writeTree(t, state, map[string]string{"dnsdir.conf": "CURRENT", "other": "O"})
	conf := filepath.Join(state, "dnsdir.conf")
	cfg := &BackupConfig{}
	e := NewBackupEngine(state, conf, "ns1", func() *BackupConfig { return cfg })
	file := filepath.Join(t.TempDir(), "b"+backupExt)
	os.WriteFile(file, raw.Bytes(), 0o600)
	if _, err := e.PrepareRestore(file, "wrong-password", "tester"); err == nil {
		t.Fatal("a wrong password was accepted")
	}
	if readPending(state) != nil {
		t.Fatal("a failed preparation left something")
	}
	sum, err := e.PrepareRestore(file, "pw-12345678", "tester")
	if err != nil || sum["same_node"] != true {
		t.Fatalf("%v %v", sum, err)
	}
	// not confirmed: nothing changes, and the preparation is dropped at the start
	applyPendingRestore(state, conf)
	if b, _ := os.ReadFile(conf); string(b) != "CURRENT" || readPending(state) != nil {
		t.Fatalf("an unconfirmed restore was applied: %q", b)
	}
	if _, err := e.PrepareRestore(file, "pw-12345678", "tester"); err != nil {
		t.Fatal(err)
	}
	if err := e.MarkReady(); err != nil {
		t.Fatal(err)
	}
	applyPendingRestore(state, conf)
	if b, _ := os.ReadFile(conf); string(b) != "FROM-BACKUP" {
		t.Fatalf("conf %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "webcert/k")); string(b) != "KEY" {
		t.Fatal("webcert not restored")
	}
	if readPending(state) != nil {
		t.Fatal("pending left behind")
	}
	if m, _ := filepath.Glob(state + ".before-restore-*"); len(m) != 1 {
		t.Fatalf("the old state is not kept: %v", m)
	}
}

// New archives have no password; a restore opens them, and opens one of v583-v591 with the password still in the settings.
func TestBackupRestoreNeedsNoPassword(t *testing.T) {
	cfg := &BackupConfig{Targets: []BackupTarget{{Host: "h", User: "u"}}}
	e, _, _ := newBackupRig(t, cfg)
	src := t.TempDir()
	writeTree(t, src, map[string]string{"dnsdir.conf": "CONF"})
	mk := func(pw string) string {
		f := filepath.Join(t.TempDir(), "b"+backupExt)
		var buf bytes.Buffer
		if _, err := writeBackupArchive(&buf, pw, src, filepath.Join(src, "dnsdir.conf"), "ns1", time.Now()); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(f, buf.Bytes(), 0o600)
		return f
	}
	if _, err := e.PrepareRestore(mk(""), "", "t"); err != nil {
		t.Fatalf("new archive: %v", err)
	}
	old := mk("old secret")
	if _, err := e.PrepareRestore(old, "", "t"); !errors.Is(err, errBackupPassword) {
		t.Fatalf("an old archive opened without its password: %v", err)
	}
	cfg.Password = "old secret"
	if _, err := e.PrepareRestore(old, "", "t"); err != nil {
		t.Fatalf("old archive with the settings' password: %v", err)
	}
	cfg.Password = ""
	if _, err := e.PrepareRestore(old, "old secret", "t"); err != nil {
		t.Fatalf("old archive with the given password: %v", err)
	}
}

// A node without the OpenSSH client gets an error that says so, not an empty one.
func TestBackupSaysWhatIsMissing(t *testing.T) {
	t.Setenv(backupEnv+"_SSHKEYGEN", "/nonexistent/ssh-keygen")
	err := backupKeygen(filepath.Join(t.TempDir(), "k"), "c")
	if err == nil || !strings.Contains(err.Error(), "not installed") || !strings.Contains(err.Error(), "openssh-client") {
		t.Fatalf("%v", err)
	}
	t.Setenv(backupEnv+"_SFTP", "/nonexistent/sftp")
	_, err = runSFTP(context.Background(), &BackupTarget{Host: "h", User: "u"}, t.TempDir(), "ls\n", "")
	if err == nil || !strings.Contains(err.Error(), "sftp is not installed") {
		t.Fatalf("%v", err)
	}
}

// sftp's last line is "Connection closed"; the error is the line that says why.
func TestSFTPErrorSaysWhy(t *testing.T) {
	e := errors.New("exit status 255")
	for _, c := range []struct{ out, want string }{
		{"dnsdir@ns1: Permission denied (publickey).\r\nConnection closed\r\n", "use Install key"},
		{"ssh: Could not resolve hostname ns1: Name or service not known\r\nConnection closed.\n", "Could not resolve hostname ns1"},
		{"ssh: connect to host ns1 port 22: Connection refused\nConnection closed\n", "Connection refused"},
		{"Connection closed\n", "the connection was closed: exit status 255"},
	} {
		if got := sftpError(c.out, e, false); !strings.Contains(got, c.want) || strings.HasPrefix(got, "Connection closed") {
			t.Errorf("%q -> %q", c.out, got)
		}
	}
	if got := sftpError("u@h: Permission denied (password).\nConnection closed\n", e, true); !strings.Contains(got, "wrong password") {
		t.Errorf("%q", got)
	}
}

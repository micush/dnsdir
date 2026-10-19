package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidNodeName(t *testing.T) {
	for _, ok := range []string{"ntp01", "NTP-02", "a", "ntp.example.com", "a-b.c-d"} {
		if _, err := validNodeName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " ", "-a", "a-", "a_b", "a b", "a;rm -rf /", "$(x)", "a..b", "a.b.c.d.e", strings.Repeat("a", 64), "ünï", "a\nb", "../x"} {
		if _, err := validNodeName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if n, _ := validNodeName("  NTP01 "); n != "ntp01" {
		t.Errorf("not trimmed and lower-cased: %q", n)
	}
}

func TestRewriteHosts(t *testing.T) {
	in := "127.0.0.1\tlocalhost\n127.0.1.1\told.example.com old\n10.0.0.5 other old # keep this\n::1 ip6-localhost\n# old stays in comments\n"
	got := rewriteHosts(in, "old.example.com", "new.example.com")
	want := "127.0.0.1\tlocalhost\n127.0.1.1\tnew.example.com\tnew\n10.0.0.5\tother\tnew # keep this\n::1 ip6-localhost\n# old stays in comments\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	// no line names the old host: a 127.0.1.1 line is added
	got = rewriteHosts("127.0.0.1 localhost\n", "old", "new")
	if got != "127.0.0.1 localhost\n127.0.1.1\tnew\n" {
		t.Fatalf("added line: %q", got)
	}
	// a file with no final newline, and an empty one
	if got := rewriteHosts("127.0.0.1 localhost", "old", "new"); got != "127.0.0.1 localhost\n127.0.1.1\tnew\n" {
		t.Fatalf("no final newline: %q", got)
	}
	if got := rewriteHosts("", "old", "a.b"); got != "127.0.1.1\ta.b\ta\n" {
		t.Fatalf("empty file: %q", got)
	}
}

func withFakeHost(t *testing.T, old string, run func(name string, args ...string) error) (hosts, hostname string) {
	t.Helper()
	d := t.TempDir()
	hosts, hostname = filepath.Join(d, "hosts"), filepath.Join(d, "hostname")
	sh, sn, sc, scur, sf := hostsFile, hostnameFile, hostCmd, hostCurrent, hostCmdIsFake
	hostsFile, hostnameFile, hostCmd, hostCurrent, hostCmdIsFake = hosts, hostname, run, func() string { return old }, true
	t.Cleanup(func() { hostsFile, hostnameFile, hostCmd, hostCurrent, hostCmdIsFake = sh, sn, sc, scur, sf })
	return
}

func TestNodeRename(t *testing.T) {
	var calls [][]string
	hosts, _ := withFakeHost(t, "old", func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	})
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n127.0.1.1 old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	m := &Mgmt{}
	msg, err := m.NodeRename("New", "tester")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(hosts)
	if string(b) != "127.0.0.1 localhost\n127.0.1.1\tnew\n" {
		t.Fatalf("hosts: %q", b)
	}
	if st, _ := os.Stat(hosts); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if len(calls) != 1 || strings.Join(calls[0], " ") != "hostnamectl set-hostname new" || !strings.Contains(msg, "new") {
		t.Fatalf("calls %v msg %q", calls, msg)
	}
	// the same name again is a no-op
	withFakeHost(t, "new", func(string, ...string) error { t.Fatal("must not run"); return nil })
	if msg, err := m.NodeRename("NEW", "tester"); err != nil || !strings.Contains(msg, "already") {
		t.Fatalf("same name: %q %v", msg, err)
	}
}

// When the host name cannot be set, /etc/hosts goes back to what it was; a bad name touches nothing.
func TestNodeRenameFailureRestoresHosts(t *testing.T) {
	hosts, _ := withFakeHost(t, "old", func(string, ...string) error { return errors.New("denied") })
	orig := "127.0.0.1 localhost\n127.0.1.1 old\n"
	os.WriteFile(hosts, []byte(orig), 0o644)
	m := &Mgmt{}
	if _, err := m.NodeRename("new", "t"); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := os.ReadFile(hosts); string(b) != orig {
		t.Fatalf("hosts not restored: %q", b)
	}
	if _, err := m.NodeRename("bad name;", "t"); err == nil {
		t.Fatal("a bad name must be refused")
	}
	if b, _ := os.ReadFile(hosts); string(b) != orig {
		t.Fatalf("hosts changed by a refused name: %q", b)
	}
}

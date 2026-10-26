package main

import (
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Against a real sshd on 127.0.0.1:2222 (set DNSDIR_TEST_SFTP=2222:USER, USER being an account whose home it may write; the
// test authorizes the node's key itself).  Skipped otherwise.
func TestBackupRealSFTP(t *testing.T) {
	spec := os.Getenv("DNSDIR_TEST_SFTP")
	if spec == "" {
		t.Skip("no sshd")
	}
	var port int
	var user string
	parts := strings.SplitN(spec, ":", 2)
	port, user = 2222, parts[1]
	cfg := &BackupConfig{Enabled: true, Targets: []BackupTarget{{Host: "127.0.0.1", Port: port, User: user, Dir: "bk/dns", Keep: 2}}, Password: "longenough"}
	tg := &cfg.Targets[0]
	state := filepath.Join(t.TempDir(), "state")
	writeTree(t, state, map[string]string{"dnsdir.conf": "C", "webcert/k": "KEY"})
	e := NewBackupEngine(state, filepath.Join(state, "dnsdir.conf"), "real1", func() *BackupConfig { return cfg })
	if err := e.ensureKey(); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(filepath.Join(e.dir, "id_ed25519.pub"))
	os.RemoveAll("/home/" + user + "/.ssh")
	if pw := os.Getenv("DNSDIR_TEST_SFTP_PASSWORD"); pw != "" {
		// the keys go to the server with the account's password: an authorized_keys that is there already is kept
		os.MkdirAll("/home/"+user+"/.ssh", 0o700)
		os.WriteFile("/home/"+user+"/.ssh/authorized_keys", []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXISTINGKEYEXISTINGKEYEXISTINGKEYEXIST old@laptop\n"), 0o600)
		osexec.Command("chown", "-R", user+":"+user, "/home/"+user+"/.ssh").Run()
		if _, err := e.InstallKeys(tg, "wrong password", []string{strings.TrimSpace(string(pub))}); err == nil {
			t.Fatal("a wrong password was accepted")
		}
		n, err := e.InstallKeys(tg, pw, []string{strings.TrimSpace(string(pub))})
		if err != nil || n != 1 {
			t.Fatalf("install: %d %v", n, err)
		}
		if n, err := e.InstallKeys(tg, pw, []string{strings.TrimSpace(string(pub))}); err != nil || n != 0 {
			t.Fatalf("second install added %d (%v)", n, err)
		}
		ak, _ := os.ReadFile("/home/" + user + "/.ssh/authorized_keys")
		if !strings.Contains(string(ak), "old@laptop") || !strings.Contains(string(ak), "restrict ssh-ed25519") {
			t.Fatalf("authorized_keys:\n%s", ak)
		}
		if fi, _ := os.Stat("/home/" + user + "/.ssh/authorized_keys"); fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode())
		}
	} else {
		os.MkdirAll("/home/"+user+"/.ssh", 0o700)
		os.WriteFile("/home/"+user+"/.ssh/authorized_keys", pub, 0o600)
		osexec.Command("chown", "-R", user+":"+user, "/home/"+user+"/.ssh").Run()
	}
	for i := 0; i < 4; i++ {
		clk := time.Date(2026, 10, 25, 12, i, 0, 0, time.Local)
		e.now = func() time.Time { return clk }
		if err := e.backup(cfg, cfg.Targets); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	names, err := e.Test(0)
	if err != nil || len(names) != 2 {
		t.Fatalf("test %v %v", names, err)
	}
	t.Logf("on the server: %v", names)
	// the list of every node's backups, fetched with the key, and one downloaded and restored
	all, err := e.ListRemote(tg, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("list %v %v", all, err)
	}
	local, err := e.fetch(tg, "", all[0].Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.PrepareRestore(local, "longenough", "tester"); err != nil {
		t.Fatal(err)
	}
	e.CancelRestore()
}

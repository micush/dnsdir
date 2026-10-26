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
	cfg := &BackupConfig{Enabled: true, Host: "127.0.0.1", Port: port, User: user, Dir: "bk/dns", Keep: 2, Password: "longenough"}
	state := filepath.Join(t.TempDir(), "state")
	writeTree(t, state, map[string]string{"dnsdir.conf": "C", "webcert/k": "KEY"})
	e := NewBackupEngine(state, filepath.Join(state, "dnsdir.conf"), "real1", func() *BackupConfig { return cfg })
	if err := e.ensureKey(); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(filepath.Join(e.dir, "id_ed25519.pub"))
	os.MkdirAll("/home/"+user+"/.ssh", 0o700)
	os.WriteFile("/home/"+user+"/.ssh/authorized_keys", pub, 0o600)
	osexec.Command("chown", "-R", user+":"+user, "/home/"+user+"/.ssh").Run()
	for i := 0; i < 4; i++ {
		clk := time.Date(2026, 10, 25, 12, i, 0, 0, time.Local)
		e.now = func() time.Time { return clk }
		if err := e.backup(cfg); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	names, err := e.Test(cfg)
	if err != nil || len(names) != 2 {
		t.Fatalf("test %v %v", names, err)
	}
	t.Logf("on the server: %v", names)
}

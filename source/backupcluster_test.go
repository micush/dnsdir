package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

const (
	tKey1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa dnsdir-backup@n1"
	tKey2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dnsdir-backup@n2"
)

// provisionRig fakes the account database: no account until useradd has run, then one with its home in a temp dir.
func provisionRig(t *testing.T, uid string) (home string, cmds *[]string) {
	t.Helper()
	home = filepath.Join(t.TempDir(), "dnsdirbackup")
	exists := false
	var ran []string
	oldL, oldR, oldC := backupLookupUser, usersRun, backupChown
	t.Cleanup(func() { backupLookupUser, usersRun, backupChown = oldL, oldR, oldC })
	backupLookupUser = func(name string) (*user.User, error) {
		if !exists {
			return nil, user.UnknownUserError(name)
		}
		return &user.User{Uid: uid, Gid: "4242", Username: name, HomeDir: home}, nil
	}
	usersRun = func(stdin string, name string, args ...string) (string, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		if name == "useradd" {
			exists = true
			return "", os.Mkdir(home, 0o755)
		}
		return "", errors.New("unexpected command")
	}
	backupChown = func(string, int, int) error { return nil }
	return home, &ran
}

func TestBackupProvisionMakesTheAccountOnceAndAddsKeysOnce(t *testing.T) {
	home, ran := provisionRig(t, "4242")
	created, added, err := backupProvisionLocal([]string{tKey1, "not a key", tKey2})
	if err != nil || !created || added != 2 {
		t.Fatalf("first run: created=%v added=%d err=%v", created, added, err)
	}
	if len(*ran) != 1 || !strings.HasPrefix((*ran)[0], "useradd ") || !strings.Contains((*ran)[0], "--password *") || !strings.HasSuffix((*ran)[0], " "+backupAccount) {
		t.Fatalf("commands: %q", *ran)
	}
	ak := filepath.Join(home, ".ssh", "authorized_keys")
	b, _ := os.ReadFile(ak)
	for _, k := range []string{tKey1, tKey2} {
		if !strings.Contains(string(b), `restrict,command="internal-sftp" `+k+"\n") {
			t.Errorf("authorized_keys lacks the restricted key %s:\n%s", k, b)
		}
	}
	if strings.Contains(string(b), "not a key") {
		t.Error("a line that is no key was written")
	}
	for p, want := range map[string]os.FileMode{ak: 0o600, filepath.Join(home, ".ssh"): 0o700, filepath.Join(home, backupClusterDir): 0o700} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v, want mode %o", p, err, want)
		}
	}
	// again, with one more key: no new account, only the new key
	created, added, err = backupProvisionLocal([]string{tKey1, tKey2})
	if err != nil || created || added != 0 || len(*ran) != 1 {
		t.Fatalf("second run: created=%v added=%d err=%v cmds=%q", created, added, err, *ran)
	}
}

func TestBackupProvisionRefuses(t *testing.T) {
	if _, _, err := backupProvisionLocal([]string{"ssh-rsa AAAA x", ""}); err == nil {
		t.Error("no usable key was accepted")
	}
	// an account that is root
	provisionRig(t, "0")
	if _, _, err := backupProvisionLocal([]string{tKey1}); err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Errorf("uid 0: %v", err)
	}
	// a .ssh that is a link somewhere else is not followed
	home, _ := provisionRig(t, "4242")
	elsewhere := t.TempDir()
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	backupLookupUser = func(name string) (*user.User, error) {
		return &user.User{Uid: "4242", Gid: "4242", Username: name, HomeDir: home}, nil
	}
	if err := os.Symlink(elsewhere, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := backupProvisionLocal([]string{tKey1}); err == nil {
		t.Error("a linked .ssh was followed")
	}
	if l, _ := os.ReadDir(elsewhere); len(l) != 0 {
		t.Errorf("something was written through the link: %v", l)
	}
}

func TestBackupClusterNeedsACluster(t *testing.T) {
	m := &Mgmt{}
	if _, err := m.BackupCluster("t"); err == nil {
		t.Error("ran without a cluster")
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSSDGPOProblem(t *testing.T) {
	dir := t.TempDir()
	sssdConfFile, sssdConfDir = filepath.Join(dir, "sssd.conf"), filepath.Join(dir, "conf.d")
	os.MkdirAll(sssdConfDir, 0o755)
	if p := sssdGPOProblem("svc"); p != "" {
		t.Fatalf("no sssd.conf: %q", p)
	}
	write := func(s string) { os.WriteFile(sssdConfFile, []byte(s), 0o600) }
	write("[sssd]\ndomains = ex.com\n[domain/ex.com]\nid_provider = ad\naccess_provider = ad\n")
	if p := sssdGPOProblem("svc"); !strings.Contains(p, "domain/ex.com") || !strings.Contains(p, "+svc") {
		t.Fatalf("AD, unmapped: %q", p)
	}
	write("[domain/ex.com]\nid_provider = ad\nad_gpo_access_control = Permissive\n")
	if p := sssdGPOProblem("svc"); p != "" {
		t.Fatalf("permissive: %q", p)
	}
	write("[domain/ex.com]\nid_provider = ad\nad_gpo_map_interactive = +other, +svc\n")
	if p := sssdGPOProblem("svc"); p != "" {
		t.Fatalf("mapped: %q", p)
	}
	write("[domain/ex.com]\nid_provider = ldap\n")
	if p := sssdGPOProblem("svc"); p != "" {
		t.Fatalf("not AD: %q", p)
	}
	write("[domain/ex.com]\nid_provider = ad\n")
	os.WriteFile(filepath.Join(sssdConfDir, "x.conf"), []byte("[domain/ex.com]\nad_gpo_map_service = +svc\n"), 0o600)
	if p := sssdGPOProblem("svc"); p != "" {
		t.Fatalf("mapped in a snippet: %q", p)
	}
}

func TestFixSSSD(t *testing.T) {
	dir := t.TempDir()
	sssdConfFile, sssdConfDir = filepath.Join(dir, "sssd.conf"), filepath.Join(dir, "conf.d")
	os.MkdirAll(sssdConfDir, 0o755)
	restarts := 0
	sssdRestart = func() error { restarts++; return nil }
	orig := "[sssd]\ndomains = ex.com\n\n[domain/ex.com]\nid_provider = ad\naccess_provider = ad\n\n[pam]\n"
	os.WriteFile(sssdConfFile, []byte(orig), 0o600)
	msg, err := fixSSSD("svc")
	if err != nil || !strings.Contains(msg, "restarted sssd") || restarts != 1 {
		t.Fatalf("fix: %q %v %d", msg, err, restarts)
	}
	b, _ := os.ReadFile(sssdConfFile)
	if !strings.Contains(string(b), "[domain/ex.com]\nad_gpo_map_interactive = +svc\nid_provider = ad") || !strings.HasSuffix(string(b), "[pam]\n") {
		t.Fatalf("conf: %q", b)
	}
	if bk, _ := os.ReadFile(sssdConfFile + ".svc.bak"); string(bk) != orig {
		t.Fatalf("backup: %q", bk)
	}
	if st, _ := os.Stat(sssdConfFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if msg, err = fixSSSD("svc"); msg != "" || err != nil || restarts != 1 {
		t.Fatalf("second run must do nothing: %q %v %d", msg, err, restarts)
	}
	// a second daemon appends to the line the first one made; an existing line gets the item added
	if msg, err = fixSSSD("other"); err != nil || restarts != 2 {
		t.Fatalf("other: %q %v", msg, err)
	}
	b, _ = os.ReadFile(sssdConfFile)
	if !strings.Contains(string(b), "ad_gpo_map_interactive = +svc, +other\n") {
		t.Fatalf("append: %q", b)
	}
	// a domain that exists only in a snippet is not edited
	os.WriteFile(sssdConfFile, []byte("[sssd]\n"), 0o600)
	os.WriteFile(filepath.Join(sssdConfDir, "d.conf"), []byte("[domain/sn.com]\nid_provider = ad\n"), 0o600)
	if msg, err = fixSSSD("svc"); err == nil || restarts != 2 {
		t.Fatalf("snippet: %q %v", msg, err)
	}
}

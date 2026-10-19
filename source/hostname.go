package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Renaming a node changes the operating system's host name and the entries for it in /etc/hosts.  It runs as root, so the
// name is validated before it reaches a command, and every file is replaced atomically with its mode kept.

var (
	hostsFile    = "/etc/hosts"
	hostnameFile = "/etc/hostname"
	// hostCmd runs a command (tests replace it).  The name is always an argument, never part of a shell line.
	hostCmd = func(name string, args ...string) error {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	hostCurrent = func() string { h, _ := os.Hostname(); return h }
	hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// validNodeName checks a host name: one to four dot-separated labels of letters, digits and hyphens (RFC 1123), 253
// characters at most.  It returns the name in lower case.
func validNodeName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", errors.New("give a host name")
	}
	if len(s) > 253 {
		return "", errors.New("a host name is at most 253 characters")
	}
	labels := strings.Split(s, ".")
	if len(labels) > 4 {
		return "", errors.New("a host name has at most four parts separated by dots")
	}
	for _, l := range labels {
		if !hostLabelRE.MatchString(l) {
			return "", errors.New("each part of a host name is 1 to 63 letters, digits or hyphens, and does not start or end with a hyphen")
		}
	}
	return s, nil
}

// rewriteHosts replaces the old host name (and its short form) with the new one on every line of an /etc/hosts body, keeping
// the addresses, the other aliases and the comments.  When no line names the old host, a "127.0.1.1 new [short]" line is added.
func rewriteHosts(body, oldName, newName string) string {
	oldShort := strings.SplitN(oldName, ".", 2)[0]
	newShort := strings.SplitN(newName, ".", 2)[0]
	lines := strings.Split(body, "\n")
	changed := false
	for i, ln := range lines {
		code, comment := ln, ""
		if k := strings.Index(ln, "#"); k >= 0 {
			code, comment = ln[:k], ln[k:]
		}
		f := strings.Fields(code)
		if len(f) < 2 {
			continue
		}
		hit := false
		for j := 1; j < len(f); j++ {
			switch {
			case oldName != "" && strings.EqualFold(f[j], oldName):
				f[j] = newName
				hit = true
			case oldShort != "" && strings.EqualFold(f[j], oldShort):
				f[j] = newShort
				hit = true
			}
		}
		if !hit {
			continue
		}
		// no name twice on one line
		seen := map[string]bool{}
		out := []string{f[0]}
		for _, a := range f[1:] {
			if !seen[strings.ToLower(a)] {
				seen[strings.ToLower(a)] = true
				out = append(out, a)
			}
		}
		lines[i] = strings.Join(out, "\t")
		if comment != "" {
			lines[i] += " " + comment
		}
		changed = true
	}
	res := strings.Join(lines, "\n")
	if !changed {
		add := "127.0.1.1\t" + newName
		if newShort != newName {
			add += "\t" + newShort
		}
		if res != "" && !strings.HasSuffix(res, "\n") {
			res += "\n"
		}
		res += add + "\n"
	}
	return res
}

// replaceFile writes data to path through a temporary file in the same directory and renames it over, keeping the mode.
func replaceFile(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// NodeRename sets this node's host name and updates /etc/hosts.
func (m *Mgmt) NodeRename(name, actor string) (string, error) {
	nn, err := validNodeName(name)
	if err != nil {
		return "", err
	}
	old := hostCurrent()
	if strings.EqualFold(old, nn) {
		return "this node is already called " + nn, nil
	}
	// /etc/hosts first: if it cannot be written nothing has changed
	body, err := os.ReadFile(hostsFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("reading %s: %v", hostsFile, err)
	}
	if err := replaceFile(hostsFile, []byte(rewriteHosts(string(body), old, nn))); err != nil {
		return "", fmt.Errorf("writing %s: %v", hostsFile, err)
	}
	// hostnamectl when systemd is running; otherwise (or when it cannot talk to systemd, as in a container) hostname(1) and /etc/hostname
	var herr error
	if _, e := exec.LookPath("hostnamectl"); e == nil || hostCmdIsFake {
		herr = hostCmd("hostnamectl", "set-hostname", nn)
	} else {
		herr = errors.New("hostnamectl is not installed")
	}
	if herr != nil {
		if herr = hostCmd("hostname", nn); herr == nil {
			herr = replaceFile(hostnameFile, []byte(nn+"\n"))
		}
	}
	if herr != nil {
		// put /etc/hosts back so it still matches the name the system has
		if rerr := replaceFile(hostsFile, body); rerr != nil {
			warnf("node rename: could not restore %s: %v", hostsFile, rerr)
		}
		return "", fmt.Errorf("could not set the host name: %v", herr)
	}
	warnf("node: host name changed from %s to %s by %s", old, nn, actor)
	return "host name is now " + nn + " (/etc/hosts updated); the cluster shows it within a few seconds", nil
}

// hostCmdIsFake lets tests use the hostnamectl branch without the program being installed.
var hostCmdIsFake bool

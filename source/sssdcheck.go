package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// sssd on an Active Directory domain (realm join, Samba AD) enforces the domain's group policy at the account step of
// PAM, and refuses every PAM service it has no logon right for.  sshd and login are known; the GUI's own service is
// not, so a user who can ssh in gets "pam: Permission denied" at the GUI after the password was accepted.  The fix is a
// line in the domain's section of sssd.conf mapping the service; sssdGPOProblem finds the case so the log can say so.

var (
	sssdConfFile = "/etc/sssd/sssd.conf"
	sssdConfDir  = "/etc/sssd/conf.d"
)

// sssdSections reads sssd.conf and its conf.d snippets into section → option → value (later files override).
func sssdSections() map[string]map[string]string {
	files := []string{sssdConfFile}
	if ents, err := filepath.Glob(filepath.Join(sssdConfDir, "*.conf")); err == nil {
		sort.Strings(ents)
		files = append(files, ents...)
	}
	out := map[string]map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		sec := ""
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			if line[0] == '[' && strings.HasSuffix(line, "]") {
				sec = line[1 : len(line)-1]
				if out[sec] == nil {
					out[sec] = map[string]string{}
				}
				continue
			}
			if k, v, ok := strings.Cut(line, "="); ok && sec != "" {
				out[sec][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// sssdGPOProblem returns advice when an AD domain of sssd would refuse the PAM service by group policy, "" otherwise
// (no sssd, no AD domain, policy not enforced, or the service is mapped).
func sssdGPOProblem(service string) string {
	var bad []string
	for sec, opts := range sssdSections() {
		if !strings.HasPrefix(sec, "domain/") {
			continue
		}
		if !sssdDomainBlocks(opts, service) {
			continue
		}
		bad = append(bad, sec)
	}
	if len(bad) == 0 {
		return ""
	}
	sort.Strings(bad)
	return "sssd enforces group policy (GPO) for " + strings.Join(bad, ", ") + " and does not know the PAM service \"" + service +
		"\", so logins of AD users are refused after the password is accepted. Add \"ad_gpo_map_interactive = +" + service +
		"\" to that domain's section of " + sssdConfFile + " and restart sssd"
}

// sssdRestart makes sssd read its changed configuration (replaceable in tests).
var sssdRestart = func() error {
	out, err := exec.Command("systemctl", "try-restart", "sssd").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl try-restart sssd: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// mapSSSDService adds "+service" to ad_gpo_map_interactive in the [domain/...] sections named in secs of the
// sssd.conf text, and returns the new text.  An existing ad_gpo_map_interactive line gets ", +service" added; a section
// without one gets the line right after its header.
func mapSSSDService(conf, service string, secs []string) string {
	want := map[string]bool{}
	for _, s := range secs {
		want[s] = true
	}
	lines := strings.Split(conf, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		out = append(out, l)
		t := strings.TrimSpace(l)
		if len(t) < 2 || t[0] != '[' || !strings.HasSuffix(t, "]") || !want[t[1:len(t)-1]] {
			continue
		}
		// the section runs to the next header
		j := i + 1
		found := false
		for ; j < len(lines); j++ {
			bt := strings.TrimSpace(lines[j])
			if strings.HasPrefix(bt, "[") && strings.HasSuffix(bt, "]") {
				break
			}
			if k, v, ok := strings.Cut(bt, "="); ok && !found && strings.ToLower(strings.TrimSpace(k)) == "ad_gpo_map_interactive" {
				found = true
				if strings.TrimSpace(v) == "" {
					lines[j] = "ad_gpo_map_interactive = +" + service
				} else {
					lines[j] = strings.TrimRight(lines[j], " \t") + ", +" + service
				}
			}
		}
		if !found {
			out = append(out, "ad_gpo_map_interactive = +"+service)
		}
	}
	return strings.Join(out, "\n")
}

// fixSSSD maps the PAM service in sssd.conf when sssdGPOProblem finds that sssd would refuse it, keeps the old file
// beside it (sssd.conf.<service>.bak, once) and restarts sssd.  It reports what it did; "" and nil when there was
// nothing to do.  A domain defined only in a conf.d snippet is not edited, and the problem is returned as an error.
func fixSSSD(service string) (string, error) {
	problem := sssdGPOProblem(service)
	if problem == "" {
		return "", nil
	}
	b, err := os.ReadFile(sssdConfFile)
	if err != nil {
		return "", errors.New(problem)
	}
	var secs []string
	for sec, opts := range sssdSections() {
		if !strings.HasPrefix(sec, "domain/") || !sssdDomainBlocks(opts, service) {
			continue
		}
		if strings.Contains(string(b), "["+sec+"]") {
			secs = append(secs, sec)
		}
	}
	sort.Strings(secs)
	if len(secs) == 0 {
		return "", errors.New(problem + " (the domain is not in " + sssdConfFile + " itself, so it was not changed)")
	}
	st, err := os.Stat(sssdConfFile)
	if err != nil {
		return "", err
	}
	bak := sssdConfFile + "." + service + ".bak"
	if _, err := os.Stat(bak); err != nil {
		if err := os.WriteFile(bak, b, 0o600); err != nil {
			return "", fmt.Errorf("saving %s: %v", bak, err)
		}
	}
	tmp := sssdConfFile + ".tmp-" + service
	if err := os.WriteFile(tmp, []byte(mapSSSDService(string(b), service, secs)), st.Mode().Perm()); err != nil {
		return "", err
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		os.Chown(tmp, int(sys.Uid), int(sys.Gid))
	}
	if err := os.Rename(tmp, sssdConfFile); err != nil {
		os.Remove(tmp)
		return "", err
	}
	msg := "added \"ad_gpo_map_interactive = +" + service + "\" to " + strings.Join(secs, ", ") + " in " + sssdConfFile + " (the old file is " + bak + ")"
	if err := sssdRestart(); err != nil {
		return msg, fmt.Errorf("%s, but sssd was not restarted: %v; restart it", msg, err)
	}
	return msg + " and restarted sssd", nil
}

// sssdDomainBlocks says whether the options of a domain make sssd refuse the PAM service by group policy.
func sssdDomainBlocks(opts map[string]string, service string) bool {
	if strings.ToLower(opts["id_provider"]) != "ad" && strings.ToLower(opts["access_provider"]) != "ad" {
		return false
	}
	switch strings.ToLower(opts["ad_gpo_access_control"]) {
	case "disabled", "permissive":
		return false
	}
	if d := strings.ToLower(opts["ad_gpo_default_right"]); d != "" && d != "deny" {
		return false
	}
	for k, v := range opts {
		if !strings.HasPrefix(k, "ad_gpo_map_") {
			continue
		}
		for _, item := range strings.Split(v, ",") {
			if strings.TrimSpace(item) == "+"+service {
				return false
			}
		}
	}
	return true
}

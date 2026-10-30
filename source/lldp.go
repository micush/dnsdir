package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LLDP (Configure ▸ Settings ▸ General ▸ Neighbor discovery).  When dns.lldp is on, every node runs lldpd: the switches
// see the nodes (host name, port, management address) and each node sees which switch and port each of its interfaces is
// plugged into, shown on Monitor ▸ Node and by --lldp.  It is a shared setting, off by default, because LLDP tells
// everything on the segment the host's name, OS and addresses.
//
// The setting decides, whoever started lldpd: on, lldpd is enabled and running; off, it is stopped and disabled, also one
// started by hand or by its package (Debian starts lldpd as soon as it is installed).  lldpWatch checks once a minute, so
// an lldpd installed, started or stopped behind dnsdir's back follows the setting again within a minute.  lldpd is optional:
// the installer adds it when the distribution has it (on RHEL and its rebuilds it is in EPEL, which is never switched on
// for it); a node without it says so.
//
// lldpOwnPath, a comments-only file in lldpd's snippet directory (lldpd reads /etc/lldpd.d/*.conf as lldpcli commands), is
// there while dnsdir has LLDP on.  The uninstaller reads it: with it, lldpd is stopped when dnsdir goes.
//
// dnsdir and ntpdir on one host share one lldpd, and dnsdir decides (as it does for the gateways ntpdir piggybacks on):
// while dnsdir is installed, ntpdir neither starts nor stops lldpd.  lldpDefer is therefore always false here.

const (
	lldpUnit         = "lldpd"
	lldpHeader       = "# Managed by dnsdir (Configure ▸ Settings ▸ General ▸ Neighbor discovery): LLDP is on there, so dnsdir keeps lldpd\n# running.  Switched off there, dnsdir stops lldpd and removes this file; the uninstaller stops lldpd when this file is here.\n"
	lldpNotInstalled = "lldpd is not installed, so LLDP cannot run: install the lldpd package (on RHEL, Rocky and Alma it is in EPEL) or run the installer again"
	lldpCliTimeout   = 5 * time.Second
	lldpSelf         = "dnsdir"
	lldpSibling      = "ntpdir" // the other product that may share this host's lldpd; it defers to dnsdir
)

var (
	lldpDir = envOr("DNSDIR_LLDP_DIR", "/etc/lldpd.d")
	// lldpRun runs systemctl; replaced in tests.
	lldpRun = func(args ...string) ([]byte, error) {
		return exec.Command(envOr("DNSDIR_SYSTEMCTL", "systemctl"), args...).CombinedOutput()
	}
	lldpInstalled = func() bool {
		if _, err := exec.LookPath("lldpd"); err == nil {
			return true
		}
		_, err := os.Stat("/usr/sbin/lldpd")
		return err == nil
	}
	// lldpCli runs lldpcli (with DNSDIR_LLDPCLI_ARGS first, e.g. "-u /path/to/socket" for a test lldpd); replaced in tests.
	lldpCli = func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), lldpCliTimeout)
		defer cancel()
		all := append(strings.Fields(os.Getenv("DNSDIR_LLDPCLI_ARGS")), args...)
		return exec.CommandContext(ctx, "lldpcli", all...).Output()
	}
	// lldpDefer says whether the sibling decides about lldpd on this host: never for dnsdir, which is the one that decides.
	lldpDefer = func() bool { return false }

	lldpMu     sync.Mutex
	lldpWarned time.Time
)

func lldpOwnPath() string     { return filepath.Join(lldpDir, lldpSelf+".conf") }
func lldpSiblingPath() string { return filepath.Join(lldpDir, lldpSibling+".conf") }

func lldpActive() bool  { _, err := lldpRun("is-active", "--quiet", lldpUnit); return err == nil }
func lldpEnabled() bool { _, err := lldpRun("is-enabled", "--quiet", lldpUnit); return err == nil }

// applyLLDP makes lldpd follow the setting: on, enabled and running; off, stopped and disabled, whoever had started it.
// It is cheap when nothing changes, so it runs at start, after every configuration change and once a minute (lldpWatch).
func applyLLDP(on bool) {
	lldpMu.Lock()
	defer lldpMu.Unlock()
	if lldpDefer() { // the sibling decides on this host
		if fileExists(lldpOwnPath()) {
			_ = os.Remove(lldpOwnPath())
			infof("lldp: %s is installed and decides about LLDP on this host; dnsdir leaves lldpd to it", lldpSibling)
		}
		return
	}
	if !on {
		_ = os.Remove(lldpOwnPath())
	}
	if !lldpInstalled() {
		if on && time.Since(lldpWarned) > time.Hour {
			lldpWarned = time.Now()
			warnf("lldp: %s", lldpNotInstalled)
		}
		return
	}
	active, enabled := lldpActive(), lldpEnabled()
	if !on {
		if !active && !enabled {
			return
		}
		if out, err := lldpRun("disable", "--now", lldpUnit); err != nil {
			warnf("lldp: could not stop lldpd: %v %s", err, strings.TrimSpace(string(out)))
			return
		}
		infof("lldp: lldpd stopped and disabled (LLDP is off)")
		return
	}
	if !fileExists(lldpOwnPath()) { // for the uninstaller: LLDP is on here
		if err := os.MkdirAll(lldpDir, 0o755); err != nil || os.WriteFile(lldpOwnPath(), []byte(lldpHeader), 0o644) != nil {
			warnf("lldp: could not write %s", lldpOwnPath())
		}
	}
	if active && enabled {
		return
	}
	if out, err := lldpRun("enable", "--now", lldpUnit); err != nil {
		warnf("lldp: could not start lldpd: %v %s", err, strings.TrimSpace(string(out)))
		return
	}
	infof("lldp: lldpd enabled and started (LLDP is on)")
}

// lldpWatch applies the setting once a minute, so a sibling installed or removed, or an lldpd stopped by hand, is noticed.
func lldpWatch(ctx context.Context, sup *Supervisor) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sup.mu.Lock()
			on := sup.dc != nil && sup.dc.DNS.LLDP
			sup.mu.Unlock()
			applyLLDP(on)
		}
	}
}

// LLDPNeighbor is one device seen on one interface.
type LLDPNeighbor struct {
	Interface    string   `json:"interface"`
	Protocol     string   `json:"protocol"` // LLDP, or CDP and the like when lldpd is told to listen for them
	Age          string   `json:"age"`
	ChassisID    string   `json:"chassis_id"`
	SystemName   string   `json:"system_name"`
	SystemDescr  string   `json:"system_descr"`
	MgmtIPs      []string `json:"mgmt_ips"`
	PortID       string   `json:"port_id"`
	PortDescr    string   `json:"port_descr"`
	VLANs        []string `json:"vlans"`
	Capabilities []string `json:"capabilities"` // the enabled ones: Bridge, Router, ...
	TTL          string   `json:"ttl"`
}

// LLDPStatus is what Configure ▸ Settings ▸ General ▸ Neighbor discovery, Monitor ▸ Node and --lldp show for one node.
type LLDPStatus struct {
	Enabled   bool           `json:"enabled"`    // the shared setting
	Installed bool           `json:"installed"`  // lldpd is on this node
	Running   bool           `json:"running"`    // lldpd is running
	ManagedBy string         `json:"managed_by"` // who decides about lldpd here: always "dnsdir"
	Deferred  bool           `json:"deferred"`   // dnsdir is installed here and decides
	Neighbors []LLDPNeighbor `json:"neighbors"`
	Error     string         `json:"error,omitempty"` // lldpcli could not be asked
}

func lldpStatus(on bool) LLDPStatus {
	st := LLDPStatus{Enabled: on, Installed: lldpInstalled(), Deferred: lldpDefer(), Neighbors: []LLDPNeighbor{}}
	st.Running = st.Installed && lldpActive()
	st.ManagedBy = lldpSelf
	if st.Deferred {
		st.ManagedBy = lldpSibling
	}
	if !st.Running {
		return st
	}
	out, err := lldpCli("-f", "json0", "show", "neighbors", "details")
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			err = errors.New(strings.TrimSpace(string(ee.Stderr)))
		}
		st.Error = "lldpcli: " + err.Error()
		return st
	}
	n, err := parseLLDPJSON0(out)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Neighbors = n
	return st
}

// parseLLDPJSON0 reads `lldpcli -f json0 show neighbors details`: the json0 format, where every value is a list (so one
// neighbor reads like several), the same in every lldpd since 0.9.
func parseLLDPJSON0(b []byte) ([]LLDPNeighbor, error) {
	type val struct {
		Type    string `json:"type"`
		Value   string `json:"value"`
		Enabled *bool  `json:"enabled"`
		VLANID  string `json:"vlan-id"`
		PVID    bool   `json:"pvid"`
	}
	type ifc struct {
		Name    string `json:"name"`
		Via     string `json:"via"`
		Age     string `json:"age"`
		Chassis []struct {
			ID    []val `json:"id"`
			Name  []val `json:"name"`
			Descr []val `json:"descr"`
			Mgmt  []val `json:"mgmt-ip"`
			Capab []val `json:"capability"`
		} `json:"chassis"`
		Port []struct {
			ID    []val `json:"id"`
			Descr []val `json:"descr"`
			TTL   []val `json:"ttl"`
		} `json:"port"`
		VLAN []val `json:"vlan"`
	}
	var doc struct {
		LLDP []struct {
			Interface []ifc `json:"interface"`
		} `json:"lldp"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("lldpcli answered something that is not its JSON: %v", err)
	}
	first := func(v []val) string {
		if len(v) == 0 {
			return ""
		}
		return v[0].Value
	}
	out := []LLDPNeighbor{}
	for _, l := range doc.LLDP {
		for _, i := range l.Interface {
			n := LLDPNeighbor{Interface: i.Name, Protocol: i.Via, Age: lldpAge(i.Age), MgmtIPs: []string{}, VLANs: []string{}, Capabilities: []string{}}
			if len(i.Chassis) > 0 {
				c := i.Chassis[0]
				if len(c.ID) > 0 {
					n.ChassisID = c.ID[0].Value
				}
				n.SystemName, n.SystemDescr = first(c.Name), first(c.Descr)
				for _, m := range c.Mgmt {
					n.MgmtIPs = append(n.MgmtIPs, m.Value)
				}
				for _, cp := range c.Capab {
					if cp.Enabled != nil && *cp.Enabled {
						n.Capabilities = append(n.Capabilities, cp.Type)
					}
				}
			}
			if len(i.Port) > 0 {
				p := i.Port[0]
				if len(p.ID) > 0 {
					n.PortID = p.ID[0].Value
				}
				n.PortDescr, n.TTL = first(p.Descr), first(p.TTL)
			}
			for _, v := range i.VLAN {
				s := v.VLANID
				if s == "" {
					s = v.Value
				}
				if v.PVID {
					s += " (untagged)"
				}
				n.VLANs = append(n.VLANs, s)
			}
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Interface < out[b].Interface })
	return out, nil
}

// LLDPSet switches LLDP on or off for the whole cluster (--lldp-enable / --lldp-disable).
func (m *Mgmt) LLDPSet(on bool, actor string) error {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if dc.DNS.LLDP == on {
		return nil
	}
	dc.DNS.LLDP = on
	return m.PutConfig(dc, actor, map[bool]string{true: "lldp: on", false: "lldp: off"}[on])
}

// lldpAge turns lldpd's "1 day, 02:03:04" (how long ago the neighbor was last heard) into "1d 2h", "2h 3m", "3m 4s" or
// "4s".  Anything else is passed on as it is.
func lldpAge(s string) string {
	s = strings.TrimSpace(s)
	var d, hh, mm, ss int
	if _, err := fmt.Sscanf(strings.Replace(s, "days", "day", 1), "%d day, %d:%d:%d", &d, &hh, &mm, &ss); err != nil {
		return s
	}
	switch {
	case d > 0:
		return fmt.Sprintf("%dd %dh", d, hh)
	case hh > 0:
		return fmt.Sprintf("%dh %dm", hh, mm)
	case mm > 0:
		return fmt.Sprintf("%dm %ds", mm, ss)
	}
	return fmt.Sprintf("%ds", ss)
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The rules of the alerts (see alerts.go) and what they read.

var alertDefs = []alertDef{
	{ID: "upstream_down", Title: "Upstream server down", Subject: "upstream server", Kind: "updown", Sev: "warning", On: true, Fix: []string{"recheck"}, Go: "dns"},
	{ID: "fallback_in_use", Title: "Only fallback servers in use", Subject: "pool", Kind: "updown", Sev: "warning", On: true, Fix: []string{"recheck"}, Go: "dns"},
	{ID: "listener_down", Title: "DNS listener down", Subject: "gateway", Kind: "updown", Sev: "critical", On: true, Fix: []string{"restart_dns"}, Go: "gateways"},
	{ID: "no_active_gateway", Title: "No active gateway", Subject: "gateway", Kind: "updown", Sev: "critical", On: true, Go: "gateways"},
	{ID: "servfail_high", Title: "Many queries fail", Subject: "pool", Kind: "value", Sev: "warning", On: true, Unit: "% SERVFAIL", Thresh: 5, ForMin: 10, Fix: []string{"recheck", "flush_cache"}, Go: "stats"},
	{ID: "no_queries", Title: "No queries received", Subject: "pool", Kind: "updown", Sev: "info", On: false, DefMode: "minutes", DefAfter: 15, Go: "stats"},
	{ID: "certificate_expiring", Title: "Certificate about to expire", Subject: "certificate", Kind: "value", Sev: "warning", On: true, Unit: "days left", Below: true, Thresh: 14, ForMin: 0, Fix: []string{"renew_certificate"}, Go: "cfg_web"},
	{ID: "backup_failed", Title: "Backup failed", Subject: "", Kind: "updown", Sev: "warning", On: true, DefMode: "minutes", DefAfter: 30, Go: "cfg_backup"},
	{ID: "cpu_high", Title: "CPU busy", Subject: "", Kind: "value", Sev: "warning", On: true, Unit: "% CPU", Thresh: 90, ForMin: 15, Go: "host"},
	{ID: "memory_high", Title: "Memory nearly full", Subject: "", Kind: "value", Sev: "warning", On: true, Unit: "% memory", Thresh: 90, ForMin: 15, Go: "host"},
	{ID: "disk_full", Title: "Disk nearly full", Subject: "filesystem", Kind: "value", Sev: "warning", On: true, Unit: "% full", Thresh: 90, ForMin: 10, Go: "host"},
}

func alertDefByID(id string) (alertDef, bool) {
	for _, d := range alertDefs {
		if d.ID == id {
			return d, true
		}
	}
	return alertDef{}, false
}

type cntPoint struct {
	at   time.Time
	q, f uint64
}

const alertCountWindow = 5 * time.Minute

// window adds this round's counters and says how many queries and failures there were over the last few minutes, and over
// how long.
func (e *AlertEngine) window(key string, now time.Time, q, f uint64) (dq, df uint64, span time.Duration) {
	pts := append(e.cnt[key], cntPoint{now, q, f})
	for len(pts) > 2 && now.Sub(pts[1].at) >= alertCountWindow {
		pts = pts[1:]
	}
	e.cnt[key] = pts
	old := pts[0]
	if q < old.q || f < old.f { // the counters started again
		e.cnt[key] = pts[len(pts)-1:]
		return 0, 0, 0
	}
	return q - old.q, f - old.f, now.Sub(old.at)
}

func poolLabel(s *StatusServer, key int) string {
	if key == 0 {
		return "shared"
	}
	if n := s.sup.groupName(key); n != "" {
		return n
	}
	return "group " + itoa(key)
}

// sampleNode reads everything the rules look at, on this node.
func (e *AlertEngine) sampleNode(now time.Time) []alertSample {
	st := e.st
	if st == nil {
		return nil
	}
	if e.cnt == nil {
		e.cnt = map[string][]cntPoint{}
	}
	var out []alertSample
	pools := st.sup.poolList()
	for _, pi := range pools {
		pl := poolLabel(st, pi.Key)
		for _, sv := range st.namedServers(pi) {
			if sv.Fallback {
				continue
			}
			who := sv.Addr
			if sv.Name != "" {
				who = sv.Name + " (" + sv.Addr + ")"
			}
			subj := sv.Addr
			if pi.Key != 0 {
				subj += " · " + pl
			}
			msg := who + " does not pass its tests"
			if sv.LastError != "" {
				msg += ": " + sv.LastError
			}
			out = append(out, alertSample{Rule: "upstream_down", Subject: subj, Bad: !sv.Healthy, Message: msg, Gateways: pi.Groups})
		}
		fb := pi.Pool.UsingFallback()
		out = append(out, alertSample{Rule: "fallback_in_use", Subject: pl, Bad: fb, Message: "every normal server of " + pl + " is down, so only fallback servers answer", Gateways: pi.Groups})
		q, f := pi.Pool.Queries.Load(), pi.Pool.Failed.Load()
		dq, df, span := e.window(pl, now, q, f)
		share := 0.0
		if dq >= 20 {
			share = 100 * float64(df) / float64(dq)
		}
		out = append(out, alertSample{Rule: "servfail_high", Subject: pl, Value: share, Gateways: pi.Groups, Bad: dq >= 20 && share > e.threshold("servfail_high"),
			Message: fmt.Sprintf("%.1f%% of the queries of %s failed over the last %d minutes", share, pl, int(span.Minutes()+0.5))})
		out = append(out, alertSample{Rule: "no_queries", Subject: pl, Gateways: pi.Groups, Bad: span >= alertCountWindow-30*time.Second && dq == 0,
			Message: pl + " has received no queries"})
	}
	type gk struct {
		gid int
		af  string
	}
	active, local, serving := map[gk]bool{}, map[gk]bool{}, map[gk]bool{}
	up := map[gk]bool{}
	for _, r := range st.snapshot() {
		k := gk{r.GroupID, r.AF}
		if r.State == "active" {
			active[k] = true
		}
		if r.Local {
			local[k] = true
			if r.State == "active" || r.State == "forward" {
				serving[k] = true
				up[k] = r.DNSUp
			}
		}
	}
	for k := range local {
		subj := fmt.Sprintf("group %d %s", k.gid, k.af)
		out = append(out, alertSample{Rule: "no_active_gateway", Subject: subj, Bad: !active[k], Message: "no node is the active gateway of " + subj, Gateways: []int{k.gid}})
		if serving[k] {
			out = append(out, alertSample{Rule: "listener_down", Subject: subj, Bad: !up[k], Message: "this node serves " + subj + " but its DNS listener is not up", Gateways: []int{k.gid}})
		}
	}
	if e.mg != nil {
		for _, c := range []struct {
			name string
			cm   *CertManager
		}{{"web", e.mg.certs}, {"dns", e.mg.dnscerts}} {
			if c.cm == nil {
				continue
			}
			lc, err := c.cm.current(false)
			if err != nil || lc == nil || lc.info.NotAfter.IsZero() {
				continue
			}
			days := time.Until(lc.info.NotAfter).Hours() / 24
			out = append(out, alertSample{Rule: "certificate_expiring", Subject: c.name, Value: days, Bad: days < e.threshold("certificate_expiring"),
				Message: fmt.Sprintf("the %s certificate runs out on %s (%.0f days)", c.name, lc.info.NotAfter.Format("2006-01-02"), days)})
		}
	}
	if e.mg != nil && e.mg.backup != nil {
		if failing, enabled, msg := e.mg.backup.Failing(); enabled {
			out = append(out, alertSample{Rule: "backup_failed", Bad: failing, Message: "the last backup failed: " + msg})
		}
	}
	if h := hoststats.lastNow(); h.At != 0 {
		out = append(out, alertSample{Rule: "cpu_high", Value: h.CPU, Bad: h.CPU > e.threshold("cpu_high"), Message: fmt.Sprintf("CPU is at %.0f%%", h.CPU)})
		out = append(out, alertSample{Rule: "memory_high", Value: h.MemPct, Bad: h.MemPct > e.threshold("memory_high"), Message: fmt.Sprintf("memory is %.0f%% in use", h.MemPct)})
		for _, f := range h.FS {
			out = append(out, alertSample{Rule: "disk_full", Subject: f.Mount, Value: f.Pct, Bad: f.Pct > e.threshold("disk_full"), Message: fmt.Sprintf("%s is %.0f%% full", f.Mount, f.Pct)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// threshold is the rule's threshold in force.
func (e *AlertEngine) threshold(id string) float64 {
	d, _ := alertDefByID(id)
	return e.cfg().rule(d).Threshold
}

// ── the Fix menu ─────────────────────────────────────────────────────────────

var alertFixes = map[string]string{
	"recheck":           "Check the upstream servers now",
	"flush_cache":       "Empty the answer cache",
	"restart_dns":       "Restart the DNS listeners",
	"renew_certificate": "Renew the automatic certificate",
}

func (e *AlertEngine) fix(action, actor string) (string, error) {
	if e.st == nil {
		return "", errors.New("not available")
	}
	switch action {
	case "recheck":
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		for _, pi := range e.st.sup.poolList() {
			go func(p *Pool) { p.ProbeNow(ctx) }(pi.Pool)
		}
		go func() { time.Sleep(60 * time.Second); cancel() }()
		return "The upstream servers are being checked.", nil
	case "flush_cache":
		return fmt.Sprintf("%d cached answers dropped.", e.st.sup.clearCache()), nil
	case "restart_dns":
		e.st.sup.mu.Lock()
		var engs []*Engine
		for _, en := range e.st.sup.engines {
			engs = append(engs, en)
		}
		e.st.sup.mu.Unlock()
		for _, en := range engs {
			en.RestartDNS()
		}
		return "The DNS listeners were restarted.", nil
	case "renew_certificate":
		if e.mg == nil {
			return "", errors.New("not available")
		}
		if _, err := e.mg.ACMERequest(actor); err != nil {
			return "", err
		}
		return "A new certificate was requested.", nil
	}
	return "", errors.New("unknown action")
}

// ── the operations behind /api/alerts ────────────────────────────────────────

func (m *Mgmt) alertsOp(cmd string, raw json.RawMessage, actor string) (any, error) {
	e := m.alerts
	if e == nil {
		return nil, errors.New("alerts are not available on this node")
	}
	var a struct {
		ID      string `json:"id"`
		Ack     bool   `json:"ack"`
		Minutes int    `json:"minutes"`
		Action  string `json:"action"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
	}
	ok := map[string]any{"ok": true}
	switch cmd {
	case "alerts.list":
		return e.View(), nil
	case "alerts.ack":
		return ok, e.Ack(a.ID, a.Ack, actor)
	case "alerts.silence":
		return ok, e.Silence(a.ID, a.Minutes, actor)
	case "alerts.resolve":
		return ok, e.Resolve(a.ID, actor)
	case "alerts.test":
		if err := e.Test(actor); err != nil {
			return nil, err
		}
		return ok, nil
	case "alerts.fix":
		view := e.View()
		var allowed bool
		for _, al := range view.Alerts {
			if al.ID == a.ID {
				d, _ := alertDefByID(al.Rule)
				allowed = containsStr(d.Fix, a.Action)
			}
		}
		if !allowed {
			return nil, errors.New("that action does not go with that alert")
		}
		msg, err := e.fix(a.Action, actor)
		if err != nil {
			return nil, err
		}
		warnf("alerts: %q ran %q for an alert", actor, alertFixes[a.Action])
		return map[string]any{"ok": true, "message": msg}, nil
	}
	return nil, fmt.Errorf("unknown command %q", cmd)
}

var _ = strings.TrimSpace

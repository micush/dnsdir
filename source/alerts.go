package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Alerts (Configure ▸ Alerts, Monitor ▸ Alerts).  Every node checks itself every alertTick against a fixed list of rules
// (alertDefs).  A rule makes an alert after its condition has held for as long as the rule says (a number of checks in a row,
// a number of minutes, M of the last N checks, or a value over a threshold for some minutes), and ends it after the condition
// has been good for the "clear after" time.  An alert is open, acknowledged (someone is on it), silenced (nobody wants to
// hear about it for a while) or closed.  Opening and closing go to the log (so to syslog) and to a webhook.  The settings are
// shared by the cluster (DNSConfig.Alerts); the alerts, acknowledgements and silences are each node's own, kept in
// alerts.json in the state directory.

const (
	alertTick       = 15 * time.Second
	alertFlapWindow = time.Hour // an alert that comes back within this long is the same alert, counted again
	alertKeepDays   = 30
	alertKeepMax    = 1000
	alertHistLen    = 100
)

// AlertsConfig is the "alerts" block of the DNS settings.
type AlertsConfig struct {
	Webhook     string               `json:"webhook,omitempty"`      // URL that gets a JSON POST for every opened and resolved alert
	RepeatHours int                  `json:"repeat_hours,omitempty"` // tell again this often while an alert stays open and unacknowledged; 0 = never
	Rules       map[string]AlertRule `json:"rules,omitempty"`        // by rule id; a rule that is not here, or a field left out, has its default
}

// AlertRule is one rule's settings.  Fields left out take the rule's default.
type AlertRule struct {
	Enabled   *bool   `json:"enabled,omitempty"`
	Severity  string  `json:"severity,omitempty"`    // info, warning, critical
	Mode      string  `json:"mode,omitempty"`        // up/down rules: in_a_row, minutes or m_of_n
	After     int     `json:"after,omitempty"`       // in_a_row: checks; minutes: minutes; m_of_n: the M
	Of        int     `json:"of,omitempty"`          // m_of_n: the N
	Threshold float64 `json:"threshold,omitempty"`   // value rules
	ForMin    *int    `json:"for_minutes,omitempty"` // value rules: how long past the threshold
	ClearMode string  `json:"clear_mode,omitempty"`  // checks (good checks in a row) or minutes
	Clear     int     `json:"clear,omitempty"`
}

// alertDef is a rule of the catalog.
type alertDef struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Subject  string   `json:"subject"` // what one alert is about: "upstream server", "certificate", ...
	Kind     string   `json:"kind"`    // updown or value
	Sev      string   `json:"severity"`
	On       bool     `json:"on"`              // enabled by default
	Unit     string   `json:"unit"`            // value rules: the unit of the threshold
	Below    bool     `json:"below,omitempty"` // value rules: bad when under the threshold
	Thresh   float64  `json:"threshold,omitempty"`
	ForMin   int      `json:"for_minutes,omitempty"`
	DefMode  string   `json:"-"`             // up/down rules: the counting the rule starts with (default in_a_row)
	DefAfter int      `json:"-"`             // and its number (default 3)
	Fix      []string `json:"fix,omitempty"` // the actions of the Fix menu
	Go       string   `json:"go,omitempty"`  // the page "Go to" opens
}

// ruleView is a rule with every default filled in, for the form and for the checks.
type ruleView struct {
	alertDef
	Enabled   bool    `json:"enabled"`
	Severity  string  `json:"severity_now"`
	Mode      string  `json:"mode"`
	After     int     `json:"after"`
	Of        int     `json:"of"`
	Threshold float64 `json:"threshold_now"`
	ForMinNow int     `json:"for_minutes_now"`
	ClearMode string  `json:"clear_mode"`
	Clear     int     `json:"clear"`
}

var alertSeverities = []string{"info", "warning", "critical"}

func (c *AlertsConfig) rule(d alertDef) ruleView {
	r := AlertRule{}
	if c != nil {
		r = c.Rules[d.ID]
	}
	v := ruleView{alertDef: d, Enabled: d.On, Severity: d.Sev, Threshold: d.Thresh, ForMinNow: d.ForMin}
	if r.Enabled != nil {
		v.Enabled = *r.Enabled
	}
	if r.Severity != "" {
		v.Severity = r.Severity
	}
	if d.Kind == "updown" {
		v.Mode, v.After, v.Of = "in_a_row", 3, 5
		if d.DefMode != "" {
			v.Mode, v.After = d.DefMode, d.DefAfter
		}
		if r.Mode != "" {
			v.Mode = r.Mode
		}
		if r.After > 0 {
			v.After = r.After
		}
		if r.Of > 0 {
			v.Of = r.Of
		}
		v.ClearMode, v.Clear = "checks", 2
	} else {
		if r.Threshold != 0 {
			v.Threshold = r.Threshold
		}
		if r.ForMin != nil {
			v.ForMinNow = *r.ForMin
		}
		v.ClearMode, v.Clear = "minutes", 5
	}
	if r.ClearMode != "" {
		v.ClearMode = r.ClearMode
	}
	if r.Clear > 0 {
		v.Clear = r.Clear
	}
	return v
}

// Validate checks the block and tidies it.
func (c *AlertsConfig) Validate() error {
	c.Webhook = strings.TrimSpace(c.Webhook)
	if c.Webhook != "" {
		u, err := url.Parse(c.Webhook)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("alerts: the webhook must be an http:// or https:// address")
		}
		if len(c.Webhook) > 2000 {
			return errors.New("alerts: the webhook address is too long")
		}
	}
	if c.RepeatHours < 0 || c.RepeatHours > 24*30 {
		return errors.New("alerts: repeat_hours is 0 (never) to 720")
	}
	for id, r := range c.Rules {
		def, ok := alertDefByID(id)
		if !ok {
			return fmt.Errorf("alerts: there is no rule %q", id)
		}
		if r.Severity != "" && !containsStr(alertSeverities, r.Severity) {
			return fmt.Errorf("alerts: %s: severity is info, warning or critical", id)
		}
		if r.Mode != "" && r.Mode != "in_a_row" && r.Mode != "minutes" && r.Mode != "m_of_n" {
			return fmt.Errorf("alerts: %s: mode is in_a_row, minutes or m_of_n", id)
		}
		if r.ClearMode != "" && r.ClearMode != "checks" && r.ClearMode != "minutes" {
			return fmt.Errorf("alerts: %s: clear_mode is checks or minutes", id)
		}
		if r.After < 0 || r.After > 100000 || r.Of < 0 || r.Of > alertHistLen || r.Clear < 0 || r.Clear > 100000 {
			return fmt.Errorf("alerts: %s: a count is out of range (of is at most %d)", id, alertHistLen)
		}
		if r.Mode == "m_of_n" {
			v := c.rule(def)
			if v.After > v.Of {
				return fmt.Errorf("alerts: %s: %d failures out of the last %d checks is not possible", id, v.After, v.Of)
			}
		}
		if math.IsNaN(r.Threshold) || math.IsInf(r.Threshold, 0) || r.Threshold < 0 {
			return fmt.Errorf("alerts: %s: the threshold is a number of 0 or more", id)
		}
		if r.ForMin != nil && (*r.ForMin < 0 || *r.ForMin > 10080) {
			return fmt.Errorf("alerts: %s: for_minutes is 0 to 10080", id)
		}
	}
	if len(c.Rules) == 0 {
		c.Rules = nil
	}
	return nil
}

func (c *AlertsConfig) clone() *AlertsConfig {
	if c == nil {
		return nil
	}
	n := *c
	if c.Rules != nil {
		n.Rules = make(map[string]AlertRule, len(c.Rules))
		for k, v := range c.Rules {
			n.Rules[k] = v
		}
	}
	return &n
}

// ── alerts and silences ──────────────────────────────────────────────────────

// Alert is one alert.  Times are unix seconds; 0 = not yet / never.
type Alert struct {
	ID         string  `json:"id"`
	Rule       string  `json:"rule"`
	Title      string  `json:"title"`
	Subject    string  `json:"subject"`
	Node       string  `json:"node"`
	Severity   string  `json:"severity"`
	Message    string  `json:"message"`
	Value      float64 `json:"value,omitempty"`
	Opened     int64   `json:"opened"`
	Closed     int64   `json:"closed,omitempty"`
	Count      int     `json:"count"`                // how many times it has opened (it comes back within an hour: the same alert)
	Recovering bool    `json:"recovering,omitempty"` // the condition is good, the clear time has not passed yet
	Acked      bool    `json:"acked,omitempty"`
	AckedBy    string  `json:"acked_by,omitempty"`
	AckedAt    int64   `json:"acked_at,omitempty"`
	Resolution string  `json:"resolution,omitempty"` // cleared, manual, rule off, auto fix
	ResolvedBy string  `json:"resolved_by,omitempty"`
	Notified   int64   `json:"notified,omitempty"` // when somebody was last told (webhook)
	Silenced   int64   `json:"silenced_until,omitempty"`
}

// Silence keeps the alerts that match quiet until it runs out.  An empty Rule or Subject matches any.
type Silence struct {
	ID      string `json:"id"`
	Rule    string `json:"rule,omitempty"`
	Subject string `json:"subject,omitempty"`
	Until   int64  `json:"until"`
	By      string `json:"by,omitempty"`
	Created int64  `json:"created"`
}

func (s Silence) matches(a *Alert) bool {
	return (s.Rule == "" || s.Rule == a.Rule) && (s.Subject == "" || s.Subject == a.Subject)
}

type alertSample struct {
	Rule, Subject, Message string
	Bad                    bool
	Value                  float64
}

type alertTrack struct {
	hist                []bool
	badRun, goodRun     int
	badSince, goodSince time.Time
	value               float64
	message             string
}

// AlertEngine keeps the alerts of this node.
type AlertEngine struct {
	mu       sync.Mutex
	path     string
	node     string
	cfg      func() *AlertsConfig
	sample   func(now time.Time) []alertSample
	now      func() time.Time
	alerts   map[string]*Alert // by ID
	tracks   map[string]*alertTrack
	silences []Silence
	opened   uint64 // alerts opened, ever (an alert that comes back counts again)
	send     func(url string, body []byte) error
	lastErr  time.Time
	st       *StatusServer // what the rules read
	mg       *Mgmt
	cnt      map[string][]cntPoint
}

func NewAlertEngine(stateDir, node string, cfg func() *AlertsConfig) *AlertEngine {
	e := &AlertEngine{path: filepath.Join(stateDir, "alerts.json"), node: node, cfg: cfg, now: time.Now,
		alerts: map[string]*Alert{}, tracks: map[string]*alertTrack{}, send: postWebhook}
	e.load()
	return e
}

func (e *AlertEngine) load() {
	b, err := os.ReadFile(e.path)
	if err != nil {
		return
	}
	var st struct {
		Alerts   []*Alert  `json:"alerts"`
		Silences []Silence `json:"silences"`
		Opened   uint64    `json:"opened_total"`
	}
	if json.Unmarshal(b, &st) != nil {
		return
	}
	for _, a := range st.Alerts {
		if a != nil && a.ID != "" {
			e.alerts[a.ID] = a
		}
	}
	e.silences, e.opened = st.Silences, st.Opened
}

// saveLocked writes the state; the caller holds e.mu.
func (e *AlertEngine) saveLocked() {
	var st struct {
		Alerts   []*Alert  `json:"alerts"`
		Silences []Silence `json:"silences"`
		Opened   uint64    `json:"opened_total"`
	}
	st.Opened = e.opened
	for _, a := range e.alerts {
		st.Alerts = append(st.Alerts, a)
	}
	sort.Slice(st.Alerts, func(i, j int) bool { return st.Alerts[i].Opened < st.Alerts[j].Opened })
	st.Silences = e.silences
	b, err := json.Marshal(st)
	if err == nil {
		err = writeFileAtomic(e.path, b)
	}
	if err != nil && time.Since(e.lastErr) > time.Hour {
		e.lastErr = time.Now()
		warnf("alerts: could not save %s: %v", e.path, err)
	}
}

func newAlertID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Run checks every alertTick until ctx ends.
func (e *AlertEngine) Run(ctx context.Context) {
	t := time.NewTicker(alertTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Tick()
		}
	}
}

// Tick makes one round of checks.
func (e *AlertEngine) Tick() {
	now := e.now()
	var samples []alertSample
	if e.sample != nil {
		samples = e.sample(now)
	}
	e.apply(now, samples)
}

type alertNote struct {
	event string
	a     Alert
}

// apply feeds one round of samples through the rules.
func (e *AlertEngine) apply(now time.Time, samples []alertSample) {
	cfg := e.cfg()
	var notes []alertNote
	e.mu.Lock()
	seen := map[string]bool{}
	for _, s := range samples {
		def, ok := alertDefByID(s.Rule)
		if !ok {
			continue
		}
		r := cfg.rule(def)
		if !r.Enabled {
			continue
		}
		key := s.Rule + "|" + s.Subject
		seen[key] = true
		notes = e.feedLocked(now, key, s, r, notes)
	}
	// a subject that was not reported this round (a server taken away, a rule turned off) counts as good
	for key := range e.tracks {
		if seen[key] {
			continue
		}
		rule, subject, _ := strings.Cut(key, "|")
		def, ok := alertDefByID(rule)
		r := cfg.rule(def)
		if !ok || !r.Enabled {
			notes = e.closeKeyLocked(now, key, "rule off", "", notes)
			delete(e.tracks, key)
			continue
		}
		notes = e.feedLocked(now, key, alertSample{Rule: rule, Subject: subject}, r, notes)
	}
	// alerts of a rule that was switched off, or that are open without a track (after a restart): close the first kind
	for _, a := range e.alerts {
		if a.Closed != 0 {
			continue
		}
		def, ok := alertDefByID(a.Rule)
		if !ok || !cfg.rule(def).Enabled {
			notes = e.closeAlertLocked(now, a, "rule off", "", notes)
		}
	}
	// tell again
	if cfg != nil && cfg.RepeatHours > 0 {
		for _, a := range e.alerts {
			if a.Closed == 0 && !a.Acked && !e.silencedLocked(a, now) && now.Unix()-a.Notified >= int64(cfg.RepeatHours)*3600 {
				a.Notified = now.Unix()
				notes = append(notes, alertNote{"repeat", *a})
			}
		}
	}
	e.trimLocked(now)
	e.saveLocked()
	e.mu.Unlock()
	e.notify(cfg, notes)
}

func (e *AlertEngine) silencedLocked(a *Alert, now time.Time) bool {
	for _, s := range e.silences {
		if s.Until > now.Unix() && s.matches(a) {
			return true
		}
	}
	return false
}

// feedLocked adds one sample to the key's track and opens or closes its alert when the rule says so.
func (e *AlertEngine) feedLocked(now time.Time, key string, s alertSample, r ruleView, notes []alertNote) []alertNote {
	t := e.tracks[key]
	if t == nil {
		t = &alertTrack{}
		e.tracks[key] = t
	}
	t.hist = append(t.hist, s.Bad)
	if len(t.hist) > alertHistLen {
		t.hist = t.hist[len(t.hist)-alertHistLen:]
	}
	if s.Bad {
		if t.badRun == 0 {
			t.badSince = now
		}
		t.badRun++
		t.goodRun, t.goodSince = 0, time.Time{}
		t.value, t.message = s.Value, s.Message
	} else {
		if t.goodRun == 0 {
			t.goodSince = now
		}
		t.goodRun++
		t.badRun, t.badSince = 0, time.Time{}
	}
	open := e.openAlertLocked(key)
	if open == nil {
		if s.Bad && alertTriggered(r, t, now) {
			notes = e.openLocked(now, key, s, r, notes)
		} else if !s.Bad && t.goodRun > alertHistLen {
			delete(e.tracks, key) // nothing to follow: a subject that has been fine for a long while
		}
		return notes
	}
	open.Value = t.value
	if s.Bad {
		open.Recovering = false
		if s.Message != "" {
			open.Message = s.Message
		}
		open.Severity = r.Severity
		return notes
	}
	if alertCleared(r, t, now) {
		return e.closeAlertLocked(now, open, "cleared", "", notes)
	}
	open.Recovering = true
	return notes
}

func (e *AlertEngine) openAlertLocked(key string) *Alert {
	rule, subject, _ := strings.Cut(key, "|")
	for _, a := range e.alerts {
		if a.Closed == 0 && a.Rule == rule && a.Subject == subject {
			return a
		}
	}
	return nil
}

func alertTriggered(r ruleView, t *alertTrack, now time.Time) bool {
	if r.Kind != "updown" {
		return t.badRun > 0 && now.Sub(t.badSince) >= time.Duration(r.ForMinNow)*time.Minute
	}
	switch r.Mode {
	case "minutes":
		return t.badRun > 0 && now.Sub(t.badSince) >= time.Duration(r.After)*time.Minute
	case "m_of_n":
		last := t.hist
		if len(last) > r.Of {
			last = last[len(last)-r.Of:]
		}
		n := 0
		for _, b := range last {
			if b {
				n++
			}
		}
		return t.badRun > 0 && n >= r.After
	}
	return t.badRun >= r.After
}

func alertCleared(r ruleView, t *alertTrack, now time.Time) bool {
	if r.ClearMode == "minutes" {
		return t.goodRun > 0 && now.Sub(t.goodSince) >= time.Duration(r.Clear)*time.Minute
	}
	return t.goodRun >= r.Clear
}

func (e *AlertEngine) openLocked(now time.Time, key string, s alertSample, r ruleView, notes []alertNote) []alertNote {
	var a *Alert
	for _, c := range e.alerts { // back within the hour: the same alert again
		if c.Closed != 0 && c.Rule == s.Rule && c.Subject == s.Subject && now.Unix()-c.Closed < int64(alertFlapWindow/time.Second) {
			a = c
			break
		}
	}
	if a == nil {
		a = &Alert{ID: newAlertID(), Rule: s.Rule, Title: r.Title, Subject: s.Subject, Node: e.node}
		e.alerts[a.ID] = a
	}
	a.Count++
	e.opened++
	a.Opened, a.Closed = now.Unix(), 0
	a.Severity, a.Message, a.Value = r.Severity, s.Message, s.Value
	a.Recovering, a.Acked, a.AckedBy, a.AckedAt, a.Resolution, a.ResolvedBy = false, false, "", 0, "", ""
	if !e.silencedLocked(a, now) {
		a.Notified = now.Unix()
		notes = append(notes, alertNote{"open", *a})
	}
	return notes
}

func (e *AlertEngine) closeKeyLocked(now time.Time, key, how, by string, notes []alertNote) []alertNote {
	if a := e.openAlertLocked(key); a != nil {
		return e.closeAlertLocked(now, a, how, by, notes)
	}
	return notes
}

func (e *AlertEngine) closeAlertLocked(now time.Time, a *Alert, how, by string, notes []alertNote) []alertNote {
	a.Closed, a.Recovering, a.Resolution, a.ResolvedBy = now.Unix(), false, how, by
	if !e.silencedLocked(a, now) {
		notes = append(notes, alertNote{"resolved", *a})
	}
	if t := e.tracks[a.Rule+"|"+a.Subject]; t != nil && how == "manual" {
		t.badRun, t.hist = 0, nil // a manual close starts the count again, so it reopens only if the condition goes on
	}
	return notes
}

func (e *AlertEngine) trimLocked(now time.Time) {
	cut := now.Add(-alertKeepDays * 24 * time.Hour).Unix()
	var closed []*Alert
	for id, a := range e.alerts {
		if a.Closed != 0 {
			if a.Closed < cut {
				delete(e.alerts, id)
				continue
			}
			closed = append(closed, a)
		}
	}
	if len(closed) > alertKeepMax {
		sort.Slice(closed, func(i, j int) bool { return closed[i].Closed < closed[j].Closed })
		for _, a := range closed[:len(closed)-alertKeepMax] {
			delete(e.alerts, a.ID)
		}
	}
	live := e.silences[:0]
	for _, s := range e.silences {
		if s.Until > now.Unix()-3600 { // kept for an hour after it ran out, so the list can say so
			live = append(live, s)
		}
	}
	e.silences = live
}

// ── telling people ───────────────────────────────────────────────────────────

func (e *AlertEngine) notify(cfg *AlertsConfig, notes []alertNote) {
	for _, n := range notes {
		a := n.a
		line := fmt.Sprintf("alert %s: [%s] %s — %s (%s)", n.event, a.Severity, a.Title, a.Message, e.node)
		switch {
		case n.event == "resolved":
			infof("%s", line)
		case a.Severity == "info":
			infof("%s", line)
		default:
			warnf("%s", line)
		}
		if cfg == nil || cfg.Webhook == "" {
			continue
		}
		body := alertWebhookBody(n.event, a, e.node)
		go func(u string) {
			if err := e.send(u, body); err != nil && time.Since(e.lastErrAt()) > time.Minute {
				e.setLastErr()
				warnf("alerts: the webhook did not take the message: %v", err)
			}
		}(cfg.Webhook)
	}
}

func (e *AlertEngine) lastErrAt() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.lastErr }
func (e *AlertEngine) setLastErr()          { e.mu.Lock(); e.lastErr = time.Now(); e.mu.Unlock() }

func alertWebhookBody(event string, a Alert, node string) []byte {
	text := fmt.Sprintf("[%s] %s — %s (%s)", a.Severity, a.Title, a.Message, node)
	switch event {
	case "resolved":
		text = "RESOLVED " + text
	case "repeat":
		text = "STILL OPEN " + text
	}
	m := map[string]any{"event": event, "text": text, "content": text, "node": node, "severity": a.Severity, "rule": a.Rule,
		"title": a.Title, "subject": a.Subject, "message": a.Message, "opened": a.Opened, "count": a.Count}
	if a.Closed != 0 {
		m["closed"] = a.Closed
		m["duration_seconds"] = a.Closed - a.Opened
		m["resolution"] = a.Resolution
	}
	b, _ := json.Marshal(m)
	return b
}

func postWebhook(u string, body []byte) error {
	req, err := newJSONPost(u, body)
	if err != nil {
		return err
	}
	resp, err := ipv4FirstClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %s", req.URL.Host, resp.Status)
	}
	return nil
}

// ── what the pages ask for ───────────────────────────────────────────────────

// AlertView is the Monitor ▸ Alerts page's data.
type AlertView struct {
	Node     string     `json:"node"`
	Now      int64      `json:"now"`
	Alerts   []Alert    `json:"alerts"`
	Silences []Silence  `json:"silences"`
	Rules    []ruleView `json:"rules"`
}

func (e *AlertEngine) View() AlertView {
	now := e.now()
	cfg := e.cfg()
	e.mu.Lock()
	defer e.mu.Unlock()
	v := AlertView{Node: e.node, Now: now.Unix(), Alerts: []Alert{}, Silences: []Silence{}}
	for _, a := range e.alerts {
		c := *a
		if c.Closed == 0 {
			for _, s := range e.silences {
				if s.Until > now.Unix() && s.matches(a) && s.Until > c.Silenced {
					c.Silenced = s.Until
				}
			}
		}
		v.Alerts = append(v.Alerts, c)
	}
	sort.Slice(v.Alerts, func(i, j int) bool { return v.Alerts[i].Opened > v.Alerts[j].Opened })
	for _, s := range e.silences {
		if s.Until > now.Unix() {
			v.Silences = append(v.Silences, s)
		}
	}
	for _, d := range alertDefs {
		v.Rules = append(v.Rules, cfg.rule(d))
	}
	return v
}

// counts is the number of open alerts that are not silenced, and of those that someone has acknowledged, by severity.
func (e *AlertEngine) counts() (active, acked map[string]int, opened uint64) {
	now := e.now()
	active, acked = map[string]int{}, map[string]int{}
	e.mu.Lock()
	defer e.mu.Unlock()
	opened = e.opened
	for _, a := range e.alerts {
		if a.Closed != 0 || e.silencedLocked(a, now) {
			continue
		}
		if a.Acked {
			acked[a.Severity]++
		} else {
			active[a.Severity]++
		}
	}
	return
}

func (e *AlertEngine) find(id string) *Alert {
	if a := e.alerts[id]; a != nil {
		return a
	}
	return nil
}

// Ack sets or clears the acknowledgement of an open alert.
func (e *AlertEngine) Ack(id string, ack bool, by string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	a := e.find(id)
	if a == nil || a.Closed != 0 {
		return errors.New("that alert is not open any more")
	}
	a.Acked = ack
	if ack {
		a.AckedBy, a.AckedAt = by, e.now().Unix()
	} else {
		a.AckedBy, a.AckedAt = "", 0
	}
	infof("alerts: %q %s %q (%s)", by, map[bool]string{true: "acknowledged", false: "took back the acknowledgement of"}[ack], a.Title, a.Subject)
	e.saveLocked()
	return nil
}

// Silence keeps the alerts of this alert's rule and subject quiet for the given minutes (0 ends it).
func (e *AlertEngine) Silence(id string, minutes int, by string) error {
	if minutes < 0 || minutes > 60*24*90 {
		return errors.New("a silence lasts up to 90 days")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	a := e.find(id)
	if a == nil {
		return errors.New("there is no such alert")
	}
	now := e.now().Unix()
	keep := e.silences[:0]
	for _, s := range e.silences {
		if !(s.Rule == a.Rule && s.Subject == a.Subject) {
			keep = append(keep, s)
		}
	}
	e.silences = keep
	if minutes > 0 {
		e.silences = append(e.silences, Silence{ID: newAlertID(), Rule: a.Rule, Subject: a.Subject, Until: now + int64(minutes)*60, By: by, Created: now})
		infof("alerts: %q silenced %q (%s) for %d minutes", by, a.Title, a.Subject, minutes)
	} else {
		infof("alerts: %q ended the silence of %q (%s)", by, a.Title, a.Subject)
	}
	e.saveLocked()
	return nil
}

// Resolve closes an alert by hand.  It opens again when the condition is still there and holds long enough again.
func (e *AlertEngine) Resolve(id, by string) error {
	e.mu.Lock()
	a := e.find(id)
	if a == nil || a.Closed != 0 {
		e.mu.Unlock()
		return errors.New("that alert is not open any more")
	}
	notes := e.closeAlertLocked(e.now(), a, "manual", by, nil)
	infof("alerts: %q marked %q (%s) resolved", by, a.Title, a.Subject)
	e.saveLocked()
	cfg := e.cfg()
	e.mu.Unlock()
	e.notify(cfg, notes)
	return nil
}

// Test sends a message to the webhook so the setting can be tried.
func (e *AlertEngine) Test(by string) error {
	cfg := e.cfg()
	if cfg == nil || cfg.Webhook == "" {
		return errors.New("there is no webhook address to try")
	}
	a := Alert{Rule: "test", Title: "Test alert", Message: "This is a test from " + by, Severity: "info", Opened: e.now().Unix(), Count: 1}
	return e.send(cfg.Webhook, alertWebhookBody("test", a, e.node))
}

func newJSONPost(u string, body []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dnsdir")
	return req, nil
}

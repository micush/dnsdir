package main

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type alertRig struct {
	t    *testing.T
	e    *AlertEngine
	cfg  *AlertsConfig
	now  time.Time
	bad  bool
	val  float64
	rule string
	mu   sync.Mutex
	sent []string
}

func newAlertRig(t *testing.T, rule string, r AlertRule) *alertRig {
	g := &alertRig{t: t, rule: rule, now: time.Unix(1_700_000_000, 0)}
	g.cfg = &AlertsConfig{Webhook: "http://hook.example/x", Rules: map[string]AlertRule{rule: r}}
	if err := g.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	g.e = NewAlertEngine(t.TempDir(), "node1", func() *AlertsConfig { return g.cfg })
	g.e.now = func() time.Time { return g.now }
	g.e.send = func(u string, b []byte) error {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		g.mu.Lock()
		g.sent = append(g.sent, m["event"].(string))
		g.mu.Unlock()
		return nil
	}
	g.e.sample = func(time.Time) []alertSample {
		return []alertSample{{Rule: g.rule, Subject: "s1", Bad: g.bad, Value: g.val, Message: "msg"}}
	}
	return g
}

// step makes n checks, alertTick apart, with the condition bad or good.
func (g *alertRig) step(bad bool, n int) {
	g.bad = bad
	for i := 0; i < n; i++ {
		g.now = g.now.Add(alertTick)
		g.e.Tick()
	}
	time.Sleep(10 * time.Millisecond) // the webhook goes out in a goroutine
}

func (g *alertRig) open() int {
	n := 0
	for _, a := range g.e.View().Alerts {
		if a.Closed == 0 {
			n++
		}
	}
	return n
}

func (g *alertRig) events() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return strings.Join(g.sent, ",")
}

func TestAlertAfterFailuresInARowAndClearAfterGoodChecks(t *testing.T) {
	g := newAlertRig(t, "upstream_down", AlertRule{Mode: "in_a_row", After: 3, ClearMode: "checks", Clear: 2})
	g.step(true, 2)
	if g.open() != 0 {
		t.Fatal("opened after 2 failures, the rule says 3")
	}
	g.step(false, 1)
	g.step(true, 2)
	if g.open() != 0 {
		t.Fatal("a good check must restart the count")
	}
	g.step(true, 1)
	if g.open() != 1 {
		t.Fatal("not open after 3 in a row")
	}
	g.step(false, 1)
	if a := g.e.View().Alerts[0]; a.Closed != 0 || !a.Recovering {
		t.Fatalf("one good check is not enough: %+v", a)
	}
	g.step(true, 1)
	if g.e.View().Alerts[0].Recovering {
		t.Fatal("bad again: no longer recovering")
	}
	g.step(false, 2)
	if g.open() != 0 || g.e.View().Alerts[0].Resolution != "cleared" {
		t.Fatalf("not cleared after 2 good checks: %+v", g.e.View().Alerts[0])
	}
	if g.events() != "open,resolved" {
		t.Fatalf("webhook events %q", g.events())
	}
}

func TestAlertAfterMinutesAndMOfN(t *testing.T) {
	g := newAlertRig(t, "upstream_down", AlertRule{Mode: "minutes", After: 2, ClearMode: "minutes", Clear: 1})
	g.step(true, 7) // 6 checks = 90 s
	if g.open() != 0 {
		t.Fatal("open before 2 minutes")
	}
	g.step(true, 2)
	if g.open() != 1 {
		t.Fatal("not open after 2 minutes")
	}
	g.step(false, 3)
	if g.open() != 1 {
		t.Fatal("closed before a minute of good")
	}
	g.step(false, 2)
	if g.open() != 0 {
		t.Fatal("not closed after a minute of good")
	}

	m := newAlertRig(t, "upstream_down", AlertRule{Mode: "m_of_n", After: 3, Of: 5, ClearMode: "checks", Clear: 1})
	for _, bad := range []bool{true, false, true, false} {
		m.step(bad, 1)
	}
	if m.open() != 0 {
		t.Fatal("2 of 4 is not 3 of 5")
	}
	m.step(true, 1) // bad,good,bad,good,bad = 3 of the last 5
	if m.open() != 1 {
		t.Fatal("3 of the last 5 should open")
	}
}

func TestAlertValueNeedsToStayPastTheThreshold(t *testing.T) {
	forMin := 1
	g := newAlertRig(t, "cpu_high", AlertRule{Threshold: 80, ForMin: &forMin})
	g.val = 95
	g.step(true, 3) // 45 s
	if g.open() != 0 {
		t.Fatal("opened before the minute")
	}
	g.step(true, 2)
	if g.open() != 1 {
		t.Fatal("not open after the minute")
	}
	g.val = 10
	g.step(false, 19) // 4m45s of good, the default clear is 5 minutes
	if g.open() != 1 {
		t.Fatal("closed before 5 minutes of good")
	}
	g.step(false, 2)
	if g.open() != 0 {
		t.Fatal("not closed after 5 minutes of good")
	}
}

func TestAlertAcknowledgeSilenceResolveAndComingBack(t *testing.T) {
	g := newAlertRig(t, "upstream_down", AlertRule{After: 1, ClearMode: "checks", Clear: 1})
	g.cfg.RepeatHours = 1
	g.step(true, 1)
	id := g.e.View().Alerts[0].ID
	if a, _, _ := g.e.counts(); a["warning"] != 1 {
		t.Fatalf("active %v", a)
	}
	if err := g.e.Ack(id, true, "ann"); err != nil {
		t.Fatal(err)
	}
	if a, k, _ := g.e.counts(); a["warning"] != 0 || k["warning"] != 1 {
		t.Fatalf("an acknowledged alert is counted as acknowledged: %v %v", a, k)
	}
	g.step(true, 4*60*1+1) // an hour: no repeat while acknowledged
	if g.events() != "open" {
		t.Fatalf("events %q", g.events())
	}
	if err := g.e.Ack(id, false, "ann"); err != nil {
		t.Fatal(err)
	}
	g.step(true, 1)
	if g.events() != "open,repeat" {
		t.Fatalf("an open alert nobody has acknowledged is repeated: %q", g.events())
	}
	// silenced: no message when it closes, not counted, still listed
	if err := g.e.Silence(id, 60, "ann"); err != nil {
		t.Fatal(err)
	}
	if v := g.e.View(); v.Alerts[0].Silenced == 0 || len(v.Silences) != 1 {
		t.Fatalf("not shown as silenced: %+v", v)
	}
	if a, k, _ := g.e.counts(); a["warning"]+k["warning"] != 0 {
		t.Fatal("a silenced alert is not counted")
	}
	g.step(false, 1)
	if g.events() != "open,repeat" {
		t.Fatalf("a silenced alert closes quietly: %q", g.events())
	}
	// it comes back within the hour: the same alert, counted again, and the acknowledgement is gone
	g.e.Silence(id, 0, "ann")
	g.step(true, 1)
	v := g.e.View()
	if len(v.Alerts) != 1 || v.Alerts[0].Count != 2 || v.Alerts[0].Acked {
		t.Fatalf("flapping alert: %+v", v.Alerts)
	}
	// resolved by hand while the condition goes on: opens again after it holds again
	if err := g.e.Resolve(id, "bob"); err != nil {
		t.Fatal(err)
	}
	if g.open() != 0 || g.e.View().Alerts[0].Resolution != "manual" {
		t.Fatal("not resolved")
	}
	g.step(true, 1)
	if g.open() != 1 {
		t.Fatal("a manual close of something still wrong must not stay closed")
	}
	if _, _, n := g.e.counts(); n != 3 {
		t.Fatalf("opened %d times, want 3", n)
	}
}

func TestAlertRuleSwitchedOffClosesItAndStateSurvivesARestart(t *testing.T) {
	g := newAlertRig(t, "upstream_down", AlertRule{After: 1})
	g.step(true, 1)
	if g.open() != 1 {
		t.Fatal("not open")
	}
	off := false
	g.cfg.Rules["upstream_down"] = AlertRule{Enabled: &off}
	g.step(true, 1)
	if g.open() != 0 || g.e.View().Alerts[0].Resolution != "rule off" {
		t.Fatalf("not closed when the rule went off: %+v", g.e.View().Alerts)
	}
	e2 := NewAlertEngine(strings.TrimSuffix(g.e.path, "/alerts.json"), "node1", func() *AlertsConfig { return g.cfg })
	if len(e2.View().Alerts) != 1 {
		t.Fatal("the alerts were not kept")
	}
}

func TestAlertConfigIsChecked(t *testing.T) {
	bad := []AlertsConfig{
		{Webhook: "ftp://x"}, {Webhook: "nonsense"}, {RepeatHours: -1},
		{Rules: map[string]AlertRule{"nope": {}}},
		{Rules: map[string]AlertRule{"cpu_high": {Severity: "dire"}}},
		{Rules: map[string]AlertRule{"cpu_high": {Mode: "sometimes"}}},
		{Rules: map[string]AlertRule{"upstream_down": {Mode: "m_of_n", After: 6, Of: 5}}},
		{Rules: map[string]AlertRule{"cpu_high": {Threshold: -1}}},
	}
	for i, c := range bad {
		c := c
		if c.Validate() == nil {
			t.Errorf("case %d was accepted: %+v", i, c)
		}
	}
	dc := newDaemonConfig()
	dc.Groups = nil
	on := true
	dc.DNS.Alerts = &AlertsConfig{Webhook: " https://hooks.example/x ", Rules: map[string]AlertRule{"cpu_high": {Enabled: &on}}}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
	if dc.DNS.Alerts.Webhook != "https://hooks.example/x" {
		t.Fatalf("webhook %q", dc.DNS.Alerts.Webhook)
	}
	// nothing set: no block in the file
	dc.DNS.Alerts = &AlertsConfig{}
	if err := dc.Validate(); err != nil || dc.DNS.Alerts != nil {
		t.Fatalf("an empty block should go away: %v %+v", err, dc.DNS.Alerts)
	}
	// defaults
	d, _ := alertDefByID("no_queries")
	if v := (*AlertsConfig)(nil).rule(d); v.Enabled || v.Mode != "minutes" || v.After != 15 {
		t.Fatalf("no_queries defaults: %+v", v)
	}
	body := string(alertWebhookBody("resolved", Alert{Title: "T", Severity: "warning", Message: "m", Opened: 10, Closed: 70, Resolution: "cleared"}, "n1"))
	if !strings.Contains(body, `"duration_seconds":60`) || !strings.Contains(body, "RESOLVED") {
		t.Fatalf("webhook body %s", body)
	}
}

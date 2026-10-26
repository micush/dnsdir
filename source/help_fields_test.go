package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every field the GUI labels must have an entry in the help panel of the screen or tab it is on
// (webui/help.js, a ["fields", [["Label", "..."]]] block). Labels come from the `l: "…"` specs in
// app.js; the controls that are labelled another way are listed below.
func TestHelpCoversEveryField(t *testing.T) {
	appB, err := os.ReadFile("webui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(appB)
	topics := helpTopics(t)
	has := func(tp, label string) bool {
		body, ok := topics[tp]
		if !ok {
			t.Fatalf("help.js has no panel %q", tp)
		}
		return strings.Contains(body, `["`+strings.ReplaceAll(label, `"`, `\"`)+`",`)
	}

	cfgAt := strings.Index(app, "const LB = [")
	if cfgAt < 0 {
		t.Fatal("cannot find the Settings schema in app.js")
	}
	// the arrays of the Settings schema and the panel their fields belong to
	arrays := []struct{ name, topic string }{
		{"GROUP_FIELDS", "config_groups"},
		{"DNS_FIELDS", ""}, // by section, below
		{"WEB_FIELDS", "config_web0"},
		{"SSO_FIELDS", ""}, // by tab, below
		{"LDAP_FIELDS", "users_ldap"},
		{"SNMP_FIELDS", "config_snmp"},
		{"PROM_FIELDS", "config_metrics"},
		{"BACKUP_FIELDS", "config_backup"},
		{"CLUSTER_FIELDS", "config_cluster"},
		{"LOG_FIELDS", "config_logs"},
		{"SYSLOG_FIELDS", "config_logs"},
		{"GENERAL_FIELDS", "config_general"},
	}
	type span struct {
		from, to int
		topic    string
		name     string
	}
	var spans []span
	for _, a := range arrays {
		i := strings.Index(app, "const "+a.name+" = [")
		if i < 0 {
			t.Fatalf("cannot find %s in app.js", a.name)
		}
		end := strings.Index(app[i:], "\n  ];")
		if eol := strings.Index(app[i:], "\n"); strings.HasSuffix(app[i:i+eol], "];") {
			end = eol // an array on one line
		}
		spans = append(spans, span{i, i + end, a.topic, a.name})
	}
	// section of the page's settings -> panel
	sections := map[string]string{
		"Upstream servers": "config_dns0", "Load Balancing": "config_dns1", "Timing": "config_dns1", "Client names": "config_dns1",
		"Listeners": "config_dns2", "Policy-Based Resolution": "config_dns3_0", "Sort List": "config_dns3_1",
		"Conditional Forwarding": "config_dns3_2", "Block Lists": "config_dns3_3",
		"Client network (ECS)": "config_dns4", "Cache": "config_dns4", "Query hardening": "config_dns4", "Client Rate Limiting": "config_dns5",
	}
	// single sign-on: the tab each field is on
	ssoTab := map[string]string{}
	for i, m := range regexp.MustCompile(`\["(?:General|Google|Microsoft|OpenID Connect)", \[([^\]]*)\]\]`).FindAllStringSubmatch(app, -1) {
		for _, k := range regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(m[1], -1) {
			ssoTab[k[1]] = "users_sso" + string(rune('0'+i))
		}
	}
	if len(ssoTab) < 10 {
		t.Fatalf("cannot read SSO_TABS: %v", ssoTab)
	}

	found := 0
	for _, m := range regexp.MustCompile(`\bl: "([^"]+)"`).FindAllStringSubmatchIndex(app, -1) {
		label := app[m[2]:m[3]]
		tp := "topology"
		if m[0] > cfgAt {
			tp = ""
			for _, sp := range spans {
				if m[0] > sp.from && m[0] < sp.to {
					tp = sp.topic
					switch sp.name {
					case "DNS_FIELDS":
						// the section heading before the label says which tab it is on
						best, bestAt := "", -1
						for sec, panel := range sections {
							if at := strings.LastIndex(app[sp.from:m[0]], `section: "`+sec+`"`); at > bestAt {
								best, bestAt = panel, at
							}
						}
						tp = best
					case "SSO_FIELDS":
						line := app[strings.LastIndex(app[:m[0]], "\n"):m[1]]
						k := regexp.MustCompile(`\bk: "([a-z_]+)"`).FindStringSubmatch(line)
						if k != nil {
							tp = ssoTab[k[1]]
						}
					}
				}
			}
			if tp == "" {
				t.Errorf("field %q: cannot tell which help panel it belongs to (new array or section in app.js?)", label)
				continue
			}
		}
		found++
		if !has(tp, label) {
			t.Errorf("field %q (panel %s) has no entry in the help's Fields list", label, tp)
		}
	}
	if found < 70 {
		t.Errorf("found only %d labelled fields in app.js; the label pattern probably changed", found)
	}

	extra := map[string][]string{
		"topology":        {"Time range"},
		"config_upgrades": {"Update every node automatically when a newer release is staged (one node at a time)", "Online repository"},
		"config_web0":     {"Username", "Password"},
		"config_web1":     {"Certificate", "Private key", "Main name", "Other names (one per line)", "IP addresses (one per line, optional)", "Pending CSR"},
		"cluster":         {"Node", "Join code"},
		"updates":         {"Release archive", "Fetch from online"},
		"anycast_bgp":     {"Local AS number", "Router ID", "New neighbor address", "New neighbor AS", "New neighbor description", "New neighbor password"},
		"anycast_ospf":    {"Router ID", "Hello interval", "Dead interval", "Metric", "New interface name", "New interface area", "New interface link type", "New interface key"},
		"history":         {"Compare version", "Configuration file"},
		"stats":           {"Time range", "From", "To"},
		"host":            {"Time range", "From", "To"},
		"capture":         {"Interface", "Filter"},
		"log":             {"Filter text", "Level", "Time range", "Lines", "Live"},
		"node":            {"Action", "When", "Minutes", "Time of day"},
		"users_local":     {"Name", "Password", "Expires"},
	}
	for tp, ls := range extra {
		for _, l := range ls {
			if !has(tp, l) {
				t.Errorf("control %q (panel %s) has no entry in the help's Fields list", l, tp)
			}
		}
	}
}

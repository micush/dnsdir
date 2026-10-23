package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// helpTopics splits webui/help.js into its topics: key -> the text of the topic.
func helpTopics(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("webui/help.js")
	if err != nil {
		t.Fatal(err)
	}
	help := string(b)
	re := regexp.MustCompile(`(?m)^  (_?[a-z][a-z_0-9]*): \{`)
	at := re.FindAllStringSubmatchIndex(help, -1)
	out := map[string]string{}
	for i, m := range at {
		end := len(help)
		if i+1 < len(at) {
			end = at[i+1][0]
		}
		out[help[m[2]:m[3]]] = help[m[0]:end]
	}
	return out
}

// The help topics every page, tab and sub-tab must have: the sidebar's pages, with the tabs of
// Configure ▸ DNS and Users, each its own panel.
func expectedHelpTopics(sidebar []string) []string {
	var want []string
	for _, id := range sidebar {
		switch id {
		case "users":
			want = append(want, "users_local", "users_sso0", "users_sso1", "users_sso2", "users_sso3", "users_ldap")
		case "anycast":
			want = append(want, "anycast_bgp", "anycast_ospf")
		case "anycastop":
			want = append(want, "anycastop_bgp", "anycastop_ospf")
		case "anycaststatus":
			want = append(want, "anycaststatus_bgp", "anycaststatus_ospf")
		case "cfg_general":
			want = append(want, "config_general")
		case "cfg_groups":
			want = append(want, "config_groups")
		case "cfg_snmp":
			want = append(want, "config_snmp")
		case "cfg_cluster":
			want = append(want, "config_cluster")
		case "cfg_dns":
			want = append(want, "config_dns0", "config_dns1", "config_dns2", "config_dns3_0", "config_dns3_1", "config_dns3_2", "config_dns3_3", "config_dns4", "config_dns5")
		case "cfg_web":
			want = append(want, "config_web0", "config_web1")
		default:
			want = append(want, id)
		}
	}
	return want
}

// Every page in the sidebar has a help panel (the "?" in the top right), the topology page's included,
// and so has every tab and sub-tab of a page that has them; and no panel is left over from a page that
// is gone.
func TestEveryPageHasHelp(t *testing.T) {
	appB, err := os.ReadFile("webui/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(appB)
	topics := helpTopics(t)
	nav := regexp.MustCompile(`\["([a-z_]+)", "[A-Za-z ]+"\]`).FindAllStringSubmatch(
		app[strings.Index(app, "const NAV_GROUPS"):strings.Index(app, "const TABS")], -1)
	ids := []string{"topology"}
	for _, m := range nav {
		ids = append(ids, m[1])
	}
	if len(ids) < 9 {
		t.Fatalf("could not read the sidebar: %v", ids)
	}
	want := expectedHelpTopics(ids)
	have := map[string]bool{}
	for _, w := range want {
		have[w] = true
		if _, ok := topics[w]; !ok {
			t.Errorf("no help panel %q", w)
		}
	}
	var stale []string
	for k := range topics {
		if k != "_default" && !have[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("help panels that no page or tab shows: %v", stale)
	}
	if strings.Contains(app, `"help", "Help"`) || strings.Contains(app, "VIEWS.help") {
		t.Error("the old Help page is still there")
	}
	// app.js picks the panel of a tab or sub-tab with helpTopicKey; it must know every family of keys
	at := strings.Index(app, "function helpTopicKey()")
	if at < 0 || !strings.Contains(app, "refreshHelp()") {
		t.Fatal("app.js does not choose the help panel by tab")
	}
	fn := app[at : at+strings.Index(app[at:], "function refreshHelp()")]
	for _, frag := range []string{"config_general", "config_groups", "config_web", "config_snmp", "config_cluster", "config_dns", "anycast_", "users_local", "users_sso", "users_ldap"} {
		if !strings.Contains(fn, frag) {
			t.Errorf("helpTopicKey does not choose %s panels", frag)
		}
	}
}

// Every panel is laid out the same way: a title, an opening paragraph, what you can do, and (when it has
// fields) a Fields list; the steps are numbered lists.
func TestHelpPanelsFollowTheLayout(t *testing.T) {
	for k, body := range helpTopics(t) {
		if k == "_default" {
			continue
		}
		if !regexp.MustCompile(`title: "[^"]+",`).MatchString(body) {
			t.Errorf("%s: no title", k)
		}
		if !regexp.MustCompile(`body: \[\n      "`).MatchString(body) {
			t.Errorf("%s: a panel starts with a paragraph that says what the screen is for", k)
		}
		if !strings.Contains(body, `What you can do here"]`) {
			t.Errorf("%s: no \"What you can do here\" section", k)
		}
		if (strings.HasPrefix(k, "config_") || strings.HasPrefix(k, "users_")) && !strings.Contains(body, `Fields"]`) {
			t.Errorf("%s: no Fields section", k)
		}
		if strings.Count(body, "\n") < 8 {
			t.Errorf("%s: suspiciously short", k)
		}
	}
}

func TestHelpScriptServedAndOldEndpointGone(t *testing.T) {
	e := newWebEnv(t)
	if r := e.do("GET", "/help.js", nil); r.code != 200 || !strings.Contains(string(r.raw), "DNSDIR_HELP") {
		t.Fatalf("help.js: %d", r.code)
	}
	e.login("alice", "pw")
	if r := e.do("GET", "/api/help", nil, withAuth(e, false)); r.code != 404 {
		t.Fatalf("the old /api/help should be gone, got %d", r.code)
	}
}

package main

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestMCPRedactHidesEverySecretKind(t *testing.T) {
	in := map[string]any{
		"groups": []any{map[string]any{"group_id": 100, "key": "gw-secret"}},
		"bgp":    map[string]any{"neighbors": []any{map[string]any{"peer": "192.0.2.1", "password": "bgp-secret"}}},
		"dns":    map[string]any{"keys": []any{"7 SHA256 HEX:abcd"}, "snmp_communities": []any{"comm-secret"}, "servers": []any{"192.0.2.9:123"}},
		"acme":   map[string]any{"eab_key": "eab-secret", "account_key": "acct-secret"},
		"web":    map[string]any{"ldap_bind_password": "ldap-secret", "key_file": "/etc/k.pem", "sso_oidc_client_secret": ""},
		"pools":  []any{map[string]any{"key": 100}},
		"join":   map[string]any{"code": "join-secret", "token": "tok-secret"},
	}
	b, _ := json.Marshal(mcpRedact(in))
	s := string(b)
	for _, secret := range []string{"gw-secret", "bgp-secret", "HEX:abcd", "comm-secret", "ldap-secret", "join-secret", "tok-secret", "eab-secret", "acct-secret"} {
		if strings.Contains(s, secret) {
			t.Errorf("%s is shown: %s", secret, s)
		}
	}
	// what is not a secret stays: servers, a file name, a numeric pool key, an empty secret (none set)
	for _, keep := range []string{`"192.0.2.9:123"`, `"key_file":"/etc/k.pem"`, `"key":100`, `"sso_oidc_client_secret":""`, `"peer":"192.0.2.1"`} {
		if !strings.Contains(s, keep) {
			t.Errorf("%s was hidden: %s", keep, s)
		}
	}
	if in["groups"].([]any)[0].(map[string]any)["key"] != "gw-secret" {
		t.Fatal("the input was changed")
	}
}

func TestMCPRestoreHiddenMatchesByIdentity(t *testing.T) {
	cur := map[string]any{
		"neighbors": []any{map[string]any{"peer": "192.0.2.1", "password": "one"}, map[string]any{"peer": "192.0.2.2", "password": "two"}},
		"key":       "top",
	}
	// the list came back reordered: each secret follows its peer, not its place
	v := map[string]any{
		"neighbors": []any{map[string]any{"peer": "192.0.2.2", "password": mcpHidden}, map[string]any{"peer": "192.0.2.1", "password": mcpHidden}},
		"key":       mcpHidden,
	}
	var miss []string
	mcpRestoreHidden(v, cur, "", &miss)
	n := v["neighbors"].([]any)
	if len(miss) != 0 || n[0].(map[string]any)["password"] != "two" || n[1].(map[string]any)["password"] != "one" || v["key"] != "top" {
		t.Fatalf("restored: %v, missing %v", v, miss)
	}
	// a new neighbor with "(hidden)" has nothing to keep: refused, and the path says where
	v = map[string]any{"neighbors": []any{map[string]any{"peer": "192.0.2.3", "password": mcpHidden}}}
	miss = nil
	mcpRestoreHidden(v, cur, "", &miss)
	if len(miss) != 1 || miss[0] != "neighbors[0].password" {
		t.Fatalf("unmatched: %v", miss)
	}
	// without an identity field, an entry is matched by place only when the list kept its length
	cur = map[string]any{"l": []any{map[string]any{"secret": "a"}, map[string]any{"secret": "b"}}}
	v = map[string]any{"l": []any{map[string]any{"secret": mcpHidden}}}
	miss = nil
	mcpRestoreHidden(v, cur, "", &miss)
	if len(miss) != 1 {
		t.Fatalf("a shorter list matched by place: %v", v)
	}
	// "(hidden)" under a key that is no secret is left for mcpFindHidden to refuse
	v = map[string]any{"name": mcpHidden}
	miss = nil
	mcpRestoreHidden(v, map[string]any{"name": "x"}, "", &miss)
	mcpFindHidden(v, "", &miss)
	if len(miss) != 1 || miss[0] != "name" {
		t.Fatalf("not a secret: %v", miss)
	}
}

func TestMCPNeverShowsSecretsEvenToRW(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1 rw")
	call := func(name, args string) (string, bool) {
		t.Helper()
		_, m := post(mcpCall(name, args))
		return toolResult(t, m)
	}
	gw := func(id int, name, key string) string {
		b, _ := json.Marshal(map[string]any{"group_id": id, "name": name, "interface": "lo", "vip4": "127.0.0." + map[int]string{100: "50", 101: "51"}[id] + "/8", "key": key})
		return string(b)
	}
	// a real secret sent in is saved, but neither the answer nor the log line shows it
	var logged lockedBuf
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	if txt, isErr := call("edit_config", `{"set":{"groups":[`+gw(100, "a", "first-gateway-secret")+`,`+gw(101, "b", "second-gateway-secret")+`]}}`); isErr || strings.Contains(txt, "secret") {
		t.Fatalf("set the keys: %s", txt)
	}
	keys := func() map[int]string {
		dc, err := loadConfig(e.conf)
		if err != nil {
			t.Fatal(err)
		}
		out := map[int]string{}
		for _, g := range dc.Groups {
			out[g.GroupID] = g.Key
		}
		return out
	}
	if k := keys(); k[100] != "first-gateway-secret" || k[101] != "second-gateway-secret" {
		t.Fatalf("keys not saved: %v", k)
	}
	if l := logged.String(); strings.Contains(l, "gateway-secret") || !strings.Contains(l, "calls edit_config") {
		t.Fatalf("the audit line shows the secret: %s", l)
	}

	// every way of reading the configuration hides them
	cfgText, isErr := call("get_config", `{}`)
	if isErr || strings.Contains(cfgText, "gateway-secret") || !strings.Contains(cfgText, `"key":"(hidden)"`) {
		t.Fatalf("get_config: %s", cfgText)
	}
	if txt, isErr := call("api_get", `{"path":"/api/config"}`); isErr || strings.Contains(txt, "gateway-secret") {
		t.Fatalf("api_get /api/config: %s", txt)
	}
	if txt, isErr := call("edit_config", `{"set":{"log_level":"debug"},"dry_run":true}`); isErr || strings.Contains(txt, "gateway-secret") {
		t.Fatalf("dry run: %s", txt)
	}
	for _, p := range []string{"/api/versions/get?id=1", "/api/versions/diff?a=1&b=2", "/api/versions/download"} {
		if txt, isErr := call("api_get", `{"path":"`+p+`"}`); !isErr || !strings.Contains(txt, "not available over MCP") {
			t.Fatalf("%s: %s", p, txt)
		}
	}

	// the groups list as read, sent back whole with one name changed and the order swapped: both keys kept
	var got struct {
		Config struct {
			Groups []map[string]any `json:"groups"`
		} `json:"config"`
	}
	if err := json.Unmarshal([]byte(cfgText), &got); err != nil || len(got.Config.Groups) != 2 {
		t.Fatalf("%v %s", err, cfgText)
	}
	g := []map[string]any{got.Config.Groups[1], got.Config.Groups[0]}
	g[1]["name"] = "renamed"
	set, _ := json.Marshal(map[string]any{"groups": g})
	if txt, isErr := call("edit_config", `{"set":`+string(set)+`}`); isErr {
		t.Fatalf("send back hidden: %s", txt)
	}
	if k := keys(); k[100] != "first-gateway-secret" || k[101] != "second-gateway-secret" {
		t.Fatalf("keys after a hidden round trip: %v", k)
	}
	dc, _ := loadConfig(e.conf)
	for _, gr := range dc.Groups {
		if gr.GroupID == 100 && gr.Name != "renamed" {
			t.Fatalf("the rename was lost: %+v", dc.Groups)
		}
	}

	// a hidden key for a gateway that has none yet is refused, and nothing is saved
	if txt, isErr := call("edit_config", `{"set":{"groups":[`+gw(102, "c", mcpHidden)+`]}}`); !isErr || !strings.Contains(txt, "groups[0].key") {
		t.Fatalf("unmatched hidden: %s", txt)
	}
	if k := keys(); len(k) != 2 {
		t.Fatalf("saved anyway: %v", k)
	}

	// api_request: the whole configuration as get_config gave it, PUT back; the hidden keys are kept
	var whole map[string]any
	_ = json.Unmarshal([]byte(cfgText), &whole)
	body, _ := json.Marshal(map[string]any{"config": whole["config"], "note": "round trip"})
	if txt, isErr := call("api_request", `{"method":"PUT","path":"/api/config","body":`+string(body)+`}`); isErr || strings.Contains(txt, "gateway-secret") {
		t.Fatalf("api_request PUT: %s", txt)
	}
	if k := keys(); k[100] != "first-gateway-secret" || k[101] != "second-gateway-secret" {
		t.Fatalf("keys after api_request: %v", k)
	}
	// and a new value is still taken
	if txt, isErr := call("edit_config", `{"set":{"groups":[`+gw(100, "a", "rotated-gateway-secret")+`,`+gw(101, "b", mcpHidden)+`]}}`); isErr {
		t.Fatalf("rotate: %s", txt)
	}
	if k := keys(); k[100] != "rotated-gateway-secret" || k[101] != "second-gateway-secret" {
		t.Fatalf("after rotating one: %v", k)
	}
}

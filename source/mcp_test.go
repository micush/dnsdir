package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMCPACLNormalised(t *testing.T) {
	got, err := normMCPACL([]string{" 10.1.1.50  RW", "10.1.0.0/24", "10.1.1.50", "Mon.Example.com.", "2001:db8::5 ro", "192.0.2.9 read-write"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "|") != "10.1.1.50 rw|10.1.0.0/24|mon.example.com|2001:db8::5|192.0.2.9 rw" {
		t.Fatalf("%q", got)
	}
	for _, bad := range []string{"10.1.0.0/24 rw", "mon.example.com rw", "10.1.1.50 admin", "10.1.1.50 rw extra", "not an address"} {
		if _, err := normMCPACL([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// mcpEnv is a web server whose MCP access list is acl; post sends one JSON-RPC message and returns the HTTP status and body.
func mcpEnv(t *testing.T, acl ...string) (*webEnv, func(msg string, hdr ...string) (int, map[string]any)) {
	t.Helper()
	e := newWebEnv(t)
	e.mg.webH = e.ws.Handler()
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.DNS.MCPACL = acl
	sup.mu.Unlock()
	return e, func(msg string, hdr ...string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader(msg))
		req.Header.Set("Content-Type", "application/json")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return res.StatusCode, m
	}
}

func mcpCall(name, args string) string {
	return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}

// toolResult is the text of a tools/call answer and whether it is an error.
func toolResult(t *testing.T, m map[string]any) (string, bool) {
	t.Helper()
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", m)
	}
	c := r["content"].([]any)[0].(map[string]any)
	return c["text"].(string), r["isError"] == true
}

func toolNames(t *testing.T, m map[string]any) []string {
	var out []string
	for _, x := range m["result"].(map[string]any)["tools"].([]any) {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	return out
}

func TestMCPNobodyUntilListed(t *testing.T) {
	_, post := mcpEnv(t)
	if code, _ := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); code != 403 {
		t.Fatalf("empty list: %d", code)
	}
	_, post = mcpEnv(t, "192.0.2.1 rw", "10.0.0.0/8")
	if code, _ := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`); code != 403 {
		t.Fatalf("not listed: %d", code)
	}
}

func TestMCPReadOnly(t *testing.T) {
	_, post := mcpEnv(t, "127.0.0.0/8")
	code, m := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	if code != 200 || m["result"].(map[string]any)["protocolVersion"] != "2025-03-26" {
		t.Fatalf("%d %v", code, m)
	}
	if code, _ := post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); code != 202 {
		t.Fatalf("notification: %d", code)
	}
	_, m = post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	names := strings.Join(toolNames(t, m), " ")
	if !strings.Contains(names, "get_log") || strings.Contains(names, "set_node_paused") || strings.Contains(names, "schedule_set") {
		t.Fatalf("read-only tools: %s", names)
	}
	if txt, isErr := toolResult(t, func() map[string]any { _, m := post(mcpCall("list_nodes", `{}`)); return m }()); isErr || !strings.Contains(txt, `"this_node":true`) {
		t.Fatalf("list_nodes: %s", txt)
	}
	if txt, isErr := toolResult(t, func() map[string]any { _, m := post(mcpCall("get_alerts", `{"node":"all"}`)); return m }()); isErr || !strings.Contains(txt, `"alerts"`) {
		t.Fatalf("get_alerts: %s", txt)
	}
	// a write is refused, whatever the client sends
	_, m = post(mcpCall("set_node_paused", `{"node":"this","paused":true}`))
	if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "read-only") {
		t.Fatalf("write as read-only: %s", txt)
	}
	_, m = post(mcpCall("no_such_tool", `{}`))
	if m["error"] == nil {
		t.Fatalf("unknown tool: %v", m)
	}
}

func TestMCPReadWriteGoesThroughTheGUIRules(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1 rw")
	_, m := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if names := strings.Join(toolNames(t, m), " "); !strings.Contains(names, "set_node_paused") || !strings.Contains(names, "update_push") {
		t.Fatalf("read-write tools: %s", names)
	}
	// shell tasks: never made, changed or run here
	_, m = post(mcpCall("schedule_set", `{"task":{"name":"x","action":"shell","command":"id","freq":"daily","at":"03:00"}}`))
	if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "shell") {
		t.Fatalf("shell task: %s", txt)
	}
	// a built-in one is made, under the caller's name
	_, m = post(mcpCall("schedule_set", `{"task":{"name":"Nightly backup","action":"backup","freq":"daily","at":"02:30"}}`))
	if txt, isErr := toolResult(t, m); isErr {
		t.Fatalf("backup task: %s", txt)
	}
	_, m = post(mcpCall("get_schedule", `{}`))
	if txt, _ := toolResult(t, m); !strings.Contains(txt, "Nightly backup") {
		t.Fatalf("not in the schedule: %s", txt)
	}
	found := false
	for _, v := range e.mg.VersionsList() {
		if v.Actor == "mcp@127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the change is not in the history under mcp@127.0.0.1: %+v", e.mg.VersionsList())
	}
	// the GUI's own guard answers: the only node cannot be paused
	_, m = post(mcpCall("set_node_paused", `{"node":"this","paused":true}`))
	if txt, isErr := toolResult(t, m); !isErr || strings.Contains(txt, "read-only") {
		t.Fatalf("pausing the only node: %v %s", isErr, txt)
	}
	// a node that does not exist
	_, m = post(mcpCall("get_dns", `{"node":"nonesuch"}`))
	if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "no node") {
		t.Fatalf("unknown node: %s", txt)
	}
}

func TestMCPRefusesBrowsersAndGET(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1 rw")
	if code, _ := post(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, "Origin", "https://evil.example"); code != 403 {
		t.Fatalf("foreign origin: %d", code)
	}
	res, err := http.Get(e.ts.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 405 {
		t.Fatalf("GET: %d", res.StatusCode)
	}
	// a batch
	res, err = http.Post(e.ts.URL+"/mcp", "application/json", bytes.NewBufferString(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.HasPrefix(string(b), "[") || strings.Count(string(b), `"id"`) != 1 {
		t.Fatalf("batch: %d %s", res.StatusCode, b)
	}
}

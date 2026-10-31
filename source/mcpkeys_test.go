package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testMCPKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "dnsdir_" + base64.RawURLEncoding.EncodeToString(b)
}

func TestNormMCPKeys(t *testing.T) {
	k := testMCPKey()
	out, err := normMCPKeys([]MCPKey{{Name: "laptop", Key: k}, {Name: "ops-1", Access: "RW", Hash: strings.ToUpper(mcpKeyHash(testMCPKey()))}})
	if err != nil || len(out) != 2 {
		t.Fatal(err, out)
	}
	if out[0].Key != "" || out[0].Hash != mcpKeyHash(k) || out[0].Access != "ro" || out[0].Created == 0 {
		t.Fatalf("new key: %+v", out[0])
	}
	if out[1].Access != "rw" || !strings.HasPrefix(out[1].Hash, "sha256:") || out[1].Hash != strings.ToLower(out[1].Hash) || out[1].Created != 0 {
		t.Fatalf("kept key: %+v", out[1])
	}
	if l, err := normMCPKeys(nil); l != nil || err != nil {
		t.Fatal("empty")
	}
	for name, bad := range map[string][]MCPKey{
		"no name":      {{Key: k}},
		"bad name":     {{Name: "my laptop", Key: k}},
		"same name":    {{Name: "a", Key: k}, {Name: "A", Key: testMCPKey()}},
		"same key":     {{Name: "a", Key: k}, {Name: "b", Key: k}},
		"short key":    {{Name: "a", Key: "short"}},
		"spaces":       {{Name: "a", Key: " " + k}},
		"no key, hash": {{Name: "a"}},
		"bad hash":     {{Name: "a", Hash: "sha256:abcd"}},
		"bad access":   {{Name: "a", Key: k, Access: "admin"}},
	} {
		if _, err := normMCPKeys(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMCPKeyOpensFromAnyAddress(t *testing.T) {
	roKey, rwKey := testMCPKey(), testMCPKey()
	e, post := mcpEnv(t) // no address may use it
	keys, err := normMCPKeys([]MCPKey{{Name: "reader", Key: roKey}, {Name: "laptop", Access: "rw", Key: rwKey}})
	if err != nil {
		t.Fatal(err)
	}
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.DNS.MCPKeys = keys
	sup.mu.Unlock()
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

	if code, _ := post(init); code != 403 {
		t.Fatalf("no key, no address: %d", code)
	}
	if code, _ := post(init, "Authorization", "Bearer "+testMCPKey()); code != 401 {
		t.Fatalf("wrong key: %d", code)
	}
	if code, _ := post(init, "Authorization", "Basic "+roKey); code != 401 {
		t.Fatalf("not Bearer: %d", code)
	}
	// read-only key: the read tools only, and a write is refused
	code, m := post(list, "Authorization", "Bearer "+roKey)
	if code != 200 || containsStr(toolNames(t, m), "edit_config") || !containsStr(toolNames(t, m), "get_config") {
		t.Fatalf("ro key: %d %v", code, m)
	}
	_, m = post(mcpCall("edit_config", `{"set":{"log_level":"debug"}}`), "Authorization", "Bearer "+roKey)
	if txt, isErr := toolResult(t, m); !isErr || !strings.Contains(txt, "read-only") {
		t.Fatalf("ro key wrote: %s", txt)
	}
	// read-write key: a change, saved under the key's name
	_, m = post(mcpCall("edit_config", `{"set":{"log_level":"debug"}}`), "Authorization", "bearer "+rwKey)
	if txt, isErr := toolResult(t, m); isErr {
		t.Fatalf("rw key: %s", txt)
	}
	found := false
	for _, v := range e.mg.VersionsList() {
		if strings.Contains(v.Actor+" "+v.Note, "mcp:laptop@127.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("not saved as the key's name: %+v", e.mg.VersionsList())
	}
	// the address list still counts, and the higher access wins
	sup.mu.Lock()
	sup.dc.DNS.MCPACL = []string{"127.0.0.1"}
	sup.mu.Unlock()
	if code, m := post(list); code != 200 || containsStr(toolNames(t, m), "edit_config") {
		t.Fatalf("address only: %d", code)
	}
	if _, m := post(list, "Authorization", "Bearer "+rwKey); !containsStr(toolNames(t, m), "edit_config") {
		t.Fatal("ro address + rw key is not rw")
	}
	if code, _ := post(list, "Authorization", "Bearer "+testMCPKey()); code != 401 {
		t.Fatalf("a wrong key from an allowed address: %d", code)
	}
}

// A key added through the configuration is kept only as its hash: not in the file, the history or any answer.
func TestMCPKeyIsSavedAsAHashOnly(t *testing.T) {
	e, post := mcpEnv(t, "127.0.0.1 rw")
	k := testMCPKey()
	set, _ := json.Marshal(map[string]any{"dns": map[string]any{"mcp_keys": []any{map[string]any{"name": "laptop", "access": "rw", "key": k}}}})
	_, m := post(mcpCall("edit_config", `{"set":`+string(set)+`}`))
	if txt, isErr := toolResult(t, m); isErr || strings.Contains(txt, k) {
		t.Fatalf("set: %s", txt)
	}
	dc, err := loadConfig(e.conf)
	if err != nil || len(dc.DNS.MCPKeys) != 1 || dc.DNS.MCPKeys[0].Hash != mcpKeyHash(k) || dc.DNS.MCPKeys[0].Key != "" {
		t.Fatalf("saved: %v %+v", err, dc.DNS.MCPKeys)
	}
	filepath.WalkDir(filepath.Dir(e.conf), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), k) {
				t.Errorf("the key is in %s", p)
			}
		}
		return nil
	})
	// and it opens the endpoint, once the daemon has the configuration
	sup := e.ws.status.sup
	sup.mu.Lock()
	sup.dc.DNS.MCPACL, sup.dc.DNS.MCPKeys = nil, dc.DNS.MCPKeys
	sup.mu.Unlock()
	if code, _ := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, "Authorization", "Bearer "+k); code != 200 {
		t.Fatalf("the saved key: %d", code)
	}
}

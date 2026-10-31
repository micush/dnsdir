package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MCP keys: besides the address list (mcp_acl), a caller may present a key, so an assistant on a laptop whose address
// changes (DHCP, VPN, Wi-Fi) can still connect.  The key goes in the request header "Authorization: Bearer KEY".  A
// valid key gives its access (ro or rw) from any address; the address list still applies too, and the caller gets the
// higher of the two.  A key that is sent but matches none is refused outright (401), never quietly ignored, so a typo
// shows at once.
//
// Only a SHA-256 hash of each key is kept in the configuration (and so in the cluster and the configuration history):
// the key itself is made once, shown once (Configure ▸ Monitoring ▸ MCP ▸ Add key), and cannot be read back.  A new key
// may be given in "key" (the GUI does this, as may edit_config or a hand-edited file); the check turns it into "hash"
// before anything is saved or sent to the other nodes.

const (
	mcpKeysMax    = 32
	mcpKeyMinLen  = 32 // a key given by hand must be at least this long
	mcpKeyNameMax = 40
)

// MCPKey is one key that may use the MCP endpoint.
type MCPKey struct {
	Name    string `json:"name"`              // who or what holds it ("laptop", "claude-ops"); the caller is logged as mcp:NAME@ADDRESS
	Access  string `json:"access"`            // "ro" or "rw"
	Hash    string `json:"hash,omitempty"`    // "sha256:" and the hex hash of the key
	Key     string `json:"key,omitempty"`     // a new key, only on the way in: replaced by Hash when the configuration is checked
	Created int64  `json:"created,omitempty"` // unix time the key was added
}

func mcpKeyHash(key string) string {
	h := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(h[:])
}

// normMCPKeys checks the keys, turns a new key into its hash, and writes the access the same way ("ro" when not given).
func normMCPKeys(list []MCPKey) ([]MCPKey, error) {
	if len(list) == 0 {
		return nil, nil
	}
	if len(list) > mcpKeysMax {
		return nil, fmt.Errorf("mcp: at most %d keys", mcpKeysMax)
	}
	out := make([]MCPKey, 0, len(list))
	names, hashes := map[string]bool{}, map[string]bool{}
	for _, k := range list {
		k.Name = strings.TrimSpace(k.Name)
		if k.Name == "" {
			return nil, errors.New("mcp: every key needs a name (who or what holds it)")
		}
		if len(k.Name) > mcpKeyNameMax || strings.IndexFunc(k.Name, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r))
		}) >= 0 {
			return nil, fmt.Errorf("mcp: key name %q: up to %d letters, digits, dots, dashes and underscores", k.Name, mcpKeyNameMax)
		}
		if names[strings.ToLower(k.Name)] {
			return nil, fmt.Errorf("mcp: two keys are named %q", k.Name)
		}
		names[strings.ToLower(k.Name)] = true
		switch strings.ToLower(strings.TrimSpace(k.Access)) {
		case "", "ro", "read-only", "readonly":
			k.Access = "ro"
		case "rw", "read-write", "readwrite":
			k.Access = "rw"
		default:
			return nil, fmt.Errorf("mcp: key %q: the access is ro or rw", k.Name)
		}
		if k.Key != "" {
			if strings.TrimSpace(k.Key) != k.Key || len(k.Key) < mcpKeyMinLen {
				return nil, fmt.Errorf("mcp: key %q: a key is at least %d characters, without spaces (Add key makes one)", k.Name, mcpKeyMinLen)
			}
			k.Hash, k.Key = mcpKeyHash(k.Key), ""
			if k.Created == 0 {
				k.Created = time.Now().Unix()
			}
		}
		h, ok := strings.CutPrefix(strings.ToLower(k.Hash), "sha256:")
		if b, err := hex.DecodeString(h); !ok || err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("mcp: key %q has no key or hash: add it again", k.Name)
		}
		k.Hash = "sha256:" + h
		if hashes[k.Hash] {
			return nil, fmt.Errorf("mcp: key %q is the same key as another one", k.Name)
		}
		hashes[k.Hash] = true
		out = append(out, k)
	}
	return out, nil
}

// mcpKeyAccess finds the key a caller presented: its name and access, or "" when it matches none.  Every hash is
// compared, in constant time, so the answer takes as long whichever key (if any) matches.
func mcpKeyAccess(keys []MCPKey, presented string) (name, access string) {
	got := mcpKeyHash(presented)
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(got), []byte(k.Hash)) == 1 && name == "" {
			name, access = k.Name, k.Access
		}
	}
	return name, access
}

// mcpBearer is the key in "Authorization: Bearer KEY"; ok is false when the header is there but not of that form.
func mcpBearer(r *http.Request) (key string, ok bool) {
	a := strings.TrimSpace(r.Header.Get("Authorization"))
	if a == "" {
		return "", true
	}
	scheme, key, found := strings.Cut(a, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	key = strings.TrimSpace(key)
	return key, key != ""
}

// mcpBadKeyLog says once a minute per address that a wrong key was sent, so a client retrying in a loop cannot fill the log.
var mcpBadKeyLog = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

func mcpWarnBadKey(from string) {
	l := &mcpBadKeyLog
	l.Lock()
	defer l.Unlock()
	if time.Since(l.at[from]) < time.Minute {
		return
	}
	if len(l.at) > 1000 {
		l.at = map[string]time.Time{}
	}
	l.at[from] = time.Now()
	warnf("mcp: %s sent a key that matches none (Configure ▸ Monitoring ▸ MCP ▸ Keys); refused", from)
}

func maxAccess(a, b string) string {
	if a == "rw" || b == "rw" {
		return "rw"
	}
	if a == "ro" || b == "ro" {
		return "ro"
	}
	return ""
}

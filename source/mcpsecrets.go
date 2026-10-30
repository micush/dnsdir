package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Secrets and MCP.  Whatever a tool answers goes into an assistant's context (and from there into a conversation, a
// transcript, a provider's logs), so no MCP caller is shown a secret, not even an rw one: every answer has the values
// of mcpSecret keys replaced by "(hidden)" (mcpRedact), the routes that hand over a whole configuration file are refused
// (mcpWholeFile), and the audit line of a write shows its arguments redacted the same way.
//
// So that a caller can still send back what it read, "(hidden)" is taken on the way in to mean "keep what is there":
// edit_config and api_request put the current value back wherever a secret key says "(hidden)" (mcpRestoreHidden),
// matching list entries by an identity field (a gateway by group_id, a BGP neighbor by peer, a backup target by name,
// ...), never by position alone when the list could have changed.  A "(hidden)" that cannot be matched is refused,
// never saved: a caller that wants a new secret sends the real value.

const mcpHidden = "(hidden)"

// mcpSecretExtra are the keys hidden from MCP besides those a read-only GUI account is not shown (secretKeys): lists of
// secrets (keys, SNMP communities), private keys (the ACME account and EAB keys too), join codes and cluster tokens.
var mcpSecretExtra = map[string]bool{"keys": true, "snmp_communities": true, "communities": true, "key_pem": true,
	"private_key": true, "eab_key": true, "account_key": true, "token": true, "tokens": true, "code": true, "server_password": true, "psk": true, "csrf": true, "cookie": true}

func mcpSecret(k string) bool {
	k = strings.ToLower(k)
	return secretKeys[k] || mcpSecretExtra[k]
}

// mcpHideable says whether a secret key's value is worth hiding: something set.  Numbers and booleans are left (a pool's
// numeric "key", a join code's numeric HTTP "code" are not secrets), and so is an empty value (it shows that none is set).
func mcpHideable(v any) bool {
	switch t := v.(type) {
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return false
}

// mcpRedact returns v as generic JSON with the value of every secret key, however deep, replaced by "(hidden)".  v is
// not changed.
func mcpRedact(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, e := range t {
				if mcpSecret(k) && mcpHideable(e) {
					t[k] = mcpHidden
					continue
				}
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(out)
	return out
}

// mcpWholeFile reports the routes that answer with a whole configuration file (as text or a download), keys and
// passwords included: not for MCP, whatever its access (a read-only GUI account is refused them too).
func mcpWholeFile(path string) bool {
	return path == "/api/versions/get" || path == "/api/versions/diff" || path == "/api/versions/download"
}

// mcpIdentity are the fields that name an entry of a list, tried in this order to find the same entry in the current
// configuration.
var mcpIdentity = []string{"group_id", "id", "peer", "name", "host", "addr", "address", "url"}

// mcpRestoreHidden puts the current value back wherever v (changed in place) has "(hidden)" under a secret key; cur is
// the same part of the current configuration (or answer).  It appends to miss the path of each one it cannot match
// (callers then look for any "(hidden)" left with mcpFindHidden, which also catches one under a key that is no secret).
func mcpRestoreHidden(v, cur any, path string, miss *[]string) {
	switch t := v.(type) {
	case map[string]any:
		cm, _ := cur.(map[string]any)
		for k, e := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if s, ok := e.(string); ok && s == mcpHidden && mcpSecret(k) {
				if cv, ok := cm[k]; ok && cv != nil {
					t[k] = cv
				} else {
					*miss = append(*miss, p)
				}
				continue
			}
			var ce any
			if cm != nil {
				ce = cm[k]
			}
			mcpRestoreHidden(e, ce, p, miss)
		}
	case []any:
		cl, _ := cur.([]any)
		for i, e := range t {
			mcpRestoreHidden(e, mcpSameEntry(e, i, len(t), cl), fmt.Sprintf("%s[%d]", path, i), miss)
		}
	}
}

// mcpSameEntry finds the entry of the current list cl that e (entry i of a list of n) stands for: the one entry with the
// same value of the first identity field that tells them apart, or, only when e has no identity field at all and the
// list kept its length, the entry at the same place.  nil when there is none.
func mcpSameEntry(e any, i, n int, cl []any) any {
	em, ok := e.(map[string]any)
	if !ok {
		return nil
	}
	hasID := false
	for _, f := range mcpIdentity {
		iv, ok := em[f]
		if !ok || iv == nil {
			continue
		}
		switch iv.(type) {
		case map[string]any, []any:
			continue
		}
		hasID = true
		var found any
		count := 0
		for _, c := range cl {
			if cm, ok := c.(map[string]any); ok && cm[f] != nil && fmt.Sprint(cm[f]) == fmt.Sprint(iv) {
				found, count = c, count+1
			}
		}
		if count == 1 {
			return found
		}
	}
	if !hasID && len(cl) == n && i < len(cl) {
		return cl[i]
	}
	return nil
}

// mcpFindHidden appends to miss the path of every "(hidden)" left anywhere in v.
func mcpFindHidden(v any, path string, miss *[]string) {
	switch t := v.(type) {
	case string:
		if t == mcpHidden {
			*miss = append(*miss, path)
		}
	case map[string]any:
		for k, e := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			mcpFindHidden(e, p, miss)
		}
	case []any:
		for i, e := range t {
			mcpFindHidden(e, fmt.Sprintf("%s[%d]", path, i), miss)
		}
	}
}

// mcpHiddenError is the refusal for values that said "(hidden)" but match no current secret.
func mcpHiddenError(miss []string) error {
	if len(miss) > 8 {
		miss = append(miss[:8], "…")
	}
	return fmt.Errorf("%q stands for a secret that is already set, but nothing set matches it at %s: send the real value, or leave the key out", mcpHidden, strings.Join(miss, ", "))
}

package main

// Backups between the nodes of a cluster (Configure ▸ Backup ▸ Use the cluster nodes, dnsdir --backup-cluster).
//
// A node can keep the backups of the others.  Setting that up by hand means an account, a password, a directory and the keys
// of every node, on every node.  One operation does it instead: every node makes itself a local account (backupAccount,
// which has no password and can only be reached with a key, for SFTP), authorizes the backup keys of all the nodes for it,
// makes the directory, and every node becomes a server in the shared list.  No password is typed or kept anywhere.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	backupAccount    = "dnsdirbackup"
	backupClusterDir = "backups"
	// what a key of a node may do with the account: file transfer, and nothing else
	backupKeyOptions = `restrict,command="internal-sftp"`
)

// replaceable in tests
var (
	backupLookupUser = user.Lookup
	backupChown      = os.Lchown
)

// backupNodeResult is what one node answers when it is asked to set itself up.
type backupNodeResult struct {
	Node    string `json:"node"`
	Host    string `json:"host,omitempty"`
	Created bool   `json:"created,omitempty"` // the account was made now
	Keys    int    `json:"keys"`              // keys added to it now
	Error   string `json:"error,omitempty"`
}

// backupProvisionLocal makes the account, its directory and its authorized_keys on this node.
func backupProvisionLocal(keys []string) (created bool, added int, err error) {
	var ok []string
	for _, k := range keys {
		if k = strings.TrimSpace(k); backupKeyRe.MatchString(k) {
			ok = append(ok, k)
		}
	}
	if len(ok) == 0 {
		return false, 0, errors.New("no node has a key yet")
	}
	u, err := backupLookupUser(backupAccount)
	if err != nil {
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return false, 0, fmt.Errorf("looking up the account %s: %v", backupAccount, err)
		}
		// "*" as the password: no password opens it, and it is not locked (sshd refuses a locked account without PAM)
		if out, rerr := usersRun("", "useradd", "--create-home", "--shell", "/bin/sh", "--password", "*", "--comment", "dnsdir backups", backupAccount); rerr != nil {
			return false, 0, fmt.Errorf("useradd failed: %s", firstNonEmpty(out, rerr.Error()))
		}
		created = true
		if u, err = backupLookupUser(backupAccount); err != nil {
			return created, 0, fmt.Errorf("the account %s was made but cannot be looked up: %v", backupAccount, err)
		}
	}
	uid, e1 := strconv.Atoi(u.Uid)
	gid, e2 := strconv.Atoi(u.Gid)
	home := filepath.Clean(u.HomeDir)
	if e1 != nil || e2 != nil || uid == 0 || !filepath.IsAbs(home) || home == "/" {
		return created, 0, fmt.Errorf("the account %s on this node is not usable for backups (uid %s, home %q)", backupAccount, u.Uid, u.HomeDir)
	}
	// the account owns its home, so nothing in it is followed: a directory must be a directory, and a file is replaced by
	// renaming a new one over it
	mkdir := func(dir string) error {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
		return backupChown(dir, uid, gid)
	}
	if fi, err := os.Lstat(home); err != nil || !fi.IsDir() {
		return created, 0, fmt.Errorf("the home of %s (%s) is not a directory", backupAccount, home)
	}
	ssh := filepath.Join(home, ".ssh")
	for _, d := range []string{ssh, filepath.Join(home, backupClusterDir)} {
		if err := mkdir(d); err != nil {
			return created, 0, err
		}
	}
	ak := filepath.Join(ssh, "authorized_keys")
	old := ""
	if fi, err := os.Lstat(ak); err == nil && fi.Mode().IsRegular() && fi.Size() < 1<<20 {
		b, _ := os.ReadFile(ak)
		old = string(b)
	}
	merged, added := authorizeKeysAs(old, ok, backupKeyOptions)
	if added == 0 {
		return created, 0, nil
	}
	tmp, err := os.CreateTemp(ssh, ".authorized_keys-")
	if err != nil {
		return created, 0, err
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.WriteString(merged)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp.Name(), 0o600)
	}
	if werr == nil {
		werr = backupChown(tmp.Name(), uid, gid)
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), ak)
	}
	if werr != nil {
		return created, 0, werr
	}
	return created, added, nil
}

// backupProvision is the answer of this node (the "backup.provision" operation, which the node that runs BackupCluster
// sends to every other node).
func (m *Mgmt) backupProvision(keys []string, actor string) (backupNodeResult, error) {
	res := backupNodeResult{Node: m.backup.nodeName()}
	created, added, err := backupProvisionLocal(keys)
	if err != nil {
		return res, err
	}
	res.Created, res.Keys = created, added
	infof("backup: %s set up the account %s on this node (%d key(s) added)", actor, backupAccount, added)
	return res, nil
}

func hostOfAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// BackupCluster sets up every node of the cluster as a backup server of the others and adds them to the shared list.
func (m *Mgmt) BackupCluster(actor string) (map[string]any, error) {
	if m.cl == nil || !m.cl.Enabled() {
		return nil, errors.New("this node is not in a cluster")
	}
	snap := m.cl.node.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var keys []string
	results := []backupNodeResult{}
	failed := map[string]bool{} // by cluster address
	for _, k := range m.backupNodeKeys(ctx) {
		if k.Key != "" {
			keys = append(keys, k.Key)
		} else {
			// a node that does not answer gets no account now; run it again when it is back
			results = append(results, backupNodeResult{Node: k.Node, Error: k.Err})
			failed[k.Node] = true
		}
	}
	self, err := m.backupProvision(keys, actor)
	self.Host = hostOfAddr(snap.SelfAddr)
	if err != nil {
		self.Error = err.Error()
	}
	results = append(results, self)
	body, _ := json.Marshal(map[string]any{"keys": keys})
	for _, p := range snap.Peers {
		if containsStr(snap.Removed, p.Addr) || failed[p.Addr] {
			continue
		}
		r := backupNodeResult{Node: p.Addr, Host: hostOfAddr(p.Addr)}
		cctx, ccancel := context.WithTimeout(ctx, 60*time.Second)
		resp, err := m.cl.Relay(cctx, p.Addr, proxyReq{User: actor, Method: http.MethodPost, Path: "/api/backup/provision", CT: "application/json", Body: body})
		ccancel()
		var v struct {
			Error string           `json:"error"`
			Data  backupNodeResult `json:"data"`
		}
		switch {
		case err != nil:
			r.Error = err.Error()
		case json.Unmarshal(resp.Body, &v) != nil || (resp.Status != http.StatusOK && v.Error == ""):
			r.Error = fmt.Sprintf("it answered %d (is it running this version?)", resp.Status)
		case v.Error != "":
			r.Error = v.Error
		default:
			r.Node, r.Created, r.Keys = firstNonEmpty(v.Data.Node, r.Node), v.Data.Created, v.Data.Keys
		}
		results = append(results, r)
	}
	// every node that is set up becomes a server of the list, unless it is one already
	dc, _, err := m.LiveConfig()
	if err != nil {
		return nil, err
	}
	bc := dc.DNS.Backup.clone()
	if bc == nil {
		bc = &BackupConfig{}
	}
	added, full := 0, 0
	for _, r := range results {
		if r.Error != "" || r.Host == "" {
			continue
		}
		t := BackupTarget{Name: r.Node, Host: r.Host, User: backupAccount, Dir: backupClusterDir}
		have := false
		for _, x := range bc.Targets {
			if strings.EqualFold(x.Host, t.Host) && x.User == t.User && x.port() == t.port() {
				have = true
			}
		}
		switch {
		case have:
		case len(bc.Targets) >= backupMaxTargets:
			full++
		default:
			bc.Targets = append(bc.Targets, t)
			added++
		}
	}
	if added > 0 {
		dc.DNS.Backup = bc
		if err := m.PutConfig(dc, actor, fmt.Sprintf("backup: %d cluster node(s) added as servers", added)); err != nil {
			return nil, fmt.Errorf("the nodes are set up, but the list of servers could not be saved: %w", err)
		}
	}
	nfail := 0
	for _, r := range results {
		if r.Error != "" {
			nfail++
		}
	}
	infof("backup: %s set up backups between the cluster nodes: %d node(s), %d failed, %d server(s) added", actor, len(results), nfail, added)
	targets := bc.Targets
	if targets == nil {
		targets = []BackupTarget{}
	}
	return map[string]any{"ok": nfail == 0, "nodes": results, "added": added, "failed": nfail, "full": full, "targets": targets}, nil
}

// runBackupCluster is `dnsdir --backup-cluster`.
func runBackupCluster(sock string) {
	var v struct {
		Nodes  []backupNodeResult `json:"nodes"`
		Added  int                `json:"added"`
		Failed int                `json:"failed"`
		Full   int                `json:"full"`
	}
	decode(op(sock, "backup.cluster", nil), &v)
	for _, r := range v.Nodes {
		switch {
		case r.Error != "":
			fmt.Printf("%-24s FAILED: %s\n", r.Node, r.Error)
		case r.Created:
			fmt.Printf("%-24s account %s made, %d key(s) added\n", r.Node, backupAccount, r.Keys)
		default:
			fmt.Printf("%-24s account %s was there, %d key(s) added\n", r.Node, backupAccount, r.Keys)
		}
	}
	fmt.Printf("%d server(s) added to Configure ▸ Backup.\n", v.Added)
	if v.Full > 0 {
		fmt.Printf("%d node(s) not added: the list holds at most %d servers.\n", v.Full, backupMaxTargets)
	}
	if v.Failed > 0 {
		fmt.Println("Run it again when the failed node(s) answer.")
		os.Exit(1)
	}
}

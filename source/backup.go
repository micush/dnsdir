package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Automatic backups.  Each node packs its state directory (the configuration, the certificates and their private keys, the
// cluster identity, the users, the configuration history, the alerts and the scheduler) into one encrypted archive and
// puts it on a server of the operator's, over SFTP.  The archives are named after the node, and only the newest few are
// kept there.  The settings are shared by the cluster; the SSH key is each node's own.
//
// The archive is a tar.gz that is sealed in 64 KiB pieces with AES-256-GCM; the key comes from the password with
// PBKDF2-HMAC-SHA256.  The password is part of the configuration, so it is in the backup itself: keep it somewhere else
// too, because it is the one thing a restore cannot read out of the archive.

const (
	backupProduct  = "dnsdir"
	backupEnv      = "DNSDIR" // prefix of the environment variables
	backupConfName = "dnsdir.conf"
	backupLogName  = "dnsdir.log"
	backupExt      = ".dnsbak"
	backupMagic    = "DNSDIRBAK1\n"
	backupChunk    = 64 << 10
	backupMaxFile  = 256 << 20
	backupRetry    = 15 * time.Minute
	backupTimeout  = 30 * time.Minute
)

// backupIter is the PBKDF2 round count (lowered by the tests).
var backupIter = 600000

// BackupTarget is one backup server.
type BackupTarget struct {
	Name string `json:"name,omitempty"` // what the page calls it (the host when empty)
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"` // SSH port, 22 when empty
	User string `json:"user,omitempty"` // the account on the backup server
	Dir  string `json:"dir,omitempty"`  // the directory there; empty = the account's home
	Keep int    `json:"keep,omitempty"` // how many archives of each node to keep there (14 when empty)
}

// BackupConfig is the "backup" block of the shared settings (Configure ▸ Backup).
type BackupConfig struct {
	Targets  []BackupTarget `json:"targets,omitempty"`
	Password string         `json:"password,omitempty"`
	// When backups run is a Scheduler task (action "backup").  Enabled, Hours and At are the schedule of v583-v591: when the
	// configuration is read, migrateBackupSchedule turns them into such a task and clears them.
	Enabled bool   `json:"enabled,omitempty"`
	Hours   int    `json:"hours,omitempty"` // 0: once a day at At; N: every N hours
	At      string `json:"at,omitempty"`    // HH:MM, the node's local time (02:30 when empty)
	// the one server of v582, which becomes the first of Targets when the block is read
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Dir  string `json:"dir,omitempty"`
	Keep int    `json:"keep,omitempty"`
}

const backupMaxTargets = 8

func (c *BackupConfig) clone() *BackupConfig {
	if c == nil {
		return nil
	}
	d := *c
	d.Targets = append([]BackupTarget(nil), c.Targets...)
	return &d
}

var (
	backupHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$|^[0-9A-Fa-f:]+$`)
	backupUserRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)
	backupDirRe  = regexp.MustCompile(`^[A-Za-z0-9._/~+@=,\-]+$`)
	backupAtRe   = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

func (t *BackupTarget) port() int {
	if t.Port == 0 {
		return 22
	}
	return t.Port
}

func (t *BackupTarget) keep() int {
	if t.Keep == 0 {
		return 14
	}
	return t.Keep
}

// key identifies the target in the status (not its name, which may be changed).
func (t *BackupTarget) key() string {
	return fmt.Sprintf("%s@%s:%d/%s", t.User, t.Host, t.port(), strings.Trim(t.Dir, "/"))
}

func (t *BackupTarget) label() string {
	if t.Name != "" {
		return t.Name
	}
	return t.Host
}

func (t *BackupTarget) validate() error {
	t.Name, t.Host, t.User, t.Dir = strings.TrimSpace(t.Name), strings.TrimSpace(t.Host), strings.TrimSpace(t.User), strings.TrimSpace(t.Dir)
	if len(t.Name) > 64 || hasControl(t.Name) {
		return errors.New("backup: the name of a server is at most 64 characters")
	}
	if t.Host != "" && (len(t.Host) > 253 || !backupHostRe.MatchString(t.Host)) {
		return errors.New("backup: the server must be a host name or an address")
	}
	if t.User != "" && !backupUserRe.MatchString(t.User) {
		return errors.New("backup: the user name is not valid")
	}
	if t.Port < 0 || t.Port > 65535 {
		return errors.New("backup: the port must be between 1 and 65535")
	}
	if t.Dir != "" {
		if len(t.Dir) > 255 || !backupDirRe.MatchString(t.Dir) || strings.Contains(t.Dir, "..") || strings.HasPrefix(t.Dir, "-") {
			return errors.New("backup: the directory may only have letters, digits and . _ / ~ + @ = , - and no ..")
		}
	}
	if t.Keep < 0 || t.Keep > 365 {
		return errors.New("backup: keep between 1 and 365 backups")
	}
	return nil
}

func (t BackupTarget) empty() bool { return t == BackupTarget{} }

// Validate cleans the block up and says what is wrong with it.
func (c *BackupConfig) Validate() error {
	c.At = strings.TrimSpace(c.At)
	if c.Host != "" || c.User != "" || c.Dir != "" || c.Port != 0 || c.Keep != 0 { // the single server of v582
		c.Targets = append([]BackupTarget{{Host: c.Host, Port: c.Port, User: c.User, Dir: c.Dir, Keep: c.Keep}}, c.Targets...)
		c.Host, c.Port, c.User, c.Dir, c.Keep = "", 0, "", "", 0
	}
	var ts []BackupTarget
	seen := map[string]bool{}
	for _, t := range c.Targets {
		if err := t.validate(); err != nil {
			return err
		}
		if t.empty() {
			continue
		}
		if t.Host == "" || t.User == "" {
			if c.Enabled {
				return errors.New("backup: every server needs a host and a user")
			}
		}
		if seen[t.key()] && t.Host != "" {
			return errors.New("backup: " + t.label() + " is in the list twice")
		}
		seen[t.key()] = true
		ts = append(ts, t)
	}
	c.Targets = ts
	if len(c.Targets) > backupMaxTargets {
		return fmt.Errorf("backup: at most %d servers", backupMaxTargets)
	}
	if c.Hours < 0 || c.Hours > 168 {
		return errors.New("backup: every 1 to 168 hours, or 0 for once a day")
	}
	if c.At != "" && !backupAtRe.MatchString(c.At) {
		return errors.New("backup: the time of day is HH:MM")
	}
	// the archive password is whatever the person types, any length, or nothing (then the archives are sealed with an
	// empty password: anyone with the file can open it)
	return nil
}

func (c *BackupConfig) empty() bool {
	return c == nil || (!c.Enabled && len(c.Targets) == 0 && c.Hours == 0 && c.At == "" && c.Password == "")
}

// ── the sealed stream ────────────────────────────────────────────────────────

func backupKeyFor(password string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iter, 32)
}

type sealWriter struct {
	w     io.Writer
	aead  cipher.AEAD
	buf   []byte
	n     uint64
	err   error
	close bool
}

func newSealWriter(w io.Writer, password string) (*sealWriter, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := backupKeyFor(password, salt, backupIter)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	hdr := append([]byte(backupMagic), 0, 0, 0, 0)
	binary.BigEndian.PutUint32(hdr[len(backupMagic):], uint32(backupIter))
	hdr = append(hdr, salt...)
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &sealWriter{w: w, aead: aead, buf: make([]byte, 0, backupChunk)}, nil
}

func (s *sealWriter) seal(final bool) error {
	nonce := make([]byte, s.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	flag := byte(0)
	if final {
		flag = 1
	}
	ct := s.aead.Seal(nil, nonce, s.buf, []byte{flag})
	hdr := make([]byte, 5)
	hdr[0] = flag
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(ct)))
	if _, err := s.w.Write(hdr); err != nil {
		return err
	}
	_, err := s.w.Write(ct)
	s.buf = s.buf[:0]
	return err
}

func (s *sealWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	total := len(p)
	for len(p) > 0 {
		room := backupChunk - len(s.buf)
		if room > len(p) {
			room = len(p)
		}
		s.buf = append(s.buf, p[:room]...)
		p = p[room:]
		if len(s.buf) == backupChunk {
			if s.err = s.seal(false); s.err != nil {
				return 0, s.err
			}
		}
	}
	return total, nil
}

func (s *sealWriter) Close() error {
	if s.close {
		return s.err
	}
	s.close = true
	if s.err == nil {
		s.err = s.seal(true)
	}
	return s.err
}

var errBackupPassword = errors.New("the password is wrong, or the file is damaged")

type openReader struct {
	r    io.Reader
	aead cipher.AEAD
	n    uint64
	cur  []byte
	done bool
}

func newOpenReader(r io.Reader, password string) (*openReader, error) {
	hdr := make([]byte, len(backupMagic)+4+16)
	if _, err := io.ReadFull(r, hdr); err != nil || string(hdr[:len(backupMagic)]) != backupMagic {
		return nil, errors.New("this is not a " + backupProduct + " backup")
	}
	iter := int(binary.BigEndian.Uint32(hdr[len(backupMagic):]))
	if iter < 1000 || iter > 10000000 {
		return nil, errors.New("this is not a " + backupProduct + " backup")
	}
	key, err := backupKeyFor(password, hdr[len(backupMagic)+4:], iter)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &openReader{r: r, aead: aead}, nil
}

func (o *openReader) Read(p []byte) (int, error) {
	for len(o.cur) == 0 {
		if o.done {
			return 0, io.EOF
		}
		h := make([]byte, 5)
		if _, err := io.ReadFull(o.r, h); err != nil {
			return 0, errors.New("the backup is cut short")
		}
		n := binary.BigEndian.Uint32(h[1:])
		if n > backupChunk+uint32(o.aead.Overhead()) || n < uint32(o.aead.Overhead()) || h[0] > 1 {
			return 0, errBackupPassword
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(o.r, ct); err != nil {
			return 0, errors.New("the backup is cut short")
		}
		nonce := make([]byte, o.aead.NonceSize())
		binary.BigEndian.PutUint64(nonce[4:], o.n)
		o.n++
		pt, err := o.aead.Open(nil, nonce, ct, h[:1])
		if err != nil {
			return 0, errBackupPassword
		}
		o.cur = pt
		if h[0] == 1 {
			o.done = true
		}
	}
	n := copy(p, o.cur)
	o.cur = o.cur[n:]
	return n, nil
}

// ── what goes in ─────────────────────────────────────────────────────────────

// backupManifest is the first entry of every archive.
type backupManifest struct {
	Format  int    `json:"format"`
	Product string `json:"product"`
	Version string `json:"version"`
	Node    string `json:"node"`
	Created string `json:"created"`
	Conf    string `json:"conf"` // where the configuration file is in the archive
}

const backupManifestName = "MANIFEST.json"
const backupExternalConf = "_config/"

// backupSkip says whether a path of the state directory is left out: what is only a copy of something that comes back
// (staged upgrades, downloaded block lists, statistics), what belongs to this run of the daemon (sessions, the log) and
// the backup's own working files.
func backupSkip(rel string) bool {
	top := rel
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		top = rel[:i]
	}
	switch top {
	case "update", "blocklists", "pairs", "capture":
		return true
	}
	switch {
	case rel == sessionsFile, rel == "stats.json.gz":
		return true
	case rel == backupLogName || strings.HasPrefix(rel, backupLogName+"."):
		return true
	case strings.HasPrefix(rel, "backup/work"), rel == "backup/status.json":
		return true
	case strings.HasSuffix(rel, ".tmp"), strings.Contains(rel, "/.tmp"), strings.HasPrefix(path.Base(rel), ".tmp"):
		return true
	}
	return false
}

func tarAdd(tw *tar.Writer, name string, mode int64, data []byte, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: mod, Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// writeBackupArchive packs the state directory (and the configuration file, when it is somewhere else) into w, sealed.
func writeBackupArchive(w io.Writer, password, stateDir, confFile, node string, now time.Time) (files int, err error) {
	sw, err := newSealWriter(w, password)
	if err != nil {
		return 0, err
	}
	gz := gzip.NewWriter(sw)
	tw := tar.NewWriter(gz)
	man := backupManifest{Format: 1, Product: backupProduct, Version: version(), Node: node, Created: now.UTC().Format(time.RFC3339), Conf: backupConfName}
	inside := false
	if rel, err := filepath.Rel(stateDir, confFile); err == nil && !strings.HasPrefix(rel, "..") {
		man.Conf, inside = filepath.ToSlash(rel), true
	} else {
		man.Conf = backupExternalConf + filepath.Base(confFile)
	}
	mb, _ := json.MarshalIndent(man, "", "  ")
	if err := tarAdd(tw, backupManifestName, 0o600, mb, now); err != nil {
		return 0, err
	}
	err = filepath.WalkDir(stateDir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if p == stateDir {
				return werr
			}
			return nil // vanished while we walked
		}
		rel, _ := filepath.Rel(stateDir, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if backupSkip(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // directories come with their files; links, sockets and devices are not backed up
		}
		fi, err := d.Info()
		if err != nil || fi.Size() > backupMaxFile {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		files++
		return tarAdd(tw, rel, int64(fi.Mode().Perm()), data, fi.ModTime())
	})
	if err != nil {
		return files, err
	}
	if !inside {
		if data, rerr := os.ReadFile(confFile); rerr == nil {
			files++
			if err := tarAdd(tw, man.Conf, 0o600, data, now); err != nil {
				return files, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return files, err
	}
	if err := gz.Close(); err != nil {
		return files, err
	}
	return files, sw.Close()
}

// ── restoring ────────────────────────────────────────────────────────────────

// readBackupArchive decrypts r and unpacks it into dir (which must be empty); it returns the manifest.  Nothing outside
// dir is written, and a path that tries to leave it, a link or a device is refused.
func readBackupArchive(r io.Reader, password, dir string) (*backupManifest, error) {
	or, err := newOpenReader(bufio.NewReader(r), password)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(or)
	if err != nil {
		return nil, errBackupPassword
	}
	tr := tar.NewReader(gz)
	var man *backupManifest
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, errBackupPassword) || strings.Contains(err.Error(), "cut short") {
				return nil, err
			}
			return nil, fmt.Errorf("the backup is damaged: %v", err)
		}
		name := path.Clean(h.Name)
		if h.Typeflag != tar.TypeReg || name == "." || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
			return nil, fmt.Errorf("the backup holds an entry that is not allowed: %q", h.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, backupMaxFile+1))
		if err != nil {
			return nil, fmt.Errorf("the backup is damaged: %v", err)
		}
		if name == backupManifestName {
			var m backupManifest
			if json.Unmarshal(data, &m) != nil || m.Format != 1 || m.Product != backupProduct {
				return nil, errors.New("this backup is not from " + backupProduct)
			}
			man = &m
			continue
		}
		if man == nil {
			return nil, errors.New("the backup has no manifest")
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		mode := os.FileMode(h.Mode).Perm() & 0o700
		if mode == 0 {
			mode = 0o600
		}
		if err := os.WriteFile(dst, data, mode); err != nil {
			return nil, err
		}
	}
	if man == nil {
		return nil, errors.New("the backup has no manifest")
	}
	return man, nil
}

// restoreBackup unpacks a backup file and puts its contents in place of the state directory's own.  The daemon must not be
// running (the command line); the GUI stages the archive and lets the next start do the second half (applyPendingRestore).
func restoreBackup(file, password, stateDir, confFile string) (*backupManifest, string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	parent := filepath.Dir(filepath.Clean(stateDir))
	stage, err := os.MkdirTemp(parent, filepath.Base(stateDir)+".restore-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(stage)
	man, err := readBackupArchive(f, password, stage)
	if err != nil {
		return nil, "", err
	}
	aside, err := installStaged(stage, man, stateDir, confFile)
	return man, aside, err
}

// installStaged puts the unpacked backup in stage in place of the state directory's own: what the archive holds replaces what
// is there (the old versions are kept in a directory next to it), and what the archive leaves out (the log, staged upgrades)
// is left alone.
func installStaged(stage string, man *backupManifest, stateDir, confFile string) (string, error) {
	parent := filepath.Dir(filepath.Clean(stateDir))
	aside := filepath.Join(parent, fmt.Sprintf("%s.before-restore-%s", filepath.Base(stateDir), time.Now().Format("20060102-150405")))
	if err := os.MkdirAll(aside, 0o700); err != nil {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	ents, _ := os.ReadDir(stage)
	for _, e := range ents {
		if e.Name() == strings.TrimSuffix(backupExternalConf, "/") {
			continue
		}
		dst := filepath.Join(stateDir, e.Name())
		if _, err := os.Lstat(dst); err == nil {
			if err := os.Rename(dst, filepath.Join(aside, e.Name())); err != nil {
				return "", err
			}
		}
		if err := os.Rename(filepath.Join(stage, e.Name()), dst); err != nil {
			return "", err
		}
	}
	if strings.HasPrefix(man.Conf, backupExternalConf) { // the configuration file was outside the state directory
		src := filepath.Join(stage, filepath.FromSlash(man.Conf))
		if _, err := os.Stat(src); err == nil {
			if _, err := os.Lstat(confFile); err == nil {
				_ = os.Rename(confFile, filepath.Join(aside, filepath.Base(confFile)))
			}
			if err := os.MkdirAll(filepath.Dir(confFile), 0o700); err != nil {
				return "", err
			}
			if err := os.Rename(src, confFile); err != nil {
				return "", err
			}
		}
	}
	return aside, nil
}

// ── the server side: SFTP ────────────────────────────────────────────────────

// sftpMkdirs makes every level of dir (sftp's mkdir is not recursive); a level that is there already is no error.
func sftpMkdirs(dir string) string {
	dir = strings.TrimRight(dir, "/")
	if dir == "" || dir == "~" {
		return ""
	}
	var out string
	cur := ""
	if strings.HasPrefix(dir, "/") {
		cur = "/"
	}
	for _, p := range strings.Split(strings.Trim(dir, "/"), "/") {
		if p == "" || p == "." || p == "~" {
			continue
		}
		if cur != "" && !strings.HasSuffix(cur, "/") {
			cur += "/"
		}
		cur += p
		out += "-mkdir " + sftpQuote(cur) + "\n"
	}
	return out
}

func sftpQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// backupSFTP runs a batch of sftp commands against a backup server with the node's key, and returns what sftp printed
// (replaceable in tests).  With a password it logs in with that instead, which is only for installing the keys and for
// fetching a backup from a server this node has no key on.
var backupSFTP = func(ctx context.Context, t *BackupTarget, dir string, script, password string) (string, error) {
	return runSFTP(ctx, t, dir, script, password)
}

func runSFTP(ctx context.Context, t *BackupTarget, dir string, script, password string) (string, error) {
	args := []string{"-b", "-", "-q",
		"-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"),
		"-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"}
	env := os.Environ()
	if password == "" {
		args = append(args, "-o", "BatchMode=yes", "-o", "IdentityFile="+filepath.Join(dir, "id_ed25519"), "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no")
	} else {
		// ssh asks for the password by running the program in SSH_ASKPASS; this one prints it from the environment
		work := filepath.Join(dir, "work")
		if err := os.MkdirAll(work, 0o700); err != nil {
			return "", err
		}
		ap, err := os.CreateTemp(work, "askpass-*.sh")
		if err != nil {
			return "", err
		}
		defer os.Remove(ap.Name())
		ap.WriteString("#!/bin/sh\nprintf '%s\\n' \"$" + backupEnv + "_ASKPASS_VALUE\"\n")
		ap.Close()
		os.Chmod(ap.Name(), 0o700)
		// sftp -b adds BatchMode=yes, and the first setting wins, so this one goes in front of it
		args = append([]string{"-o", "BatchMode=no"}, args...)
		args = append(args, "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1")
		env = append(env, "SSH_ASKPASS="+ap.Name(), "SSH_ASKPASS_REQUIRE=force", "DISPLAY=none:0", backupEnv+"_ASKPASS_VALUE="+password)
	}
	args = append(args, "-P", fmt.Sprint(t.port()), t.User+"@"+t.Host)
	cmd := exec.CommandContext(ctx, envOr(backupEnv+"_SFTP", "sftp"), args...)
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(out.String())
		if i := strings.LastIndexByte(msg, '\n'); i >= 0 {
			msg = strings.TrimSpace(msg[i+1:])
		}
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), errors.New(msg)
	}
	return out.String(), nil
}

// backupKeygen makes the node's SSH key (replaceable in tests).
var backupKeygen = func(file, comment string) error {
	out, err := exec.Command(envOr(backupEnv+"_SSHKEYGEN", "ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", file).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ssh-keygen: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ── the engine ───────────────────────────────────────────────────────────────

// BackupTargetStatus is what happened with one backup server.
type BackupTargetStatus struct {
	LastStart int64    `json:"last_start,omitempty"`
	LastOK    int64    `json:"last_ok,omitempty"`
	LastError string   `json:"last_error,omitempty"`
	LastFile  string   `json:"last_file,omitempty"`
	LastSize  int64    `json:"last_size,omitempty"`
	Remote    []string `json:"remote,omitempty"` // this node's archives on the server, oldest first, after the last run
	Pruned    int      `json:"pruned,omitempty"`
}

// BackupStatus is what the page shows about this node's backups.
type BackupStatus struct {
	LastStart int64                          `json:"last_start,omitempty"` // the last run of any kind
	LastFull  int64                          `json:"last_full,omitempty"`  // the last run that went to every server (the schedule counts from it)
	LastOK    int64                          `json:"last_ok,omitempty"`    // the last time a server took a backup
	LastFiles int                            `json:"last_files,omitempty"`
	LastSecs  float64                        `json:"last_seconds,omitempty"`
	Targets   map[string]*BackupTargetStatus `json:"targets,omitempty"` // by BackupTarget.key
}

type BackupEngine struct {
	mu        sync.Mutex
	dir       string // <state>/backup
	stateDir  string
	confFile  string
	node      string
	cfg       func() *BackupConfig
	now       func() time.Time
	status    BackupStatus
	running   bool
	runCtx    context.Context
	onRunDone func()
	// scheduled says the Scheduler has a backup task that runs on this node: only then are failed servers tried again, and
	// a server added later gets its first backup at once.
	scheduled func() bool
}

func (e *BackupEngine) isScheduled() bool { return e.scheduled != nil && e.scheduled() }

func NewBackupEngine(stateDir, confFile, node string, cfg func() *BackupConfig) *BackupEngine {
	e := &BackupEngine{dir: filepath.Join(stateDir, "backup"), stateDir: stateDir, confFile: confFile, node: node, cfg: cfg, now: time.Now,
		runCtx: context.Background()}
	if b, err := os.ReadFile(filepath.Join(e.dir, "status.json")); err == nil {
		_ = json.Unmarshal(b, &e.status)
	}
	if e.status.Targets == nil {
		e.status.Targets = map[string]*BackupTargetStatus{}
	}
	return e
}

var backupNodeRe = regexp.MustCompile(`[^a-z0-9.\-]+`)

// nodeName is the node's name as it goes into the file names.
func (e *BackupEngine) nodeName() string {
	n := strings.Trim(backupNodeRe.ReplaceAllString(strings.ToLower(e.node), "-"), "-.")
	if n == "" {
		n = "node"
	}
	return n
}

func (e *BackupEngine) fileName(t time.Time) string {
	return e.nodeName() + "-" + t.Format("20060102-150405") + backupExt
}

func (e *BackupEngine) nameRe() *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(e.nodeName()) + `-[0-9]{8}-[0-9]{6}` + regexp.QuoteMeta(backupExt) + `$`)
}

// anyNameRe matches the name of a backup of any node.
var backupAnyRe = regexp.MustCompile(`^(.+)-([0-9]{8})-([0-9]{6})` + regexp.QuoteMeta(backupExt) + `$`)

func (e *BackupEngine) saveStatusLocked() {
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return
	}
	b, _ := json.Marshal(e.status)
	_ = os.WriteFile(filepath.Join(e.dir, "status.json"), b, 0o600)
}

func (e *BackupEngine) tstat(t *BackupTarget) *BackupTargetStatus {
	if e.status.Targets == nil {
		e.status.Targets = map[string]*BackupTargetStatus{}
	}
	s := e.status.Targets[t.key()]
	if s == nil {
		s = &BackupTargetStatus{}
		e.status.Targets[t.key()] = s
	}
	return s
}

// Status is the status for the page, with this node's public key and the state of every server.
func (e *BackupEngine) Status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	pub, _ := os.ReadFile(filepath.Join(e.dir, "id_ed25519.pub"))
	c := e.cfg()
	var ts []map[string]any
	if c != nil {
		for i := range c.Targets {
			t := &c.Targets[i]
			st := e.status.Targets[t.key()]
			if st == nil {
				st = &BackupTargetStatus{}
			}
			ts = append(ts, map[string]any{"label": t.label(), "host": t.Host, "user": t.User, "status": st})
		}
	}
	sched := e.isScheduled()
	out := map[string]any{"status": e.status, "targets": ts, "running": e.running, "node": e.nodeName(), "public_key": strings.TrimSpace(string(pub)), "enabled": sched}
	if c != nil && sched && !e.running {
		if _, next := e.retryLocked(c); !next.IsZero() {
			out["retry"] = next.Unix()
		}
	}
	if p := e.pendingSummary(); p != nil {
		out["pending_restore"] = p
	}
	return out
}

// Failing says whether the last attempt to a server of an enabled backup failed (the alert rule).
func (e *BackupEngine) Failing() (failing, enabled bool, msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.cfg()
	sched := e.isScheduled()
	if c == nil || !sched || e.running {
		return false, c != nil && sched, ""
	}
	var bad []string
	for i := range c.Targets {
		if st := e.status.Targets[c.Targets[i].key()]; st != nil && st.LastError != "" {
			bad = append(bad, c.Targets[i].label()+": "+st.LastError)
		}
	}
	return len(bad) > 0, true, strings.Join(bad, "; ")
}

// ensureKey makes the node's SSH key when it has none.
func (e *BackupEngine) ensureKey() error {
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	key := filepath.Join(e.dir, "id_ed25519")
	if _, err := os.Stat(key); err == nil {
		if _, err := os.Stat(key + ".pub"); err == nil {
			return nil
		}
	}
	os.Remove(key)
	os.Remove(key + ".pub")
	return backupKeygen(key, backupProduct+"-backup@"+e.nodeName())
}

// retryLocked is the servers that need another try now: the ones that failed (after a pause) and the ones that never had a
// backup (at once).
func (e *BackupEngine) retryLocked(c *BackupConfig) (ts []BackupTarget, next time.Time) {
	now := e.now()
	for _, t := range c.Targets {
		st := e.status.Targets[t.key()]
		switch {
		case st == nil || (st.LastStart == 0 && st.LastError == ""):
			ts = append(ts, t)
		case st.LastError != "":
			at := time.Unix(st.LastStart, 0).Add(backupRetry)
			if !at.After(now) {
				ts = append(ts, t)
			} else if next.IsZero() || at.Before(next) {
				next = at
			}
		}
	}
	return ts, next
}

// pickLocked is the servers to back up to between the Scheduler's runs: the ones that failed (after a pause) and the
// ones that never had a backup.
func (e *BackupEngine) pickLocked(c *BackupConfig) []BackupTarget {
	if len(c.Targets) == 0 {
		return nil
	}
	ts, _ := e.retryLocked(c)
	return ts
}

func (e *BackupEngine) due() bool {
	c := e.cfg()
	if c == nil || !e.isScheduled() || c.Validate() != nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return false
	}
	return len(e.pickLocked(c)) > 0
}

// Run tries failed servers again between the Scheduler's runs (the runs themselves are the Scheduler's "backup" task).
func (e *BackupEngine) Run(ctx context.Context) {
	e.runCtx = ctx
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if e.due() {
				_ = e.start(false)
			}
		}
	}
}

// start begins a backup in the background: to every server (all), or to those that are due.
func (e *BackupEngine) start(all bool) error {
	c := e.cfg()
	if c == nil || len(c.Targets) == 0 {
		return errors.New("say which server to back up to first")
	}
	if !all && !e.isScheduled() {
		return errors.New("backups are not scheduled")
	}
	cc := c.clone()
	if err := cc.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("a backup is already running")
	}
	targets, full := cc.Targets, true
	if !all {
		targets, full = e.pickLocked(cc), false
		if len(targets) == 0 {
			e.mu.Unlock()
			return errors.New("nothing is due")
		}
	}
	e.running = true
	e.status.LastStart = e.now().Unix()
	if full {
		e.status.LastFull = e.status.LastStart
	}
	for i := range targets {
		e.tstat(&targets[i]).LastStart = e.status.LastStart
	}
	e.mu.Unlock()
	go func() {
		err := e.backup(cc, targets)
		e.mu.Lock()
		e.running = false
		if err != nil {
			warnf("backup: %v", err)
		}
		e.saveStatusLocked()
		done := e.onRunDone
		e.mu.Unlock()
		if done != nil {
			done()
		}
	}()
	return nil
}

// RunScheduled is the Scheduler's "backup" action: a backup of this node to every server, waited for, so the task's
// history says how it went.
func (e *BackupEngine) RunScheduled(actor string) (string, error) {
	if err := e.start(true); err != nil {
		return "", err
	}
	infof("backup: started by %s", actor)
	e.mu.Lock()
	began := e.status.LastStart
	e.mu.Unlock()
	for deadline := time.Now().Add(backupTimeout + time.Minute); time.Now().Before(deadline); time.Sleep(time.Second) {
		e.mu.Lock()
		running := e.running
		e.mu.Unlock()
		if !running {
			break
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.cfg()
	if c == nil {
		return "", errors.New("the backup settings are gone")
	}
	var ok, bad []string
	for i := range c.Targets {
		t := &c.Targets[i]
		st := e.status.Targets[t.key()]
		switch {
		case st == nil || st.LastStart < began:
		case st.LastError != "":
			bad = append(bad, t.label()+": "+st.LastError)
		default:
			ok = append(ok, t.label()+" ("+st.LastFile+")")
		}
	}
	if e.running {
		return "", errors.New("still running after " + backupTimeout.String())
	}
	out := "backed up to " + strings.Join(ok, ", ")
	if len(ok) == 0 {
		out = ""
	}
	if len(bad) > 0 {
		return out, errors.New(strings.Join(bad, "; "))
	}
	return out, nil
}

// RunNow starts a backup to every server now (the button).
func (e *BackupEngine) RunNow(actor string) error {
	if err := e.start(true); err != nil {
		return err
	}
	infof("backup: started by %s", actor)
	return nil
}

func (t *BackupTarget) prefix() string {
	if t.Dir == "" {
		return ""
	}
	if t.Dir == "/" {
		return "/"
	}
	return strings.TrimRight(t.Dir, "/") + "/"
}

// backup makes one archive and puts it on each of the servers, then removes the oldest ones there.  A server that fails does not
// keep the others from getting theirs.
func (e *BackupEngine) backup(c *BackupConfig, targets []BackupTarget) error {
	began := e.now()
	fail := func(err error) error {
		e.mu.Lock()
		for i := range targets {
			e.tstat(&targets[i]).LastError = err.Error()
		}
		e.mu.Unlock()
		return err
	}
	if err := e.ensureKey(); err != nil {
		return fail(err)
	}
	work := filepath.Join(e.dir, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return fail(err)
	}
	name := e.fileName(began)
	local := filepath.Join(work, name)
	defer os.Remove(local)
	f, err := os.OpenFile(local, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fail(err)
	}
	files, err := writeBackupArchive(f, c.Password, e.stateDir, e.confFile, e.nodeName(), began)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail(fmt.Errorf("packing the backup: %v", err))
	}
	fi, _ := os.Stat(local)
	var size int64
	if fi != nil {
		size = fi.Size()
	}
	var errs []string
	for i := range targets {
		t := &targets[i]
		ctx, cancel := context.WithTimeout(e.runCtx, backupTimeout)
		names, pruned, err := e.upload(ctx, t, local, name)
		cancel()
		e.mu.Lock()
		st := e.tstat(t)
		st.LastStart = began.Unix()
		if names != nil {
			st.Remote, st.Pruned = names, pruned
		}
		if err != nil {
			st.LastError = err.Error()
			errs = append(errs, t.label()+": "+err.Error())
		} else {
			st.LastError, st.LastOK, st.LastFile, st.LastSize = "", e.now().Unix(), name, size
			e.status.LastOK = st.LastOK
		}
		e.status.LastFiles, e.status.LastSecs = files, e.now().Sub(began).Seconds()
		e.mu.Unlock()
		if err == nil {
			infof("backup: %s uploaded to %s (%d files, %d bytes); %d old ones removed", name, t.label(), files, size, pruned)
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// upload puts the archive on one server and prunes there.  names is what this node has there afterwards.
func (e *BackupEngine) upload(ctx context.Context, t *BackupTarget, local, name string) (names []string, pruned int, err error) {
	pre := t.prefix()
	script := sftpMkdirs(t.Dir)
	script += "put " + sftpQuote(local) + " " + sftpQuote(pre+name+".part") + "\n"
	script += "rename " + sftpQuote(pre+name+".part") + " " + sftpQuote(pre+name) + "\n"
	if _, err := backupSFTP(ctx, t, e.dir, script, ""); err != nil {
		return nil, 0, fmt.Errorf("uploading to %s: %v", t.Host, err)
	}
	names, pruned, perr := e.prune(ctx, t)
	if perr != nil {
		return names, pruned, fmt.Errorf("the backup was uploaded, but removing old ones failed: %v", perr)
	}
	return names, pruned, nil
}

// lsDir lists the file names in the server's directory.
func (e *BackupEngine) lsDir(ctx context.Context, t *BackupTarget, password string) ([]string, error) {
	where := "."
	if t.Dir != "" {
		where = t.Dir
	}
	out, err := backupSFTP(ctx, t, e.dir, "ls -1 "+sftpQuote(where)+"\n", password)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "sftp>") {
			continue
		}
		names = append(names, path.Base(l))
	}
	return names, nil
}

// list returns this node's archives on a server, oldest first.
func (e *BackupEngine) list(ctx context.Context, t *BackupTarget) ([]string, error) {
	all, err := e.lsDir(ctx, t, "")
	if err != nil {
		return nil, err
	}
	re := e.nameRe()
	var names []string
	for _, n := range all {
		if re.MatchString(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

// prune removes this node's oldest archives beyond the number to keep, and returns the ones that are left.
func (e *BackupEngine) prune(ctx context.Context, t *BackupTarget) (left []string, removed int, err error) {
	names, err := e.list(ctx, t)
	if err != nil {
		return nil, 0, err
	}
	if extra := len(names) - t.keep(); extra > 0 {
		script := ""
		for _, n := range names[:extra] {
			script += "-rm " + sftpQuote(t.prefix()+n) + "\n"
		}
		if _, err := backupSFTP(ctx, t, e.dir, script, ""); err != nil {
			return names, 0, err
		}
		removed, names = extra, names[extra:]
	}
	return names, removed, nil
}

// targetAt is the i-th server of the saved settings.
func (e *BackupEngine) targetAt(i int) (*BackupTarget, error) {
	c := e.cfg()
	if c == nil || i < 0 || i >= len(c.Targets) {
		return nil, errors.New("no such server (save the settings first)")
	}
	t := c.Targets[i]
	if t.Host == "" || t.User == "" {
		return nil, errors.New("fill in the server and the user, and save, first")
	}
	return &t, nil
}

// Test logs in to a server and lists the node's backups there; it makes the key when there is none.
func (e *BackupEngine) Test(i int) ([]string, error) {
	t, err := e.targetAt(i)
	if err != nil {
		return nil, err
	}
	if err := e.ensureKey(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	names, err := e.list(ctx, t)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.tstat(t).Remote = names
	e.saveStatusLocked()
	e.mu.Unlock()
	return names, nil
}

// ── installing the keys ──────────────────────────────────────────────────────

var backupKeyRe = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( [^\r\n]{0,200})?$`)

// authorizeKeys adds the keys (public key lines) to the text of an authorized_keys file, as restricted keys, unless they are
// in it already.  It returns the new text and how many were added.
func authorizeKeys(existing string, keys []string) (string, int) {
	have := map[string]bool{}
	for _, l := range strings.Split(existing, "\n") {
		f := strings.Fields(l)
		for i, x := range f {
			if strings.HasPrefix(x, "ssh-") && i+1 < len(f) {
				have[x+" "+f[i+1]] = true
				break
			}
		}
	}
	out := existing
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	added := 0
	for _, k := range keys {
		f := strings.Fields(k)
		if len(f) < 2 || have[f[0]+" "+f[1]] {
			continue
		}
		have[f[0]+" "+f[1]] = true
		out += "restrict " + strings.TrimSpace(k) + "\n"
		added++
	}
	return out, added
}

// InstallKeys logs in to a backup server once with the account's password and adds the public keys of the nodes to its
// authorized_keys.  The password is used for these two logins and kept nowhere.
func (e *BackupEngine) InstallKeys(t *BackupTarget, password string, keys []string) (added int, err error) {
	if t == nil || t.Host == "" || t.User == "" {
		return 0, errors.New("fill in the server and the user, and save, first")
	}
	if err := t.validate(); err != nil {
		return 0, err
	}
	if password == "" || len(password) > 512 || hasControl(password) {
		return 0, errors.New("type the password of that account on the server")
	}
	var ok []string
	for _, k := range keys {
		if k = strings.TrimSpace(k); backupKeyRe.MatchString(k) {
			ok = append(ok, k)
		}
	}
	if len(ok) == 0 {
		return 0, errors.New("no node has a key yet")
	}
	if err := os.MkdirAll(filepath.Join(e.dir, "work"), 0o700); err != nil {
		return 0, err
	}
	local, err := os.MkdirTemp(filepath.Join(e.dir, "work"), "keys-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(local)
	ctx, cancel := context.WithTimeout(e.runCtx, 2*time.Minute)
	defer cancel()
	in, outp := filepath.Join(local, "authorized_keys.in"), filepath.Join(local, "authorized_keys")
	// the account's authorized_keys as it is (it may not be there); a failed login ends here, a missing file does not
	if _, err := backupSFTP(ctx, t, e.dir, "-mkdir .ssh\n-chmod 700 .ssh\n-get .ssh/authorized_keys "+sftpQuote(in)+"\n", password); err != nil {
		return 0, fmt.Errorf("logging in to %s: %v", t.Host, err)
	}
	old, _ := os.ReadFile(in)
	merged, added := authorizeKeys(string(old), ok)
	if added > 0 {
		if err := os.WriteFile(outp, []byte(merged), 0o600); err != nil {
			return 0, err
		}
		if _, err := backupSFTP(ctx, t, e.dir, "put "+sftpQuote(outp)+" .ssh/authorized_keys\nchmod 600 .ssh/authorized_keys\n", password); err != nil {
			return 0, fmt.Errorf("writing authorized_keys on %s: %v", t.Host, err)
		}
	}
	return added, nil
}

type backupNodeKey struct {
	Node string
	Key  string
	Err  string
}

// nodeKeys are the public keys of this node and of the other nodes of the cluster.
func (m *Mgmt) backupNodeKeys(ctx context.Context) []backupNodeKey {
	var out []backupNodeKey
	if err := m.backup.ensureKey(); err == nil {
		pub, _ := os.ReadFile(filepath.Join(m.backup.dir, "id_ed25519.pub"))
		out = append(out, backupNodeKey{Node: m.backup.nodeName(), Key: strings.TrimSpace(string(pub))})
	} else {
		out = append(out, backupNodeKey{Node: m.backup.nodeName(), Err: err.Error()})
	}
	if m.cl == nil || !m.cl.Enabled() {
		return out
	}
	snap := m.cl.node.Snapshot()
	for _, p := range snap.Peers {
		if containsStr(snap.Removed, p.Addr) {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		resp, err := m.cl.Relay(cctx, p.Addr, proxyReq{User: "backup", Method: http.MethodGet, Path: "/api/backup"})
		cancel()
		var v struct {
			Data struct {
				Node      string `json:"node"`
				PublicKey string `json:"public_key"`
			} `json:"data"`
		}
		switch {
		case err != nil:
			out = append(out, backupNodeKey{Node: p.Addr, Err: err.Error()})
		case resp.Status != http.StatusOK || json.Unmarshal(resp.Body, &v) != nil || v.Data.PublicKey == "":
			out = append(out, backupNodeKey{Node: p.Addr, Err: "it has no backup key (is it running a version with backups?)"})
		default:
			out = append(out, backupNodeKey{Node: v.Data.Node, Key: v.Data.PublicKey})
		}
	}
	return out
}

// ── restoring from the GUI ───────────────────────────────────────────────────
//
// The GUI cannot swap the state directory under a running daemon.  It unpacks and checks the archive into a directory next
// to the state directory (<state>.restore-pending), shows what is in it, and on the operator's word restarts; the next start
// swaps the directories before it reads its configuration (applyPendingRestore, main.go).

type pendingRestore struct {
	Manifest backupManifest `json:"manifest"`
	Files    int            `json:"files"`
	By       string         `json:"by"`
	At       int64          `json:"at"`
	Ready    bool           `json:"ready,omitempty"`
}

func pendingDir(stateDir string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(stateDir)), filepath.Base(stateDir)+".restore-pending")
}

func readPending(stateDir string) *pendingRestore {
	b, err := os.ReadFile(filepath.Join(pendingDir(stateDir), "pending.json"))
	if err != nil {
		return nil
	}
	var p pendingRestore
	if json.Unmarshal(b, &p) != nil {
		return nil
	}
	return &p
}

func (e *BackupEngine) pendingSummary() map[string]any {
	p := readPending(e.stateDir)
	if p == nil {
		return nil
	}
	return map[string]any{"node": p.Manifest.Node, "created": p.Manifest.Created, "version": p.Manifest.Version, "files": p.Files, "by": p.By,
		"same_node": strings.EqualFold(p.Manifest.Node, e.nodeName()), "newer": versionGreater(p.Manifest.Version, version()), "ready": p.Ready}
}

// PrepareRestore opens the backup file with the password and keeps what is in it, checked, for the restart.
func (e *BackupEngine) PrepareRestore(file, password, actor string) (map[string]any, error) {
	pd := pendingDir(e.stateDir)
	if err := os.RemoveAll(pd); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(pd, "data"), 0o700); err != nil {
		return nil, err
	}
	f, err := os.Open(file)
	if err != nil {
		os.RemoveAll(pd)
		return nil, err
	}
	defer f.Close()
	man, err := readBackupArchive(f, password, filepath.Join(pd, "data"))
	if err != nil {
		os.RemoveAll(pd)
		return nil, err
	}
	n := 0
	filepath.WalkDir(filepath.Join(pd, "data"), func(_ string, d fs.DirEntry, _ error) error {
		if d != nil && d.Type().IsRegular() {
			n++
		}
		return nil
	})
	p := pendingRestore{Manifest: *man, Files: n, By: actor, At: e.now().Unix()}
	b, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(pd, "pending.json"), b, 0o600); err != nil {
		os.RemoveAll(pd)
		return nil, err
	}
	warnf("backup: %s prepared the restore of a backup of %s from %s", actor, man.Node, man.Created)
	return e.pendingSummary(), nil
}

// CancelRestore forgets a prepared restore.
func (e *BackupEngine) CancelRestore() { os.RemoveAll(pendingDir(e.stateDir)) }

// MarkReady says the prepared restore is to be applied at the next start.
func (e *BackupEngine) MarkReady() error {
	p := readPending(e.stateDir)
	if p == nil {
		return errors.New("no restore is prepared")
	}
	p.Ready = true
	b, _ := json.Marshal(p)
	return os.WriteFile(filepath.Join(pendingDir(e.stateDir), "pending.json"), b, 0o600)
}

// applyPendingRestore runs at the start of the daemon, before anything reads the state directory: a restore that the GUI
// prepared and confirmed is put in place.
func applyPendingRestore(stateDir, confFile string) {
	p := readPending(stateDir)
	if p == nil {
		return
	}
	pd := pendingDir(stateDir)
	if !p.Ready {
		os.RemoveAll(pd) // prepared but never confirmed
		return
	}
	aside, err := installStaged(filepath.Join(pd, "data"), &p.Manifest, stateDir, confFile)
	if err != nil {
		warnf("backup: the restore of the backup of %s failed: %v (the old files are in %s)", p.Manifest.Node, err, aside)
		os.Rename(filepath.Join(pd, "pending.json"), filepath.Join(pd, "failed.json"))
		return
	}
	os.RemoveAll(pd)
	infof("backup: restored the backup of %s made %s; what was there before is in %s", p.Manifest.Node, p.Manifest.Created, aside)
}

// RemoteBackup is a backup file on a server.
type RemoteBackup struct {
	Name string `json:"name"`
	Node string `json:"node"`
	Time string `json:"time"`
}

// ListRemote lists the backups of every node on a server.  With a password it logs in with it (a server this node has no key
// on, as on a node that was just installed).
func (e *BackupEngine) ListRemote(t *BackupTarget, password string) ([]RemoteBackup, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if t.Host == "" || t.User == "" {
		return nil, errors.New("fill in the server and the user")
	}
	if err := e.ensureKey(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	all, err := e.lsDir(ctx, t, password)
	if err != nil {
		return nil, err
	}
	var out []RemoteBackup
	for _, n := range all {
		if m := backupAnyRe.FindStringSubmatch(n); m != nil {
			ts, _ := time.ParseInLocation("20060102150405", m[2]+m[3], time.Local)
			out = append(out, RemoteBackup{Name: n, Node: m[1], Time: ts.Format(time.RFC3339)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// fetch copies one backup file from a server to the working directory.
func (e *BackupEngine) fetch(t *BackupTarget, password, name string) (string, error) {
	if !backupAnyRe.MatchString(name) {
		return "", errors.New("that is not the name of a backup")
	}
	if err := os.MkdirAll(filepath.Join(e.dir, "work"), 0o700); err != nil {
		return "", err
	}
	local := filepath.Join(e.dir, "work", "restore"+backupExt)
	os.Remove(local)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := backupSFTP(ctx, t, e.dir, "get "+sftpQuote(t.prefix()+name)+" "+sftpQuote(local)+"\n", password); err != nil {
		return "", fmt.Errorf("fetching %s from %s: %v", name, t.Host, err)
	}
	return local, nil
}

// uploadPath is where an uploaded backup file waits.
func (e *BackupEngine) uploadPath() string {
	return filepath.Join(e.dir, "work", "upload"+backupExt)
}

func (e *BackupEngine) SaveUpload(body []byte) error {
	if err := os.MkdirAll(filepath.Join(e.dir, "work"), 0o700); err != nil {
		return err
	}
	return os.WriteFile(e.uploadPath(), body, 0o600)
}

// ── the operations behind /api/backup ────────────────────────────────────────

// backupServerArg is a server named in a request: one of the saved ones (index), or another one with its own login.
type backupServerArg struct {
	Index    *int   `json:"index"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Dir      string `json:"dir"`
	Password string `json:"server_password"` // the account's password: for a server this node has no key on
}

func (e *BackupEngine) resolve(a backupServerArg) (*BackupTarget, string, error) {
	if a.Index != nil {
		t, err := e.targetAt(*a.Index)
		return t, "", err
	}
	t := &BackupTarget{Host: a.Host, Port: a.Port, User: a.User, Dir: a.Dir}
	if err := t.validate(); err != nil {
		return nil, "", err
	}
	if t.Host == "" || t.User == "" {
		return nil, "", errors.New("fill in the server and the user")
	}
	return t, a.Password, nil
}

func (m *Mgmt) backupOp(cmd string, raw json.RawMessage, actor string) (any, error) {
	e := m.backup
	if e == nil {
		return nil, errors.New("backups are not available on this node")
	}
	var a struct {
		backupServerArg
		Password string `json:"password"` // the password of the backup, or the account's for install
		File     string `json:"file"`
		Source   string `json:"source"` // "upload" or "server"
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
	}
	switch cmd {
	case "backup.status":
		if err := e.ensureKey(); err != nil {
			warnf("backup: %v", err)
		}
		return e.Status(), nil
	case "backup.run":
		if err := e.RunNow(actor); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "backup.test":
		i := 0
		if a.Index != nil {
			i = *a.Index
		}
		names, err := e.Test(i)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "remote": names}, nil
	case "backup.install":
		if a.Index == nil {
			return nil, errors.New("which server?")
		}
		t, err := e.targetAt(*a.Index)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		var keys, missing []string
		for _, k := range m.backupNodeKeys(ctx) {
			if k.Key != "" {
				keys = append(keys, k.Key)
			} else {
				missing = append(missing, k.Node+": "+k.Err)
			}
		}
		added, err := e.InstallKeys(t, a.Password, keys)
		if err != nil {
			return nil, err
		}
		infof("backup: %s installed %d key(s) on %s", actor, added, t.Host)
		res := map[string]any{"ok": true, "added": added, "nodes": len(keys), "missing": missing}
		if names, terr := e.Test(*a.Index); terr == nil {
			res["connected"], res["remote"] = true, names
		} else {
			res["connected"], res["test_error"] = false, terr.Error()
		}
		return res, nil
	case "backup.files":
		t, pw, err := e.resolve(a.backupServerArg)
		if err != nil {
			return nil, err
		}
		l, err := e.ListRemote(t, pw)
		if err != nil {
			return nil, err
		}
		return map[string]any{"files": l}, nil
	case "backup.restore.prepare":
		file := ""
		switch a.Source {
		case "upload":
			file = e.uploadPath()
		case "server":
			t, pw, err := e.resolve(a.backupServerArg)
			if err != nil {
				return nil, err
			}
			if file, err = e.fetch(t, pw, a.File); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("where is the backup?")
		}
		defer os.Remove(file)
		return e.PrepareRestore(file, a.Password, actor)
	case "backup.restore.apply":
		if m.restartFn == nil {
			return nil, errors.New("this process cannot restart itself")
		}
		if err := e.MarkReady(); err != nil {
			return nil, err
		}
		warnf("backup: %s restores a backup: restarting", actor)
		go func() {
			time.Sleep(1500 * time.Millisecond) // let the answer go out first
			waitUntilSafe(m.updateSafeToApply, false, restartRecheck, func(string) {})
			m.handOver("backup", "restoring a backup")
			m.restartFn()
		}()
		return map[string]any{"ok": true, "restarting": true}, nil
	case "backup.restore.cancel":
		e.CancelRestore()
		return map[string]any{"ok": true}, nil
	}
	return nil, fmt.Errorf("unknown command %q", cmd)
}

// backupDaemonRunning says whether a daemon answers on the control socket (a restore must not run beside one).
func backupDaemonRunning(sock string) bool {
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// ── the command line ─────────────────────────────────────────────────────────

func showBackupStatus(sock string) {
	raw := op(sock, "backup.status", nil)
	var v struct {
		Enabled   bool         `json:"enabled"`
		Running   bool         `json:"running"`
		PublicKey string       `json:"public_key"`
		Retry     int64        `json:"retry"`
		Status    BackupStatus `json:"status"`
		Targets   []struct {
			Label  string             `json:"label"`
			Host   string             `json:"host"`
			Status BackupTargetStatus `json:"status"`
		} `json:"targets"`
	}
	if json.Unmarshal(raw, &v) != nil {
		fmt.Println(string(raw))
		return
	}
	at := func(u int64) string {
		if u == 0 {
			return "never"
		}
		return time.Unix(u, 0).Format("2006-01-02 15:04:05")
	}
	fmt.Printf("Backups:       %s\n", map[bool]string{true: "scheduled (a \"Back up this node\" task in --schedule)", false: "not scheduled: add a task with the action backup (--schedule-set)"}[v.Enabled])
	if v.Running {
		fmt.Println("Running now:   yes")
	}
	fmt.Printf("Last started:  %s\nLast success:  %s\n", at(v.Status.LastStart), at(v.Status.LastOK))
	if v.Retry != 0 {
		fmt.Printf("Retry:         %s\n", at(v.Retry))
	}
	for _, t := range v.Targets {
		fmt.Printf("\nServer %s (%s)\n  last success: %s", t.Label, t.Host, at(t.Status.LastOK))
		if t.Status.LastFile != "" {
			fmt.Printf("  %s (%d bytes)", t.Status.LastFile, t.Status.LastSize)
		}
		fmt.Println()
		if t.Status.LastError != "" {
			fmt.Printf("  last error:   %s\n", t.Status.LastError)
		}
		if len(t.Status.Remote) > 0 {
			fmt.Printf("  on the server: %d (newest %s)\n", len(t.Status.Remote), t.Status.Remote[len(t.Status.Remote)-1])
		}
	}
	fmt.Printf("\nSSH key of this node (add it to authorized_keys on the backup servers, or use Install key on the Backup page):\n%s\n", v.PublicKey)
}

// runRestore is `--restore FILE`: it puts the contents of a backup in place of this node's state directory.
func runRestore(file, pwFile, stateDir, conf, sock string) error {
	if backupDaemonRunning(sock) {
		return errors.New("the service is running: stop it first (systemctl stop " + backupProduct + "), then restore, then start it again")
	}
	pw := ""
	switch {
	case pwFile != "":
		b, err := os.ReadFile(pwFile)
		if err != nil {
			return err
		}
		pw = strings.TrimRight(string(b), "\r\n")
	case os.Getenv(backupEnv+"_BACKUP_PASSWORD") != "":
		pw = os.Getenv(backupEnv + "_BACKUP_PASSWORD")
	default:
		fmt.Fprint(os.Stderr, "Backup password: ")
		tty := false
		if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			tty = true
			c := exec.Command("stty", "-echo")
			c.Stdin = os.Stdin
			_ = c.Run()
		}
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if tty {
			c := exec.Command("stty", "echo")
			c.Stdin = os.Stdin
			_ = c.Run()
			fmt.Fprintln(os.Stderr)
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	man, aside, err := restoreBackup(file, pw, stateDir, conf)
	if err != nil {
		return err
	}
	fmt.Printf("Restored the backup of %s (%s, v%s) into %s.\n", man.Node, man.Created, man.Version, stateDir)
	fmt.Printf("What was there before is in %s; delete it when you no longer need it.\n", aside)
	fmt.Printf("Start the service again: systemctl start %s\n", backupProduct)
	return nil
}

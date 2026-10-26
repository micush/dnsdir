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
	"hash/fnv"
	"io"
	"io/fs"
	"net"
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

// BackupConfig is the "backup" block of the shared settings (Configure ▸ Backup).
type BackupConfig struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`  // SSH port, 22 when empty
	User     string `json:"user,omitempty"`  // the account on the backup server
	Dir      string `json:"dir,omitempty"`   // the directory there; empty = the account's home
	Keep     int    `json:"keep,omitempty"`  // how many archives of each node to keep (14 when empty)
	Hours    int    `json:"hours,omitempty"` // 0: once a day at At; N: every N hours
	At       string `json:"at,omitempty"`    // HH:MM, this node's local time (02:30 when empty)
	Password string `json:"password,omitempty"`
}

func (c *BackupConfig) clone() *BackupConfig {
	if c == nil {
		return nil
	}
	d := *c
	return &d
}

var (
	backupHostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$|^[0-9A-Fa-f:]+$`)
	backupUserRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$`)
	backupDirRe  = regexp.MustCompile(`^[A-Za-z0-9._/~+@=,\-]+$`)
	backupAtRe   = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

func (c *BackupConfig) port() int {
	if c.Port == 0 {
		return 22
	}
	return c.Port
}

func (c *BackupConfig) keep() int {
	if c.Keep == 0 {
		return 14
	}
	return c.Keep
}

func (c *BackupConfig) at() string {
	if c.At == "" {
		return "02:30"
	}
	return c.At
}

// Validate cleans the block up and says what is wrong with it.
func (c *BackupConfig) Validate() error {
	c.Host, c.User, c.Dir, c.At = strings.TrimSpace(c.Host), strings.TrimSpace(c.User), strings.TrimSpace(c.Dir), strings.TrimSpace(c.At)
	if c.Host != "" && (len(c.Host) > 253 || !backupHostRe.MatchString(c.Host)) {
		return errors.New("backup: the server must be a host name or an address")
	}
	if c.User != "" && !backupUserRe.MatchString(c.User) {
		return errors.New("backup: the user name is not valid")
	}
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("backup: the port must be between 1 and 65535")
	}
	if c.Dir != "" {
		if len(c.Dir) > 255 || !backupDirRe.MatchString(c.Dir) || strings.Contains(c.Dir, "..") || strings.HasPrefix(c.Dir, "-") {
			return errors.New("backup: the directory may only have letters, digits and . _ / ~ + @ = , - and no ..")
		}
	}
	if c.Keep < 0 || c.Keep > 365 {
		return errors.New("backup: keep between 1 and 365 backups")
	}
	if c.Hours < 0 || c.Hours > 168 {
		return errors.New("backup: every 1 to 168 hours, or 0 for once a day")
	}
	if c.At != "" && !backupAtRe.MatchString(c.At) {
		return errors.New("backup: the time of day is HH:MM")
	}
	if len(c.Password) > 512 || hasControl(c.Password) {
		return errors.New("backup: the password is not valid")
	}
	if c.Enabled {
		switch {
		case c.Host == "":
			return errors.New("backup: say which server to back up to")
		case c.User == "":
			return errors.New("backup: say which user to log in as")
		case len(c.Password) < 8:
			return errors.New("backup: the password that encrypts the archives needs at least 8 characters")
		}
	}
	return nil
}

func (c *BackupConfig) empty() bool {
	return c == nil || *c == BackupConfig{}
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

// restoreBackup puts the contents of a backup file in place of the state directory's own: what the archive holds replaces
// what is there (the old versions are kept in a directory next to it), and what the archive leaves out (the log, staged
// upgrades) is left alone.  The daemon must not be running.
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
	aside := filepath.Join(parent, fmt.Sprintf("%s.before-restore-%s", filepath.Base(stateDir), time.Now().Format("20060102-150405")))
	if err := os.MkdirAll(aside, 0o700); err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, "", err
	}
	ents, _ := os.ReadDir(stage)
	for _, e := range ents {
		if e.Name() == strings.TrimSuffix(backupExternalConf, "/") {
			continue
		}
		dst := filepath.Join(stateDir, e.Name())
		if _, err := os.Lstat(dst); err == nil {
			if err := os.Rename(dst, filepath.Join(aside, e.Name())); err != nil {
				return nil, "", err
			}
		}
		if err := os.Rename(filepath.Join(stage, e.Name()), dst); err != nil {
			return nil, "", err
		}
	}
	if strings.HasPrefix(man.Conf, backupExternalConf) { // the configuration file was outside the state directory
		src := filepath.Join(stage, filepath.FromSlash(man.Conf))
		if _, err := os.Stat(src); err == nil {
			if _, err := os.Lstat(confFile); err == nil {
				_ = os.Rename(confFile, filepath.Join(aside, filepath.Base(confFile)))
			}
			if err := os.MkdirAll(filepath.Dir(confFile), 0o700); err != nil {
				return nil, "", err
			}
			if err := os.Rename(src, confFile); err != nil {
				return nil, "", err
			}
		}
	}
	return man, aside, nil
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

// backupSFTP runs a batch of sftp commands against the backup server and returns what sftp printed (replaceable in tests).
var backupSFTP = func(ctx context.Context, c *BackupConfig, dir string, script string) (string, error) {
	args := []string{"-b", "-", "-q",
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + filepath.Join(dir, "known_hosts"),
		"-o", "IdentityFile=" + filepath.Join(dir, "id_ed25519"), "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=20",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4", "-o", "PasswordAuthentication=no",
		"-P", fmt.Sprint(c.port()), c.User + "@" + c.Host}
	cmd := exec.CommandContext(ctx, envOr(backupEnv+"_SFTP", "sftp"), args...)
	cmd.Stdin = strings.NewReader(script)
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

// BackupStatus is what the page shows about this node's backups.
type BackupStatus struct {
	LastStart int64    `json:"last_start,omitempty"`
	LastOK    int64    `json:"last_ok,omitempty"`
	LastError string   `json:"last_error,omitempty"`
	LastFile  string   `json:"last_file,omitempty"`
	LastSize  int64    `json:"last_size,omitempty"`
	LastFiles int      `json:"last_files,omitempty"`
	LastSecs  float64  `json:"last_seconds,omitempty"`
	Remote    []string `json:"remote,omitempty"` // this node's archives on the server, oldest first, after the last run
	Pruned    int      `json:"pruned,omitempty"`
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
	jitter    time.Duration
	runCtx    context.Context
	onRunDone func()
}

func NewBackupEngine(stateDir, confFile, node string, cfg func() *BackupConfig) *BackupEngine {
	h := fnv.New32a()
	h.Write([]byte(node))
	e := &BackupEngine{dir: filepath.Join(stateDir, "backup"), stateDir: stateDir, confFile: confFile, node: node, cfg: cfg, now: time.Now,
		jitter: time.Duration(h.Sum32()%300) * time.Second, runCtx: context.Background()}
	if b, err := os.ReadFile(filepath.Join(e.dir, "status.json")); err == nil {
		_ = json.Unmarshal(b, &e.status)
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

func (e *BackupEngine) saveStatusLocked() {
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return
	}
	b, _ := json.Marshal(e.status)
	_ = os.WriteFile(filepath.Join(e.dir, "status.json"), b, 0o600)
}

// Status is the status for the page, with this node's public key.
func (e *BackupEngine) Status() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	pub, _ := os.ReadFile(filepath.Join(e.dir, "id_ed25519.pub"))
	c := e.cfg()
	out := map[string]any{"status": e.status, "running": e.running, "node": e.nodeName(), "public_key": strings.TrimSpace(string(pub)), "enabled": c != nil && c.Enabled}
	if c != nil && c.Enabled {
		if next := e.nextLocked(c); !next.IsZero() {
			out["next"] = next.Unix()
		}
	}
	return out
}

// Failing says whether the last attempt of an enabled backup failed (the alert rule).
func (e *BackupEngine) Failing() (failing, enabled bool, msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.cfg()
	if c == nil || !c.Enabled {
		return false, false, ""
	}
	return e.status.LastError != "" && !e.running, true, e.status.LastError
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

// nextLocked is when the next scheduled backup starts.
func (e *BackupEngine) nextLocked(c *BackupConfig) time.Time {
	now := e.now()
	last := time.Unix(e.status.LastStart, 0)
	if e.status.LastStart == 0 {
		return now
	}
	if e.status.LastError != "" {
		if t := last.Add(backupRetry); t.After(now) {
			return t
		}
		return now
	}
	if c.Hours > 0 {
		return last.Add(time.Duration(c.Hours) * time.Hour)
	}
	var hh, mm int
	fmt.Sscanf(c.at(), "%d:%d", &hh, &mm)
	t := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, now.Location()).Add(e.jitter)
	if t.After(now) { // today's time has not come: the one that counts is yesterday's
		t = t.AddDate(0, 0, -1)
	}
	if last.Before(t) {
		return now // missed it: now
	}
	return t.AddDate(0, 0, 1)
}

func (e *BackupEngine) due() bool {
	c := e.cfg()
	if c == nil || !c.Enabled || c.Validate() != nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.running && !e.nextLocked(c).After(e.now())
}

// Run starts the scheduled backups.
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
				if err := e.start(); err != nil {
					continue
				}
			}
		}
	}
}

// start begins a backup in the background.
func (e *BackupEngine) start() error {
	c := e.cfg()
	if c == nil || !c.Enabled {
		return errors.New("backups are not switched on")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("a backup is already running")
	}
	e.running = true
	e.status.LastStart = e.now().Unix()
	e.mu.Unlock()
	cc := *c
	go func() {
		err := e.backup(&cc)
		e.mu.Lock()
		e.running = false
		if err != nil {
			e.status.LastError = err.Error()
			warnf("backup: %v", err)
		} else {
			e.status.LastError = ""
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

// RunNow starts a backup now (the button).
func (e *BackupEngine) RunNow(actor string) error {
	if err := e.start(); err != nil {
		return err
	}
	infof("backup: started by %s", actor)
	return nil
}

// backup makes one archive, puts it on the server and removes the oldest ones there.
func (e *BackupEngine) backup(c *BackupConfig) error {
	began := e.now()
	if err := e.ensureKey(); err != nil {
		return err
	}
	work := filepath.Join(e.dir, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	name := e.fileName(began)
	local := filepath.Join(work, name)
	defer os.Remove(local)
	f, err := os.OpenFile(local, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	files, err := writeBackupArchive(f, c.Password, e.stateDir, e.confFile, e.nodeName(), began)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("packing the backup: %v", err)
	}
	fi, _ := os.Stat(local)
	ctx, cancel := context.WithTimeout(e.runCtx, backupTimeout)
	defer cancel()
	prefix := ""
	if c.Dir != "" {
		prefix = strings.TrimRight(c.Dir, "/") + "/"
		if c.Dir == "/" {
			prefix = "/"
		}
	}
	script := sftpMkdirs(c.Dir)
	script += "put " + sftpQuote(local) + " " + sftpQuote(prefix+name+".part") + "\n"
	script += "rename " + sftpQuote(prefix+name+".part") + " " + sftpQuote(prefix+name) + "\n"
	if _, err := backupSFTP(ctx, c, e.dir, script); err != nil {
		return fmt.Errorf("uploading to %s: %v", c.Host, err)
	}
	names, pruned, perr := e.prune(ctx, c, prefix)
	e.mu.Lock()
	e.status.LastOK, e.status.LastFile, e.status.LastFiles = e.now().Unix(), name, files
	if fi != nil {
		e.status.LastSize = fi.Size()
	}
	e.status.LastSecs = e.now().Sub(began).Seconds()
	e.status.Remote, e.status.Pruned = names, pruned
	e.mu.Unlock()
	if perr != nil {
		return fmt.Errorf("the backup was uploaded, but removing old ones failed: %v", perr)
	}
	infof("backup: %s uploaded to %s (%d files, %d bytes); %d old ones removed", name, c.Host, files, e.status.LastSize, pruned)
	return nil
}

// list returns this node's archives on the server, oldest first.
func (e *BackupEngine) list(ctx context.Context, c *BackupConfig) ([]string, error) {
	where := "."
	if c.Dir != "" {
		where = c.Dir
	}
	out, err := backupSFTP(ctx, c, e.dir, "ls -1 "+sftpQuote(where)+"\n")
	if err != nil {
		return nil, err
	}
	re := e.nameRe()
	var names []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "sftp>") {
			continue
		}
		if b := path.Base(l); re.MatchString(b) {
			names = append(names, b)
		}
	}
	sort.Strings(names)
	return names, nil
}

// prune removes this node's oldest archives beyond the number to keep, and returns the ones that are left.
func (e *BackupEngine) prune(ctx context.Context, c *BackupConfig, prefix string) (left []string, removed int, err error) {
	names, err := e.list(ctx, c)
	if err != nil {
		return nil, 0, err
	}
	if extra := len(names) - c.keep(); extra > 0 {
		script := ""
		for _, n := range names[:extra] {
			script += "-rm " + sftpQuote(prefix+n) + "\n"
		}
		if _, err := backupSFTP(ctx, c, e.dir, script); err != nil {
			return names, 0, err
		}
		removed, names = extra, names[extra:]
	}
	return names, removed, nil
}

// Test logs in to the server and lists the node's backups there; it makes the key when there is none.
func (e *BackupEngine) Test(c *BackupConfig) ([]string, error) {
	if c == nil || c.Host == "" || c.User == "" {
		return nil, errors.New("fill in the server and the user first")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if err := e.ensureKey(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	names, err := e.list(ctx, c)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.status.Remote = names
	e.saveStatusLocked()
	e.mu.Unlock()
	return names, nil
}

// ── the operations behind /api/backup ────────────────────────────────────────

func (m *Mgmt) backupOp(cmd string, raw json.RawMessage, actor string) (any, error) {
	e := m.backup
	if e == nil {
		return nil, errors.New("backups are not available on this node")
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
		names, err := e.Test(e.cfg())
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "remote": names}, nil
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
		Node      string       `json:"node"`
		PublicKey string       `json:"public_key"`
		Next      int64        `json:"next"`
		Status    BackupStatus `json:"status"`
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
	fmt.Printf("Backups:       %s\n", map[bool]string{true: "on", false: "off"}[v.Enabled])
	if v.Running {
		fmt.Println("Running now:   yes")
	}
	fmt.Printf("Last started:  %s\nLast success:  %s\n", at(v.Status.LastStart), at(v.Status.LastOK))
	if v.Status.LastFile != "" {
		fmt.Printf("Last file:     %s (%d files, %d bytes)\n", v.Status.LastFile, v.Status.LastFiles, v.Status.LastSize)
	}
	if v.Status.LastError != "" {
		fmt.Printf("Last error:    %s\n", v.Status.LastError)
	}
	if v.Next != 0 && v.Enabled {
		fmt.Printf("Next:          %s\n", at(v.Next))
	}
	if len(v.Status.Remote) > 0 {
		fmt.Printf("On the server: %d (newest %s)\n", len(v.Status.Remote), v.Status.Remote[len(v.Status.Remote)-1])
	}
	fmt.Printf("SSH key of this node (add it to authorized_keys on the backup server):\n%s\n", v.PublicKey)
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

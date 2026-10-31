package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The daemon's log goes to stderr (journald under systemd) and, so that the GUI and
// `dnsdir --log` can show and filter all of it, also to a size-rotated file in the state
// directory: dnsdir.log, plus dnsdir.log.1 and dnsdir.log.2 (the two previous files).

const (
	logFileName    = "dnsdir.log"
	logFileMax     = 100 << 20 // rotate when the current file reaches this size
	logFileKeep    = 2         // rotated files kept
	logReadMax     = 5000      // most lines one GUI request returns
	logReadDefault = 1000
)

// rotatingFile is an io.Writer that appends to path and rotates it by size.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	keep int
	f    *os.File
	size int64
}

func openRotatingFile(path string, max int64, keep int) (*rotatingFile, error) {
	r := &rotatingFile{path: path, max: max, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return len(p), nil
	}
	if r.size+int64(len(p)) > r.max && r.size > 0 {
		r.f.Close()
		for i := r.keep; i >= 1; i-- {
			from := r.path
			if i > 1 {
				from = fmt.Sprintf("%s.%d", r.path, i-1)
			}
			_ = os.Rename(from, fmt.Sprintf("%s.%d", r.path, i))
		}
		if err := r.open(); err != nil {
			r.f = nil
			return len(p), nil // logging must never break the daemon
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	if err != nil {
		return len(p), nil
	}
	return n, nil
}

// logDir is where ReadLog looks; set by startLogFile.
var logDir string

// startLogFile makes the default logger write to stderr and to the log file in dir.
// Without a writable dir it leaves logging on stderr only.
func startLogFile(dir string) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		warnf("log file: cannot create %s (%v); logging to stderr only", dir, err)
		return
	}
	rf, err := openRotatingFile(filepath.Join(dir, logFileName), logFileMax, logFileKeep)
	if err != nil {
		warnf("log file: cannot open it in %s (%v); logging to stderr only", dir, err)
		return
	}
	logDir = dir
	slog.SetDefault(slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, rf, sysSink), &slog.HandlerOptions{Level: logLevel})))
}

// LogQuery selects log lines.  Zero values mean "no filter"; Limit 0 means all.
type LogQuery struct {
	Level string        // minimum level: debug, info, warn, error
	Text  string        // words that must appear, joined by AND / OR (case-insensitive); plain words are AND
	Since time.Duration // only lines newer than now-Since
	Limit int           // newest N matching lines
}

// LogLine is one parsed log line.
type LogLine struct {
	Time  string `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
	Raw   string `json:"raw"`
}

// LogResult is the answer to a query.
type LogResult struct {
	Lines     []LogLine `json:"lines"`
	Matched   int       `json:"matched"`   // lines that matched before Limit cut them
	Truncated bool      `json:"truncated"` // Limit cut older matching lines
	Scanned   int       `json:"scanned"`   // lines read in all log files
	Oldest    string    `json:"oldest"`    // time of the oldest line kept on disk
	File      string    `json:"file"`
}

var logLineRe = regexp.MustCompile(`^time=(\S+) level=(\w+) msg=(.*)$`)

func levelRank(l string) int {
	switch strings.ToUpper(l) {
	case "DEBUG":
		return 0
	case "WARN", "WARNING":
		return 2
	case "ERROR":
		return 3
	}
	return 1
}

// parseLogLine splits a slog text line; a line that is not in that format (a panic
// trace, say) is kept as an INFO-level line of its own.
func parseLogLine(raw string) LogLine {
	m := logLineRe.FindStringSubmatch(raw)
	if m == nil {
		return LogLine{Level: "INFO", Msg: raw, Raw: raw}
	}
	msg := m[3]
	if u, err := strconv.Unquote(msg); err == nil {
		msg = u
	}
	return LogLine{Time: m[1], Level: strings.ToUpper(m[2]), Msg: msg, Raw: raw}
}

// ReadLog returns the lines of the log files that match q, oldest first.
//
// The files hold up to 300 MB (a busy node with policy logging on fills one in a few days), and the Log page asks again
// every few seconds, so the scan is kept cheap: a rotated file last written before the time range is not read line by
// line (its lines are only counted), the time of a line is read only until the first one inside the range (the lines
// are in time order), the level and time come from the line's start without the regular expression, a line is copied
// only when it matches, and only the lines kept (the newest Limit) are parsed.
func ReadLog(q LogQuery) (*LogResult, error) {
	if logDir == "" {
		return nil, fmt.Errorf("the log file is not available on this node (logging to stderr only)")
	}
	base := filepath.Join(logDir, logFileName)
	res := &LogResult{Lines: []LogLine{}, File: base}
	expr := parseMatch(q.Text)
	min := 0 // no level given: every line, debug included
	if q.Level != "" {
		min = levelRank(q.Level)
	}
	var cutoff time.Time
	if q.Since > 0 {
		cutoff = time.Now().Add(-q.Since)
	}
	// the newest matching lines, a ring of at most Limit (all of them when there is no limit)
	var keep []string
	head := 0
	add := func(raw string) {
		res.Matched++
		if q.Limit <= 0 || len(keep) < q.Limit {
			keep = append(keep, raw)
			return
		}
		keep[head] = raw
		head = (head + 1) % len(keep)
		res.Truncated = true
	}
	paths := []string{}
	for i := logFileKeep; i >= 1; i-- {
		paths = append(paths, fmt.Sprintf("%s.%d", base, i))
	}
	paths = append(paths, base)
	inRange := cutoff.IsZero() // once a line is inside the time range, so is every later one
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		if st, err := f.Stat(); err == nil && !inRange && st.ModTime().Before(cutoff) {
			// written to last before the range began: nothing in it can match; count its lines, and take its first time
			// for Oldest
			n, first := countLines(f)
			res.Scanned += n
			if res.Oldest == "" {
				res.Oldest = first
			}
			f.Close()
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			raw := sc.Bytes()
			if len(raw) == 0 {
				continue
			}
			res.Scanned++
			ts, lvl := logHead(raw)
			if res.Oldest == "" && ts != nil {
				res.Oldest = string(ts)
			}
			if levelRankBytes(lvl) < min {
				continue
			}
			if !inRange && ts != nil {
				if t, err := time.Parse(time.RFC3339Nano, string(ts)); err == nil {
					if t.Before(cutoff) {
						continue
					}
					inRange = true
				}
			}
			if len(expr) > 0 && !logMatches(expr, strings.ToLower(string(raw))) {
				continue
			}
			add(string(raw))
		}
		f.Close()
	}
	if len(keep) > 0 {
		res.Lines = make([]LogLine, 0, len(keep))
		for i := range keep {
			res.Lines = append(res.Lines, parseLogLine(keep[(head+i)%len(keep)]))
		}
	}
	return res, nil
}

// logHead reads the time and level at the start of a slog text line ("time=T level=L msg=..."); nil for a line in another
// format (its level counts as INFO, and it has no time).
func logHead(raw []byte) (ts, lvl []byte) {
	if !bytes.HasPrefix(raw, []byte("time=")) {
		return nil, nil
	}
	rest := raw[len("time="):]
	sp := bytes.IndexByte(rest, ' ')
	if sp <= 0 || !bytes.HasPrefix(rest[sp:], []byte(" level=")) {
		return nil, nil
	}
	ts, rest = rest[:sp], rest[sp+len(" level="):]
	if e := bytes.IndexByte(rest, ' '); e >= 0 {
		rest = rest[:e]
	}
	return ts, rest
}

// levelRankBytes is levelRank without making a string.
func levelRankBytes(l []byte) int {
	switch {
	case bytes.EqualFold(l, []byte("DEBUG")):
		return 0
	case bytes.EqualFold(l, []byte("WARN")), bytes.EqualFold(l, []byte("WARNING")):
		return 2
	case bytes.EqualFold(l, []byte("ERROR")):
		return 3
	}
	return 1
}

// countLines counts the non-empty lines of a file without parsing them, and gives the time of the first one that has one.
func countLines(f *os.File) (n int, first string) {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if b := sc.Bytes(); len(b) > 0 {
			n++
			if first == "" {
				if ts, _ := logHead(b); ts != nil {
					first = string(ts)
				}
			}
		}
	}
	return n, first
}

// parseSince reads "15m", "6h", "2d" or plain seconds; empty or "all" is no limit.
func parseSince(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "all" || s == "0" {
		return 0, nil
	}
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return time.Duration(n) * time.Second, nil
	}
	if strings.HasSuffix(s, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q is not a time span: use 15m, 6h, 2d or seconds", s)
	}
	return d, nil
}

// logQueryFromArgs builds a query from the string arguments of the API and CLI.
func logQueryFromArgs(level, text, since, n string) (LogQuery, error) {
	q := LogQuery{Level: level, Text: text}
	d, err := parseSince(since)
	if err != nil {
		return q, err
	}
	q.Since = d
	if n == "" {
		q.Limit = logReadDefault
	} else {
		v, err := strconv.Atoi(n)
		if err != nil || v < 0 {
			return q, fmt.Errorf("%q is not a line count", n)
		}
		q.Limit = v
	}
	return q, nil
}

// logMatches says whether a (lower-case) log line satisfies the filter: one of the OR alternatives must have all its AND
// terms, and every word of a term must appear in the line (so plain words with no operator are all required, in any order).
func logMatches(e matchExpr, line string) bool {
	for _, group := range e {
		all := true
		for _, term := range group {
			for _, w := range strings.Fields(term) {
				if !strings.Contains(line, w) {
					all = false
					break
				}
			}
			if !all {
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

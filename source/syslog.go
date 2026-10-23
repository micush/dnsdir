package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Forwarding the daemon's log to a syslog server (Configure ▸ Settings ▸ Logs).
//
// The sink is one more writer behind the logger, next to stderr and the log file.  Every line the logger
// writes is turned into a syslog message and put on a bounded queue; a sender goroutine takes it from there
// and writes it to the server over UDP, TCP or TLS.  A slow or dead server therefore never holds up the
// daemon: when the queue is full the oldest message is dropped and counted.
//
// The setting is per node (never replicated): each node sends its own log.

const (
	syslogQueueMax   = 2000
	syslogDialWait   = 5 * time.Second
	syslogWriteWait  = 5 * time.Second
	syslogBackoffMin = time.Second
	syslogBackoffMax = 30 * time.Second
)

// SyslogConfig is this node's syslog forwarding.  A pointer in DaemonConfig with omitempty, so a config that never used
// it has no "syslog" key and older versions still read it.
type SyslogConfig struct {
	Enabled  bool   `json:"enabled"`
	Protocol string `json:"protocol,omitempty"`     // tcp (default), udp or tls
	Server   string `json:"server,omitempty"`       // host or host:port; the port defaults to 514 (6514 for tls)
	Facility string `json:"facility,omitempty"`     // daemon (default), local0..local7, …
	Format   string `json:"format,omitempty"`       // rfc5424 (default) or rfc3164
	CAFile   string `json:"ca_file,omitempty"`      // tls: PEM file of the CA that signed the server's certificate (default: the system's)
	Insecure bool   `json:"tls_insecure,omitempty"` // tls: do not check the server's certificate
}

var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
	"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

func (c *SyslogConfig) clone() *SyslogConfig {
	if c == nil {
		return nil
	}
	n := *c
	return &n
}

func (c *SyslogConfig) protocol() string {
	if p := strings.ToLower(strings.TrimSpace(c.Protocol)); p != "" {
		return p
	}
	return "tcp"
}

func (c *SyslogConfig) format() string {
	if f := strings.ToLower(strings.TrimSpace(c.Format)); f != "" {
		return f
	}
	return "rfc5424"
}

func (c *SyslogConfig) facility() int {
	if f, ok := syslogFacilities[strings.ToLower(strings.TrimSpace(c.Facility))]; ok {
		return f
	}
	return syslogFacilities["daemon"]
}

// address is host:port with the default port added.
func (c *SyslogConfig) address() (host, addr string, err error) {
	s := strings.TrimSpace(c.Server)
	if s == "" {
		return "", "", errors.New("syslog: the server is empty")
	}
	def := "514"
	if c.protocol() == "tls" {
		def = "6514"
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil { // no port (a bare host, or a bare IPv6 address)
		h, p = strings.Trim(s, "[]"), def
	}
	if h == "" || strings.ContainsAny(h, " \t/") {
		return "", "", fmt.Errorf("syslog: %q is not a host name or address", s)
	}
	if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("syslog: %q is not a port", p)
	}
	return h, net.JoinHostPort(h, p), nil
}

// Validate checks the fields that are filled in; the server is required only while forwarding is on.
func (c *SyslogConfig) Validate() error {
	if c == nil {
		return nil
	}
	switch c.protocol() {
	case "udp", "tcp", "tls":
	default:
		return fmt.Errorf("syslog: protocol %q must be udp, tcp or tls", c.Protocol)
	}
	switch c.format() {
	case "rfc5424", "rfc3164":
	default:
		return fmt.Errorf("syslog: format %q must be rfc5424 or rfc3164", c.Format)
	}
	if f := strings.ToLower(strings.TrimSpace(c.Facility)); f != "" {
		if _, ok := syslogFacilities[f]; !ok {
			return fmt.Errorf("syslog: facility %q is not one of the standard names (daemon, local0 … local7, …)", c.Facility)
		}
	}
	if c.Enabled || strings.TrimSpace(c.Server) != "" {
		if _, _, err := c.address(); err != nil {
			return err
		}
	}
	if strings.ContainsAny(c.CAFile, "\n\r\x00") {
		return errors.New("syslog: the CA file name is not valid")
	}
	return nil
}

// empty reports whether the settings carry nothing worth keeping.
func (c *SyslogConfig) empty() bool {
	return c == nil || (!c.Enabled && strings.TrimSpace(c.Server) == "" && c.Protocol == "" && c.Facility == "" && c.Format == "" && c.CAFile == "" && !c.Insecure)
}

// SyslogStatus is what the Logs tab shows under the settings.
type SyslogStatus struct {
	Enabled   bool   `json:"enabled"`
	Address   string `json:"address,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Connected bool   `json:"connected"` // UDP is "connected" once a message went out without an error
	Sent      int64  `json:"sent"`
	Dropped   int64  `json:"dropped"`
	Queued    int    `json:"queued"`
	LastError string `json:"last_error,omitempty"`
	LastSent  string `json:"last_sent,omitempty"`
}

type syslogSink struct {
	on atomic.Bool // forwarding is running: Write is a no-op while it is not

	mu      sync.Mutex
	cfg     *SyslogConfig
	q       chan []byte
	stop    chan struct{}
	done    chan struct{}
	host    string
	app     string
	pid     int
	addr    string
	sent    int64
	dropped int64
	lastErr string
	lastOK  time.Time
	conn    bool
}

var sysSink = &syslogSink{}

func (s *syslogSink) appName() string { return strings.TrimSuffix(logFileName, ".log") }

// Apply starts, restarts or stops forwarding to match c.  An unchanged setting does nothing (no reconnect).
func (s *syslogSink) Apply(c *SyslogConfig) {
	s.mu.Lock()
	if c.empty() || !c.Enabled || c.Validate() != nil {
		old := s.stopLocked()
		s.cfg = c.clone()
		s.mu.Unlock()
		if old != nil {
			<-old
		}
		return
	}
	if s.cfg != nil && *s.cfg == *c && s.stop != nil {
		s.mu.Unlock()
		return
	}
	old := s.stopLocked()
	if old != nil {
		s.mu.Unlock()
		<-old
		s.mu.Lock()
	}
	s.cfg = c.clone()
	_, s.addr, _ = c.address()
	s.host, _ = os.Hostname()
	if s.host == "" {
		s.host = "-"
	}
	s.app, s.pid = s.appName(), os.Getpid()
	s.sent, s.lastErr, s.conn, s.lastOK = 0, "", false, time.Time{}
	atomic.StoreInt64(&s.dropped, 0)
	s.q = make(chan []byte, syslogQueueMax)
	s.stop, s.done = make(chan struct{}), make(chan struct{})
	cfg, q, stop, done := *s.cfg, s.q, s.stop, s.done
	s.on.Store(true)
	s.mu.Unlock()
	go s.run(cfg, q, stop, done)
}

// stopLocked asks the sender to stop; the returned channel closes when it has.  s.mu is held.
func (s *syslogSink) stopLocked() <-chan struct{} {
	s.on.Store(false)
	if s.stop == nil {
		return nil
	}
	close(s.stop)
	done := s.done
	s.stop, s.done, s.q = nil, nil, nil
	s.conn = false
	return done
}

// Write is the logger's writer: one call per log line.
func (s *syslogSink) Write(p []byte) (int, error) {
	if !s.on.Load() {
		return len(p), nil
	}
	line := strings.TrimRight(string(p), "\r\n")
	s.mu.Lock()
	q, cfg := s.q, s.cfg
	host, app, pid := s.host, s.app, s.pid
	s.mu.Unlock()
	if q == nil || cfg == nil {
		return len(p), nil
	}
	msg := formatSyslog(cfg, host, app, pid, line, time.Now())
	for {
		select {
		case q <- msg:
			return len(p), nil
		default:
			select {
			case <-q: // full: the oldest goes
				atomic.AddInt64(&s.dropped, 1)
			default:
			}
		}
	}
}

// formatSyslog turns one log line (time=… level=… msg=…) into a syslog message.
func formatSyslog(c *SyslogConfig, host, app string, pid int, line string, now time.Time) []byte {
	sev, ts, text := 6, now, line
	if m := logLineRe.FindStringSubmatch(line); m != nil {
		if t, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
			ts = t
		}
		switch strings.ToUpper(m[2]) {
		case "DEBUG":
			sev = 7
		case "WARN", "WARNING":
			sev = 4
		case "ERROR":
			sev = 3
		}
		text = strings.TrimPrefix(line, "time="+m[1]+" ") // the time is in the header already
	}
	text = strings.NewReplacer("\r", " ", "\n", " ").Replace(text)
	pri := c.facility()*8 + sev
	if c.format() == "rfc3164" {
		return []byte(fmt.Sprintf("<%d>%s %s %s[%d]: %s", pri, ts.Local().Format(time.Stamp), host, app, pid, text))
	}
	return []byte(fmt.Sprintf("<%d>1 %s %s %s %d - - %s", pri, ts.UTC().Format("2006-01-02T15:04:05.000Z"), host, app, pid, text))
}

// frame is how a message goes on the wire: a datagram as it is; on a stream, RFC 6587 octet counting for RFC 5424 and a
// line for RFC 3164.
func syslogFrame(c *SyslogConfig, msg []byte) []byte {
	if c.protocol() == "udp" {
		return msg
	}
	if c.format() == "rfc3164" {
		return append(append([]byte{}, msg...), '\n')
	}
	return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
}

func (s *syslogSink) dial(c SyslogConfig) (net.Conn, error) {
	host, addr, err := c.address()
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: syslogDialWait}
	switch c.protocol() {
	case "udp":
		return d.Dial("udp", addr)
	case "tls":
		tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.Insecure}
		if f := strings.TrimSpace(c.CAFile); f != "" {
			pem, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("syslog: CA file: %v", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("syslog: %s holds no certificate", f)
			}
			tc.RootCAs = pool
		}
		return tls.DialWithDialer(d, "tcp", addr, tc)
	}
	return d.Dial("tcp", addr)
}

func (s *syslogSink) note(err error, sent bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr, s.conn = err.Error(), false
		return
	}
	s.lastErr, s.conn = "", true
	if sent {
		s.sent++
		s.lastOK = time.Now()
	}
}

func (s *syslogSink) run(c SyslogConfig, q chan []byte, stop, done chan struct{}) {
	defer close(done)
	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	backoff := syslogBackoffMin
	var pending []byte
	for {
		if conn == nil { // connect first, so the state is known before the first message
			cn, err := s.dial(c)
			if err != nil {
				s.note(err, false)
				select {
				case <-stop:
					return
				case <-time.After(backoff):
				}
				if backoff *= 2; backoff > syslogBackoffMax {
					backoff = syslogBackoffMax
				}
				continue
			}
			conn, backoff = cn, syslogBackoffMin
			s.note(nil, false)
		}
		if pending == nil {
			select {
			case <-stop:
				return
			case pending = <-q:
			}
		}
		conn.SetWriteDeadline(time.Now().Add(syslogWriteWait))
		if _, err := conn.Write(syslogFrame(&c, pending)); err != nil {
			s.note(err, false)
			conn.Close()
			conn = nil
			if c.protocol() == "udp" {
				pending = nil // a datagram is not worth a retry
			}
			continue
		}
		s.note(nil, true)
		pending = nil
	}
}

// Status is the state of forwarding for the GUI and the CLI.
func (s *syslogSink) Status() SyslogStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := SyslogStatus{Enabled: s.stop != nil, Sent: s.sent, Dropped: atomic.LoadInt64(&s.dropped), Connected: s.conn, LastError: s.lastErr}
	if s.cfg != nil {
		st.Protocol = s.cfg.protocol()
		st.Address = s.addr
		if st.Address == "" {
			_, st.Address, _ = s.cfg.address()
		}
	}
	if s.q != nil {
		st.Queued = len(s.q)
	}
	if !s.lastOK.IsZero() {
		st.LastSent = s.lastOK.Format(time.RFC3339)
	}
	return st
}

// SendTest logs a message that goes everywhere the log goes and waits briefly to see whether it reached the server.
func (s *syslogSink) SendTest(actor string) (SyslogStatus, error) {
	if !s.on.Load() {
		return s.Status(), errors.New("syslog forwarding is off: turn it on and fill in the server first")
	}
	before := s.Status().Sent
	infof("syslog: test message (sent by %s)", actor)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if st := s.Status(); st.Sent > before {
			return st, nil
		} else if st.LastError != "" {
			return st, errors.New(st.LastError)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return s.Status(), errors.New("the message is queued but has not been delivered yet")
}

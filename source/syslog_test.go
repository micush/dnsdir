package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSyslogValidate(t *testing.T) {
	ok := []SyslogConfig{
		{},
		{Enabled: true, Server: "10.0.0.5"},
		{Enabled: true, Server: "log.example.com:6514", Protocol: "TLS", Facility: "local3", Format: "rfc3164"},
		{Enabled: true, Server: "[2001:db8::1]:514", Protocol: "udp"},
		{Enabled: true, Server: "2001:db8::1"},
		{Server: "kept.example.com"}, // off, but the server is kept
	}
	for _, c := range ok {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := []SyslogConfig{
		{Enabled: true},
		{Enabled: true, Server: "a b"},
		{Enabled: true, Server: "h:99999"},
		{Enabled: true, Server: "h", Protocol: "sctp"},
		{Enabled: true, Server: "h", Facility: "bogus"},
		{Enabled: true, Server: "h", Format: "json"},
	}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v should not validate", c)
		}
	}
	c := SyslogConfig{Server: "h", Protocol: "tls"}
	if _, a, _ := c.address(); a != "h:6514" {
		t.Errorf("tls default port: %s", a)
	}
	c.Protocol = ""
	if _, a, _ := c.address(); a != "h:514" {
		t.Errorf("default port: %s", a)
	}
	if _, a, _ := (&SyslogConfig{Server: "2001:db8::1"}).address(); a != "[2001:db8::1]:514" {
		t.Errorf("bare v6: %s", a)
	}
}

func TestSyslogFormat(t *testing.T) {
	now := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)
	line := `time=2026-10-23T07:59:58.123456789Z level=WARN msg="dns: server A is DOWN" gw=1`
	m := string(formatSyslog(&SyslogConfig{Facility: "local0"}, "h1", "dnsdir", 42, line, now))
	if want := `<132>1 2026-10-23T07:59:58.123Z h1 dnsdir 42 - - level=WARN msg="dns: server A is DOWN" gw=1`; m != want {
		t.Fatalf("5424:\n got %s\nwant %s", m, want)
	}
	m = string(formatSyslog(&SyslogConfig{Format: "rfc3164"}, "h1", "dnsdir", 42, `time=2026-10-23T07:59:58Z level=ERROR msg=boom`, now))
	if !strings.HasPrefix(m, "<27>") || !strings.Contains(m, " h1 dnsdir[42]: level=ERROR msg=boom") { // daemon.err = 3*8+3
		t.Fatalf("3164: %s", m)
	}
	if m := string(formatSyslog(&SyslogConfig{}, "h", "a", 1, "stray\ncontinuation", now)); !strings.HasPrefix(m, "<30>1 ") || strings.Contains(m, "\n") {
		t.Fatalf("a line without a time is info and one line: %q", m)
	}
	if m := string(formatSyslog(&SyslogConfig{}, "h", "a", 1, `time=2026-10-23T07:59:58Z level=DEBUG msg=x`, now)); !strings.HasPrefix(m, "<31>") {
		t.Fatalf("debug: %s", m)
	}
	f := syslogFrame(&SyslogConfig{Protocol: "tcp"}, []byte("<14>1 abc"))
	if string(f) != "9 <14>1 abc" {
		t.Fatalf("octet counting: %q", f)
	}
	if f := syslogFrame(&SyslogConfig{Protocol: "tcp", Format: "rfc3164"}, []byte("x")); string(f) != "x\n" {
		t.Fatalf("newline framing: %q", f)
	}
	if f := syslogFrame(&SyslogConfig{Protocol: "udp"}, []byte("x")); string(f) != "x" {
		t.Fatalf("datagram: %q", f)
	}
}

func waitSent(t *testing.T, s *syslogSink, n int64) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if s.Status().Sent >= n {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("not delivered: %+v", s.Status())
}

func TestSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	s := &syslogSink{}
	defer s.Apply(nil)
	s.Apply(&SyslogConfig{Enabled: true, Protocol: "udp", Server: pc.LocalAddr().String()})
	s.Write([]byte("time=2026-10-23T07:59:58Z level=INFO msg=hello\n"))
	buf := make([]byte, 2048)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "<30>1 2026-10-23T07:59:58.000Z ") || !strings.HasSuffix(string(buf[:n]), "level=INFO msg=hello") {
		t.Fatalf("%v %q", err, buf[:n])
	}
	waitSent(t, s, 1)
	if st := s.Status(); !st.Enabled || !st.Connected || st.Protocol != "udp" {
		t.Fatalf("%+v", st)
	}
	// turning it off stops sending and Write becomes a no-op
	s.Apply(&SyslogConfig{Enabled: false, Server: pc.LocalAddr().String()})
	if s.Status().Enabled {
		t.Fatal("still on")
	}
	s.Write([]byte("time=2026-10-23T07:59:59Z level=INFO msg=silent\n"))
	pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatalf("sent while off: %q", buf[:n])
	}
}

func readFramed(t *testing.T, c net.Conn) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	l, err := r.ReadString(' ')
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(l))
	if err != nil {
		t.Fatalf("no octet count: %q", l)
	}
	b := make([]byte, n)
	for i := 0; i < n; {
		m, err := r.Read(b[i:])
		if err != nil {
			t.Fatal(err)
		}
		i += m
	}
	return string(b)
}

func TestSyslogTCPReconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	s := &syslogSink{}
	defer s.Apply(nil)
	s.Apply(&SyslogConfig{Enabled: true, Server: ln.Addr().String()})
	s.Write([]byte("time=2026-10-23T07:59:58Z level=ERROR msg=one\n"))
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if m := readFramed(t, c); !strings.HasPrefix(m, "<27>1 ") || !strings.HasSuffix(m, "msg=one") {
		t.Fatalf("%q", m)
	}
	c.Close()
	// the next messages find the connection gone and go over a new one
	for i := 0; i < 20; i++ {
		s.Write([]byte("time=2026-10-23T07:59:58Z level=INFO msg=two\n"))
		time.Sleep(20 * time.Millisecond)
	}
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	c2, err := ln.Accept()
	if err != nil {
		t.Fatalf("no reconnect: %v (%+v)", err, s.Status())
	}
	defer c2.Close()
	if m := readFramed(t, c2); !strings.HasSuffix(m, "msg=two") {
		t.Fatalf("%q", m)
	}
}

func TestSyslogDropsOldestWhenFull(t *testing.T) {
	s := &syslogSink{}
	defer s.Apply(nil)
	// nothing listens: the sender keeps retrying, the queue fills and the oldest go
	s.Apply(&SyslogConfig{Enabled: true, Server: "127.0.0.1:1"})
	for i := 0; i < syslogQueueMax+50; i++ {
		s.Write([]byte("time=2026-10-23T07:59:58Z level=INFO msg=x\n"))
	}
	st := s.Status()
	if st.Dropped < 40 || st.Queued > syslogQueueMax {
		t.Fatalf("%+v", st)
	}
}

func TestSyslogTLS(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	got := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					l, err := r.ReadString(' ')
					if err != nil {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(l))
					b := make([]byte, n)
					for i := 0; i < n; {
						m, err := r.Read(b[i:])
						if err != nil {
							return
						}
						i += m
					}
					got <- string(b)
				}
			}()
		}
	}()
	addr := ln.Addr().String()
	s := &syslogSink{}
	defer s.Apply(nil)

	// the server's certificate is not trusted: no delivery, and the error says why
	s.Apply(&SyslogConfig{Enabled: true, Protocol: "tls", Server: addr})
	s.Write([]byte("time=2026-10-23T07:59:58Z level=INFO msg=untrusted\n"))
	time.Sleep(400 * time.Millisecond)
	if st := s.Status(); st.Sent != 0 || !strings.Contains(st.LastError, "certificate") {
		t.Fatalf("an untrusted certificate must not be used: %+v", st)
	}
	// trusting its CA
	s.Apply(&SyslogConfig{Enabled: true, Protocol: "tls", Server: addr, CAFile: ca})
	s.Write([]byte("time=2026-10-23T07:59:58Z level=INFO msg=trusted\n"))
	select {
	case m := <-got:
		if !strings.HasSuffix(m, "msg=trusted") {
			t.Fatalf("%q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("not delivered: %+v", s.Status())
	}
	// or skipping the check
	s.Apply(&SyslogConfig{Enabled: true, Protocol: "tls", Server: addr, Insecure: true})
	s.Write([]byte("time=2026-10-23T07:59:58Z level=INFO msg=insecure\n"))
	select {
	case m := <-got:
		if !strings.HasSuffix(m, "msg=insecure") {
			t.Fatalf("%q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("not delivered: %+v", s.Status())
	}
}

func TestSyslogSendTest(t *testing.T) {
	s := &syslogSink{}
	if _, err := s.SendTest("x"); err == nil {
		t.Fatal("a test while off must say so")
	}
}

func TestSyslogConfigRoundTrip(t *testing.T) {
	dc := newDaemonConfig()
	if b, _ := json.Marshal(dc); strings.Contains(string(b), "syslog") {
		t.Fatalf("an unused setting must leave no key: %s", b)
	}
	dc.Syslog = &SyslogConfig{}
	if err := dc.Validate(); err != nil || dc.Syslog != nil {
		t.Fatalf("empty settings are dropped: %v %+v", err, dc.Syslog)
	}
	dc.Syslog = &SyslogConfig{Enabled: true}
	if err := dc.Validate(); err == nil {
		t.Fatal("on without a server must not validate")
	}
	dc.Syslog = &SyslogConfig{Enabled: true, Server: "h", Protocol: "udp"}
	if err := dc.Validate(); err != nil {
		t.Fatal(err)
	}
}

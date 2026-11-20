package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DNS registration (Configure ▸ Settings ▸ DNS): this node puts its own interface addresses into DNS with RFC 2136 dynamic
// updates, the way the autoregdns script did.
//
//	hostname.domain           the node's first address of each family (A and AAAA)
//	hostname-interface.domain every address of that interface
//	PTR                       each address points back at the first of its names
//
// The zone's primary server comes from the SOA record (or from the setting), the updates go over TCP and are signed with a TSIG
// key when there is one.  The loop checks the records every interval (plus up to 30 % of jitter, so a rack of nodes does not
// all ask in the same second) and only sends an update for a record that is wrong or missing.
//
// The setting is per node (never replicated): every node registers its own addresses.  The shared addresses of the gateways
// (VIPs, anycast) are never registered: they move between nodes and are not any one node's.

const (
	dnsRegDefaultInterval = 300
	dnsRegDefaultTTL      = 900
	dnsRegJitter          = 0.30
	dnsRegWait            = 5 * time.Second
	dnsRegMaxRecords      = 200 // records kept in the status
)

// DNSRegConfig is this node's DNS registration.  A pointer in DaemonConfig with omitempty: a config that never used it has no
// "dns_register" key and older versions still read it.
type DNSRegConfig struct {
	Enabled  bool     `json:"enabled"`
	Key      string   `json:"key,omitempty"`             // TSIG key: a BIND key file, or name:base64secret[:algorithm]
	Domain   string   `json:"domain,omitempty"`          // default: the first search domain of /etc/resolv.conf
	Server   string   `json:"server,omitempty"`          // the server that takes the updates; default: the primary of the zone's SOA
	Interval int      `json:"interval_sec,omitempty"`    // seconds between checks (default 300)
	TTL      int      `json:"ttl,omitempty"`             // seconds (default 900)
	Skip     []string `json:"skip_interfaces,omitempty"` // interface names (patterns like "docker*") left out
}

func (c *DNSRegConfig) clone() *DNSRegConfig {
	if c == nil {
		return nil
	}
	n := *c
	n.Skip = append([]string(nil), c.Skip...)
	return &n
}

func (c *DNSRegConfig) interval() time.Duration {
	if c.Interval > 0 {
		return time.Duration(c.Interval) * time.Second
	}
	return dnsRegDefaultInterval * time.Second
}

func (c *DNSRegConfig) ttl() uint32 {
	if c.TTL > 0 {
		return uint32(c.TTL)
	}
	return dnsRegDefaultTTL
}

func (c *DNSRegConfig) same(o *DNSRegConfig) bool {
	if c == nil || o == nil {
		return c == o
	}
	if c.Enabled != o.Enabled || c.Key != o.Key || c.Domain != o.Domain || c.Server != o.Server || c.Interval != o.Interval || c.TTL != o.TTL || len(c.Skip) != len(o.Skip) {
		return false
	}
	for i := range c.Skip {
		if c.Skip[i] != o.Skip[i] {
			return false
		}
	}
	return true
}

var dnsLabelRe = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

// validDNSName reports whether s is a host or domain name (no trailing dot, labels of letters, digits, '-' and '_').
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !dnsLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// Validate checks the fields that are filled in.
func (c *DNSRegConfig) Validate() error {
	if c == nil {
		return nil
	}
	if d := strings.TrimSuffix(strings.TrimSpace(c.Domain), "."); d != "" && !validDNSName(d) {
		return fmt.Errorf("dns_register: %q is not a domain name", c.Domain)
	}
	if s := strings.TrimSpace(c.Server); s != "" {
		h, _, err := net.SplitHostPort(s)
		if err != nil {
			h = strings.Trim(s, "[]")
		}
		if _, err := netip.ParseAddr(h); err != nil && !validDNSName(h) {
			return fmt.Errorf("dns_register: %q is not a server name or address", c.Server)
		}
	}
	if c.Interval != 0 && (c.Interval < 30 || c.Interval > 86400) {
		return errors.New("dns_register: the interval must be between 30 and 86400 seconds")
	}
	if c.TTL != 0 && (c.TTL < 1 || c.TTL > 604800) {
		return errors.New("dns_register: the TTL must be between 1 and 604800 seconds")
	}
	for _, p := range c.Skip {
		if _, err := path.Match(p, "x"); err != nil || strings.TrimSpace(p) == "" || len(p) > 64 {
			return fmt.Errorf("dns_register: %q is not an interface name pattern", p)
		}
	}
	if k := strings.TrimSpace(c.Key); k != "" {
		if strings.ContainsAny(k, "\r\n\x00") {
			return errors.New("dns_register: the key is not valid")
		}
		if st, err := os.Stat(k); err != nil || st.IsDir() { // not a file: it has to be name:secret[:algorithm]
			if _, err := parseTSIGSpec(k); err != nil {
				return fmt.Errorf("dns_register: the key must be the path of a BIND key file or name:base64secret[:algorithm] (%v)", err)
			}
		}
	}
	return nil
}

// empty reports whether the settings carry nothing worth keeping.
func (c *DNSRegConfig) empty() bool {
	return c == nil || (!c.Enabled && c.Key == "" && c.Domain == "" && c.Server == "" && c.Interval == 0 && c.TTL == 0 && len(c.Skip) == 0)
}

// ─── DNS wire format ────────────────────────────────────────────────────────────

const (
	dnsTypeA    = 1
	dnsTypeSOA  = 6
	dnsTypePTR  = 12
	dnsTypeAAAA = 28
	dnsTypeTSIG = 250
	dnsTypeANY  = 255
	dnsClassIN  = 1
	dnsClassANY = 255
	dnsOpUpdate = 5
)

var dnsRcodeNames = map[int]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}

// regWireName is a domain name in wire format, without compression.
func regWireName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > 253 {
		return nil, fmt.Errorf("%q is too long for a domain name", name)
	}
	var b []byte
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return nil, fmt.Errorf("%q is not a domain name", name)
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0), nil
}

// dnsReadName reads a (possibly compressed) name at off; it returns the name without the trailing dot and the offset after it.
func dnsReadName(msg []byte, off int) (string, int, error) {
	var labels []string
	end, jumps, total := -1, 0, 0
	for {
		if off >= len(msg) {
			return "", 0, errors.New("short DNS message")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("short DNS message")
			}
			if end < 0 {
				end = off + 2
			}
			if jumps++; jumps > 20 {
				return "", 0, errors.New("DNS name loops")
			}
			off = (l&0x3F)<<8 | int(msg[off+1])
		case l&0xC0 != 0:
			return "", 0, errors.New("bad DNS label")
		default:
			if off+1+l > len(msg) {
				return "", 0, errors.New("short DNS message")
			}
			if total += l + 1; total > 255 {
				return "", 0, errors.New("DNS name too long")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

func dnsRandID() uint16 {
	n, err := rand.Int(rand.Reader, big.NewInt(65536))
	if err != nil {
		return uint16(time.Now().UnixNano())
	}
	return uint16(n.Int64())
}

// dnsBuildQuery is a standard query for name/qtype with recursion desired.
func dnsBuildQuery(name string, qtype uint16) (uint16, []byte, error) {
	w, err := regWireName(name)
	if err != nil {
		return 0, nil, err
	}
	id := dnsRandID()
	b := make([]byte, 12, 12+len(w)+4)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x0100)
	binary.BigEndian.PutUint16(b[4:], 1)
	b = append(b, w...)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, dnsClassIN)
	return id, b, nil
}

// regRR is one record of an answer; Data is the address (A, AAAA) or the target name (PTR, SOA primary).
type regRR struct {
	Name string
	Type uint16
	TTL  uint32
	Data string
}

type regReply struct {
	ID        uint16
	Rcode     int
	Truncated bool
	Answers   []regRR
	Authority []regRR
}

// dnsParseReply reads the header, the answers and the authority section of a reply.
func dnsParseReply(msg []byte) (*regReply, error) {
	if len(msg) < 12 {
		return nil, errors.New("short DNS reply")
	}
	r := &regReply{ID: binary.BigEndian.Uint16(msg), Rcode: int(msg[3] & 0x0F), Truncated: msg[2]&0x02 != 0}
	qd, an, ns := int(binary.BigEndian.Uint16(msg[4:])), int(binary.BigEndian.Uint16(msg[6:])), int(binary.BigEndian.Uint16(msg[8:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, n, err := dnsReadName(msg, off)
		if err != nil {
			return nil, err
		}
		off = n + 4
	}
	read := func(count int) ([]regRR, error) {
		var out []regRR
		for i := 0; i < count; i++ {
			name, n, err := dnsReadName(msg, off)
			if err != nil {
				return nil, err
			}
			if n+10 > len(msg) {
				return nil, errors.New("short DNS reply")
			}
			rr := regRR{Name: name, Type: binary.BigEndian.Uint16(msg[n:]), TTL: binary.BigEndian.Uint32(msg[n+4:])}
			rdlen := int(binary.BigEndian.Uint16(msg[n+8:]))
			rd := n + 10
			if rd+rdlen > len(msg) {
				return nil, errors.New("short DNS reply")
			}
			switch rr.Type {
			case dnsTypeA:
				if rdlen == 4 {
					rr.Data = netip.AddrFrom4([4]byte(msg[rd : rd+4])).String()
				}
			case dnsTypeAAAA:
				if rdlen == 16 {
					rr.Data = netip.AddrFrom16([16]byte(msg[rd : rd+16])).String()
				}
			case dnsTypePTR, dnsTypeSOA:
				if d, _, err := dnsReadName(msg, rd); err == nil {
					rr.Data = d
				}
			}
			off = rd + rdlen
			out = append(out, rr)
		}
		return out, nil
	}
	var err error
	if r.Answers, err = read(an); err != nil {
		return nil, err
	}
	if r.Authority, err = read(ns); err != nil {
		return nil, err
	}
	return r, nil
}

// ─── TSIG ───────────────────────────────────────────────────────────────────────

type tsigKey struct {
	Name   string
	Secret []byte
	Alg    string // the algorithm's name on the wire: hmac-sha256, …
}

func tsigAlgName(s string) (string, error) {
	t := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.TrimSpace(s)))
	switch {
	case t == "":
		return "hmac-sha256", nil
	case strings.Contains(t, "sha512"):
		return "hmac-sha512", nil
	case strings.Contains(t, "sha384"):
		return "hmac-sha384", nil
	case strings.Contains(t, "sha256"):
		return "hmac-sha256", nil
	case strings.Contains(t, "sha1"):
		return "hmac-sha1", nil
	case strings.Contains(t, "md5"):
		return "hmac-md5.sig-alg.reg.int", nil
	}
	return "", fmt.Errorf("the algorithm %q is not one of hmac-md5, hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512", s)
}

func (k *tsigKey) hash() func() hash.Hash {
	switch k.Alg {
	case "hmac-sha512":
		return sha512.New
	case "hmac-sha384":
		return sha512.New384
	case "hmac-sha1":
		return sha1.New
	case "hmac-md5.sig-alg.reg.int":
		return md5.New
	}
	return sha256.New
}

// parseTSIGSpec reads name:base64secret[:algorithm].
func parseTSIGSpec(spec string) (*tsigKey, error) {
	p := strings.Split(strings.TrimSpace(spec), ":")
	if len(p) < 2 || len(p) > 3 || p[0] == "" || p[1] == "" {
		return nil, errors.New("not name:secret[:algorithm]")
	}
	if _, err := regWireName(p[0]); err != nil {
		return nil, err
	}
	sec, err := base64.StdEncoding.DecodeString(p[1])
	if err != nil || len(sec) == 0 {
		return nil, errors.New("the secret is not base64")
	}
	alg := ""
	if len(p) == 3 {
		alg = p[2]
	}
	a, err := tsigAlgName(alg)
	if err != nil {
		return nil, err
	}
	return &tsigKey{Name: p[0], Secret: sec, Alg: a}, nil
}

var (
	keyNameRe1  = regexp.MustCompile(`key\s+"([^"]+)"`)
	keyNameRe2  = regexp.MustCompile(`key\s+(\S+)\s*\{`)
	keyAlgRe    = regexp.MustCompile(`algorithm\s+([^;]+);`)
	keySecretRe = regexp.MustCompile(`secret\s+"([^"]+)"`)
)

// loadTSIGKey reads the key: the path of a BIND key file, or name:base64secret[:algorithm].
func loadTSIGKey(spec string) (*tsigKey, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	if st, err := os.Stat(spec); err == nil && !st.IsDir() {
		b, err := os.ReadFile(spec)
		if err != nil {
			return nil, err
		}
		nm := keyNameRe1.FindSubmatch(b)
		if nm == nil {
			nm = keyNameRe2.FindSubmatch(b)
		}
		sm := keySecretRe.FindSubmatch(b)
		if nm == nil || sm == nil {
			return nil, fmt.Errorf("%s has no key name or secret", spec)
		}
		alg := ""
		if am := keyAlgRe.FindSubmatch(b); am != nil {
			alg = string(am[1])
		}
		a, err := tsigAlgName(alg)
		if err != nil {
			return nil, err
		}
		sec, err := base64.StdEncoding.DecodeString(string(sm[1]))
		if err != nil || len(sec) == 0 {
			return nil, fmt.Errorf("%s: the secret is not base64", spec)
		}
		return &tsigKey{Name: string(nm[1]), Secret: sec, Alg: a}, nil
	}
	return parseTSIGSpec(spec)
}

// sign appends the TSIG record (RFC 8945) to a request.
func (k *tsigKey) sign(msg []byte, id uint16, now time.Time) ([]byte, error) {
	kn, err := regWireName(strings.ToLower(k.Name))
	if err != nil {
		return nil, err
	}
	an, err := regWireName(strings.ToLower(k.Alg))
	if err != nil {
		return nil, err
	}
	const fudge = 300
	ts := uint64(now.Unix())
	tsb := []byte{byte(ts >> 40), byte(ts >> 32), byte(ts >> 24), byte(ts >> 16), byte(ts >> 8), byte(ts)}
	// what the MAC covers: the message as it is (ARCOUNT before the TSIG record is added) and the TSIG variables
	vars := append([]byte{}, kn...)
	vars = binary.BigEndian.AppendUint16(vars, dnsClassANY)
	vars = binary.BigEndian.AppendUint32(vars, 0)
	vars = append(vars, an...)
	vars = append(vars, tsb...)
	vars = binary.BigEndian.AppendUint16(vars, fudge)
	vars = binary.BigEndian.AppendUint16(vars, 0) // error
	vars = binary.BigEndian.AppendUint16(vars, 0) // other data length
	mac := hmac.New(k.hash(), k.Secret)
	mac.Write(msg)
	mac.Write(vars)
	sum := mac.Sum(nil)

	rd := append([]byte{}, an...)
	rd = append(rd, tsb...)
	rd = binary.BigEndian.AppendUint16(rd, fudge)
	rd = binary.BigEndian.AppendUint16(rd, uint16(len(sum)))
	rd = append(rd, sum...)
	rd = binary.BigEndian.AppendUint16(rd, id)
	rd = binary.BigEndian.AppendUint16(rd, 0)
	rd = binary.BigEndian.AppendUint16(rd, 0)

	out := append([]byte{}, msg...)
	binary.BigEndian.PutUint16(out[10:], binary.BigEndian.Uint16(out[10:])+1)
	out = append(out, kn...)
	out = binary.BigEndian.AppendUint16(out, dnsTypeTSIG)
	out = binary.BigEndian.AppendUint16(out, dnsClassANY)
	out = binary.BigEndian.AppendUint32(out, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
	return append(out, rd...), nil
}

// dnsUpdateOp is one change of an UPDATE message: delete the whole RRset of name/typ, or add one record.
type dnsUpdateOp struct {
	Add   bool
	Name  string
	Type  uint16
	TTL   uint32
	RData []byte // Add only
}

// dnsBuildUpdate is an UPDATE message (RFC 2136) for zone, signed when key is set.  The changes of one message are applied
// together by the server: deleting a name's RRset and adding the new one in the same message is never seen half done.
func dnsBuildUpdate(zone string, ops []dnsUpdateOp, key *tsigKey, now time.Time) (uint16, []byte, error) {
	zw, err := regWireName(zone)
	if err != nil {
		return 0, nil, err
	}
	id := dnsRandID()
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], dnsOpUpdate<<11)
	binary.BigEndian.PutUint16(b[4:], 1) // zone count
	binary.BigEndian.PutUint16(b[8:], uint16(len(ops)))
	b = append(b, zw...)
	b = binary.BigEndian.AppendUint16(b, dnsTypeSOA)
	b = binary.BigEndian.AppendUint16(b, dnsClassIN)
	for _, o := range ops {
		nw, err := regWireName(o.Name)
		if err != nil {
			return 0, nil, err
		}
		b = append(b, nw...)
		b = binary.BigEndian.AppendUint16(b, o.Type)
		if o.Add {
			b = binary.BigEndian.AppendUint16(b, dnsClassIN)
			b = binary.BigEndian.AppendUint32(b, o.TTL)
			b = binary.BigEndian.AppendUint16(b, uint16(len(o.RData)))
			b = append(b, o.RData...)
		} else { // delete the RRset: class ANY, no data
			b = binary.BigEndian.AppendUint16(b, dnsClassANY)
			b = binary.BigEndian.AppendUint32(b, 0)
			b = binary.BigEndian.AppendUint16(b, 0)
		}
	}
	if key != nil {
		if b, err = key.sign(b, id, now); err != nil {
			return 0, nil, err
		}
	}
	return id, b, nil
}

// ─── transport ──────────────────────────────────────────────────────────────────

// dnsExchange sends one message to host:port and returns the reply.  UDP for queries, TCP for updates.
func dnsExchange(host, port string, tcp bool, id uint16, msg []byte) ([]byte, error) {
	addr := net.JoinHostPort(host, port)
	d := &net.Dialer{Timeout: dnsRegWait}
	netw := "udp"
	if tcp {
		netw = "tcp"
	}
	c, err := dialPrefer4(context.Background(), d, netw, addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsRegWait))
	if tcp {
		if len(msg) > 65535 {
			return nil, errors.New("DNS message too long")
		}
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)); err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		reply := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, reply); err != nil {
			return nil, err
		}
		if len(reply) >= 2 && binary.BigEndian.Uint16(reply) != id {
			return nil, errors.New("the reply is not for this request")
		}
		return reply, nil
	}
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for { // a reply with another ID (a late one for an earlier try) is not ours
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && binary.BigEndian.Uint16(buf) == id {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// dnsAsk asks host for name/qtype; a truncated UDP reply is asked again over TCP.
func dnsAsk(host, port, name string, qtype uint16) (*regReply, error) {
	id, q, err := dnsBuildQuery(name, qtype)
	if err != nil {
		return nil, err
	}
	raw, err := dnsExchange(host, port, false, id, q)
	if err != nil {
		return nil, err
	}
	r, err := dnsParseReply(raw)
	if err != nil {
		return nil, err
	}
	if r.Truncated {
		if raw, err = dnsExchange(host, port, true, id, q); err != nil {
			return nil, err
		}
		if r, err = dnsParseReply(raw); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// ─── the registrar ──────────────────────────────────────────────────────────────

// DNSRegRecord is one record the last run looked at.
type DNSRegRecord struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // A, AAAA or PTR
	Value  string `json:"value"`
	Result string `json:"result"` // ok (was right), updated, removed, absent (nothing to remove), failed
	Error  string `json:"error,omitempty"`
}

// DNSRegStatus is what the DNS tab shows under the settings.
type DNSRegStatus struct {
	Enabled   bool           `json:"enabled"`
	Running   bool           `json:"running"`
	Hostname  string         `json:"hostname,omitempty"`
	Domain    string         `json:"domain,omitempty"`
	Server    string         `json:"server,omitempty"` // the server the updates went to
	LastRun   string         `json:"last_run,omitempty"`
	NextRun   string         `json:"next_run,omitempty"`
	Action    string         `json:"action,omitempty"` // register or remove
	Existing  int            `json:"existing"`
	Updated   int            `json:"updated"`
	Removed   int            `json:"removed"`
	Failed    int            `json:"failed"`
	LastError string         `json:"last_error,omitempty"`
	Records   []DNSRegRecord `json:"records,omitempty"`
}

type dnsRegAddr struct {
	Iface string
	Addr  netip.Addr
}

type dnsReg struct {
	mu   sync.Mutex
	cfg  *DNSRegConfig
	vips map[netip.Addr]bool
	stop chan struct{}
	done chan struct{}
	st   DNSRegStatus

	runMu sync.Mutex // one run at a time, the loop's or a manual one

	// seams for the tests
	port       string
	resolvPath string
	hostFn     func() string
	addrsFn    func() ([]dnsRegAddr, error)
	now        func() time.Time
}

var dnsRegistrar = &dnsReg{port: "53", resolvPath: "/etc/resolv.conf"}

func (r *dnsReg) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// dnsRegVIPs are the shared addresses of the gateways: not this node's own, never registered.
func dnsRegVIPs(dc *DaemonConfig) map[netip.Addr]bool {
	v := map[netip.Addr]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		if a, err := netip.ParseAddr(s); err == nil {
			v[a.Unmap()] = true
		}
	}
	for _, g := range dc.Groups {
		add(g.VIP4)
		add(g.VIP6)
		for _, a := range g.MoreVIP4 {
			add(a)
		}
		for _, a := range g.MoreVIP6 {
			add(a)
		}
		for _, a := range g.ExtraVIPs {
			add(a)
		}
	}
	return v
}

// Apply starts, restarts or stops the loop to match dc.  An unchanged setting does nothing.  Turning registration off leaves
// the records where they are; --dnsreg-remove takes them out.
func (r *dnsReg) Apply(dc *DaemonConfig) {
	c := dc.DNSReg
	vips := dnsRegVIPs(dc)
	r.mu.Lock()
	on := !c.empty() && c.Enabled && c.Validate() == nil
	if on && r.stop != nil && r.cfg.same(c) && sameAddrSet(r.vips, vips) {
		r.mu.Unlock()
		return
	}
	var old chan struct{}
	if r.stop != nil {
		close(r.stop)
		old = r.done
		r.stop, r.done = nil, nil
	}
	r.cfg, r.vips = c.clone(), vips
	r.st.Enabled, r.st.Running = on, false
	if !on {
		r.st.NextRun = ""
	}
	r.mu.Unlock()
	if old != nil {
		<-old
	}
	if !on {
		return
	}
	r.mu.Lock()
	r.stop, r.done = make(chan struct{}), make(chan struct{})
	stop, done, cfg := r.stop, r.done, *r.cfg
	r.mu.Unlock()
	go r.loop(cfg, vips, stop, done)
}

func sameAddrSet(a, b map[netip.Addr]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// loop registers a few seconds after it starts (the network is up by then) and then every interval plus up to 30 % jitter.
func (r *dnsReg) loop(cfg DNSRegConfig, vips map[netip.Addr]bool, stop, done chan struct{}) {
	defer close(done)
	wait := 3 * time.Second
	for {
		r.mu.Lock()
		r.st.NextRun = r.clock().Add(wait).UTC().Format(time.RFC3339)
		r.mu.Unlock()
		select {
		case <-stop:
			return
		case <-time.After(wait):
		}
		select { // the stop may have come together with the timer
		case <-stop:
			return
		default:
		}
		r.run(cfg, vips, false)
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(float64(cfg.interval())*dnsRegJitter)+1))
		wait = cfg.interval() + time.Duration(j.Int64())
	}
}

// RunNow registers (or, with remove, removes) this node's records now, with the settings as they are, and returns the result.
func (r *dnsReg) RunNow(dc *DaemonConfig, remove bool) DNSRegStatus {
	c := dc.DNSReg
	if c == nil {
		c = &DNSRegConfig{}
	}
	return r.run(*c, dnsRegVIPs(dc), remove)
}

// Status is the state of the last run.
func (r *dnsReg) Status() DNSRegStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.st
	st.Records = append([]DNSRegRecord(nil), st.Records...)
	return st
}

func (r *dnsReg) hostname() string {
	var h string
	if r.hostFn != nil {
		h = r.hostFn()
	} else {
		h, _ = os.Hostname()
	}
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i >= 0 {
		h = h[:i]
	}
	return h
}

// resolvConf reads the nameservers and the first search domain of the resolver's configuration.
func (r *dnsReg) resolvConf() (servers []string, domain string) {
	f, err := os.Open(r.resolvPath)
	if err != nil {
		return []string{"127.0.0.1"}, ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 2 || strings.HasPrefix(p[0], "#") || strings.HasPrefix(p[0], ";") {
			continue
		}
		switch p[0] {
		case "nameserver":
			servers = append(servers, p[1])
		case "search":
			if domain == "" {
				domain = p[1]
			}
		case "domain":
			if domain == "" { // "search" wins over "domain" when both are there, as in the resolver
				domain = p[1]
			}
		}
	}
	if len(servers) == 0 {
		servers = []string{"127.0.0.1"}
	}
	return servers, strings.TrimSuffix(domain, ".")
}

func (r *dnsReg) ifAddrs() ([]dnsRegAddr, error) {
	if r.addrsFn != nil {
		return r.addrsFn()
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []dnsRegAddr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		as, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ad, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, dnsRegAddr{ifc.Name, ad.Unmap()})
			}
		}
	}
	return out, nil
}

// usable reports whether an address is one to register: not loopback, link-local, multicast or unspecified.
func dnsRegUsable(a netip.Addr) bool {
	return a.IsValid() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && !a.IsMulticast() && !a.IsUnspecified()
}

func dnsRegLabel(ifname string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(ifname) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// dnsRegFwd is one forward RRset to be right: all the addresses of a name and type.
type dnsRegFwd struct {
	Name  string
	Type  uint16
	Addrs []netip.Addr
}

// dnsRegPTR is one reverse record.
type dnsRegPTR struct {
	Addr   netip.Addr
	Target string
}

// dnsRegPlan works out the records of this node from its addresses: the first address of each family gets hostname.domain, every
// address gets hostname-interface.domain, and each address points back at the first of its names.
func dnsRegPlan(host, domain string, addrs []dnsRegAddr, skip []string, vips map[netip.Addr]bool) ([]dnsRegFwd, []dnsRegPTR) {
	var fwd []dnsRegFwd
	idx := map[string]int{}
	var ptrs []dnsRegPTR
	seen := map[netip.Addr]bool{}
	primary := map[bool]bool{} // by "is IPv6": the family's first address has been given
	put := func(name string, a netip.Addr) {
		typ := uint16(dnsTypeA)
		if a.Is6() {
			typ = dnsTypeAAAA
		}
		k := name + "/" + strconv.Itoa(int(typ))
		i, ok := idx[k]
		if !ok {
			i = len(fwd)
			idx[k] = i
			fwd = append(fwd, dnsRegFwd{Name: name, Type: typ})
		}
		fwd[i].Addrs = append(fwd[i].Addrs, a)
	}
	for _, fam6 := range []bool{false, true} { // IPv4 before IPv6
		for _, x := range addrs {
			if x.Addr.Is6() != fam6 || !dnsRegUsable(x.Addr) || vips[x.Addr] || seen[x.Addr] {
				continue
			}
			skipped := false
			for _, p := range skip {
				if ok, _ := path.Match(strings.TrimSpace(p), x.Iface); ok {
					skipped = true
				}
			}
			lab := dnsRegLabel(x.Iface)
			if skipped || lab == "" {
				continue
			}
			seen[x.Addr] = true
			ifName := host + "-" + lab + "." + domain
			target := ifName
			if !primary[fam6] {
				primary[fam6] = true
				target = host + "." + domain
				put(target, x.Addr)
			}
			put(ifName, x.Addr)
			ptrs = append(ptrs, dnsRegPTR{x.Addr, target})
		}
	}
	return fwd, ptrs
}

// dnsRegReverse is the PTR owner name and its zone (a /24 for IPv4, a /64 for IPv6).
func dnsRegReverse(a netip.Addr) (name, zone string) {
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0]), fmt.Sprintf("%d.%d.%d.in-addr.arpa", b[2], b[1], b[0])
	}
	b := a.As16()
	n := make([]string, 0, 32)
	for i := 15; i >= 0; i-- {
		n = append(n, fmt.Sprintf("%x", b[i]&0x0F), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(n, ".") + ".ip6.arpa", strings.Join(n[16:], ".") + ".ip6.arpa"
}

func dnsRegRData(typ uint16, v string) ([]byte, error) {
	switch typ {
	case dnsTypeA, dnsTypeAAAA:
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, err
		}
		return a.AsSlice(), nil
	}
	return regWireName(v)
}

// dnsZone is where updates for a zone go.
type dnsZone struct {
	Zone string // the apex of the zone, the name in the update's zone section
	Host string // the server's address or name
	Port string
}

// findZone finds the zone that holds name and its primary server: the SOA record asked from the resolvers, or from the
// configured server.
func (r *dnsReg) findZone(cfg *DNSRegConfig, name string) (dnsZone, error) {
	type srv struct{ host, port string }
	var asked []srv
	fixed := false
	if s := strings.TrimSpace(cfg.Server); s != "" {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			h, p = strings.Trim(s, "[]"), r.port
		}
		asked, fixed = []srv{{h, p}}, true
	} else {
		ns, _ := r.resolvConf()
		for _, n := range ns {
			asked = append(asked, srv{n, r.port})
		}
	}
	var lastErr error
	for _, ns := range asked {
		rep, err := dnsAsk(ns.host, ns.port, name, dnsTypeSOA)
		if err != nil {
			lastErr = err
			continue
		}
		var soa *regRR
		for _, set := range [][]regRR{rep.Answers, rep.Authority} { // the apex answers itself; a name below it gets the SOA in the authority section
			for i := range set {
				if set[i].Type == dnsTypeSOA && soa == nil {
					soa = &set[i]
				}
			}
		}
		if soa == nil {
			lastErr = fmt.Errorf("%s has no SOA record", name)
			continue
		}
		m := strings.ToLower(soa.Data)
		if strings.Contains(m, "root-servers") || strings.Contains(m, "-servers.arpa") || soa.Name == "" || soa.Name == "arpa" || soa.Name == "in-addr.arpa" || soa.Name == "ip6.arpa" {
			lastErr = fmt.Errorf("%s is not in a zone of this network (its SOA is %s)", name, soa.Name)
			continue
		}
		z := dnsZone{Zone: soa.Name, Host: ns.host, Port: ns.port}
		if !fixed { // the primary: its address from the resolver, else the name itself
			z.Host, z.Port = soa.Data, r.port
			for _, t := range []uint16{dnsTypeA, dnsTypeAAAA} {
				if ar, err := dnsAsk(ns.host, ns.port, soa.Data, t); err == nil {
					for _, a := range ar.Answers {
						if a.Type == t && a.Data != "" {
							z.Host = a.Data
							break
						}
					}
				}
				if z.Host != soa.Data {
					break
				}
			}
		}
		return z, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS server to ask")
	}
	return dnsZone{}, lastErr
}

// current returns what the zone's server holds for name/typ.
func (r *dnsReg) current(z dnsZone, name string, typ uint16) ([]string, error) {
	rep, err := dnsAsk(z.Host, z.Port, name, typ)
	if err != nil {
		return nil, err
	}
	if rep.Rcode != 0 && rep.Rcode != 3 {
		return nil, fmt.Errorf("%s answered %s", z.Host, dnsRcodeNames[rep.Rcode])
	}
	var out []string
	for _, a := range rep.Answers {
		if a.Type == typ && a.Data != "" && strings.EqualFold(strings.TrimSuffix(a.Name, "."), strings.TrimSuffix(name, ".")) {
			out = append(out, strings.ToLower(a.Data))
		}
	}
	sort.Strings(out)
	return out, nil
}

// update sends one UPDATE message over TCP and returns an error when the server does not accept it.
func (r *dnsReg) update(z dnsZone, ops []dnsUpdateOp, key *tsigKey) error {
	id, msg, err := dnsBuildUpdate(z.Zone, ops, key, r.clock())
	if err != nil {
		return err
	}
	raw, err := dnsExchange(z.Host, z.Port, true, id, msg)
	if err != nil {
		return err
	}
	if len(raw) < 12 { // only the header matters here: the result code
		return errors.New("short DNS reply")
	}
	if rc := int(raw[3] & 0x0F); rc != 0 {
		n := dnsRcodeNames[rc]
		if n == "" {
			n = strconv.Itoa(rc)
		}
		hint := ""
		switch rc {
		case 5:
			hint = " (the server wants a TSIG key, or does not accept this one for the zone)"
		case 9:
			hint = " (the server is not the primary of the zone)"
		}
		return fmt.Errorf("%s answered %s%s", z.Host, n, hint)
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// run registers (or removes) the records once and keeps the result as the status.
func (r *dnsReg) run(cfg DNSRegConfig, vips map[netip.Addr]bool, remove bool) DNSRegStatus {
	r.runMu.Lock()
	defer r.runMu.Unlock()
	r.mu.Lock()
	r.st.Running = true
	r.mu.Unlock()

	st := DNSRegStatus{Action: "register"}
	if remove {
		st.Action = "remove"
	}
	fail := func(err error) DNSRegStatus {
		st.LastError = err.Error()
		st.Failed++
		return st
	}
	st = r.work(&cfg, vips, remove, st, fail)

	r.mu.Lock()
	st.Enabled = r.st.Enabled
	st.LastRun = r.clock().UTC().Format(time.RFC3339)
	st.NextRun = r.st.NextRun
	r.st = st
	out := st
	r.mu.Unlock()
	switch {
	case st.Failed > 0:
		warnf("DNS registration: %d failed (%s)", st.Failed, st.LastError)
	case st.Updated > 0 || st.Removed > 0:
		infof("DNS registration (%s): %d updated, %d removed, %d already right", st.Action, st.Updated, st.Removed, st.Existing)
	default:
		debugf("DNS registration: %d records already right", st.Existing)
	}
	return out
}

func (r *dnsReg) work(cfg *DNSRegConfig, vips map[netip.Addr]bool, remove bool, st DNSRegStatus, fail func(error) DNSRegStatus) DNSRegStatus {
	host := r.hostname()
	if !validDNSName(host) {
		return fail(fmt.Errorf("the host name %q cannot be used in DNS", host))
	}
	domain := strings.TrimSuffix(strings.TrimSpace(cfg.Domain), ".")
	if domain == "" {
		_, domain = r.resolvConf()
	}
	if domain == "" || !validDNSName(domain) {
		return fail(errors.New("no domain: set one, or put a search line in /etc/resolv.conf"))
	}
	st.Hostname, st.Domain = host, domain
	key, err := loadTSIGKey(cfg.Key)
	if err != nil {
		return fail(fmt.Errorf("TSIG key: %v", err))
	}
	zone, err := r.findZone(cfg, domain)
	if err != nil {
		return fail(fmt.Errorf("zone of %s: %v", domain, err))
	}
	st.Server = zone.Host
	addrs, err := r.ifAddrs()
	if err != nil {
		return fail(fmt.Errorf("interfaces: %v", err))
	}
	fwd, ptrs := dnsRegPlan(host, domain, addrs, cfg.Skip, vips)
	ttl := cfg.ttl()

	rec := func(name, typ, val, res string, err error) {
		x := DNSRegRecord{Name: name, Type: typ, Value: val, Result: res}
		if err != nil {
			x.Error = err.Error()
			st.LastError = fmt.Sprintf("%s %s: %v", typ, name, err)
		}
		switch res {
		case "ok":
			st.Existing++
		case "updated":
			st.Updated++
		case "removed":
			st.Removed++
		case "failed":
			st.Failed++
		}
		if len(st.Records) < dnsRegMaxRecords {
			st.Records = append(st.Records, x)
		}
	}
	typName := map[uint16]string{dnsTypeA: "A", dnsTypeAAAA: "AAAA", dnsTypePTR: "PTR"}

	for _, f := range fwd {
		want := make([]string, 0, len(f.Addrs))
		for _, a := range f.Addrs {
			want = append(want, a.String())
		}
		sort.Strings(want)
		val := strings.Join(want, ", ")
		have, err := r.current(zone, f.Name, f.Type)
		if err != nil {
			rec(f.Name, typName[f.Type], val, "failed", err)
			continue
		}
		if remove {
			if len(have) == 0 {
				rec(f.Name, typName[f.Type], val, "absent", nil)
				continue
			}
			err = r.update(zone, []dnsUpdateOp{{Name: f.Name, Type: f.Type}}, key)
			if err != nil {
				rec(f.Name, typName[f.Type], val, "failed", err)
			} else {
				rec(f.Name, typName[f.Type], val, "removed", nil)
			}
			continue
		}
		if sameStrings(have, want) {
			rec(f.Name, typName[f.Type], val, "ok", nil)
			continue
		}
		ops := []dnsUpdateOp{{Name: f.Name, Type: f.Type}}
		for _, a := range f.Addrs {
			ops = append(ops, dnsUpdateOp{Add: true, Name: f.Name, Type: f.Type, TTL: ttl, RData: a.AsSlice()})
		}
		if err := r.update(zone, ops, key); err != nil {
			rec(f.Name, typName[f.Type], val, "failed", err)
		} else {
			rec(f.Name, typName[f.Type], val, "updated", nil)
		}
	}

	rzones := map[string]dnsZone{}
	for _, p := range ptrs {
		name, zn := dnsRegReverse(p.Addr)
		z, ok := rzones[zn]
		if !ok { // the reverse zone's own server; without an SOA of its own, the forward zone's server
			if z, err = r.findZone(cfg, zn); err != nil {
				z = dnsZone{Zone: zn, Host: zone.Host, Port: zone.Port}
			}
			rzones[zn] = z
		}
		have, err := r.current(z, name, dnsTypePTR)
		if err != nil {
			rec(name, "PTR", p.Target, "failed", err)
			continue
		}
		want := strings.ToLower(p.Target)
		if remove {
			if len(have) == 0 {
				rec(name, "PTR", p.Target, "absent", nil)
				continue
			}
			if !(len(have) == 1 && have[0] == want) { // a PTR that points somewhere else is not this node's to remove
				rec(name, "PTR", p.Target, "absent", nil)
				continue
			}
			if err := r.update(z, []dnsUpdateOp{{Name: name, Type: dnsTypePTR}}, key); err != nil {
				rec(name, "PTR", p.Target, "failed", err)
			} else {
				rec(name, "PTR", p.Target, "removed", nil)
			}
			continue
		}
		if len(have) == 1 && have[0] == want {
			rec(name, "PTR", p.Target, "ok", nil)
			continue
		}
		rd, _ := dnsRegRData(dnsTypePTR, p.Target)
		ops := []dnsUpdateOp{{Name: name, Type: dnsTypePTR}, {Add: true, Name: name, Type: dnsTypePTR, TTL: ttl, RData: rd}}
		if err := r.update(z, ops, key); err != nil {
			rec(name, "PTR", p.Target, "failed", err)
		} else {
			rec(name, "PTR", p.Target, "updated", nil)
		}
	}
	return st
}

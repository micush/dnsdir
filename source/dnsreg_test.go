package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// regFakeDNS is a small authoritative server for one zone: it answers queries from its records and applies UPDATE messages,
// checking the TSIG signature the way a real server does (computed here again from the fields of the message).
type regFakeDNS struct {
	mu      sync.Mutex
	recs    map[string][]string // "name/type" -> values (lowercase)
	zone    string
	key     *tsigKey // nil: updates need no signature
	updates int
	port    string
	tcp     net.Listener
	udp     net.PacketConn
}

func regNewFakeDNS(t *testing.T, zone string, key *tsigKey) *regFakeDNS {
	t.Helper()
	f := &regFakeDNS{recs: map[string][]string{}, zone: zone, key: key}
	var err error
	for i := 0; i < 20; i++ {
		if f.tcp, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		_, p, _ := net.SplitHostPort(f.tcp.Addr().String())
		if f.udp, err = net.ListenPacket("udp", "127.0.0.1:"+p); err == nil {
			f.port = p
			break
		}
		f.tcp.Close()
	}
	if f.port == "" {
		t.Fatal("no port for the fake DNS server")
	}
	f.set("ns."+zone, dnsTypeA, "127.0.0.1")
	go func() {
		for {
			c, err := f.tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				var l [2]byte
				if _, err := c.Read(l[:]); err != nil {
					return
				}
				buf := make([]byte, binary.BigEndian.Uint16(l[:]))
				n := 0
				for n < len(buf) {
					m, err := c.Read(buf[n:])
					if err != nil {
						return
					}
					n += m
				}
				if r := f.handle(buf); r != nil {
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
				}
			}()
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, a, err := f.udp.ReadFrom(buf)
			if err != nil {
				return
			}
			if r := f.handle(append([]byte(nil), buf[:n]...)); r != nil {
				f.udp.WriteTo(r, a)
			}
		}
	}()
	t.Cleanup(func() { f.tcp.Close(); f.udp.Close() })
	return f
}

func (f *regFakeDNS) set(name string, typ uint16, vals ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs[strings.ToLower(name)+"/"+strconv.Itoa(int(typ))] = vals
}

func (f *regFakeDNS) get(name string, typ uint16) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := append([]string(nil), f.recs[strings.ToLower(name)+"/"+strconv.Itoa(int(typ))]...)
	sort.Strings(v)
	return v
}

func (f *regFakeDNS) reply(msg []byte, rcode int, qend int, an []byte, ancount int) []byte {
	r := append([]byte(nil), msg[:12]...)
	r[2] = 0x84
	r[3] = byte(rcode)
	binary.BigEndian.PutUint16(r[6:], uint16(ancount))
	binary.BigEndian.PutUint16(r[8:], 0)
	binary.BigEndian.PutUint16(r[10:], 0)
	r = append(r, msg[12:qend]...)
	return append(r, an...)
}

func fakeRR(name string, typ uint16, rd []byte) []byte {
	w, _ := regWireName(name)
	b := append([]byte{}, w...)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, dnsClassIN)
	b = binary.BigEndian.AppendUint32(b, 60)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	return append(b, rd...)
}

func (f *regFakeDNS) handle(msg []byte) []byte {
	if len(msg) < 12 {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if (msg[2]>>3)&0x0F == dnsOpUpdate {
		return f.update(msg)
	}
	name, off, err := dnsReadName(msg, 12)
	if err != nil {
		return nil
	}
	qtype := binary.BigEndian.Uint16(msg[off:])
	qend := off + 4
	name = strings.ToLower(name)
	var an []byte
	n := 0
	switch qtype {
	case dnsTypeSOA:
		if name == f.zone {
			m, _ := regWireName("ns." + f.zone)
			rn, _ := regWireName("admin." + f.zone)
			rd := append(append([]byte{}, m...), rn...)
			for i := 0; i < 5; i++ {
				rd = binary.BigEndian.AppendUint32(rd, 3600)
			}
			an, n = fakeRR(name, dnsTypeSOA, rd), 1
		}
	default:
		for _, v := range f.recs[name+"/"+strconv.Itoa(int(qtype))] {
			var rd []byte
			switch qtype {
			case dnsTypeA, dnsTypeAAAA:
				a, _ := netip.ParseAddr(v)
				rd = a.AsSlice()
			default:
				rd, _ = regWireName(v)
			}
			an = append(an, fakeRR(name, qtype, rd)...)
			n++
		}
	}
	return f.reply(msg, 0, qend, an, n)
}

func (f *regFakeDNS) update(msg []byte) []byte {
	zn, off, err := dnsReadName(msg, 12)
	if err != nil {
		return nil
	}
	qend := off + 4
	up, ad := int(binary.BigEndian.Uint16(msg[8:])), int(binary.BigEndian.Uint16(msg[10:]))
	off = qend
	type op struct {
		add  bool
		name string
		typ  uint16
		val  string
	}
	var ops []op
	for i := 0; i < up; i++ {
		nm, n, err := dnsReadName(msg, off)
		if err != nil {
			return f.reply(msg, 1, qend, nil, 0)
		}
		typ, cls, rdlen := binary.BigEndian.Uint16(msg[n:]), binary.BigEndian.Uint16(msg[n+2:]), int(binary.BigEndian.Uint16(msg[n+8:]))
		rd := n + 10
		o := op{add: cls == dnsClassIN, name: strings.ToLower(nm), typ: typ}
		if o.add {
			switch typ {
			case dnsTypeA, dnsTypeAAAA:
				a, _ := netip.AddrFromSlice(msg[rd : rd+rdlen])
				o.val = a.String()
			default:
				o.val, _, _ = dnsReadName(msg, rd)
				o.val = strings.ToLower(o.val)
			}
		}
		ops = append(ops, o)
		off = rd + rdlen
	}
	if f.key != nil {
		if ad != 1 {
			return f.reply(msg, 5, qend, nil, 0) // REFUSED: not signed
		}
		tsStart := off
		kn, n, err := dnsReadName(msg, off)
		if err != nil || binary.BigEndian.Uint16(msg[n:]) != dnsTypeTSIG {
			return f.reply(msg, 5, qend, nil, 0)
		}
		rd := n + 10
		alg, p, _ := dnsReadName(msg, rd)
		timeSigned := msg[p : p+6]
		fudge := msg[p+6 : p+8]
		ml := int(binary.BigEndian.Uint16(msg[p+8:]))
		mac := msg[p+10 : p+10+ml]
		origID := msg[p+10+ml : p+12+ml]
		signed := append([]byte{}, msg[:tsStart]...)
		binary.BigEndian.PutUint16(signed[10:], 0)
		copy(signed[0:2], origID)
		kw, _ := regWireName(strings.ToLower(kn))
		aw, _ := regWireName(strings.ToLower(alg))
		vars := append([]byte{}, kw...)
		vars = binary.BigEndian.AppendUint16(vars, dnsClassANY)
		vars = binary.BigEndian.AppendUint32(vars, 0)
		vars = append(vars, aw...)
		vars = append(vars, timeSigned...)
		vars = append(vars, fudge...)
		vars = append(vars, 0, 0, 0, 0)
		h := hmac.New(sha256.New, f.key.Secret)
		h.Write(signed)
		h.Write(vars)
		if !strings.EqualFold(kn, f.key.Name) || alg != "hmac-sha256" || !hmac.Equal(h.Sum(nil), mac) {
			return f.reply(msg, 9, qend, nil, 0) // NOTAUTH
		}
	}
	_ = zn
	f.updates++
	for _, o := range ops {
		k := o.name + "/" + strconv.Itoa(int(o.typ))
		if o.add {
			f.recs[k] = append(f.recs[k], o.val)
		} else {
			delete(f.recs, k)
		}
	}
	return f.reply(msg, 0, qend, nil, 0)
}

func testRegistrar(t *testing.T, f *regFakeDNS, addrs []dnsRegAddr) *dnsReg {
	t.Helper()
	rc := filepath.Join(t.TempDir(), "resolv.conf")
	os.WriteFile(rc, []byte("# test\nnameserver 127.0.0.1\nsearch "+f.zone+" other.test\n"), 0o644)
	return &dnsReg{port: f.port, resolvPath: rc, hostFn: func() string { return "Node1.lab.test" },
		addrsFn: func() ([]dnsRegAddr, error) { return addrs, nil }}
}

func ap(s string) netip.Addr { return netip.MustParseAddr(s) }

var testAddrs = []dnsRegAddr{
	{"lo", ap("127.0.0.1")}, {"lo", ap("::1")},
	{"eth0", ap("10.1.2.3")}, {"eth0", ap("10.1.2.4")}, {"eth0", ap("10.1.2.99")}, // .99 is a VIP
	{"eth1", ap("192.168.5.9")}, {"eth1", ap("fe80::1")}, {"eth1", ap("2001:db8:0:1::5")},
	{"docker0", ap("172.17.0.1")},
}

func TestDNSRegisterUpdateAndRemove(t *testing.T) {
	key := &tsigKey{Name: "reg-key", Secret: []byte("0123456789abcdef0123456789abcdef"), Alg: "hmac-sha256"}
	f := regNewFakeDNS(t, "example.test", key)
	r := testRegistrar(t, f, testAddrs)
	spec := key.Name + ":" + base64.StdEncoding.EncodeToString(key.Secret)
	cfg := DNSRegConfig{Enabled: true, Key: spec, Skip: []string{"docker*"}, TTL: 120}
	vips := map[netip.Addr]bool{ap("10.1.2.99"): true}

	st := r.run(cfg, vips, false)
	if st.Failed != 0 || st.LastError != "" {
		t.Fatalf("first run: %+v", st)
	}
	if st.Hostname != "node1" || st.Domain != "example.test" || st.Server != "127.0.0.1" {
		t.Fatalf("names: %+v", st)
	}
	want := map[string][]string{
		"node1.example.test/1":        {"10.1.2.3"},
		"node1-eth0.example.test/1":   {"10.1.2.3", "10.1.2.4"},
		"node1-eth1.example.test/1":   {"192.168.5.9"},
		"node1.example.test/28":       {"2001:db8:0:1::5"},
		"node1-eth1.example.test/28":  {"2001:db8:0:1::5"},
		"3.2.1.10.in-addr.arpa/12":    {"node1.example.test"},
		"4.2.1.10.in-addr.arpa/12":    {"node1-eth0.example.test"},
		"9.5.168.192.in-addr.arpa/12": {"node1-eth1.example.test"},
		"5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa/12": {"node1.example.test"},
	}
	for k, v := range want {
		i := strings.LastIndexByte(k, '/')
		typ, _ := strconv.Atoi(k[i+1:])
		if got := f.get(k[:i], uint16(typ)); strings.Join(got, ",") != strings.Join(v, ",") {
			t.Errorf("%s = %v, want %v", k, got, v)
		}
	}
	for _, k := range []string{"node1-docker0.example.test", "99.2.1.10.in-addr.arpa", "node1-lo.example.test"} {
		if len(f.get(k, 1)) != 0 || len(f.get(k, 12)) != 0 {
			t.Errorf("%s was registered", k)
		}
	}
	if st.Updated != len(want) || st.Existing != 0 {
		t.Fatalf("counts after the first run: updated %d existing %d, want %d updated", st.Updated, st.Existing, len(want))
	}

	// a second run finds everything right and sends nothing
	n := f.updates
	st = r.run(cfg, vips, false)
	if st.Updated != 0 || st.Existing != len(want) || f.updates != n {
		t.Fatalf("second run: %+v (updates %d -> %d)", st, n, f.updates)
	}

	// a record that changed under us is put right, and only that one
	f.set("node1-eth1.example.test", dnsTypeA, "192.168.5.77")
	st = r.run(cfg, vips, false)
	if st.Updated != 1 || st.Failed != 0 || f.updates != n+1 {
		t.Fatalf("after a change: %+v", st)
	}
	if got := f.get("node1-eth1.example.test", dnsTypeA); len(got) != 1 || got[0] != "192.168.5.9" {
		t.Fatalf("eth1 A = %v", got)
	}

	// remove takes this node's records out and leaves other names alone
	f.set("other.example.test", dnsTypeA, "10.9.9.9")
	f.set("7.7.7.10.in-addr.arpa", dnsTypePTR, "other.example.test")
	st = r.run(cfg, vips, true)
	if st.Failed != 0 || st.Removed != len(want) {
		t.Fatalf("remove: %+v", st)
	}
	for k := range want {
		i := strings.LastIndexByte(k, '/')
		typ, _ := strconv.Atoi(k[i+1:])
		if got := f.get(k[:i], uint16(typ)); len(got) != 0 {
			t.Errorf("%s is still there: %v", k, got)
		}
	}
	if len(f.get("other.example.test", dnsTypeA)) != 1 || len(f.get("7.7.7.10.in-addr.arpa", dnsTypePTR)) != 1 {
		t.Fatal("remove touched records that are not this node's")
	}
	st = r.run(cfg, vips, true)
	if st.Removed != 0 || st.Failed != 0 {
		t.Fatalf("second remove: %+v", st)
	}
}

func TestDNSRegisterNeedsTheRightKey(t *testing.T) {
	key := &tsigKey{Name: "reg-key", Secret: []byte("0123456789abcdef0123456789abcdef"), Alg: "hmac-sha256"}
	f := regNewFakeDNS(t, "example.test", key)
	r := testRegistrar(t, f, testAddrs[2:3])

	st := r.run(DNSRegConfig{}, nil, false) // no key
	if st.Failed == 0 || !strings.Contains(st.LastError, "REFUSED") || !strings.Contains(st.LastError, "TSIG") {
		t.Fatalf("no key: %+v", st)
	}
	bad := "reg-key:" + base64.StdEncoding.EncodeToString([]byte("another secret, 32 bytes long!!!"))
	st = r.run(DNSRegConfig{Key: bad}, nil, false)
	if st.Failed == 0 || !strings.Contains(st.LastError, "NOTAUTH") {
		t.Fatalf("wrong secret: %+v", st)
	}
	if len(f.get("node1.example.test", dnsTypeA)) != 0 {
		t.Fatal("a record was written without a valid signature")
	}
	good := "reg-key:" + base64.StdEncoding.EncodeToString(key.Secret) + ":hmac-sha256"
	if st = r.run(DNSRegConfig{Key: good}, nil, false); st.Failed != 0 {
		t.Fatalf("right key: %+v", st)
	}
}

func TestDNSRegisterUnsignedServerAndServerSetting(t *testing.T) {
	f := regNewFakeDNS(t, "example.test", nil)
	r := testRegistrar(t, f, testAddrs[2:3])
	r.resolvPath = "/nonexistent" // the resolver is not used: the server and the domain are set
	st := r.run(DNSRegConfig{Domain: "example.test.", Server: "127.0.0.1:" + f.port}, nil, false)
	if st.Failed != 0 || st.Updated != 3 { // node1 A, node1-eth0 A, one PTR
		t.Fatalf("%+v", st)
	}
	if got := f.get("node1.example.test", dnsTypeA); len(got) != 1 || got[0] != "10.1.2.3" {
		t.Fatalf("A = %v", got)
	}
	// no domain anywhere is an error that says what to do
	if st = r.run(DNSRegConfig{}, nil, false); !strings.Contains(st.LastError, "no domain") {
		t.Fatalf("%+v", st)
	}
}

func TestDNSRegReverseNames(t *testing.T) {
	n, z := dnsRegReverse(ap("192.0.2.45"))
	if n != "45.2.0.192.in-addr.arpa" || z != "2.0.192.in-addr.arpa" {
		t.Fatal(n, z)
	}
	n, z = dnsRegReverse(ap("2001:db8:1:2:3:4:5:6"))
	if n != "6.0.0.0.5.0.0.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" || z != "2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Fatal(n, z)
	}
}

func TestDNSRegPlan(t *testing.T) {
	fwd, ptrs := dnsRegPlan("h", "d.test", testAddrs, []string{"docker*"}, map[netip.Addr]bool{ap("10.1.2.99"): true})
	var got []string
	for _, f := range fwd {
		var a []string
		for _, x := range f.Addrs {
			a = append(a, x.String())
		}
		got = append(got, f.Name+"/"+strconv.Itoa(int(f.Type))+"="+strings.Join(a, "+"))
	}
	want := []string{"h.d.test/1=10.1.2.3", "h-eth0.d.test/1=10.1.2.3+10.1.2.4", "h-eth1.d.test/1=192.168.5.9", "h.d.test/28=2001:db8:0:1::5", "h-eth1.d.test/28=2001:db8:0:1::5"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("forward:\n%v\nwant\n%v", got, want)
	}
	if len(ptrs) != 4 || ptrs[0].Target != "h.d.test" || ptrs[1].Target != "h-eth0.d.test" || ptrs[2].Target != "h-eth1.d.test" || ptrs[3].Target != "h.d.test" {
		t.Fatalf("ptrs: %+v", ptrs)
	}
	if dnsRegLabel("eth0.100") != "eth0-100" || dnsRegLabel("br_lan") != "br-lan" {
		t.Fatal("interface labels")
	}
}

func TestTSIGKeyFormats(t *testing.T) {
	sec := base64.StdEncoding.EncodeToString([]byte("secretsecretsecret"))
	for spec, alg := range map[string]string{"k:" + sec: "hmac-sha256", "k:" + sec + ":hmac-md5": "hmac-md5.sig-alg.reg.int", "k:" + sec + ":HMAC-SHA512": "hmac-sha512", "k:" + sec + ":sha1": "hmac-sha1"} {
		k, err := parseTSIGSpec(spec)
		if err != nil || k.Alg != alg || k.Name != "k" {
			t.Errorf("%q: %v %+v", spec, err, k)
		}
	}
	for _, bad := range []string{"justaname", "k:!!notbase64", "k:" + sec + ":hmac-foo", ":" + sec} {
		if _, err := parseTSIGSpec(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	file := filepath.Join(t.TempDir(), "k.key")
	os.WriteFile(file, []byte("key \"my-key\" {\n\talgorithm hmac-sha384;\n\tsecret \""+sec+"\";\n};\n"), 0o600)
	k, err := loadTSIGKey(file)
	if err != nil || k.Name != "my-key" || k.Alg != "hmac-sha384" || string(k.Secret) != "secretsecretsecret" {
		t.Fatalf("%v %+v", err, k)
	}
	if err := (&DNSRegConfig{Key: file}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRegConfigValidateAndOldConfigs(t *testing.T) {
	sec := base64.StdEncoding.EncodeToString([]byte("secretsecretsecret"))
	for _, c := range []DNSRegConfig{{}, {Enabled: true}, {Key: "k:" + sec, Domain: "lab.example.com", Server: "10.0.0.2:53", Interval: 60, TTL: 300, Skip: []string{"docker*", "veth*"}}, {Server: "ns1.example.com"}} {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	for _, c := range []DNSRegConfig{{Domain: "bad domain"}, {Server: "a b"}, {Interval: 5}, {TTL: -1}, {Skip: []string{"["}}, {Key: "nocolon"}, {Key: "k:%%%"}} {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v was accepted", c)
		}
	}
	// a config that never used it has no key, and an empty block is dropped
	dc := newDaemonConfig()
	b, _ := json.Marshal(dc)
	if strings.Contains(string(b), "dns_register") {
		t.Fatal("an unused setting leaves a key in the file")
	}
	dc.DNSReg = &DNSRegConfig{}
	if err := dc.Validate(); err != nil || dc.DNSReg != nil {
		t.Fatalf("empty block: %v %v", err, dc.DNSReg)
	}
	dc.DNSReg = &DNSRegConfig{Enabled: true, Interval: 10}
	if err := dc.Validate(); err == nil {
		t.Fatal("a bad interval was accepted")
	}
}

func TestDNSRegApplyStartsAndStops(t *testing.T) {
	r := &dnsReg{port: "1", resolvPath: "/nonexistent"}
	dc := &DaemonConfig{DNSReg: &DNSRegConfig{Enabled: true}}
	r.Apply(dc)
	if !r.Status().Enabled || r.stop == nil {
		t.Fatal("not started")
	}
	stop := r.stop
	r.Apply(dc) // unchanged: the same loop
	if r.stop != stop {
		t.Fatal("restarted for nothing")
	}
	done := make(chan struct{})
	go func() { r.Apply(&DaemonConfig{}); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stopping the loop hangs")
	}
	if r.Status().Enabled || r.stop != nil {
		t.Fatal("not stopped")
	}
}

func TestDNSRegVIPsAreTheGatewaysAddresses(t *testing.T) {
	dc := &DaemonConfig{Groups: []GroupConfig{{VIP4: "10.0.0.5", VIP6: "2001:db8::5", MoreVIP4: []string{"10.0.0.6"}, ExtraVIPs: []string{"192.0.2.1/32"}}}}
	v := dnsRegVIPs(dc)
	for _, a := range []string{"10.0.0.5", "2001:db8::5", "10.0.0.6", "192.0.2.1"} {
		if !v[ap(a)] {
			t.Errorf("%s is not excluded", a)
		}
	}
}

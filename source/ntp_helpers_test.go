package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNTP is a UDP NTP server on loopback with tunable behaviour.
type fakeNTP struct {
	addr    string
	delay   atomic.Int64 // ns the answer is held back
	mode    atomic.Int32 // fakeOK, fakeKoD, fakeDrop, fakeUnsync, fakeWrongOrigin, fakeMode6
	stratum atomic.Int32 // the stratum answered (default 2)
	offset  atomic.Int64 // ns this server's clock is ahead of the real one
	rootDel atomic.Int64 // ns
	rootDsp atomic.Int64 // ns
	hits    atomic.Int64
	only4   atomic.Bool // answer only version 4 requests (what the probes send): a server that cannot serve a version 3 client
	pc      net.PacketConn
	lastReq atomic.Value // []byte: the last request seen
}

const (
	fakeOK = iota
	fakeKoD
	fakeDrop
	fakeUnsync
	fakeWrongOrigin
)

func q1616(d time.Duration) uint32 { return uint32(float64(d) / float64(time.Second) * 65536) }

func (f *fakeNTP) answer(q []byte) []byte {
	f.hits.Add(1)
	f.lastReq.Store(append([]byte(nil), q...))
	if len(q) < ntpHeaderLen {
		return nil
	}
	if f.only4.Load() && ntpVersion(q) != 4 {
		return nil
	}
	if d := f.delay.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
	switch f.mode.Load() {
	case fakeDrop:
		return nil
	case fakeKoD:
		return kodResponse(q, "DENY")
	case fakeUnsync:
		return unsyncResponse(q)
	}
	now := time.Now().Add(time.Duration(f.offset.Load()))
	r := make([]byte, ntpHeaderLen)
	r[0] = byte(ntpVersion(q))<<3 | ntpModeServer
	r[1] = byte(f.stratum.Load())
	r[2] = q[2]
	r[3] = 0xEC // precision -20
	binary.BigEndian.PutUint32(r[4:], q1616(time.Duration(f.rootDel.Load())))
	binary.BigEndian.PutUint32(r[8:], q1616(time.Duration(f.rootDsp.Load())))
	copy(r[12:16], []byte{127, 127, 1, 0})
	binary.BigEndian.PutUint64(r[16:], ntpTimestamp(now.Add(-time.Minute)))
	if f.mode.Load() == fakeWrongOrigin {
		binary.BigEndian.PutUint64(r[24:], 12345)
	} else {
		copy(r[24:32], q[40:48])
	}
	binary.BigEndian.PutUint64(r[32:], ntpTimestamp(now))
	binary.BigEndian.PutUint64(r[40:], ntpTimestamp(now))
	return r
}

func newFakeNTP(t *testing.T) *fakeNTP {
	t.Helper()
	f, err := newFakeNTPOn(t, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// newFakeNTPOn is a fake server on the given network and address (an error when the machine cannot listen there).
func newFakeNTPOn(t *testing.T, network, laddr string) (*fakeNTP, error) {
	t.Helper()
	pc, err := net.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	f := &fakeNTP{addr: pc.LocalAddr().String(), pc: pc}
	f.stratum.Store(2)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			go func() {
				if r := f.answer(q); r != nil {
					pc.WriteTo(r, from)
				}
			}()
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return f, nil
}

// testNTPCfg is a pool configuration with short timeouts for the given servers.
func testNTPCfg(servers ...string) NTPConfig {
	d := defaultNTP()
	d.Servers = servers
	d.ProbeTimeoutMS = 300
	d.QueryTimeoutMS = 300
	d.FailThreshold = 1
	d.LatencyAlpha = 0.5
	return d
}

func rankedAddrs(p *Pool) []string {
	var out []string
	for _, s := range p.Ranked() {
		out = append(out, s.Addr)
	}
	return out
}

// clientReq is a request as a client sends it: version 4, mode 3, the given transmit timestamp.
func clientReq(xmit uint64) []byte { return buildNTPRequest(xmit) }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pauseTestConfig is a one-gateway configuration with two servers, for the pause tests.
func pauseTestConfig() *DaemonConfig {
	dc := newDaemonConfig()
	g := defaultGroup()
	g.NTP = nil
	dc.Groups = []GroupConfig{g}
	dc.NTP.Servers = []string{"192.0.2.1:123", "192.0.2.2:123"}
	if err := dc.Validate(); err != nil {
		panic(err)
	}
	return dc
}

func fmtN(i int) string { return strconv.Itoa(i) }

// Helpers that build packets for the fake servers (the daemon itself only asks and reads).

// kodCodes are the kiss-o'-death codes this proxy sends (RFC 5905, section 7.4).
const (
	kodRestricted = "RSTR" // access denied by local policy: the client is not allowed
	kodRate       = "RATE" // the client is asking too often
)

// ntpVersion is the version of a packet, or 0 when it is too short to say.
func ntpVersion(b []byte) int {
	if len(b) < ntpHeaderLen {
		return 0
	}
	return int(b[0]>>3) & 7
}

// ntpRelayable says whether a datagram is a client request this proxy may pass on: a version 1 to 4 packet in
// client mode.  Modes 6 and 7 (ntpq control and private requests such as monlist) are never relayed: they reach a
// server's management functions, and some answer with much more than they were sent.
func ntpRelayable(b []byte) bool {
	if len(b) < ntpHeaderLen || len(b) > ntpMaxPacket {
		return false
	}
	v := ntpVersion(b)
	return ntpMode(b) == ntpModeClient && v >= 1 && v <= 4
}

// ntpTimestamp converts a time to the 32.32 fixed-point form NTP uses (seconds since 1900).
func ntpTimestamp(t time.Time) uint64 {
	sec := uint64(t.Unix()) + ntpUnixEpoch
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return sec<<32 | frac
}

// kodResponse is the answer for a request that is turned away: stratum 0 with an ASCII code in the reference ID,
// the alarm leap bit, and the request's transmit timestamp as the origin (without which the client would ignore it).
// It is nil for a request too short to answer.
func kodResponse(req []byte, code string) []byte {
	if len(req) < ntpHeaderLen {
		return nil
	}
	r := make([]byte, ntpHeaderLen)
	v := byte(ntpVersion(req))
	if v < 1 || v > 4 {
		v = 4
	}
	r[0] = ntpLeapUnsynch<<6 | v<<3 | ntpModeServer
	// stratum 0 (r[1]); poll echoes the request's, so a client keeps its own idea of the interval
	r[2] = req[2]
	copy(r[12:16], code)
	copy(r[24:32], req[40:48])
	return r
}

// unsyncResponse is the answer for a request the proxy cannot serve because no upstream server answered: the
// leap indicator at its alarm value and stratum 16, which is what a server that has lost its time says.  A client
// treats it as a server that is not usable now, and tries another one at once instead of waiting out a timeout.
func unsyncResponse(req []byte) []byte {
	if len(req) < ntpHeaderLen {
		return nil
	}
	r := make([]byte, ntpHeaderLen)
	v := byte(ntpVersion(req))
	if v < 1 || v > 4 {
		v = 4
	}
	r[0] = ntpLeapUnsynch<<6 | v<<3 | ntpModeServer
	r[1] = 16
	r[2] = req[2]
	copy(r[12:16], "INIT")
	copy(r[24:32], req[40:48])
	return r
}

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ── Minimal NTP wire helpers (RFC 5905): just enough to probe a server and to relay a client's request ──────────

const (
	ntpHeaderLen = 48   // the fixed part of every NTP packet
	ntpMaxPacket = 1232 // the most a request or an answer may carry (extension fields, a MAC); larger ones are not relayed

	ntpModeClient    = 3
	ntpModeServer    = 4
	ntpEra1Threshold = 1 << 31 // NTP seconds below this are taken to be in era 1 (after 2036)

	ntpUnixEpoch = 2208988800 // seconds from 1900-01-01 (the NTP epoch) to 1970-01-01
)

// Leap indicator values.
const (
	ntpLeapNone    = 0
	ntpLeapAdd     = 1
	ntpLeapDel     = 2
	ntpLeapUnsynch = 3 // the clock is not synchronised (an alarm)
)

// ntpPacket is the fixed header of an NTP packet.
type ntpPacket struct {
	Leap      uint8
	Version   uint8
	Mode      uint8
	Stratum   uint8
	Poll      int8
	Precision int8
	RootDelay time.Duration
	RootDisp  time.Duration
	RefID     [4]byte
	Ref       uint64 // reference timestamp
	Orig      uint64 // origin timestamp: the client's transmit time, copied by the server
	Recv      uint64 // receive timestamp (server)
	Xmit      uint64 // transmit timestamp
}

// parseNTP reads the fixed header of b.  ok is false for anything shorter than 48 bytes.
func parseNTP(b []byte) (p ntpPacket, ok bool) {
	if len(b) < ntpHeaderLen {
		return p, false
	}
	p.Leap, p.Version, p.Mode = b[0]>>6, (b[0]>>3)&7, b[0]&7
	p.Stratum, p.Poll, p.Precision = b[1], int8(b[2]), int8(b[3])
	p.RootDelay = ntpShort(binary.BigEndian.Uint32(b[4:]))
	p.RootDisp = ntpShort(binary.BigEndian.Uint32(b[8:]))
	copy(p.RefID[:], b[12:16])
	p.Ref = binary.BigEndian.Uint64(b[16:])
	p.Orig = binary.BigEndian.Uint64(b[24:])
	p.Recv = binary.BigEndian.Uint64(b[32:])
	p.Xmit = binary.BigEndian.Uint64(b[40:])
	return p, true
}

// ntpShort turns a 16.16 fixed-point number of seconds into a duration.
func ntpShort(v uint32) time.Duration {
	return time.Duration(float64(v) / 65536 * float64(time.Second))
}

// buildNTPRequest encodes a client request (version 4, mode 3) whose transmit timestamp is xmit.
func buildNTPRequest(xmit uint64) []byte {
	b := make([]byte, ntpHeaderLen)
	b[0] = 4<<3 | ntpModeClient
	binary.BigEndian.PutUint64(b[40:], xmit)
	return b
}

// randomXmit is a transmit timestamp for a probe.  It is random rather than the time: a server copies it back, so
// only a server that has really seen the request can send the matching answer (RFC 5905, section 8), and the
// timestamps the offset is worked out from are the ones this side took itself.  It is never zero.
func randomXmit() uint64 {
	var b [8]byte
	for {
		rand.Read(b[:])
		if v := binary.BigEndian.Uint64(b[:]); v != 0 {
			return v
		}
	}
}

// ntpMode is the mode of a packet, or -1 when it is too short to say.
func ntpMode(b []byte) int {
	if len(b) < ntpHeaderLen {
		return -1
	}
	return int(b[0] & 7)
}

// ntpAnswers reports whether resp is the server's answer to req: a server-mode packet whose origin timestamp is
// the transmit timestamp of the request.  A socket that is reused can receive the late answer to an earlier request,
// and that must not be taken for this one's (it would also hand a client somebody else's time).
func ntpAnswers(req, resp []byte) bool {
	if len(req) < ntpHeaderLen || len(resp) < ntpHeaderLen {
		return false
	}
	if m := ntpMode(resp); m != ntpModeServer {
		return false
	}
	return binary.BigEndian.Uint64(resp[24:]) == binary.BigEndian.Uint64(req[40:])
}

// ntpToTime converts an NTP timestamp to a time.  Seconds with the high bit clear are taken to be after 2036 (the
// next era), as RFC 4330 describes.
func ntpToTime(v uint64) time.Time {
	sec := int64(v >> 32)
	frac := int64((v & 0xFFFFFFFF) * 1e9 >> 32)
	if sec < ntpEra1Threshold {
		sec += 1 << 32
	}
	return time.Unix(sec-ntpUnixEpoch, frac).UTC()
}

// kodCode returns the kiss code of an answer, or "" when it is not a kiss-o'-death packet.
func kodCode(resp []byte) string {
	if len(resp) < ntpHeaderLen || resp[1] != 0 || ntpMode(resp) != ntpModeServer {
		return ""
	}
	return strings.TrimRight(string(resp[12:16]), "\x00 ")
}

// refIDString shows a reference ID the way ntpq does: the ASCII name of a stratum 1 source (GPS, PPS), the
// address of the server a deeper one follows.
func refIDString(stratum uint8, id [4]byte) string {
	switch {
	case stratum == 0:
		return strings.TrimRight(string(id[:]), "\x00 ")
	case stratum == 1:
		s := strings.TrimRight(string(id[:]), "\x00 ")
		for _, c := range []byte(s) {
			if c < 0x20 || c > 0x7e {
				return fmt.Sprintf("%02x%02x%02x%02x", id[0], id[1], id[2], id[3])
			}
		}
		return s
	}
	return fmt.Sprintf("%d.%d.%d.%d", id[0], id[1], id[2], id[3])
}

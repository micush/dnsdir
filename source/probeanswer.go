package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// answerText says what a response answered, for the tooltip of a test domain in the Topology: the records in its answer
// section of the type asked for (and the CNAMEs on the way), as "93.184.216.34, 2606:…" or "10 mail.example.com".  It is a
// short summary, not the whole message: at most a few records, each cut to a sensible length.
const (
	answerMaxRecords = 6
	answerMaxText    = 160
)

func answerText(msg []byte, qtype uint16) string {
	rrs, _ := parseRRs(msg)
	var out []string
	more := 0
	for _, rr := range rrs {
		if rr.sec != 0 {
			continue
		}
		if rr.typ != qtype && rr.typ != 5 { // 5: CNAME
			continue
		}
		s := answerRData(msg, rr)
		if s == "" {
			continue
		}
		if rr.typ == 5 && qtype != 5 {
			s = "CNAME " + s
		}
		if len(out) >= answerMaxRecords {
			more++
			continue
		}
		if len(s) > answerMaxText {
			s = s[:answerMaxText] + "…"
		}
		out = append(out, s)
	}
	t := strings.Join(out, ", ")
	if more > 0 {
		t += fmt.Sprintf(" (+%d more)", more)
	}
	return t
}

// answerRData writes one record's data the way a zone file would, for the types a test is likely to ask for.
func answerRData(msg []byte, rr msgRR) string {
	d := msg[rr.off : rr.off+rr.length]
	switch rr.typ {
	case 1: // A
		if len(d) == 4 {
			return net.IP(d).String()
		}
	case 28: // AAAA
		if len(d) == 16 {
			return net.IP(d).String()
		}
	case 2, 5, 12: // NS, CNAME, PTR
		if n, _, err := readName(msg, rr.off); err == nil {
			return n
		}
	case 15: // MX
		if len(d) > 2 {
			if n, _, err := readName(msg, rr.off+2); err == nil {
				return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(d), n)
			}
		}
	case 16: // TXT: the character strings, joined
		var b strings.Builder
		for i := 0; i < len(d); {
			l := int(d[i])
			if i+1+l > len(d) {
				break
			}
			b.Write(d[i+1 : i+1+l])
			i += 1 + l
		}
		return fmt.Sprintf("%q", b.String())
	case 6: // SOA: primary, contact, serial
		m, off, err := readName(msg, rr.off)
		if err == nil {
			r, off2, err := readName(msg, off)
			if err == nil && off2+4 <= len(msg) {
				return fmt.Sprintf("%s %s serial %d", m, r, binary.BigEndian.Uint32(msg[off2:]))
			}
		}
	case 33: // SRV
		if len(d) > 6 {
			if n, _, err := readName(msg, rr.off+6); err == nil {
				return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(d), binary.BigEndian.Uint16(d[2:]), binary.BigEndian.Uint16(d[4:]), n)
			}
		}
	}
	return fmt.Sprintf("(%d bytes of type %d)", len(d), rr.typ)
}

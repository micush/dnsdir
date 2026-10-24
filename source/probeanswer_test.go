package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

// reply builds a response to a question for name, with the given answer records (type, rdata).
func testReply(t *testing.T, name, qtype string, rrs ...struct {
	typ uint16
	rd  []byte
}) []byte {
	t.Helper()
	q, err := buildQuery(1, name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	b := append([]byte{}, q...)
	binary.BigEndian.PutUint16(b[2:], 0x8180)
	binary.BigEndian.PutUint16(b[6:], uint16(len(rrs)))
	for _, r := range rrs {
		b = append(b, 0xc0, 0x0c) // the name: a pointer to the question
		b = binary.BigEndian.AppendUint16(b, r.typ)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, 60)
		b = binary.BigEndian.AppendUint16(b, uint16(len(r.rd)))
		b = append(b, r.rd...)
	}
	return b
}

type ansRR = struct {
	typ uint16
	rd  []byte
}

func TestAnswerText(t *testing.T) {
	a := testReply(t, "example.com", "A", ansRR{1, []byte{93, 184, 216, 34}}, ansRR{1, []byte{10, 0, 0, 1}})
	if got := answerText(a, 1); got != "93.184.216.34, 10.0.0.1" {
		t.Errorf("A: %q", got)
	}
	txt := testReply(t, "example.com", "TXT", ansRR{16, append([]byte{5}, []byte("v=spf")...)}, ansRR{16, append([]byte{3, 'a', 'b', 'c', 2}, []byte("de")...)})
	if got := answerText(txt, 16); got != `"v=spf", "abcde"` {
		t.Errorf("TXT: %q", got)
	}
	mx := testReply(t, "example.com", "MX", ansRR{15, []byte{0, 10, 0xc0, 0x0c}})
	if got := answerText(mx, 15); got != "10 example.com" {
		t.Errorf("MX: %q", got)
	}
	cn := testReply(t, "www.example.com", "A", ansRR{5, []byte{0xc0, 0x0c}}, ansRR{1, []byte{1, 2, 3, 4}})
	if got := answerText(cn, 1); !strings.Contains(got, "CNAME www.example.com") || !strings.HasSuffix(got, "1.2.3.4") {
		t.Errorf("CNAME chain: %q", got)
	}
	var many []ansRR
	for i := 0; i < 9; i++ {
		many = append(many, ansRR{1, []byte{10, 0, 0, byte(i)}})
	}
	if got := answerText(testReply(t, "example.com", "A", many...), 1); !strings.HasSuffix(got, "(+3 more)") {
		t.Errorf("many: %q", got)
	}
	if got := answerText([]byte{1, 2, 3}, 1); got != "" {
		t.Errorf("garbage: %q", got)
	}
}

package main

// Fuzz targets for the code that parses what other machines send: NTP answers from upstream servers, chrony's
// command output, the gateway packets, and ARP, neighbour and capture frames.  `go test` runs each on its seeds; to
// hunt for new failures run for a while:
//
//	go test -run xxx -fuzz FuzzNTPAndChronyParsers -fuzztime 5m
//	go test -run xxx -fuzz FuzzEngineAndFrames -fuzztime 5m
//
// A failing input is saved under testdata/fuzz/ and replayed by every later `go test`; fix the bug and keep the file.
// A hang or a very slow input fails too (the 2 second check), since one packet must not stall a worker.

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"
)

func FuzzNTPAndChronyParsers(f *testing.F) {
	req := buildNTPRequest(0x1122334455667788)
	f.Add(req, req)
	f.Add(make([]byte, 48), make([]byte, 100))
	f.Add([]byte("A9FE0101,ntp1,2,1.0,0.0,0.0,0.0,0.0,0.0,0.0,0.01,0.01,64.0,Normal\n^,*,10.0.0.1,2,6,377,12,0.0,0.0,0.0\n"), []byte("127.0.0.9,-,0,0,0,4294967295,0,0,0,0\n1.2.3.4,x,1,2\n"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		t0 := time.Now()
		defer func() {
			if d := time.Since(t0); d > 2*time.Second {
				t.Fatalf("slow input: %v", d)
			}
		}()
		if p, ok := parseNTP(a); ok {
			refIDString(p.Stratum, p.RefID)
			ntpToTime(p.Xmit)
			ntpToTime(p.Orig)
		}
		ntpMode(a)
		ntpAnswers(a, b)
		ntpAnswers(b, a)
		kodCode(a)
		parseTracking(a)
		parseSources(a)
		parseClients(a)
		parseAuthdata(b)
		parseServerAuth([]string{string(a), string(b)}, nil)
		parseServerAuth([]string{string(a)}, map[uint32]bool{1: true})
	})
}

func FuzzEngineAndFrames(f *testing.F) {
	e0 := newTestEngine()
	for _, ip := range []string{"10.0.0.9"} {
		g := e0.cfg
		if b, err := buildPacket(&g, pktHello, afIPv4, 1, 0, ip); err == nil {
			f.Add(b[:headerSize], []byte("frame"))
		}
	}
	f.Add(make([]byte, headerSize), make([]byte, 64))
	f.Fuzz(func(t *testing.T, hdr, frame []byte) {
		t0 := time.Now()
		defer func() {
			if d := time.Since(t0); d > 2*time.Second {
				t.Fatalf("slow input: %v", d)
			}
		}()
		e := newTestEngine()
		e.cfg.RealMACs = len(frame)%2 == 0
		if len(hdr) == headerSize {
			// a correctly signed packet with arbitrary header fields
			mac := hmac.New(sha256.New, e.cfg.keyBytes())
			mac.Write(hdr)
			pkt := append(append([]byte(nil), hdr...), mac.Sum(nil)...)
			for _, st := range []State{stateInit, stateListen, stateSpeak, stateActive, stateForward} {
				e.mu.Lock()
				e.state = st
				e.onPacketLocked(pkt, nil)
				e.mu.Unlock()
			}
		}
		e.onPacketLocked(hdr, nil)
		self := [6]byte{2, 0, 0, 0, 0, 1}
		e.arpAnswerAny(frame, self, [][4]byte{{10, 0, 0, 123}})
		e.nsAnswerAny(frame, self, [][16]byte{{0x20, 1, 0xd, 0xb8, 15: 1}})
		for _, lt := range []int{1, 101, 0, 113, 228} {
			parsePkt(lt, frame)
			summarizePacket(lt, frame)
		}
		readPcap(frame)
		isARPReplyTo(frame, self, [4]byte{10, 0, 0, 1})
		isNAReplyTo(frame, self, [16]byte{1})
	})
}

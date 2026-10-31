package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

// Connections to DNS-over-TLS and DNS-over-HTTPS upstreams are kept and reused (RFC 7858 and RFC 8484 both expect it),
// for the probes and the clients' queries alike: a query on a warm connection costs one round trip, where a new one
// first costs the TCP and TLS handshakes.  A DoT connection carries one query at a time and goes back to a small idle
// list after its answer; a DoH server has one HTTP client, whose HTTP/2 connection carries many queries at once.  A
// connection idle for upstreamIdle is closed.  A server may close an idle connection at any time, so a query that fails
// on a reused connection (but not one that ran out of time) is sent once more on a new one before it counts as failed.

const (
	upstreamIdle    = 30 * time.Second
	dotIdlePerKey   = 4                // idle DoT connections kept per server
	dohClientUnused = 10 * time.Minute // a DoH client not used this long is dropped (the server left the configuration)
)

// ── DNS over TLS ─────────────────────────────────────────────────────────────

type idleTLS struct {
	c    net.Conn // a *tls.Conn for DoT, a plain TCP connection for DNS over TCP
	idle time.Time
}

type dotConnPool struct {
	mu   sync.Mutex
	idle map[string][]idleTLS
}

var dotConns = &dotConnPool{idle: map[string][]idleTLS{}}

// dotKey: a connection is only reused for the same server, the same certificate check (none, or against which name) and
// the same trusted authorities (a connection made under other rules is not one these rules would have accepted)
func dotKey(hp string, t upTLS) string {
	return hp + "|" + strconv.FormatBool(t.insecure) + "|" + t.name + "|" + fmt.Sprintf("%p", dotRootCAs)
}

// tlsName is the name a server's certificate is checked against (and sent in the handshake): its own, or host.
func (t upTLS) tlsName(host string) string {
	if t.name != "" {
		return t.name
	}
	return host
}

// take returns the most recently used idle connection to key, closing the ones idle too long.
func (p *dotConnPool) take(key string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.idle[key]
	for len(l) > 0 {
		e := l[len(l)-1]
		l = l[:len(l)-1]
		if time.Since(e.idle) < upstreamIdle {
			p.idle[key] = l
			return e.c
		}
		e.c.Close()
	}
	delete(p.idle, key)
	return nil
}

func (p *dotConnPool) give(key string, c net.Conn) {
	c.SetDeadline(time.Time{})
	p.mu.Lock()
	defer p.mu.Unlock()
	l := p.idle[key]
	// drop the stale ones, and the oldest when there are too many
	keep := l[:0]
	for _, e := range l {
		if time.Since(e.idle) < upstreamIdle {
			keep = append(keep, e)
		} else {
			e.c.Close()
		}
	}
	keep = append(keep, idleTLS{c: c, idle: time.Now()})
	for len(keep) > dotIdlePerKey {
		keep[0].c.Close()
		keep = keep[1:]
	}
	p.idle[key] = keep
}

// count is the number of idle connections kept for key (for the tests).
func (p *dotConnPool) count(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle[key])
}

func dialDoT(ctx context.Context, hp string, deadline time.Time, t upTLS) (*tls.Conn, error) {
	host, _, _ := net.SplitHostPort(hp)
	var d net.Dialer
	tc, err := dialUpstream(ctx, &d, "tcp", hp) // a name is looked up as in bootstrap.go
	if err != nil {
		return nil, err
	}
	tc.SetDeadline(deadline)
	tl := tls.Client(tc, &tls.Config{ServerName: t.tlsName(host), RootCAs: dotRootCAs, MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.insecure})
	if err := tl.HandshakeContext(ctx); err != nil {
		tc.Close()
		return nil, err
	}
	return tl, nil
}

// exchangeDoT sends one query to the DoT server hp (host:port), on a kept connection when there is one.
func exchangeDoT(ctx context.Context, hp string, query []byte, deadline time.Time, t upTLS) ([]byte, time.Duration, error) {
	key := dotKey(hp, t)
	for attempt := 0; ; attempt++ {
		c := dotConns.take(key)
		reused := c != nil
		if !reused {
			var err error
			if c, err = dialDoT(ctx, hp, deadline, t); err != nil {
				return nil, 0, err
			}
		}
		c.SetDeadline(deadline)
		resp, rtt, err := tcpRoundTrip(c, query)
		if err == nil {
			dotConns.give(key, c)
			return resp, rtt, nil
		}
		c.Close()
		if reused && attempt == 0 && retryable(ctx, err) {
			continue // the server had closed the kept connection: once more on a new one
		}
		return nil, 0, err
	}
}

// exchangeTCP sends one query to a plain DNS server over TCP (a client that asked over TCP, or an answer too large for
// UDP), on a kept connection when there is one: the same pool as DoT, under its own key.
func exchangeTCP(ctx context.Context, addr string, query []byte, deadline time.Time) ([]byte, time.Duration, error) {
	key := "tcp|" + addr
	for attempt := 0; ; attempt++ {
		c := dotConns.take(key)
		reused := c != nil
		if !reused {
			var d net.Dialer
			var err error
			if c, err = dialUpstream(ctx, &d, "tcp", addr); err != nil {
				return nil, 0, err
			}
		}
		c.SetDeadline(deadline)
		resp, rtt, err := tcpRoundTrip(c, query)
		if err == nil {
			dotConns.give(key, c)
			return resp, rtt, nil
		}
		c.Close()
		if reused && attempt == 0 && retryable(ctx, err) {
			continue
		}
		return nil, 0, err
	}
}

// retryable says a query that failed on a kept connection may be sent again on a new one: not when the time is up.
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

// tcpRoundTrip writes one length-prefixed query and reads its answer (DNS over TCP and over TLS).
func tcpRoundTrip(conn net.Conn, query []byte) ([]byte, time.Duration, error) {
	id := binary.BigEndian.Uint16(query)
	start := time.Now()
	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query)))
	copy(msg[2:], query)
	if _, err := conn.Write(msg); err != nil {
		return nil, 0, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return nil, 0, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, 0, err
	}
	rtt := time.Since(start)
	if h, ok := parseHeader(resp); !ok || h.id != id || !h.qr {
		return nil, 0, errors.New("malformed or mismatched response")
	}
	return resp, rtt, nil
}

// ── DNS over HTTPS ───────────────────────────────────────────────────────────

type dohClient struct {
	c    *http.Client
	tr   *http.Transport
	used time.Time
}

var dohClients = struct {
	sync.Mutex
	m map[string]*dohClient
}{m: map[string]*dohClient{}}

// dohClientFor is the kept HTTP client for the DoH server of u (one per scheme, host and port, and certificate check).
func dohClientFor(u *url.URL, t upTLS) *dohClient {
	key := dotKey(u.Host, t) // same rules as for DoT connections
	dohClients.Lock()
	defer dohClients.Unlock()
	now := time.Now()
	if c := dohClients.m[key]; c != nil {
		c.used = now
		return c
	}
	for k, c := range dohClients.m { // servers that left the configuration
		if now.Sub(c.used) > dohClientUnused {
			c.tr.CloseIdleConnections()
			delete(dohClients.m, k)
		}
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{ServerName: t.tlsName(u.Hostname()), RootCAs: dotRootCAs, MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.insecure},
		ForceAttemptHTTP2:   true,
		IdleConnTimeout:     upstreamIdle,
		MaxIdleConnsPerHost: 4,
		Proxy:               nil, // never through a proxy from the environment
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialUpstream(ctx, &net.Dialer{}, network, addr) // the name is looked up as in bootstrap.go
		},
	}
	c := &dohClient{tr: tr, used: now, c: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	dohClients.m[key] = c
	return c
}

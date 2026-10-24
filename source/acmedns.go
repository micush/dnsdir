package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// acme-dns (https://github.com/joohoi/acme-dns) is a tiny DNS server that does one thing: it holds the two newest
// dns-01 TXT values for a name it hands out.  The person adds a CNAME from _acme-challenge.<name> to that name once; after
// that dnsdir changes the TXT value through acme-dns's small HTTPS API, and the CA, following the CNAME, finds it.  Nothing
// is ever sent to the person's own DNS servers, and nothing needs to reach this host from outside.

const defaultACMEDNS = "https://auth.acme-dns.io"

// acmeDNSReg is one registration: the credentials for one name on the acme-dns server and the name the CNAME points to.
type acmeDNSReg struct {
	Server     string `json:"server"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Subdomain  string `json:"subdomain"`
	FullDomain string `json:"fulldomain"`
}

// checkServerURL accepts an https:// address, or http:// to a loopback address (for tests and a server on this host).
func checkServerURL(raw, what string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("%s must be a web address such as https://example.com", what)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("%s must use https://", what)
		}
	default:
		return "", fmt.Errorf("%s must be a web address such as https://example.com", what)
	}
	return raw, nil
}

func acmeDNSCall(ctx context.Context, hc *http.Client, url string, hdr map[string]string, in, out any) error {
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dnsdir/"+version())
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("acme-dns answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return errors.New("acme-dns gave an answer that was not understood")
		}
	}
	return nil
}

// acmeDNSRegister asks the server for a new name to point a CNAME at.
func acmeDNSRegister(ctx context.Context, hc *http.Client, server string) (acmeDNSReg, error) {
	var r struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Subdomain  string `json:"subdomain"`
		FullDomain string `json:"fulldomain"`
	}
	if err := acmeDNSCall(ctx, hc, server+"/register", nil, struct{}{}, &r); err != nil {
		return acmeDNSReg{}, err
	}
	if r.Username == "" || r.Password == "" || r.Subdomain == "" || r.FullDomain == "" {
		return acmeDNSReg{}, errors.New("acme-dns did not hand out a complete registration")
	}
	return acmeDNSReg{Server: server, Username: r.Username, Password: r.Password, Subdomain: r.Subdomain, FullDomain: strings.TrimSuffix(r.FullDomain, ".")}, nil
}

// Update sets the TXT value at the registered name (acme-dns keeps the two newest, which is what a wildcard plus its
// base name needs, and lets two clusters renew at the same moment).
func (r acmeDNSReg) Update(ctx context.Context, hc *http.Client, txt string) error {
	return acmeDNSCall(ctx, hc, r.Server+"/update", map[string]string{"X-Api-User": r.Username, "X-Api-Key": r.Password},
		map[string]string{"subdomain": r.Subdomain, "txt": txt}, nil)
}

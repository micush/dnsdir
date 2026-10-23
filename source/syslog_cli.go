package main

import (
	"fmt"
	"strings"
)

// SyslogState is the answer of syslog.status: the settings and what forwarding is doing.
type SyslogState struct {
	Config SyslogConfig `json:"config"`
	Status SyslogStatus `json:"status"`
}

// SyslogStatus is the settings of this node and the state of forwarding.
func (m *Mgmt) SyslogStatus() (SyslogState, error) {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return SyslogState{}, err
	}
	st := SyslogState{Status: sysSink.Status()}
	if dc.Syslog != nil {
		st.Config = *dc.Syslog
	}
	return st, nil
}

// SyslogSet saves this node's syslog settings; forwarding follows at once.
func (m *Mgmt) SyslogSet(c SyslogConfig, actor string) error {
	dc, _, err := m.LiveConfig()
	if err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	note := "syslog: off"
	if c.Enabled {
		note = "syslog: " + c.protocol() + " to " + strings.TrimSpace(c.Server)
	}
	if c.empty() {
		dc.Syslog = nil
	} else {
		dc.Syslog = &c
	}
	return m.PutConfig(dc, actor, note)
}

// runSyslog is the --syslog family:
//
//	--syslog                                  show the settings and the state of forwarding
//	--syslog-server HOST[:PORT]               set the server (and turn forwarding on); "-" clears it and turns it off
//	--syslog-protocol P | --syslog-facility F | --syslog-format F | --syslog-ca FILE   ("-" = default / none)
//	--syslog-tls-insecure                     do not check the server's certificate (tls)
//	--syslog-disable | --syslog-enable        stop / restart forwarding, keeping the settings
//	--syslog-test                             send a test message and report whether it arrived
func runSyslog(sock string, f *cliFlags) {
	var st SyslogState
	decode(op(sock, "syslog.status", nil), &st)
	c := st.Config
	changed := false
	if v := *f.syslogServer; v != "" {
		if v == "-" {
			c.Server, c.Enabled = "", false
		} else {
			c.Server, c.Enabled = v, true
		}
		changed = true
	}
	for _, t := range []struct {
		flag string
		dst  *string
	}{{*f.syslogProto, &c.Protocol}, {*f.syslogFacility, &c.Facility}, {*f.syslogFormat, &c.Format}, {*f.syslogCA, &c.CAFile}} {
		if t.flag == "" {
			continue
		}
		if t.flag == "-" {
			*t.dst = ""
		} else {
			*t.dst = t.flag
		}
		changed = true
	}
	if *f.syslogInsecure {
		c.Insecure, changed = true, true
	}
	if *f.syslogOff && *f.syslogOn {
		fatalf("--syslog-disable and --syslog-enable cannot be used together")
	}
	if *f.syslogOff && c.Enabled {
		c.Enabled, changed = false, true
	}
	if *f.syslogOn && !c.Enabled {
		c.Enabled, changed = true, true
	}
	if changed {
		decode(op(sock, "syslog.set", c), &st)
	}
	printSyslog(st)
	if *f.syslogTest {
		var ts SyslogStatus
		decode(op(sock, "syslog.test", nil), &ts)
		fmt.Printf("Test message delivered to %s (%d sent so far).\n", ts.Address, ts.Sent)
	}
}

func printSyslog(st SyslogState) {
	c, s := st.Config, st.Status
	if !s.Enabled {
		if strings.TrimSpace(c.Server) != "" {
			fmt.Printf("Syslog forwarding is off on this node (server %s kept); turn it on with --syslog-enable\n", c.Server)
		} else {
			fmt.Println("Syslog forwarding is off on this node.")
			fmt.Printf("  Set it up with: %s --syslog-server logs.example.com --syslog-protocol tls\n", strings.TrimSuffix(logFileName, ".log"))
		}
		return
	}
	state := "not connected"
	if s.Connected {
		state = "connected"
	}
	fmt.Printf("Syslog forwarding is on: %s to %s, %s, facility %s, %s\n", s.Protocol, s.Address, c.format(), orDefault(c.Facility, "daemon"), state)
	fmt.Printf("  Sent %d, dropped %d, queued %d", s.Sent, s.Dropped, s.Queued)
	if s.LastSent != "" {
		fmt.Printf(", last sent %s", s.LastSent)
	}
	fmt.Println()
	if s.LastError != "" {
		fmt.Printf("  Last error: %s\n", s.LastError)
	}
}

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// runOSPF is the --ospf family:
//
//	--ospf                                       show the settings, the neighbors' OSPF state, the announced addresses
//	--ospf-router-id A.B.C.D                     set the router id
//	--ospf-interface-add NAME [--ospf-area A] [--ospf-network point-to-point|broadcast] [--ospf-key K]
//	--ospf-interface-del NAME
//	--ospf-hello S | --ospf-dead S | --ospf-metric N     timers and the cost of the announced addresses ("-" = default)
//	--ospf-disable | --ospf-enable               stop / restart OSPF on this node, keeping the settings
//	--ospf-interface-disable NAME | --ospf-interface-enable NAME
func runOSPF(sock string, f *cliFlags) {
	var st OSPFStatus
	decode(op(sock, "ospf.status", nil), &st)
	changed := false
	c := st.Config

	if *f.ospfRouterID != "" {
		if *f.ospfRouterID == "-" {
			c.RouterID = ""
		} else {
			c.RouterID = *f.ospfRouterID
		}
		changed = true
	}
	for _, t := range []struct {
		flag, name string
		dst        *int
	}{{*f.ospfHello, "ospf-hello", &c.Hello}, {*f.ospfDead, "ospf-dead", &c.Dead}, {*f.ospfMetric, "ospf-metric", &c.Metric}} {
		if t.flag == "" {
			continue
		}
		if t.flag == "-" {
			*t.dst = 0
		} else if v, err := strconv.Atoi(t.flag); err != nil || v < 1 {
			fatalf("--%s must be a number, or - for the default", t.name)
		} else {
			*t.dst = v
		}
		changed = true
	}
	if *f.ospfIfAdd != "" {
		nf := OSPFInterface{Name: *f.ospfIfAdd, Area: *f.ospfArea, Network: *f.ospfNetwork, Password: *f.ospfKey}
		c.Interfaces = append(c.Interfaces, nf)
		changed = true
	}
	if *f.ospfIfDel != "" {
		kept := c.Interfaces[:0:0]
		found := false
		for _, i := range c.Interfaces {
			if i.Name == strings.TrimSpace(*f.ospfIfDel) {
				found = true
				continue
			}
			kept = append(kept, i)
		}
		if !found {
			fatalf("there is no OSPF interface %s (see --ospf)", *f.ospfIfDel)
		}
		c.Interfaces, changed = kept, true
	}
	if changed {
		decode(op(sock, "ospf.set", c), &st)
	}
	switch {
	case *f.ospfDisable && *f.ospfEnable:
		fatalf("--ospf-disable and --ospf-enable cannot be used together")
	case *f.ospfDisable:
		decode(op(sock, "ospf.operate", OSPFOperateArgs{Enabled: false}), &st)
	case *f.ospfEnable:
		decode(op(sock, "ospf.operate", OSPFOperateArgs{Enabled: true}), &st)
	}
	if *f.ospfIfDisable != "" && *f.ospfIfEnable != "" {
		fatalf("--ospf-interface-disable and --ospf-interface-enable cannot be used together")
	}
	if *f.ospfIfDisable != "" {
		decode(op(sock, "ospf.operate", OSPFOperateArgs{Interface: *f.ospfIfDisable, Enabled: false}), &st)
	}
	if *f.ospfIfEnable != "" {
		decode(op(sock, "ospf.operate", OSPFOperateArgs{Interface: *f.ospfIfEnable, Enabled: true}), &st)
	}
	printOSPF(st)
}

func printOSPF(st OSPFStatus) {
	c := st.Config
	if st.Blocked != "" {
		fmt.Println("OSPF is not available on this host:", st.Blocked)
		return
	}
	if c.Configured() && c.Disabled {
		fmt.Printf("OSPF is disabled on this node (%d interface(s) kept); enable it with --ospf-enable\n", len(c.Interfaces))
		return
	}
	if !c.Active() {
		fmt.Println("OSPF is off on this node (no interface set).")
		fmt.Println("  Set it up with: dnsdir --ospf-router-id 192.0.2.10 --ospf-interface-add eth0")
		return
	}
	h, d := c.timers()
	fmt.Printf("OSPF is on: router id %s, hello %d s, dead %d s, BFD on every interface (OSPFv2 for IPv4, OSPFv3 for IPv6)\n", c.RouterID, h, d)
	if c.Metric > 0 {
		fmt.Printf("  Metric of the announced addresses: %d\n", c.Metric)
	}
	fmt.Printf("  FRR: %s", map[bool]string{true: "installed", false: "NOT installed"}[st.Installed])
	if st.Installed {
		fmt.Printf(", ospfd %s", map[bool]string{true: "answering", false: "not answering"}[st.Running])
	}
	fmt.Printf(" — %s\n", st.Applied.Detail)
	if len(st.Addresses) == 0 {
		fmt.Println("  Announces: nothing (add anycast addresses to a gateway)")
	}
	for _, a := range st.Addresses {
		if a.Up {
			fmt.Printf("  announced  %s\n", a.Addr)
		} else {
			fmt.Printf("  withdrawn  %s  (%s)\n", a.Addr, orDefault(a.Reason, "not held"))
		}
	}
	for _, i := range c.Interfaces {
		line := fmt.Sprintf("  interface %-15s area %-9s", i.Name, i.Area)
		if i.Network != "" {
			line += " " + i.Network
		}
		if i.Disabled {
			line += " disabled"
		}
		fmt.Println(line)
		for _, p := range st.Peers {
			if p.Interface != i.Name {
				continue
			}
			ver := map[string]string{"ipv4": "OSPFv2", "ipv6": "OSPFv3"}[p.AF]
			l := fmt.Sprintf("    neighbor %-15s %s  %-9s", p.Neighbor, ver, p.State)
			if p.Uptime != "" {
				l += " up " + p.Uptime
			}
			if p.BFD != "" {
				l += " bfd " + p.BFD
			}
			fmt.Println(l)
		}
	}
	for _, note := range st.Notes {
		fmt.Println("  note:", note)
	}
}

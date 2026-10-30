package main

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"
)

// runLLDP is the --lldp family:
//
//	--lldp                          the setting, lldpd on this node and what it sees on each interface
//	--lldp-enable | --lldp-disable  switch LLDP on or off for the whole cluster (shared setting)
func runLLDP(sock string, f *cliFlags) {
	if *f.lldpOn && *f.lldpOff {
		fatalf("--lldp-enable and --lldp-disable cannot be used together")
	}
	if *f.lldpOn || *f.lldpOff {
		op(sock, "lldp.set", map[string]any{"enabled": *f.lldpOn})
		fmt.Println("LLDP is now", map[bool]string{true: "ON on every node of the cluster", false: "off"}[*f.lldpOn])
		if !*f.lldpOn {
			return
		}
	}
	var st LLDPStatus
	decode(op(sock, "lldp.status", nil), &st)
	// just switched on: the daemon starts lldpd once it has reloaded the configuration, a moment later
	for i := 0; *f.lldpOn && i < 20 && st.Installed && !st.Running && !st.Deferred; i++ {
		time.Sleep(250 * time.Millisecond)
		decode(op(sock, "lldp.status", nil), &st)
	}
	fmt.Print(lldpStatusText(st))
}

// lldpStatusText is the --lldp report.
func lldpStatusText(st LLDPStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "LLDP: %s (shared setting)\n", map[bool]string{true: "on", false: "off"}[st.Enabled])
	fmt.Fprintf(&b, "lldpd on this node: %s\n", lldpStateWords(st))
	if !st.Running {
		return b.String()
	}
	if st.Error != "" {
		fmt.Fprintf(&b, "Neighbors: cannot be read (%s)\n", st.Error)
		return b.String()
	}
	if len(st.Neighbors) == 0 {
		b.WriteString("Neighbors: none seen yet (a switch announces itself every 30 s or so; a virtual switch or a cloud network may not pass LLDP at all)\n")
		return b.String()
	}
	b.WriteString("\n")
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "INTERFACE\tSWITCH\tPORT\tVLAN\tMANAGEMENT\tSEEN")
	for _, n := range st.Neighbors {
		port := n.PortID
		if n.PortDescr != "" && n.PortDescr != n.PortID {
			port = n.PortDescr + " (" + n.PortID + ")"
		}
		sw := n.SystemName
		if sw == "" {
			sw = n.ChassisID
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", n.Interface, dash(sw), dash(port), dash(strings.Join(n.VLANs, ", ")), dash(strings.Join(n.MgmtIPs, ", ")), dash(n.Age))
	}
	tw.Flush()
	return b.String()
}

// lldpStateWords says in a few words what lldpd is doing here, as the GUI does.
func lldpStateWords(st LLDPStatus) string {
	switch {
	case !st.Installed:
		return "not installed (install the lldpd package; on RHEL, Rocky and Alma it is in EPEL)"
	case st.Running && st.ManagedBy == "other":
		return "running, started outside dnsdir (left alone: switching LLDP off here does not stop it)"
	case st.Running && st.ManagedBy == "ntpdir":
		return "running, started by AnyTime (ntpdir) on this host (dnsdir decides here)"
	case st.Running:
		return "running"
	case st.Enabled:
		return "stopped (it should be running: see the log)"
	}
	return "stopped"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

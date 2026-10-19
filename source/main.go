// ntpdir — AnyTime NTP Director: a Distributed Gateway Load Balancing Protocol
// daemon that tests the configured NTP servers and gives chrony the ones that pass; chrony serves the VIP.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const usageText = `ntpdir — AnyTime NTP Director (Distributed Gateway Load Balancing Protocol + chrony NTP serving)
Run as a systemd service or directly. All options are runtime-configurable
and persisted to /var/lib/ntpdir/ntpdir.conf.

Usage:
    ntpdir [options]
    ntpdir ?|-h|--help
    ntpdir --configure       interactive configuration wizard
    ntpdir --show-config     print current configuration

Options:
  --log-level LEVEL     debug|info|warning|error (default: info)
  --configure           Interactive configuration wizard (edits all groups)
  --show-config         Print current configuration and exit
  --show-neighbors      Print live neighbor table and exit
  --show-gateways       Print all nodes per group with role (AGC/AFN) and exit
  --show-ntp            Print chrony's state and the NTP server pool(s): health
  --canvas              Print the gateway diagram as a tree with live status
  --version             Print the release number and exit
  --assert-agc          Make this node the active gateway (AGC) for all groups
  --config FILE         Config file path (default: /var/lib/ntpdir/ntpdir.conf)
  --status-socket PATH  Status socket path (default: /run/ntpdir/ntpdir.sock)
  --state-dir DIR       Where history, cluster identity, certificates and update
                        data live (default: /var/lib/ntpdir)

Environment of the daemon:
  NTPDIR_MEMORY_LIMIT_PERCENT  memory use (1-99, default 85) at which the memory guard drops the
                        oldest statistics and host history

Management commands (talk to the running daemon; root only; every one is also in
the web GUI):
  Topology         --canvas-add gateway --vip ADDR/PREFIX [--vip6 ADDR/PREFIX] [--group N]
                                        [--interface IF] [--label NAME] [--anycast ADDR[,ADDR]]
                                        [--server ADDR]
                   --canvas-add server  --group N --server ADDR [--label NAME]
                   --canvas-add fallback --group N --server ADDR   (used only while every server of the gateway is down)
                   --canvas-add anycast --group N --address ADDR   (one anycast address; see --anycast)
                   --canvas-add dnsdirvip --group N --address ADDR   (also answer NTP on an anycast address of dnsdir,
                                        which must be installed here and announce it; --canvas-del dnsdirvip stops)
                   --canvas-set gateway --group N [--vip A/P] [--vip6 A/P] [--interface IF]
                                        [--label NAME|-]   (a name shown under the address; - clears)
                                        [--anycast ADDR[,ADDR]|-]   (extra addresses of ANY subnet, held on lo
                                         by every running node while its NTP answers, for BGP; - clears)
                                        [--real-macs on|off]   (run without virtual MACs on every node)
                                        [--max-stratum N] [--max-root-distance MS] [--max-offset MS|off]
                                        [--fail-threshold N]
                                          (this gateway's own health checks; --lb settings goes back to
                                           following Settings, which is the default)
                   --tshoot [--all-nodes] [--tshoot-file F.tgz]
                                         (a troubleshooting bundle for support: logs, configuration, gateway, NTP, BGP and
                                         anycast state, addresses, routes, neighbors, firewall, FRR, service status, host
                                         numbers, 8 s of ARP / neighbor-discovery traffic per gateway interface, a goroutine dump — of
                                         this node, or of every node with --all-nodes. Passwords, the gateway key, tokens
                                         and join codes are removed. kill -USR1 on a daemon that is up but not answering
                                         writes the goroutine dump to the journal.)
                   --test-vmac [--group N]   (can clients' replies reach this node through virtual MACs? sends an ARP/NS
                                         probe from a throwaway virtual MAC and listens for the answer; changes nothing.
                                         When it says "not delivered": --canvas-set gateway --group N --real-macs on)
                   --canvas-set server  --group N --server ADDR --label NAME|-   (name shown instead of the
                                         address on the Topology page; - clears)
                   --canvas-pause|--canvas-resume gateway --group N   (this node stops/starts serving it)
                   --canvas-pause|--canvas-resume server --group N --server ADDR  (no requests/probes)
                   --canvas-del node --group N --node NODE   (remove a cluster node from the gateway: it stops serving it, on every
                                         node's view; NODE is its address or host name, as --cluster-status lists them)
                   --canvas-add node --group N --node NODE   (put it back; a node that joins starts out removed from every gateway)
                   --host-lookup IP|NAME   (the reverse name of an address, or the address of a name, as the Add NTP server form fills them in)
                   --server-stats ADDR [--stats-range 1h|1d|7d]   (how one NTP server has answered: latency, offset and loss)
                   --gateway-stats GROUP [--stats-range 1h|1d|7d]  (one gateway: client latency, errors, traffic, availability)
                   --schedule | --schedule-history   (the scheduled tasks and when this node runs them next; what ran, with its output)
                   --schedule-set JSON | --schedule-del ID | --schedule-run ID   (add or replace a task, remove one, run one on this node now)
                   --node-pause | --node-resume | --node-status   (this whole node stops/starts serving)
                   --node-rename NAME   (this node's host name and its /etc/hosts entry; on another node: pick it in the Node menu)
                   --canvas-move server  --group N --server ADDR --to N   (its place in the row, 1 = leftmost; the drag in the drawing)
                   --canvas-move anycast --group N --address ADDR --to N   (its place in the list, 1 = top)
                   --canvas-pause|--canvas-resume anycast --group N --address ADDR --scope node|all
                                        (stop/start announcing one anycast address on this node only, or on every node)
                   --canvas-del gateway --group N          (removes everything under it)
                   --canvas-del server  --group N --server ADDR
                   --canvas-del fallback --group N --server ADDR
                   --canvas-del anycast --group N --address ADDR
  Config history   --versions  --version-show ID  --version-diff A[..B]
                   --version-snapshot [--note TEXT]  --version-restore ID
                   --version-export [ID]  --config-import FILE
  GUI certificate  --tls-status  --tls-install --cert-file F --key-file F
                   --tls-csr --cn NAME [--san NAME_OR_IP,...]
                   --tls-revert  --tls-regenerate
  BGP (FRR)        --bgp   (this node's settings, announced addresses, neighbor and BFD state)
                   --asn N|off [--router-id A.B.C.D|-]     (BGP runs while an AS is set)
                   [--keepalive S] [--hold S] [--as-prepend on|off]   (on: the local AS three more times on every announcement)
                   --bgp-neighbor-add ADDR --remote-as N [--description T] [--password P] [--multihop N]
                   --bgp-neighbor-del ADDR
                   --bgp-disable | --bgp-enable   (stop / restart BGP on this node, settings kept)
                   --bgp-neighbor-disable ADDR | --bgp-neighbor-enable ADDR
                                                 (per node; ntpdir then owns /etc/frr/frr.conf; BFD is always on)
  Cluster          --cluster-status  --cluster-token  --cluster-join CODE
                   --cluster-promote  --cluster-remove ADDR
                   --cluster-unremove ADDR  --cluster-leave  --cluster-sync
                   (GUI: the Node menu, top right, configures any member)
  Upgrade          --update-status  --update-history  --update-upload FILE
                   --update-apply  --update-push all|ADDR,...
                   --update-cancel all|ADDR,...  --update-auto on|off
                   --update-repo URL|default   (where "fetch online" downloads from;
                   default https://github.com/micush/ntpdir)
  Statistics       --stats [--stats-range now|1h|1d|7d|30d]
                   [--stats-outcome answered|failed|kod|refused]
                   [--stats-client ADDR | --stats-server ADDR]
                   [--all-nodes]   (every cluster node's numbers added together)
                   --stats-clear [--all-nodes]   (forget the counts and top lists, here or on every node)
                   --scan ADDR   (nmap of a client, run from this node; needs the nmap package)
                   --ping ADDR|NAME  --traceroute ADDR|NAME   (ping / mtr of a client or server, run from this node; needs ping and mtr)
                   --whois NAME   (registration data of a host name or address, asked of its registry from this node)
  Capture          --capture IFACE [--capture-seconds N] [--capture-filter EXPR] [--capture-file FILE] [--all-nodes]
                   --capture-interfaces   (a packet capture on this node, printed or written as .pcap;
                                           --all-nodes: every cluster node at once, one .pcap each in a .tgz)
  Host             --host [--host-range 1h|1d|7d|30d] [--all-nodes]   (CPU, memory, disk and network use; the cluster as one)
  Log              --log [--log-min debug|info|warn|error] [--log-grep WORDS]
                   [--log-since 15m|6h|2d] [--log-lines N]   (the whole log if no --log-lines)
  Users            --users   (the accounts that may sign in to the web GUI)
                   --user-add NAME [--expires YYYY-MM-DD]   (asks for the password)
                   --user-passwd NAME   --user-del NAME
                   --user-grant NAME   (an account that already exists joins the group)   --user-revoke NAME
                   --user-expiry NAME --expires YYYY-MM-DD|never
  Power            --power restart|shutdown [--in MINUTES | --at HH:MM]
                   --power cancel  --power status
                   (restarts or shuts down the whole host; refused while it is the only
                   node serving a gateway unless --yes)
  Modifiers        --yes (no confirmation)  --no-wait (do not wait for a restart)

Per-group settings are managed via --configure or by editing the config
file directly. Each group entry supports:
  group_id, interface, vip4, vip6, priority, lb_method, weight,
  hello_ms, hold_ms, preempt, max_afns, key, neighbors, real_macs, ntp

  vip4: IPv4 VIP with prefix, e.g. 10.0.0.1/24  (required when no vip6)
  vip6: IPv6 VIP with prefix, e.g. 2001:db8::1/64 (required when no vip4)
  neighbors: list of peer IP addresses for unicast mode (optional).
    When present, ntpdir sends hellos directly to each neighbor via unicast
    instead of multicast — required when peers are on different VNIs or
    separated by a routed boundary.
  Every ACTIVE/FORWARD node answers NTP on the VIP through chrony (there is no switch for it).

NTP ("ntp" block at the top level of the config):
  chrony serves the clients; ntpdir tests the upstream servers and gives chrony the ones that pass (see
  the NTP page and --show-ntp).
  servers            upstream NTP servers, e.g. ["10.0.0.123", "10.0.1.123:1123", "ntp.example.com"]
                     (a host name is resolved when the server is probed; the default port is 123)
  fallback_servers   used only while every server in "servers" is down; never probed, always counted as up
  listen_port        UDP port chrony serves on (default 123; written to chrony as "port")
  allowed_clients    networks that may ask, e.g. ["10.0.0.0/8", "192.168.1.5"]; empty (default) =
                     everyone (chrony "allow"); the node itself always may
  client_rate        requests per second one client may send; 0 (default) = no limit (chrony "ratelimit")
  client_burst       how many it may send at once before client_rate applies; 0 (default) = twice the rate, at least 10
  client_action      drop (default) or kod: what chrony mostly sends a client over its rate (the ratelimit leak)
  max_stratum        a server answering with a higher stratum counts as down (default 15)
  max_root_distance_ms  a server whose root distance is larger counts as down (default 1500)
  max_rtt_ms         a server whose round trip is longer is too slow and counts as down (default 500; 0 = off)
  serve_offset_ms    this node serves only while its clock is within this of what chrony measures (default 50; 0 = off)
  max_offset_ms      with three or more servers, one whose clock differs from the median by more than this is
                     a falseticker and counts as down (default 128; 0 = off)
  probe_interval_ms  default 16000    probe_timeout_ms  default 1000
  fail_threshold     consecutive failures before a server is dropped (2)
  server_names       optional names shown under the addresses: {"10.0.0.123": "ntp-a"}
  spread, spread_band, query_timeout_ms, max_attempts, latency_alpha, client_exempt and client_limits are
  still accepted in a file but have no effect: chrony picks among its sources itself and answers the clients.
  Every few seconds the servers that pass are written to /etc/chrony/ntpdir.sources.d/ntpdir.sources and chrony
  re-reads them (chronyc reload sources); a server that stops passing is dropped from there. With none passing,
  chrony keeps the sources it has. The allow, ratelimit and port settings go to /etc/chrony/ntpdir.conf.d/ntpdir.conf
  and chrony is restarted when they change. The installer points chrony at both directories.
A group can have its own servers: put the same keys in a "ntp" block inside the group (that is what the
Topology page writes); groups without one share the top-level block. Every node's chrony uses the servers of
all its gateways together. An explicit "groups": [] means no gateways.

Web GUI ("web" block): everything above is also available in a browser.
  Served over HTTPS (default port 12380). Log in with a system account that
  is a member of the ntpdir group; passwords are checked through PAM (service
  "ntpdir", see contrib/pam.d/). The page follows the system light/dark theme.
  The GUI is always on.      listen   default ":12380"
  group                default "ntpdir"      pam_service  default "ntpdir"
  session_idle_minutes default 30
  max_failed_logins    default 3   wrong passwords ...
  failed_login_window_minutes default 1    ... within this window lock the
  lockout_minutes      default 15  address (and address with user name) out for this long
  min_password_length  default 8   fewest characters of a password set on the Users page
  The certificate is managed with --tls-* / Configure ▸ Web GUI (the old
  cert_file/key_file settings still work and take precedence).
  Pages: Topology (--canvas, --canvas-add/-del: draw gateways and NTP servers
  as circles and squares), Gateways (--show-gateways, --show-neighbors),
  Cluster monitor (--cluster-status), NTP (--show-ntp), Configure (--show-config,
  --configure: form), History (--versions...), Certificate
  (--tls-...), Node (--assert-agc, --node-pause..., --power), Cluster (--cluster-...), Upgrade (--update-...); the ? at the top right
  opens help for the page. Version is in the header. A certificate installed through the GUI/CLI is
  picked up without restarting the GUI.

Config history: every change (GUI, CLI, cluster sync or a hand edit of the
  file) is stored as a version in <state-dir>/versions (newest 200 kept). Any
  version can be compared, downloaded or restored; secrets are hidden in summaries.

Cluster ("cluster" block; management only, independent of the AGC/AFN election):
  listen             default ":12381" (TCP)
  self               address other nodes use to reach this one, e.g. "10.0.0.5:12381"
  sync_interval_sec  default 5
  One node is the primary, the others replicas. Settings shared by the cluster
  (the NTP block, group VIPs/keys/timers, ...) are edited anywhere and applied
  on the primary; interface, priority, weight and the web/cluster blocks stay
  per node. Create a join code on a member (--cluster-token), use it on the new
  node (--cluster-join). Nodes pin each other's certificates and sign requests;
  a code works once for an hour. Promotion is explicit (--cluster-promote), apart from the
  automatic failover (from three members, after 5 minutes) and the hand-over before a planned restart.
  The primary's GUI certificate is replicated to every member.

Updates: upload ntpdir_vN.tgz (or .zip) on any node (--update-upload); the node
  checks it, keeps the source, and each member that is asked to update (or all of
  them with --update-auto on) pulls it from a peer, builds it with its own Go
  toolchain (gcc + PAM headers needed), swaps the binary and restarts - one node
  at a time. A new binary that fails to start is rolled back automatically.

Live reload: the daemon watches the config file via inotify.
  Edit and save ntpdir.conf — changes apply within ~50ms, no restart needed.
  Live fields (no engine restart): priority, lb_method, weight,
    hello_ms, hold_ms, preempt, max_afns, log_level, the whole "ntp" block,
    web group/pam_service/session timeout, web cert/key (only listen restarts the GUI)
  Restart fields (engine restarts, brief per-group disruption):
    interface, vip4, vip6, group_id, key, neighbors, real_macs
  Adding/removing groups: new groups start, removed groups stop cleanly.`

// the cgroup CPU limit applied at start-up (see cpulimit.go)
var (
	cpuQuota float64
	cpuProcs int
	memLimit int64 // the soft memory limit set for the collector (see memlimit.go)
)

func main() {
	cpuQuota, cpuProcs = limitProcsToCgroup() // logged by the daemon only, not by every CLI command
	memLimit = limitMemoryToCgroup()
	if len(os.Args) > 1 && os.Args[1] == "?" {
		fmt.Println(usageText)
		return
	}
	fs := flag.NewFlagSet("ntpdir", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		configure    = fs.Bool("configure", false, "")
		showConfig   = fs.Bool("show-config", false, "")
		showNeigh    = fs.Bool("show-neighbors", false, "")
		showGateways = fs.Bool("show-gateways", false, "")
		showNTP      = fs.Bool("show-ntp", false, "")
		showVersion  = fs.Bool("version", false, "")
		assertAGC    = fs.Bool("assert-agc", false, "")
		conf         = fs.String("config", confPath, "")
		sock         = fs.String("status-socket", statusSocket, "")
		level        = fs.String("log-level", "", "")
		stateDir     = fs.String("state-dir", defaultStateDir, "")
		cli          = registerCLIFlags(fs)
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println(usageText)
			return
		}
		fmt.Fprintln(os.Stderr, "ntpdir:", err)
		fmt.Fprintln(os.Stderr, "try: ntpdir --help")
		os.Exit(2)
	}

	if *showVersion {
		fmt.Println("ntpdir v" + version())
		return
	}

	// pre-v15 installs kept the config in /etc/liras: bring it over once, and never
	// use that location again, even if an old service unit still names it
	if *conf == legacyConfPath {
		fmt.Fprintf(os.Stderr, "ntpdir: %s is no longer used; using %s (update the service unit's --config, or re-run install.sh)\n", legacyConfPath, confPath)
	}
	*conf = canonicalConf(*conf)
	if *conf == confPath && os.Geteuid() == 0 {
		if moved, err := migrateLegacyConfig(confPath, legacyConfPath); err != nil {
			fmt.Fprintf(os.Stderr, "ntpdir: could not move %s to %s: %v\n", legacyConfPath, confPath, err)
		} else if moved {
			fmt.Fprintf(os.Stderr, "ntpdir: moved your configuration from %s to %s and removed the old files\n",
				legacyConfPath, confPath)
		}
	}

	switch {
	case *configure:
		if err := interactiveConfigure(*conf); err != nil {
			fatal(err)
		}
		return
	case *showNeigh:
		showNeighbors(*sock)
		return
	case *showGateways:
		showGatewayTable(*sock)
		return
	case *showNTP:
		showNTPTable(*sock)
		return
	case cli.run(*sock):
		return
	case *assertAGC:
		res := mustStatus(*sock, "assert-agc")
		if ok, _ := res["ok"].(bool); !ok {
			fmt.Printf("assert-agc failed: %v\n", res["error"])
			os.Exit(1)
		}
		for _, m := range res["messages"].([]any) {
			fmt.Println(m)
		}
		return
	}

	_, statErr := os.Stat(*conf)
	configExists := statErr == nil
	created := false
	dc, err := loadConfig(*conf)
	if err != nil {
		fatalf("Configuration error: %v", err)
	}
	if *level != "" {
		dc.LogLevel = *level
	}
	if *showConfig {
		b, _ := json.MarshalIndent(dc, "", "  ")
		fmt.Println(string(b))
		return
	}

	if configExists {
		if err := dc.Validate(); err != nil {
			fatalf("Configuration error: %v", err)
		}
	} else {
		// Absent config: write one with the defaults and no gateways, then start.
		dc.Groups = []GroupConfig{}
		if err := dc.save(*conf); err != nil {
			fatalf("cannot create %s: %v", *conf, err)
		}
		created = true
	}

	setupLogging(dc.LogLevel)
	startLogFile(*stateDir)
	if !created {
		infof("ntpdir starting — %d group(s)", len(dc.Groups))
	} else {
		infof("ntpdir starting — config file %s not found, created it with the defaults", *conf)
	}
	if err := run(dc, *conf, *sock, *stateDir); err != nil {
		fatal(err)
	}
}

func run(dc *DaemonConfig, confFile, sockPath, stateDir string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// kill -USR1 writes every goroutine's stack to the log (the journal): the way to see what a daemon that is up but not
	// answering is stuck on, when its own pages and the troubleshooting bundle cannot be reached
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-usr1:
				warnf("SIGUSR1: every goroutine's stack is written to standard error (journalctl -u ntpdir)")
				fmt.Fprintf(os.Stderr, "--- goroutine dump (SIGUSR1) %s ---\n%s--- end of goroutine dump ---\n", time.Now().Format(time.RFC3339), goroutineDump())
			}
		}
	}()

	// the path of the running binary, taken before any update can replace it
	exe, _ := os.Executable()
	exe = strings.TrimSuffix(exe, " (deleted)")

	mg, err := NewMgmt(confFile, stateDir, dc)
	if err != nil {
		return err
	}
	mg.upd.exePath = func() (string, error) { return exe, nil }
	if mg.upd.GuardOnStart() { // the previous update never stayed up: back to the old binary
		warnf("restarting into the restored previous version")
		return syscall.Exec(exe, os.Args, os.Environ())
	}
	if n := mg.upd.RolledBackNotice(); n != "" {
		warnf("update: %s", n)
	}
	var reexec atomic.Bool
	mg.restartFn = func() { reexec.Store(true); stop() }

	// the saved statistics come back before any query is counted; the last save happens once the NTP frontends have stopped
	savedStats := startPersistence(stateDir, ctx.Done())

	sup := NewSupervisor(ctx, dc)
	sup.StartAll()
	qstats.SetNames(dc.NTP.ClientNames)
	go applySNMP(dc.snmpSettings())
	go memguard.Run(ctx.Done())
	go mg.sched.Run(ctx)

	st := NewStatusServer(sockPath, sup)
	st.mg = mg
	mg.gwIPsFn = func() []string {
		var out []string
		seen := map[string]bool{}
		for _, r := range st.snapshot() {
			if r.Local && r.PeerIP != "" && !seen[r.PeerIP] {
				seen[r.PeerIP] = true
				out = append(out, r.PeerIP)
			}
		}
		sort.Strings(out)
		return out
	}
	mg.gwFn = func() []GwState {
		cfg, snap := sup.config(), st.snapshot()
		gs := gatewayStates(cfg, snap)
		// each gateway's health as this node's own drawing colours it, so the other nodes can show it too
		groups := buildCanvas(cfg, snap, sup.poolList())
		markWarming(groups, sup.warmingGroups())
		markOffnet(groups, sup.offnetGroups())
		off := sup.offnetGroups()
		for i := range gs {
			_, gs[i].Offnet = off[gs[i].GroupID]
			for _, g := range cfg.Groups { // removed from the gateway: it can never serve it either
				if g.GroupID == gs[i].GroupID && containsStr(g.ExcludedNodes, localNodeID()) {
					gs[i].Offnet = true
				}
			}
			for _, g := range groups {
				if g.GroupID == gs[i].GroupID {
					gs[i].Health, gs[i].HealthWhy = g.Status, g.Detail
				}
			}
		}
		return gs
	}
	mg.pausedFn = func() bool { return sup.config().NodePaused }
	mg.anycastFn = sup.AllAnycastStates
	mg.poolOf = sup.poolFor
	mg.tshootFn = func() map[string]any {
		return map[string]any{"canvas": st.canvasGroups(), "ntp-pools": st.ntpStatus(), "gateway-snapshot": st.snapshot()}
	}
	if err := st.Start(); err != nil {
		warnf("status socket unavailable (%s): %v — --show-* commands will not work", sockPath, err)
	}

	var web *WebServer
	reload := func() error {
		nu, err := loadConfig(confFile)
		if err == nil {
			err = nu.Validate()
		}
		if err != nil {
			warnf("Config reload skipped — %v", err)
			return err
		}
		infof("Config file changed — reloading")
		sup.Reload(nu)
		qstats.SetNames(nu.NTP.ClientNames)
		go applySNMP(nu.snmpSettings())
		mg.OnConfigLoaded(nu)
		if web != nil {
			go web.Apply(nu.Web) // async: a listener restart must not wait on the request that triggered it
		}
		return nil
	}
	mg.reloadFn = reload
	web = NewWebServer(mg, st, sysAuth{})
	mg.webH = web.Handler()
	web.Apply(dc.Web)
	defer web.Stop()
	mg.OnConfigLoaded(dc) // first history entry, cluster listener
	defer mg.cl.Stop()
	go mg.cl.Run(ctx)
	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(bootConfirmAfter):
			mg.upd.GuardConfirm(mg.cl.selfAddrForEvents())
		}
	}()
	go certExpiryWatch(ctx, mg)
	w := NewConfigWatcher(confFile, func() { reload() })
	if err := w.Start(ctx); err != nil {
		warnf("config watch unavailable: %v — edits need a restart", err)
	}

	infof("ntpdir running — %d group(s), watching %s", len(dc.Groups), confFile)
	if cpuProcs > 0 {
		infof("CPU limit of %.2f in this cgroup: using %d scheduler threads instead of %d", cpuQuota, cpuProcs, runtime.NumCPU())
	}
	if memLimit > 0 {
		infof("memory: garbage collector soft limit %d MiB", memLimit>>20)
	}
	<-ctx.Done()
	infof("Shutdown signal received")
	st.Stop()
	done := make(chan struct{})
	go func() { sup.StopAll(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		warnf("shutdown timed out")
	}
	savedStats()
	if reexec.Load() {
		web.Stop()
		mg.cl.Stop()
		infof("re-executing %s", exe)
		return syscall.Exec(exe, os.Args, os.Environ())
	}
	return nil
}

// certExpiryWatch logs a warning at start and then daily when the GUI
// certificate has expired or is about to.
func certExpiryWatch(ctx context.Context, mg *Mgmt) {
	for {
		if w := mg.certs.ExpiryWarning(); w != "" {
			warnf("web: %s — replace it under Configure ▸ Web GUI or with ntpdir --tls-install", w)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func fatal(err error)           { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

// ── CLI views ────────────────────────────────────────────────────────────────

func mustStatus(sock, cmd string) map[string]any {
	res, err := statusRequest(sock, map[string]any{"cmd": cmd})
	if err != nil {
		fatal(err)
	}
	return res
}

func decodeData(res map[string]any, v any) {
	b, _ := json.Marshal(res["data"])
	json.Unmarshal(b, v)
}

func showNeighbors(sock string) {
	var rows []SnapshotRow
	decodeData(mustStatus(sock, "snapshot"), &rows)
	peers := peersOnly(rows)
	if len(peers) == 0 {
		fmt.Println("No neighbors.")
		return
	}
	const f = "%-8s %-5s %-42s %-5s %-5s %-7s %-13s %s\n"
	fmt.Printf(f, "GROUP", "AF", "PEER IP", "PRI", "AFN", "WEIGHT", "HELLO avg/max", "STATE")
	fmt.Println(strings.Repeat("-", 90))
	for _, p := range peers {
		state := p.State
		if p.Preempt {
			state += " preempt"
		}
		fmt.Printf(f, itoa(p.GroupID), p.AF, p.PeerIP, itoa(p.Priority), itoa(p.AfnID),
			itoa(p.Weight), helloText(p.HelloAvgMS, p.HelloMaxMS), state)
	}
}

func showGatewayTable(sock string) {
	var rows []SnapshotRow
	res := mustStatus(sock, "snapshot")
	decodeData(res, &rows)
	groups := buildGateways(rows)
	ipNames := map[string]string{}
	if nm, ok := res["names"].(map[string]any); ok {
		for ip, n := range nm {
			ipNames[ip], _ = n.(string)
		}
	}
	nameMembers(groups, ipNames)
	if len(groups) == 0 {
		fmt.Println("No gateway groups.")
		return
	}
	names := map[int]string{}
	if res, err := statusRequestTimeout(sock, map[string]any{"cmd": "canvas"}, 10*time.Second); err == nil {
		var cg []CanvasGateway
		decodeData(res, &cg)
		for _, c := range cg {
			names[c.GroupID] = c.Name
		}
	}
	for _, g := range groups {
		title := fmt.Sprintf("Group %d", g.GroupID)
		if n := names[g.GroupID]; n != "" {
			title = fmt.Sprintf("%s (group %d)", n, g.GroupID)
		}
		fmt.Printf("%s  VIP %s\n", title, g.VIP)
		fmt.Printf("%-18s %-40s %-5s %-5s %-7s %-8s %-10s %-13s %s\n", "NODE NAME", "NODE IP", "PRI", "SLOT", "WEIGHT", "ROLE", "STATE", "HELLO avg/max", "VMAC")
		fmt.Println(strings.Repeat("-", 113))
		for _, m := range g.Members {
			hello, flag := helloText(m.HelloAvgMS, m.HelloMaxMS), ""
			if m.Local {
				hello, flag = "(local)", " *"
			}
			fmt.Printf("%-18s %-40s %-5d %-5d %-7d %-8s %-10s %-13s %s\n", orDefault(m.Name, "-")+flag, m.IP, m.Priority,
				m.Slot, m.Weight, m.Role, strings.ToUpper(m.State), hello, orDefault(m.VMAC, "-"))
		}
		fmt.Println()
	}
	fmt.Println("* = this node")
}

func showNTPTable(sock string) {
	res := mustStatus(sock, "ntp")
	if ok, _ := res["ok"].(bool); !ok {
		fmt.Println(res["error"])
		os.Exit(1)
	}
	var d struct {
		Pools []struct {
			Key     int          `json:"key"`
			Name    string       `json:"name"`
			Groups  []int        `json:"groups"`
			Servers []ServerStat `json:"servers"`
			UsingFB bool         `json:"using_fallback"`
			FailThr int          `json:"fail_threshold"`
			MaxStr  int          `json:"max_stratum"`
			MaxOff  int          `json:"max_offset_ms"`
			MaxRD   int          `json:"max_root_distance_ms"`
			MaxRTT  int          `json:"max_rtt_ms"`
		} `json:"pools"`
		Listeners []string    `json:"listeners"`
		Chrony    ChronyState `json:"chrony"`
		Roll      string      `json:"chrony_roll"`
		Stats     ServerStats `json:"server_stats"`
		Allowed   int         `json:"allowed_clients"`
		Rate      int         `json:"client_rate"`
		Burst     int         `json:"client_burst"`
		Action    string      `json:"client_action"`
	}
	decodeData(res, &d)
	c := d.Chrony
	fmt.Println("time: " + time.Now().UTC().Format("2006-01-02 15:04:05") + " UTC")
	switch {
	case !c.Running:
		fmt.Println("chrony: not running (" + orDefault(c.Err, "no answer") + "); this node cannot serve NTP; in a container, run the installer again so chrony starts with -x")
	case !c.Synced:
		fmt.Println("chrony: running, not synchronised yet (" + orDefault(c.Leap, "no source") + ")")
	default:
		fmt.Printf("chrony: synchronised, stratum %d, to %s, system clock %+.3f ms off, root delay %.2f ms\n", c.Stratum, orDefault(c.Ref, "-"), c.OffsetMS, c.RootDelay)
	}
	if d.Roll != "" {
		fmt.Println("chrony restart (port or rate limit changed): " + d.Roll)
	}
	if len(d.Listeners) == 0 {
		fmt.Println("Serving: (no gateway answers on this node)")
	} else {
		fmt.Println("Serving: " + strings.Join(d.Listeners, ", "))
	}
	if d.Stats.Err == "" {
		fmt.Printf("Requests chrony has handled: %d  dropped: %d\n", d.Stats.Received, d.Stats.Dropped)
	}
	if d.Allowed > 0 {
		fmt.Printf("allowed clients: %d network(s) listed (allowed_clients)\n", d.Allowed)
	} else {
		fmt.Println("allowed clients: everyone (allowed_clients is empty)")
	}
	if d.Rate > 0 {
		fmt.Printf("client rate limit: %d requests/s per client (burst %d), over the limit: %s\n", d.Rate, d.Burst, d.Action)
	} else {
		fmt.Println("client rate limit: off")
	}
	const f = "%-16s %-28s %-9s %-8s %-8s %-11s %-8s %-8s %-8s %s\n"
	for _, p := range d.Pools {
		who := "shared servers"
		if p.Key != 0 {
			who = "gateway " + itoa(p.Key)
			if p.Name != "" {
				who += " (" + p.Name + ")"
			}
		}
		var gl []string
		for _, g := range p.Groups {
			gl = append(gl, itoa(g))
		}
		used := ""
		if len(gl) > 0 {
			used = " (used by group " + strings.Join(gl, ",") + ")"
		}
		fmt.Printf("\n%s%s: a server is out after %d failed probes in a row; usable up to stratum %d, root distance %d ms, %s, %s\n",
			who, used, p.FailThr, p.MaxStr, p.MaxRD, rttLimit(p.MaxRTT), offLimit(p.MaxOff))
		if p.UsingFB {
			fmt.Println("no configured server is in service (down or paused): chrony uses the fallback servers")
		}
		fmt.Printf(f, "SERVER NAME", "SERVER IP", "STATE", "STRATUM", "OFFSET(ms)", "RTT(ms)", "IN CHRONY", "OK", "FAIL", "LAST ERROR")
		fmt.Println(strings.Repeat("-", 140))
		for _, s := range p.Servers {
			state := "down"
			if s.Healthy {
				state = "up"
			}
			if s.Falseticker {
				state = "false"
			}
			stratum, offset := "-", "-"
			if t := s.Time; t != nil {
				stratum, offset = itoa(t.Stratum), fmt.Sprintf("%+.2f", t.OffsetMS)
			}
			addr := s.Addr
			if s.Fallback {
				addr += " (fallback)"
			}
			in := orDefault(s.Chrony, "no")
			fmt.Printf(f, orDefault(s.Name, "-"), addr, state, stratum, offset, fmt.Sprintf("%.2f", s.EWMAMS), in,
				strconv.FormatUint(s.Successes, 10), strconv.FormatUint(s.Failures, 10), s.LastError)
		}
	}
	fmt.Println("\nIN CHRONY: * chrony is synchronised to it, + combined with it, - not combined, ? not reachable, x falseticker, ~ too variable, no = not a chrony source")
}

// ── Interactive configure ────────────────────────────────────────────────────

type prompter struct{ r *bufio.Reader }

func (p *prompter) ask(label, cur string) string {
	fmt.Printf("  %s [%s]: ", label, cur)
	s, _ := p.r.ReadString('\n')
	if s = strings.TrimSpace(s); s != "" {
		return s
	}
	return cur
}

func (p *prompter) askInt(label string, cur int) int {
	for {
		v, err := strconv.Atoi(p.ask(label, strconv.Itoa(cur)))
		if err == nil {
			return v
		}
		fmt.Println("    please enter a number")
	}
}

func yes(s string) bool {
	switch strings.ToLower(s) {
	case "yes", "y", "true", "1":
		return true
	}
	return false
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func interactiveConfigure(path string) error {
	dc, err := loadConfig(path)
	if err != nil {
		return err
	}
	p := &prompter{bufio.NewReader(os.Stdin)}
	fmt.Println("Distributed Gateway Interactive Configuration")
	fmt.Printf("Config file: %s\nPress Enter to keep current value.\n\n", path)

	dc.LogLevel = p.ask("Log level (debug/info/warning/error)", dc.LogLevel)
	fmt.Printf("\nCurrently %d group(s) configured.\n", len(dc.Groups))
	n := p.askInt("How many groups?", len(dc.Groups))
	for len(dc.Groups) < n {
		g := newGatewayGroup()
		g.GroupID = firstGroupID + len(dc.Groups)
		dc.Groups = append(dc.Groups, g)
	}
	if n < len(dc.Groups) && n >= 0 {
		dc.Groups = dc.Groups[:n]
	}
	for i := range dc.Groups {
		g := &dc.Groups[i]
		fmt.Printf("\n  Group %d\n", i+1)
		g.GroupID = p.askInt("Group ID (1-255)", g.GroupID)
		g.Interface = p.ask("Interface", g.Interface)
		g.VIP4 = blankable(p.ask("IPv4 VIP/prefix (e.g. 10.0.0.1/24, '-' to disable)", orDash(g.VIP4)))
		g.VIP6 = blankable(p.ask("IPv6 VIP/prefix (e.g. 2001:db8::1/64, '-' to disable)", orDash(g.VIP6)))
		g.Priority = p.askInt("Priority (0-255)", g.Priority)
		g.HelloMS = p.askInt("Hello interval ms", g.HelloMS)
		g.HoldMS = p.askInt("Hold time ms", g.HoldMS)
		g.MaxAFNs = p.askInt("Max active forwarders (1-255)", g.MaxAFNs)
		fmt.Println("    LB methods: roundrobin, weighted, hostpinned, failover")
		for {
			m, err := parseLB(p.ask("LB method", g.LBMethod.String()))
			if err == nil {
				g.LBMethod = m
				break
			}
			fmt.Println("   ", err)
		}
		g.Weight = p.askInt("Weight (weighted mode)", g.Weight)
		g.Preempt = yes(p.ask("Preemption enabled? (yes/no)", yn(g.Preempt)))
		g.RealMACs = yes(p.ask("Use real MAC addresses instead of virtual MACs? (yes/no; for VMware port groups that are not promiscuous or clouds that allow one MAC per interface)", yn(g.RealMACs)))
		g.Key = p.ask("HMAC-SHA256 shared key", g.Key)
	}
	if len(dc.Groups) > 0 {
		fmt.Println("\n  NTP")
		servers := p.ask("Upstream NTP servers (comma separated)", strings.Join(dc.NTP.Servers, ","))
		dc.NTP.Servers = splitList(servers)
		dc.NTP.FailThreshold = p.askInt("A server is down after this many failed probes in a row", dc.NTP.FailThreshold)
		dc.NTP.ListenPort = p.askInt("NTP port chrony serves on", dc.NTP.ListenPort)
	}
	if err := dc.Validate(); err != nil {
		return fmt.Errorf("not saved: %w", err)
	}
	if err := dc.save(path); err != nil {
		return err
	}
	fmt.Printf("\nConfiguration saved to %s\n", path)
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func blankable(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// offLimit words the falseticker limit for --show-ntp.
func rttLimit(ms int) string {
	if ms <= 0 {
		return "round trip not checked"
	}
	return fmt.Sprintf("round trip up to %d ms", ms)
}

func offLimit(ms int) string {
	if ms <= 0 {
		return "falseticker check off"
	}
	return fmt.Sprintf("a falseticker beyond %d ms", ms)
}

// helloText is a peer's measured hello gaps as "average/largest" in ms, "-" before two hellos have arrived.
func helloText(avg, max int64) string {
	if avg <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", avg, max)
}

# Changelog

## [v125] - 2026-10-18 — One BGP switch, in Operate only

### Removed
- The Enabled box for BGP as a whole in Configure ▸ Anycast (added in the previous version): switching BGP off and on stays under Operate ▸ Anycast ▸ Disable BGP. The Enabled box on each neighbor's row stays.

## [v124] - 2026-10-18 — BGP on/off switch in Configure ▸ Anycast

### Added
- **An Enabled box in Configure ▸ Anycast** turns BGP off and on for this node, with a confirmation when switching it off. It does what Disable / Enable BGP under Operate ▸ Anycast does: every setting is kept, no session is started and no anycast address is announced. It is greyed out until a local AS number is set.
- **An Enabled box on each neighbor's row** shuts that one session down and back up (a confirmation when switching it off), the same as Disable / Enable in Operate ▸ Anycast. The neighbor and its settings stay; editing a neighbor does not change whether it is enabled.

## [v123] - 2026-10-18 — Gateways are listed alphabetically

### Changed
- **The gateways under Topology are listed in alphabetical order** (by the name shown, numbers in natural order so 10.0.0.2 comes before 10.0.0.10), instead of in the order they were created. The first one in the list is the one opened when none was chosen.

## [v122] - 2026-10-18 — Server statistics of a gateway this node does not serve

### Fixed
- **Statistics for a server on a gateway this node is not part of said "Nothing recorded for this server yet"**: a node probes only the servers of the gateways it serves, so it has no history of the others. When the node you are looking at has none, it now asks the other nodes that do and shows their history added together, with the line "Counted on N other node(s) (this node does not probe it)" above the graphs (`--server-stats` too). The history a node has itself is shown as before. The cluster call that fetches the buckets now answers for a server or a domain as well as a gateway; a node on an older version does not answer it and is counted as not answering.

## [v121] - 2026-10-18 — The sign-in lockout and minimum password length are replicated

### Changed
- **Configure ▸ Web: failed logins before lockout, the window they count in, how long the lockout lasts, and the minimum password length are shared settings**: set on any node, the primary replicates them, so the same rules hold on every node (like the login groups). While all four are the defaults (3 in 1 minute, locked for 15 minutes, 8 characters) nothing is replicated and the document's hash is unchanged, which keeps a rolling update in agreement; any other value is replicated. A node that receives none, from an older primary, keeps its own. Update every node before changing them.

## [v120] - 2026-10-18 — The login groups are replicated in a cluster

### Changed
- **Configure ▸ Web ▸ Login groups (`web.group`) is a shared setting**: set on any node, the primary replicates it, so the same people can sign in on every node. A cluster whose login group is still the single `ntpdir` that every earlier version had shares nothing (the replicated document, and so its hash, is unchanged, which keeps a rolling update in agreement); any other value is replicated. A node that receives no value, from an older primary, keeps its own. Update every node before changing it: a node on an older version ignores the setting.

## [v119] - 2026-10-18 — AD sign-in in a container: the ID range is set

### Added
- **In an unprivileged container (LXC, Proxmox) Active Directory users could not sign in, because sssd made their IDs from 200000 up and the container only has IDs up to 65535**: at start, when `/proc/self/uid_map` shows such a container and an AD domain in `sssd.conf` has no `ldap_idmap_range_*` and does not turn ID mapping off, the daemon adds `ldap_idmap_range_min = 10000`, `ldap_idmap_range_max = 60000` and `ldap_idmap_range_size = 50000` to that domain's section, stops sssd, deletes its cache (`/var/lib/sss/db`, `/var/lib/sss/mc`: the IDs it made are kept there) and starts it again. This is done together with the group-policy mapping, with one backup of the file (`sssd.conf.ntpdir.bak`) and one restart. A range you set yourself is left alone; a container with fewer than 60000 IDs, or a domain defined only in a `conf.d` snippet, only gets a warning in the log. A host or virtual machine is not touched. The README (*Signing in with Active Directory*) and the help explain it; use the same range on every node.

## [v118] - 2026-10-18 — Help: signing in with Active Directory

### Changed
- **Help (Users)**: a new *Active Directory* part with the steps (join, directory group `ntpdir-users`, Login groups, group policy mapping, checks). No other change.

## [v117] - 2026-10-18 — README: signing in with Active Directory

### Changed
- **README**: a new section, *Signing in with Active Directory*, covers joining the node with sssd, the sssd settings, the directory group (`ntpdir-users`) next to the local one in **Login groups**, the group policy mapping the daemon adds, the checks to run from the shell and what the log messages mean. No code change.

## [v116] - 2026-10-18 — Several login groups: a local one and a directory one

### Changed
- **Login group takes a list**: `web.group` (Configure ▸ Web ▸ Login groups) may name several groups separated by commas, and a member of any of them may sign in. The default for a new configuration is `ntpdir,ntpdir-users`: `ntpdir` is the local group the Users page manages and `ntpdir-users` is meant for a group in Active Directory, so the directory group cannot be hidden by a local group of the same name. A group that does not exist on a node is skipped (the log warns only when none exists). The Users page, the command line and the installer keep working with the first login group that is local. An existing configuration is not changed.

## [v115] - 2026-10-18 — sssd.conf is fixed at start; directory accounts can be added to the group

### Added
- **The daemon now adds the mapping to sssd.conf itself**: at start (and whenever the web listener is set up again) it checks sssd.conf and, when an AD domain enforces group policy and has no mapping for the PAM service, adds `ad_gpo_map_interactive = +ntpdir` to that domain's section (an existing line gets `, +ntpdir` appended), keeps the old file as `sssd.conf.ntpdir.bak` (once) and runs `systemctl try-restart sssd`. A node where it is already mapped, or has no sssd, or has a domain that is not AD, is left alone; a domain defined only in a `conf.d` snippet is not edited and the log says what to add. The file keeps its owner and mode.
- **Users: an account from a directory can be added to the group**: "Add an existing account" accepts Active Directory / LDAP names (upper case, dots, `@`, `DOMAIN\\name`) and adds them to the local ntpdir group with `gpasswd -a`, which works where `usermod` refused them; the other nodes do the same. Such an account's password and expiry are kept in the directory, so those buttons refuse it with a message; Remove from the group works as for any account.

## [v114] - 2026-10-18 — Active Directory logins through sssd: the daemon now says what is wrong

### Added
- **A GUI login of an Active Directory user (Samba AD, Windows AD, `realm join`) failed with "pam: Permission denied" although ssh worked**: sssd enforces the domain's group policy and refuses a PAM service it has no logon right for, which includes `ntpdir`. The log now tells the two PAM steps apart (`authentication failed: pam account check (password accepted): ...` means the password was right and the account was refused), and when sssd.conf shows an AD domain with enforced group policy and no mapping for the service, the daemon says so at start and on the failed login, with the line to add: `ad_gpo_map_interactive = +ntpdir` in the domain's section, then restart sssd. The README and the help (Settings, PAM service) have the same advice. Nothing in sssd.conf is changed by the daemon.

## [v113] - 2026-10-18 — AND and OR in the Log filter

### Changed
- **Monitor ▸ Log: the filter takes AND and OR**, like the Statistics filters: `error OR warn` shows lines with either, `dns AND timeout OR ntp` is (dns and timeout) or ntp, AND binding first. Words with no operator are still all required, in any order, and any case, so existing filters give the same lines.

## [v112] - 2026-10-18 — A wider filter box with AND and OR

### Changed
- **The filter boxes of Top Clients and Top Servers are twice as wide, and take AND and OR**: `ubuntu AND ntp` keeps what contains both, `ubuntu OR debian` what contains either; AND binds first, so `a AND b OR c` is (a and b) or c. The words may be in any case. A client matches a word by its address, its name or any of its host names, and each word may be found in a different one of them. Text with no operator is looked for as typed, as before. The longest text is now 200 characters.

## [v111] - 2026-10-18 — Ctrl-click several clients or servers

### Added
- **Statistics: Ctrl-click (Cmd-click on a Mac) adds more rows to a picked client or server**: pick several clients and the list beside them shows what any of them asked for (counts added together); pick several servers and it shows who asked for any of them. Ctrl-click a picked row again to take it off; a plain click picks that row alone, and clicking the only picked row clears it. The picks travel as a comma-separated list in the existing `client` / `server` parameters (up to 100), so the CLI takes the same.

## [v110] - 2026-10-18 — The whole list for a picked server or client

### Changed
- **Picking a server in Top Servers (or a client in Top Clients) lists up to 5000 entries, not 500.** The pairs are on disk since v109, so the lists can be that long; the ordinary top lists stay at 500. In a cluster each node sends up to 5000 and the merged list keeps 5000.
- Names (reverse DNS) are looked up for the first 500 rows only, so a long list does not queue lookups for minutes; the rest show their names once they are known from the lookups of other lists.

## [v109] - 2026-10-18 — Who asked for what is kept on disk, all of it

### Changed
- **Picking a domain in Top Domains (or a client in Top Clients) now lists every client (or domain), not the first few and "(others)".** The (client, domain) pairs behind it are no longer a capped table in memory: each 10-minute unit is written to its own file, `<state-dir>/pairs/p<unit>.gz` (gzip, a string table and varint rows, private to root), and read back only when you pick something. The 30 days of the statistics are kept; older files are deleted as new ones are written. A unit stops taking new pairs after 400,000 (a flood of random names), and what it could not keep still shows as "(others)". Memory for the statistics drops by what the pair tables took, and the open unit's pairs are saved with the statistics every five minutes and at stop.
- **Clear removes the pair files too**, with the rest of the statistics.
- The pairs the earlier versions had saved in `stats.json.gz` are moved into the new files at the first start; from then on the file does not hold them. Pairs already dropped by the old caps are not recoverable: the lists fill in properly from this version on.
- Replaces the larger pair caps of v456.

### Notes
- Disk use grows with the number of distinct pairs: roughly 5 bytes per pair per 10-minute unit before compression, so a busy server can use hundreds of MB over 30 days (an estimate, not measured).

## [v108] - 2026-10-18 — Gateways in the Node menu of Host

### Added
- **Monitor ▸ Host offers the gateways in the Node menu too**, as Statistics does: the nodes that serve the gateway, added together (`gw` on `/api/clusterhost`).

## [v107] - 2026-10-18 — Gateway entries in the Node menu

### Changed
- **A gateway in the Node menu of Statistics reads "Gateway ptx.int (4)"**, the number of nodes in brackets as Cluster has it, not "(4 nodes)".

## [v106] - 2026-10-18 — Packaging only

### Changed
- No code change from the previous version. The source archive no longer carries a compiled program by mistake.

## [v105] - 2026-10-18 — Node menu order on Statistics

### Changed
- **The Node menu on Statistics lists the nodes first, then the gateways, then Cluster last.**

## [v104] - 2026-10-18 — Who asked for a domain: more of them listed

### Changed
- **Picking a domain in Top Domains (or a client in Top Clients) showed most of the answer as "(others)".** Each 10-minute slot kept only the first 500 client / domain pairs, so on a busy server everything after them was lumped together. A short-range slot (up to the last day) now keeps up to 3000 pairs and an hour slot (longer ranges) 1000; the failure kinds scale the same way. Memory for the statistics grows with it (up to roughly 100 MB when every slot is full). A pair beyond the cap is still counted under "(others)", so on a very busy server some of it can remain.

## [v103] - 2026-10-18 — Gateways in the Node menu of Statistics

### Added
- **Monitor ▸ Statistics: the Node menu lists each gateway after Cluster** ("Gateway ptx.int (2 nodes)"). It shows the statistics of the nodes that serve that gateway (every node except those removed from it) added together, the way Cluster adds all of them. The numbers are kept per node, not per gateway, so a node that serves several gateways counts all of its traffic in each. Clear is not offered for a gateway (pick the node or Cluster). `gw` on `/api/clusterstats`. `TestGatewayNodesSkipsTheRemovedOnes`.

## [v102] - 2026-10-18 — Statistics page error fixed

### Fixed
- **Statistics showed "partialLast is not defined"** (v101): the helper that leaves the unfinished last step out of the charts was declared inside one function and used by another. It is now declared once where both can see it.

## [v101] - 2026-10-18 — No false drop at the end of the charts

### Fixed
- **The time charts (Statistics, and the per-gateway and per-server charts) no longer end in a drop to nearly nothing.** The last point was the step still in progress, holding only the part of it that has passed. It is now left out until it is complete.

## [v100] - 2026-10-18 — Controller mark on a node whose gateway is drawn from it

### Fixed
- **The topology drawing could leave the controller dot off the only node of a gateway.** For a gateway the signed-in node does not serve, the picture is taken from a node that does, and that node's own entry was matched to nodes by address only; when the address on the gateway subnet is not one the signed-in node knows for it, no node got the dot even though Monitor ▸ Gateways showed it as the controller. The serving node's own entry is now flagged (`via_local`) and matched to that node directly. `TestTakeFromClearsLocalOnMembers` checks the flag.

## [v99] - 2026-10-18 — The log filters stay when the node changes

### Changed
- **Monitor ▸ Log keeps its filter words, level, time range, number of lines and the Live box when another node is picked** (or another page and back), and applies them to the new node's log. They were reset to the defaults each time. They are kept until the page is reloaded.

## [v98] - 2026-10-18 — The Age column is gone

### Changed
- **Monitor ▸ Gateways and the CLI tables no longer have an Age column** (the time since the last packet at the instant of the refresh, a random point inside the hello gap). `Hello avg / max` replaces it, and its maximum now counts a silence still in progress, so a node that has gone quiet shows a growing maximum at once instead of only when its next hello arrives. `--show-neighbors` prints the same column. `age_ms` stays in the API.

## [v97] - 2026-10-18 — Live hello timing

### Added
- **Monitor ▸ Gateways shows what each peer's hellos really do**: `Hello avg / max (ms)` is the average gap between the peer's hellos and the largest gap in the last 30 to 60 seconds, measured on this node from the hellos that arrive (the configured interval is in the gateway's edit form). `--show-gateways` prints it as `HELLO avg/max`; the gateway snapshot has `hello_avg_ms` and `hello_max_ms`. A maximum near the hold time means hellos are being lost or delayed. `TestHelloGapStats`.

### Notes
- It is measured by this node, so each node can show different numbers for the same peer; a gap seen here may be a lost frame or a stall on either side.

## [v96] - 2026-10-18 — Faster gateway timers; hello can no longer exceed hold

### Changed
- **New gateways start with hello 150 ms and hold 750 ms** (were 333 and 999): a lost hello or two no longer matters (hold is five hellos) and a dead node is noticed in under a second. Gateways that already exist keep the values they have; change them under the gateway's edit dialog or with the CLI.
- **`hello_ms` larger than `hold_ms` is refused** (in the form, the CLI and a loaded configuration), because the neighbour would be declared gone between two hellos. `TestHelloNotLargerThanHold`.

### Notes
- A configuration file that already has hello above hold is now refused when loaded; fix it by lowering hello or raising hold.

## [v95] - 2026-10-18 — Menu order

### Changed
- The menu groups are now in the order Topology, Configure, Operate, Monitor (Monitor was second).

## [v94] - 2026-10-18 — A node no longer probes the servers of gateways it was removed from

### Fixed
- **A node removed from a gateway (`excluded_nodes`) still probed that gateway's NTP servers** and used them as time sources for its own chrony: a node serving only `phx` logged `europe.pool.ntp.org` and `in.pool.ntp.org` going up and down, and its chrony sources listed them. The pools now start only for the gateways the node has not been removed from. A node removed from every gateway has no pool at all, and so no NTP server for its own chrony either (its chrony is given no sources, as for a topology with no server at all, until the node is put back on a gateway). `TestPoolsSkipExcludedGateways`.

## [v92] - 2026-10-17 — Months in two even rows

### Changed
- The `Only in` months are laid out as two rows of six (Jan to Jun, Jul to Dec) instead of wrapping wherever the width ran out.

## [v91] - 2026-10-17 — Scheduler column headings

### Changed
- The scheduler table's headings read `Next run` / `Last run` with `(this node)` on a second line, instead of wrapping in the middle of the phrase.

## [v90] - 2026-10-17 — Only in these months

### Added
- **Daily, weekly and monthly tasks can be limited to months of the year** (`months`, 1 to 12; the form's `Only in` row has a box for each month, none ticked meaning every month). A task for the 2nd or 3rd Saturday or Sunday, 01:00 to 06:00, April to October is now one task. All twelve ticked is saved as none; the field is dropped from other frequencies; the description ends with e.g. `April to October`. `TestMonthsLimitATask`.

### Notes
- A node on an older version ignores `months` and would run the task in every month until it is upgraded.
- Not seen in a real browser; not tried on a live multi-node cluster.

## [v89] - 2026-10-17 — The online update is for one node when auto-update is on

### Changed
- **With auto-update on, the `Update from online` task is for one node of a cluster.** The task fetches the newest release and stages it on the node it runs on; with auto-update on, every other node then updates itself from that. On every node, each would fetch the release itself and queue its own update outside the cluster's one-at-a-time order. So in the task form, when the action is `Update from online`, auto-update is on and the cluster has more than one node, `Runs on` offers only one node at a time (this node is the default) and no `Every node`. The server refuses the task for every node (or for several) in the same situation, with a message that says what to do. A cluster of one node, or auto-update off, is not asked anything.
- The scheduler's status says whether auto-update is on (`auto_update`), which is how the form knows. `TestOnlineUpdateNeedsOneNode`; the help says it.

### Notes
- Nothing is checked for a task saved before this version, or when auto-update is turned on after the task was made: it keeps its nodes until it is edited.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64; `node --check` on `app.js` and `help.js`.
- One `-race` run of the dnsdir tests failed in a test whose name I did not capture; the next run passed. The tests that look for a free port and bind it later (`freeAddr`) are known to lose the port now and then; not changed here.

### Not verified
- The task form in a browser, and the refusal on a real cluster with auto-update on: the rule is covered as a function (`onlineUpdateNeedsOneNode`), not through two clustered nodes.

## [v88] - 2026-10-17 — Clearing a To time now clears it

### Fixed
- **Removing the To time of a task and saving kept the old window.** The task form sent back the window the server had worked out from the To time (4 hours for 09:00 to 13:00, say), so the task came back with a To time again and it had to be removed a second time. A task that has a To time now sends no window when To is cleared.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race` for the web, session, scheduler and help tests, `node --check` on `app.js`. The full suite was not run again: only `app.js` changed since v87, which passed it.

### Not verified
- The fix itself in a browser: the form is JavaScript with no test; checked by reading the code path (the stored window is dropped when the task has a To time).

## [v87] - 2026-10-17 — One of those days, chosen per node

### Added
- **A monthly or yearly task that names several days (the 1st or 2nd Friday or Saturday) can run on one of them, a different one on each node.** In the task form, `run on` has a third choice, `one of those days, chosen per node` (`"pick_day": true` in the settings). Each node takes one matching day of the month, worked out from the node, the task and the month, so a node keeps its day all month and the nodes do not all act on the same day. `At` and `To` still set the time of day. Before, the choices were the first of those days (every node on the same day) or each of them (every node on every one).
- The task list says it as `one day per node out of the 1st, 2nd, 3rd or 4th Sunday or Saturdays`. The next-run time shown is the node's own. `TestPickDayPerNode`; help and README say it.

### Notes
- The day is picked by a hash, not handed out in turn, so with few nodes two can land on the same day. Nodes on the same day run it at the same time unless `To` spreads them.
- A cluster of mixed versions: a node older than v87 does not know `pick_day` and runs the task on the first of the days.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64; `node --check` on `app.js` and `help.js`.
- One run of the `CGO_ENABLED=0` tests in dnsdir failed in `TestRegisterHostNameSigned` ("bind: address already in use"): a test that looks for a free port and binds it afterwards, which can lose the port to another test. It passed on the next run. Not changed here.

### Not verified
- The task form was not looked at in a browser, and the day choice was not seen across a real cluster. The mixed-version behaviour above is from reading the code, not tried.

## [v86] - 2026-10-17 — Version bump to test the page reload

### Changed
- Nothing but the version number, so an open page loaded from v85 can be seen reloading itself after the upgrade.

### Verified
- `go build`, `go vet`, gofmt, and the web tests (`go test -race -run 'Web|Security|Session' ./...`). The full suite was not run again: only `VERSION` and this file changed since v85, which passed it.

### Not verified
- The reload in a browser.

## [v85] - 2026-10-17 — The web page reloads itself after an upgrade

### Added
- **An open web page reloads itself after an upgrade.** The daemon puts its version into `app.js` when it serves it. The page asks the daemon for its session (the same call it makes when it loads) every 15 seconds while the tab is visible, and again after a login; when the version differs from the one the page was loaded with, it reloads. It waits while a dialog is open, a text field or list has the keyboard, or a Configure page is open (it may hold changes not yet saved), and tries again every 3 seconds. While the daemon restarts the check simply fails and tries again later.
- `TestSecurityHeadersAndStatic` also checks that `app.js` carries the daemon's version.

### Not verified
- The reload itself was not seen in a browser, and not across a real upgrade; only that the served file carries the version and the script parses. A page open on a version older than this one still needs one manual refresh to get this behaviour.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64; `node --check` on `app.js`.

## [v84] - 2026-10-17 — Local time box also changes next run and last run

### Changed
- The `Local time` box on the scheduler's History header now switches **every** time on the page: the next run and last run of the task list as well as the history. Before it changed the history only. Unticked, all of them are UTC.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64; `node --check` on `app.js` and `help.js`.

### Not verified
- The page was not looked at in a browser.

## [v83] - 2026-10-17 — One-time tasks

### Added
- **Once** in the scheduler's How often list: a task that runs one time, on a date you pick (UTC) at the time of day you set, with the same optional To window as the other frequencies. It is shown in the task list as `once on 2026-11-14 at 03:30` (or `between 03:30 and 05:00 UTC`) and does not come round again. dnsdir has had it for a long time; the code is the same.
- `TestOnceRunsOnlyOnItsDate`; help and README name it.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64; `node --check` on `app.js` and `help.js`.

### Not verified
- The task form was not looked at in a browser, and a one-time task was not run live on a cluster.
- A cluster of mixed versions: a node older than v83 does not know `once` (its check refuses the frequency), so update every node before adding a one-time task. What an old node does with the task was not tried.

## [v82] - 2026-10-17 — The offset window is gone: At and To are the window

### Changed
- **The task form has no Offset window.** `At` is when the task is due and `To` (optional) ends the window: each node runs it at a time of its own between the two, the same as before. Without `To` every node runs it at `At`. The offset only said the same thing a different way.
- **An hourly task can have a To minute** (`At minute` and `To minute`, both minutes past the hour). The window is at most 59 minutes, and the next hour when To is earlier than At; To equal to At is refused. Shown in the task list as `every hour between minute 10 and minute 40`.
- **Tasks saved by an older version keep working.** The server still reads `window_sec`. The form shows an offset window of whole minutes (under a day, under an hour for an hourly task) as its To time; one that does not fit (several days, or odd seconds) is kept as it was until the task gets a To time.
- Help and README say it in terms of At and To.

### Added
- `TestHourlyToMinute`.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64; `node --check` on `app.js` and `help.js`.

### Not verified
- The task form was not looked at in a browser; the offset-to-To conversion in the form is JavaScript with no test.

## [v81] - 2026-10-17 — The online update task names the release once

### Fixed
- The history line of the **Update from online** task said the release twice (`v80 (v80) staged; ...`, and `newest release v80 (v80)` when up to date). It now says `v80 staged; this node is queued to update (running v78)`. The version in brackets is shown only when it differs from the tag. Added `TestReleaseNameSaysItOnce`.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64.

### Not verified
- A real online update was not run (no network access to GitHub from the build sandbox); the message is covered by the unit test only.

## [v80] - 2026-10-17 — Shorter task names in the scheduler's "Does" list

### Changed
- The notes in brackets are gone from the task names in the **Does** list (`Update from online`, `Reboot this node`). The help now says what they said: a restart or reboot waits until it is safe for the node to go down, and the online update installs the newest release only when it is newer than the one running.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64; `node --check` on `help.js`.

### Not verified
- The page was not looked at in a browser.

## [v79] - 2026-10-17 — Scheduler page: UTC times, Local time box, cleaner forms

### Changed
- **The scheduler page shows times in UTC**, the zone the schedules are set in (the task times were UTC but the run times followed the browser, which was confusing). The next-run and last-run times of the task list are always UTC, and each says `UTC`.
- **A `Local time` box on the right of the History header** shows the history's times in this browser's time zone instead. The choice is kept in this browser.
- **Runs on** lists the node names, or `every node`; the `(this one)` after this node's name is gone.
- **The task form hides Offset window** while a To time is filled in (the window is then At to To, so the offset was not used; before, the field was greyed out).
- **Three hints are gone** (under the task list, under the offset window, under the shell command); the help now says them: the right-click menu, UTC times and the Local time box, how the window works with a To time and a node that was off, and how a shell command runs.
- A little more space between the weekday boxes and the "of the month, run on" line in the task form.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64; `node --check` on `app.js` and `help.js`.

### Not verified
- The page was not looked at in a browser.
- `--schedule` and `--schedule-history` on the command line still print the machine's local time; not changed.

## [v78] - 2026-10-16 — Gateway messages cannot be replayed; keys; crash safety net; fuzz targets

### Changed
- **Protocol version 3: a signed timestamp in every gateway message.** The message grew from 79 to 87 bytes. The 8-byte Unix-millisecond time sits under the HMAC. A receiver drops a message more than 30 seconds off its own clock, and a message from a sender that is not newer than the last one it took from that sender, so a recorded message can no longer be replayed to win an election or move the virtual address. The table of senders is bounded (4096). A skewed clock is logged once a minute per sender.
- **Version 2 nodes and version 3 nodes do not hear each other.** During a rolling update the two halves each see no peer and may both take the controller role until all nodes are updated. Update all nodes of a gateway within a short window.
- **A gateway you add (GUI, `--canvas-add`, `--configure`) gets a random 128-bit key** instead of `ntpdir`. Existing gateways and the first-start default keep their key, so nothing running changes key.
- A well-known or short (under 12 characters) key is logged at start-up, flagged in the GUI beside the key field, and flagged in the CLI canvas listing. It is a warning, not a refusal.

### Added
- **Crash safety net.** A panic in a gateway packet, a DNS/NTP query handler, a probe goroutine or a raw responder is logged with its stack (at most once a second) and the daemon carries on, instead of the process dying.
- **Fuzz targets** in `fuzz_test.go` (parsers, the gateway packet and frame handling), with a two-second slow-input check. Run with `go test -fuzz=<name>`.
- Tests for replay, stale and future stamps, the sender table bound, weak keys, random keys and panic containment.
- README section "The gateway key, clocks and replay" and a rewritten help entry for the shared key.

### Fixed
- Anyone on the network who knew the key (or the default one) could replay captured gateway messages. See above.

### Wire change
- **Golden vectors are new**: `testdata/testdata_v4.hex` and `testdata_v6.hex` are protocol 3 (stamp 2026-10-16T12:00:00Z). The protocol 2 vectors are kept as `testdata_proto2_v4.hex` and `testdata_proto2_v6.hex` and are tested as refused.

### Verified
- gofmt clean, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, cross-builds for linux/amd64, arm64, arm, 386, riscv64.

### Not verified
- No live multi-node election or rolling-update test (no `ip`/network namespaces in the build sandbox).
- Cluster key push, PAM login, the installer and the GUI were not run live; the GUI change was not looked at in a browser.
- Non-amd64 cross-builds use the PAM stub.

## [v77] - 2026-10-16 — Memory, CPU and disk tuning

### Changed
- **One `chronyc` run per look instead of two.** The daemon reads chrony's state every two seconds, which was two forks and execs (`tracking`, then `sources`). It is now one run, `chronyc -c -m tracking "sources -n"`: the sources stay numeric as before and tracking still names the reference. If the combined run fails, the two are asked for one at a time as before, so a chrony that answers one and not the other reads as it did.
- **Garbage collector soft memory limit.** At start-up the daemon sets a soft limit of 75% of the cgroup memory limit or, without one, of the machine's memory (`memlimit.go`; a `GOMEMLIMIT` in the environment wins). Garbage on a big heap (30 days of statistics) counted as memory in use and could make the memory guard drop statistics that were not a problem. It is soft: the collector never takes more than half the CPU to keep to it. Logged at start-up.
- **Cheaper statistics saves.** `stats.json.gz` is compressed at gzip's fastest level, and the save made by the five-minute timer no longer fsyncs before the rename (the saves before a stop, a restart and an update still do). The file format is unchanged and old files still load.
- **`/proc/cpuinfo` is read once** for the core count instead of at every host sample (every 10 seconds).

### Added
- `TestSoftMemLimit`, and a fallback case in the chrony state test.

### Not changed
- ntpdir has no answer cache (chrony answers clients), so the cache changes made to its sibling dnsdir do not apply.

### Verified
- `gofmt -l .` empty, `go build`, `go vet ./...`, `go test -race -count=1 ./...` and `CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...` all pass (native amd64 with PAM headers).
- Cross-compiled for linux/amd64, arm64, arm, 386 and riscv64.
- Live run against a real private `chronyd -x` (chrony 4.5) with two stub NTP servers on `lo`: the sources were written and chrony took both; the combined call returned tracking and the sources together; killing one stub removed it from `chronyc sources` and the log said "sources now 127.0.0.2"; `--show-ntp` showed chrony synchronised and the IN CHRONY column; `stats.json.gz` was written.

### Not verified
- No load measurement, so the gain from fewer forks, the memory limit and the faster saves is not measured.
- Serving clients through chrony was not tested (the private chronyd had its NTP port off). Chrony versions before 4.0 were not tried; `-m` has been in chronyc for a long time but was only run against 4.5.
- The cluster, web GUI, PAM, installer and BGP paths were not touched and not re-run live. Cross-compiled targets other than amd64 build the PAM stub.

## [v76] - 2026-10-16 — Scheduler: first day or each day

### Added
- A monthly or yearly task that names several occurrences or weekdays has a new choice, **run on: first of those days only / each of those days**. The first is the v75 behaviour (once a month); *each* runs on every matching day, so *the 2nd or 3rd Saturday or Sunday* can run on all four. The list describes the task as "the first of the…" or "each of the…". Saved as `"each_day": true`.

## [v75] - 2026-10-16 — Scheduler: once a month

### Fixed
- A monthly or yearly task set to several occurrences and weekdays, such as *the 2nd or 3rd Saturday or Sunday*, ran on every one of those days (four times a month). It now runs **once** in the month, on the first of the days that match; the *At* to *To* window still spreads the nodes. A single occurrence and weekday behaves as before.

## [v74] - 2026-10-16 — Scheduler: one minute apart

### Changed
- The gap used to stagger jobs is now 1 minute instead of 30 seconds: between the nodes of *Run now on… ▸ all nodes* (a reboot needs longer than 30 seconds), and between jobs whose windows overlap on a node (a smaller gap when a window is too small to fit them).

## [v73] - 2026-10-16 — Scheduler: run now on all nodes

### Changed
- The right-click entry *Run now on this node* is now a sub-menu, **Run now on… ▸ this node / all nodes**. *All nodes* asks each node the task is for to run it now, one after another 30 seconds apart in node-ID order; each node queues it behind whatever it is running. A node that already has the task running or waiting says so in the result. The sub-menu works with the mouse and with the arrow keys.

## [v72] - 2026-10-16 — Scheduler: one job at a time

### Changed
- Only one scheduled job runs at a time on a node. A job that falls due while another is running waits in a queue (kept across a restart, first come, first served) and starts as soon as the previous one has finished, however late that is. The task table shows *waiting for another task*. *Run now* is refused while a job is running. A task whose own previous run is still going or waiting skips its next occurrence, as before. The 30-second staggering of overlapping windows stays; it only makes it less likely that jobs queue behind each other.

## [v71] - 2026-10-16 — Scheduler: no Paste button

### Removed
- The Paste button next to New task on the Scheduler page. Paste is in the right-click menu (on a task or on the empty table).

## [v70] - 2026-10-16 — Scheduler: no seconds

### Changed
- The At field of a task takes hours and minutes only (it showed seconds). Tasks saved with seconds keep them.

## [v70] - 2026-10-16 — Scheduler: no seconds, history stays open

### Changed
- The At field of a task takes hours and minutes only (it showed seconds). Tasks saved with seconds keep them.

### Fixed
- An expanded output in the scheduler history closed again after a few seconds, when the page refreshed. It stays open until you close it, and the page no longer redraws when only the clock has moved.

## [v69] - 2026-10-16 — Scheduler: overlapping tasks are staggered

### Changed
- Tasks whose windows overlap no longer start at the same time. On each node the jobs whose windows overlap are placed together: a task with no window keeps its time, the others take their usual hashed place or, if another job starts less than 30 seconds away, the next free place in their window (a smaller gap when a window is very small). The result is the same every time it is worked out, so a run is never moved once calculated, and each node still has its own order.

## [v68] - 2026-10-16 — Scheduler shell environment

### Changed
- A scheduled shell command gets the usual command directories on its PATH (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, added to whatever the daemon has) and `HOME=/root` when unset, so `ls`, `systemctl` and the like are found as in a root shell. It does not read a login profile (`~/.bashrc`, `/etc/profile`); use full paths or source one in the command. `NTPDIR_TASK` holds the task name.

## [v67] - 2026-10-16 — Scheduler: update, reboot, UTC

### Added
- Two built-in scheduler actions. **Update from online** looks up the newest release the way the Upgrade page's *Fetch from online* does and, when it is newer than the running version, stages it and queues this node for the normal update (one node at a time, canary, rollback); nothing is downloaded when the node is current. **Reboot this node** restarts the host once no gateway would lose its last serving member.

### Changed
- Scheduler times are UTC on every node and the per-task time zone field is gone (a zone saved by v65 or v66 is ignored, so such a task now runs at its UTC time).

## [v66] - 2026-10-16 — Scheduler rules, join fix

### Added
- **Scheduler rules**: a monthly or yearly task can pick several occurrences and several weekdays at once ("the 2nd or 3rd Saturday or Sunday of every month"), and the offset window can be stated as an end time ("between 01:00 and 10:00", running into the next day if the end is not later than the start) instead of "up to N after". Each node still runs once, at a time of its own inside the window. Tasks saved with the single `nth`/`weekday` form are converted when loaded.

### Fixed
- A node that joins the cluster through a replica is no longer added to every gateway: the primary now excludes it when it learns of the newcomer from the replica's broadcast, as it already did when the node joined the primary directly.

## [v65] - 2026-10-16 — Scheduler

### Added
- **Operate ▸ Scheduler**: tasks that run on every cluster node or on chosen nodes. Frequencies: hourly, daily, weekly (chosen days), monthly (a day of the month, the last day, or the 1st to 4th / last weekday, e.g. the 3rd Saturday) and yearly, each "every N". All times are UTC.
- **Offset window**: a task is due at its time and each node runs it at its own stable place (a hash of node, task and occurrence) inside that window, so the nodes do not all run it at once. A node that was down runs a missed task once on return if still inside the window; older runs are skipped and logged. A task that is still running is not started again.
- Actions: restart chrony, pause or resume the node, clear the statistics, update from online (fetches the newest release and queues this node for the normal, one-at-a-time update when it is newer), reboot the host (once it is safe), or a shell command (`/bin/sh -c`, as root, with a time limit; the whole process group is stopped on timeout). Output and result of the last 300 runs are kept per node (`scheduler.json` in the state directory).
- The list: New task, and right-click ▸ Edit, Copy, Paste, Run now on this node, Disable/Enable, Delete (Paste adds a copy with a new name; double-click edits). The task list is part of the shared `ntp` settings (`schedule`) and replicates; a replica's change goes through the primary like any shared edit.
- CLI: `--schedule`, `--schedule-history`, `--schedule-set JSON`, `--schedule-del ID`, `--schedule-run ID`. Help topic, README section.

### Changed
- README: the anycast section now says an address also needs BGP to be able to carry it (v60 behaviour).

### Verified
- `go test -race ./...` passes, with tests for every frequency, the 3rd Saturday of each month of 2026, last days and day clamping, every-N, offsets (stable, inside the window, different per node), catch-up inside and outside the window, nodes the task is not for, shell output/timeout/exit status, history across a restart, validation, config save and the shared hash.
- A real daemon: tasks added over the CLI, a shell task run now and one that fired on its schedule about twelve seconds later, history kept across a restart. Headless Chromium: New, Edit, Copy, Paste, Delete, the form for each frequency.

### Not verified
- Not run on a cluster of real nodes (replication of the list uses the same path as other shared settings). Built-in actions other than the statistics were not run against real chrony.
- Daylight-saving changes were not tested; a time that does not exist that day runs an hour later.

## [v64] - 2026-10-16 — A shared address cannot be a node's address

### Added
- Saving a gateway is refused when a shared address (VIP, more addresses) or an anycast address that is new in the change is an address a node already has: this host's own interface addresses, and the addresses the cluster members are reached on. A shared address moves between nodes, so a member's own address used as one ends up answered by whichever node holds it, and that member then fails the cluster identity check ("peer identity does not match the pinned fingerprint"). Addresses already in the saved configuration are not checked, so such a configuration can still be saved and fixed.

### Verified
- `go test -race .` passes, with a test for shared and anycast addresses and for an existing address still saving.

### Not verified
- The cluster-member side of the check (peer addresses) is not covered by a test; names are not resolved, only addresses.

## [v63] - 2026-10-16 — Traceroute: resolve names

### Added
- The traceroute popup has a **Resolve names** tickbox. Ticked, each hop is shown by its reverse-DNS name where it has one; unticked, by its address. It can be switched while the trace runs or after it ends, with no new trace; the choice is remembered in the browser. The node looks the hop names up in the background as hops appear (the job now also carries the table as data: `hops` in `/api/nettool`).

### Verified
- `go test -race .` passes, with a test that a hop's table row and background name arrive; headless Chromium check of the tickbox switching names and addresses.

### Not verified
- Not run with a real `mtr`; the sandbox has none.

## [v62] - 2026-10-16 — Lookup on clients and servers

### Added
- Statistics ▸ Top Clients and Top Servers: right-click ▸ **Lookup** (as in dnsdir). A client address shows its reverse (PTR) names as this node's resolver answers; a server name shows its addresses, canonical name, mail servers, name servers and text records. Asked once when requested; nothing is stored. `GET /api/dnslookup/full?lookup=…`.

### Verified
- `go test -race .` passes, with a test of both lookup kinds; `node --check` on the UI scripts.

### Not verified
- Not clicked through in a browser against a live node.

## [v61] - 2026-10-16 — Server tags no longer cut off

### Fixed
- Server table: the tags after a server address (v4, v6, NTS/key, fallback) were clipped when the address was long, leaving a half-drawn tag. The Server IP cell now wraps the tags onto a second line instead.

### Verified
- Rendered the table at its real column widths in headless Chromium: address plus three tags wraps with every tag whole. Go suite unchanged from v60.

### Verified
- `go test -race .` passes, with a new test that closes the gate for no BGP, disabled BGP, and no established neighbor and reopens it on Established. Browser check of the per-topology time zone (e2e/t23.py).

### Not verified
- Not run against a real FRR with live sessions or on a real `lo`; the sandbox has neither.

## [v60] - 2026-10-16 — Anycast addresses follow BGP

### Changed
- An anycast address is now held on `lo` (and answered) only while BGP can carry it: BGP anycast is configured and enabled on the node, and at least one BGP neighbor of the address's family is in the Established state. With BGP not configured, disabled, or every neighbor of that family down, the address is removed and stops answering; it returns within a few seconds of a session coming up. Partly established sets stay up and show amber.
- The time zone chosen for the graphs is remembered separately for each topology (gateway); a gateway with none picked uses the last global choice, then UTC.

## [v59] - 2026-10-15 — Clock difference between nodes

### Added
- The members table (Operate ▸ Cluster and the Monitor page) has a **Clock vs this node (ms)** column: how far each member's clock is from the node you are logged in to, and under the table **Largest difference between nodes** with the two members furthest apart. Each node reports how far its clock is from the time chrony believes (`chronyc tracking`) in its cluster status; every node measures against the same servers, so the difference of two readings is the difference of the clocks, to within chrony's own estimate error (hover a figure for both readings). Members that are not synchronised, not reachable or on an older version are marked and left out of the comparison.

### Verified
- Go tests: the comparison (reachable, synchronised nodes only; nothing with fewer than two; older nodes left out) and the status message carrying the reading. Headless Chromium: the column, the "this node" / "not synchronised" / "–" states and the summary line.

## [v58] - 2026-10-15 — Authentication status in the server table

### Added
- The server table (Monitor) shows, after the Server IP of a server set to use NTS or a key, whether the authentication works: a green **NTS** or **key** tag when chrony authenticates with it (hover: the number of NTS cookies), a red tag with a cross when it does not (NTS key establishment failed, the key is refused or unanswered, or chrony uses the server without it), a grey tag with dots while chrony has not yet restarted with the setting. It reads `chronyc authdata`, only while a server is set to be authenticated.

### Verified
- Go tests: the authdata parser and every state (pending, working, no cookies, key not answered, used without authentication, not yet a source, server not set to be authenticated).

### Not verified
- The exact column layout of `chronyc -c authdata` on every chrony version (written from chrony's documented columns; an older chrony without `authdata` shows no tag).

## [v57] - 2026-10-15 — NTS, symmetric keys and leap-second handling

### Added
- Configure ▸ NTP ▸ **Security**: **Keys** (chrony key-file lines, `ID HASH KEY`, validated: IDs, hash names, ASCII or HEX keys, no duplicates, at most 64); **Authenticated servers** (`host nts` or `host key N`, the key must exist); **Serve NTS to clients** (chrony's NTS-KE on TCP 4460 with the web GUI certificate, copied to `/etc/chrony/ntpdir.auth.d/` for chrony's group and followed when the certificate is renewed).
- Configure ▸ NTP ▸ **Leap seconds**: **Leap second table** (`leapsectz`, e.g. `right/UTC`), **Leap second mode** (`leapsecmode`: system, step, slew, ignore) and **Smear leap seconds** (`smoothtime 400 0.001 leaponly`).
- All shared by the cluster. They go into the chrony client file and, because chrony reads them only at start, a change rolls a chrony restart through the nodes one at a time (the same mechanism as a new port). An authenticated server stays out of chrony's sources until chrony has been restarted with its key or NTS setting, so it is never used without authentication.
- Safeguards: a leap table that is not on a node, or NTS on a chrony built without it, is left out with a Log warning instead of stopping chrony from starting. The keys are redacted in support bundles and the history says only how many there are.
- Help pages for the two tabs; the NTP page now has five tabs.
- Uninstall `--purge` removes `/etc/chrony/ntpdir.auth.d`.

### Changed
- A gateway's own NTP pool and the probe pool no longer carry copies of the node-wide settings (SNMP, keys, NTS, leap seconds).

### Verified
- Go tests: validation (good and bad keys, server_auth, leap values), the chrony file (keyfile, ntsservercert/key, leapsectz, leapsecmode, smoothtime, the sum that makes a renewed certificate restart chrony), the files' permissions and removal when switched off, a missing leap table, chrony without NTS, source lines with `nts` / `key N`, the authenticated server waiting for the restart, replication, redaction and history. Headless Chromium: both tabs, saving through `/api/config`.

### Not verified
- Not run against a real chrony: NTS key establishment, key-signed answers and leap-second behaviour were not exercised (the sandbox has no chrony, systemd or NTS servers).

## [v56] - 2026-10-15 — Server table: tags no longer run into the State column

### Fixed
- Topology/NTP server table: the "fallback" tag (and the v4/v6 tags) spilled over the State pill because the Server IP column was too narrow. The column is wider and anything that still does not fit is cut with an ellipsis instead of overlapping.

### Verified
- Headless Chromium at a narrow width: no overlap.

## [v55] - 2026-10-15 — SNMP: nothing under the form

### Changed
- Configure ▸ SNMP: the last note ("Could not read what snmpd is doing on this node") is removed too. The ACTIVE tag beside the heading is the only status; no tag when snmpd is not running or the node cannot be asked.

### Verified
- The page in headless Chromium.

## [v54] - 2026-10-15 — SNMP: no status notes

### Changed
- Configure ▸ SNMP: the notes under the form ("SNMP is off", "snmpd is not installed", "snmpd is not running yet") are removed. The ACTIVE tag beside the heading is the only status; no tag means SNMP is not answering. A node that cannot be asked (an older version) still says so.

### Verified
- The page in headless Chromium; the help tests.

## [v53] - 2026-10-15 — SNMP: ACTIVE tag

### Changed
- Configure ▸ SNMP: a green ACTIVE tag sits beside the heading while snmpd is running, and is gone when it is not. The line "snmpd is on and answering SNMP on UDP 161." is removed. The warnings (not installed, not running) and the "SNMP is off" note stay.

### Verified
- The page in headless Chromium (tag shown once snmpd runs); the help tests.

## [v52] - 2026-10-15 — SNMP status of the node picked in the top bar

### Fixed
- Configure ▸ SNMP: the line under the form (snmpd installed / running / on / off) now follows the node picked in the top bar. Before, the request was refused for any node but the one you are logged in to and the line stayed empty. If a node cannot answer (an older version), the page now says so instead of staying blank.

### Verified
- A test that the status request is relayable; the page in headless Chromium.

## [v51] - 2026-10-15 — SNMP field descriptions are in Help

### Changed
- Configure ▸ SNMP: the explanations under the Community strings, Location and Contact boxes moved into Help (they were already there; the examples and the shared / not-shared notes were added). The page shows just the boxes.

### Verified
- The help tests (every field has an entry); the page loads and saves in headless Chromium.

## [v50] - 2026-10-15 — SNMP community strings and contact are shared

### Changed
- Configure ▸ SNMP: the **community strings and the contact are now cluster settings** (replicated like Allowed clients: edit them on any node, every node answers the same communities and reports the same contact; a node that is the only member behaves as before). The **location stays local** to each node. They moved from the node's `snmp` block to `ntp.snmp_communities` and `ntp.snmp_contact`; a v49 config's local communities and contact are moved there automatically on the first start.
- The community strings still stay out of support bundles, and the history says only how many there are.

### Verified
- Go tests: replication to a replica (location untouched), emptying on the primary, the v49 migration, validation of the shared strings, history never showing the strings.

## [v49] - 2026-10-15 — SNMP

### Added
- Configure ▸ SNMP: community strings (any number, one per line, up to 16), a Location and a Contact. **A community string set: snmpd is enabled and running. None: snmpd is disabled.** Each community gives read-only access over IPv4 and IPv6 on UDP 161; Location and Contact become `sysLocation` and `sysContact`. The page also says whether snmpd is installed and running.
- ntpdir writes `/etc/snmp/snmpd.conf` (mode 0600, first line marks it as managed) and enables/restarts/disables `snmpd` when the settings change and when it starts. An existing `snmpd.conf` is kept once as `snmpd.conf.ntpdir-orig` and put back when the communities are emptied; an snmpd that ntpdir never took over is left alone.
- Installer prerequisite: `snmpd` (`net-snmp` on Fedora, RHEL and Arch). A failed install is a warning. A freshly installed snmpd is switched off at once (Debian starts it on install), so with no community string SNMP is off. The uninstaller switches snmpd off again and puts the original `snmpd.conf` back; snmpd stays installed.
- The settings are local to the node (a location differs per node) and not replicated. The community strings are left out of support bundles, and the history says only how many there are.

### Verified
- Go tests (with `-race`): validation, the generated snmpd.conf, enable / restart only when the file changed / disable and restore the original, a foreign snmpd left alone, snmpd not installed, redaction and history wording. Headless Chromium: the page, saving through `/api/config`, the status line. The uninstall step on temporary files; the installer in `--dry-run`.
- The full suite passes.

### Not verified
- Not run against a real snmpd (no snmpd or systemd in the build sandbox): the `agentaddress`, `rocommunity` and `rocommunity6` lines are from net-snmp's documentation. Try `snmpwalk -v2c -c <community> <node> system` after setting a community.

## [v48] - 2026-10-15 — Configure ▸ NTP: the Servers tab has its cards again

### Fixed
- Configure ▸ NTP: the Servers tab was empty because its card (Upstream Servers, with Servers and Fallback servers) sat under Clients. The card headings went to title case in v38 and the tab code matched cards to tabs by their exact old spelling. The match now ignores case, and the tab shows its card.
- (v47 hid the tab while the shared lists were empty; that is undone. The tab is always there, as before.)

### Verified
- Headless Chromium: the Servers tab holds Upstream Servers, Health holds Health and Timing, Clients holds Serving and Client Rate Limiting; no script errors. The project builds.

### Not verified
- Go tests not re-run (UI-only change; they passed on v46).

## [v46] - 2026-10-15 — Block a client from Statistics

### Added
- Blocked clients: `blocked_clients` in the `ntp` block (Configure ▸ Settings ▸ Blocked clients, one address or network per line). Written to chrony's client file as `deny all <net>` after the `allow` lines and put into the running chrony at once, without a restart. A block wins over Allowed clients, also for a network inside an allowed one. Loopback (this node) cannot be blocked. Shared by the cluster like Allowed clients.
- Statistics ▸ Top Clients ▸ right-click a client: **Block** (adds its address), **Unblock** (removes it), or, when a network in the list holds it, a line saying which one. A 🚫 marks blocked clients (dim when a network holds the address).
- There is no per-client limit: chrony has only one rate limit for all clients (Configure ▸ Settings ▸ client rate), so the menu has Block but no Limit.

### Verified
- Go tests (with `-race`): the deny lines in the file and in the live rules, after the allows; the muted file has none; validation rejects loopback, whole-internet and malformed entries and normalises the rest. Headless Chromium: marks, the three menu variants, Block saving `blocked_clients` through `/api/config`.

### Not verified
- Not run against a real chrony: the `deny all` syntax is from chrony's documentation.

## [v45] - 2026-10-15 — Server statistics: the clock offset graph has data

### Fixed
- Topology ▸ right-click a server ▸ Statistics: the *Clock offset* graph was always empty. The probes measured each server's offset but never put it into the server's history (only the gateway's graph was fed, from chrony). Every real, synchronised answer now adds its offset to the minute under way — a falseticker's too, which is what the graph is for; a refusal (kiss-o'-death) or an unsynchronised clock is left out.
- The graph fills from now on; the minutes recorded before this version have no offset to show.

### Verified
- Go tests (with `-race`): a probe of a server 250 ms ahead leaves one offset sample of about 250 ms; an unsynchronised server leaves none. The full suite passes.

### Not verified
- The graph itself was not looked at in a browser.

## [v44] - 2026-10-15 — Eye button on the BGP neighbor password

### Changed
- Configure ▸ Anycast ▸ Neighbors: the Password box of each neighbor (and of the new-neighbor row) has an eye button beside it. Click it to see the password, click again to hide it. The box still starts hidden, and the toggle changes nothing that is saved.

### Verified
- Headless Chromium: the box is `password` at first, `text` after one click (aria-pressed true, label “Hide password”), `password` after the second; no script errors; the layout looks right.

### Not verified
- The Go test suite was not re-run for this UI-only change (it passed on v43).

## [v43] - 2026-10-15 — Servers are probed over IPv4 and IPv6; IPv4 preferred

### Changed
- A server named by host name is probed over IPv4 (its A record) and over IPv6 (its AAAA record), each on its own socket, at the same time. Before, the system picked one address and only that family was ever tested.
- The server is up when either family answers well. IPv4 is preferred: the round trip, offset, stratum and root distance that are shown and used (ranking, falseticker check) are IPv4's whenever IPv4 passes, and IPv6's only when it does not. A dead IPv6 path no longer shows as an error on a server that IPv4 reaches; both failing gives `IPv4: …; IPv6: …`.
- The server list marks `v4` / `v6` next to the address of a host-named server (green: the family the numbers come from; red: it failed, hover for the reason). `/api/ntp` and the status data carry `via` and `families` for each server. A server given as an address is probed over its own family only, as before.

### Verified
- Go tests (with `-race`), including: both families answering with IPv4 chosen although slower; IPv6 dead while the server stays up; IPv4 dead and IPv6 carrying the server; neither answering; a name that does not resolve. In this sandbox (no IPv6 in the kernel) the tests stand in for an AAAA record with a second loopback address, since the family is the one the name was looked up as.

### Not verified
- Not run over a real IPv6 network, and the literal-IPv6-address server test is skipped where the machine has no IPv6.
- The `v4` / `v6` marks were not looked at in a browser.

## [v42] - 2026-10-15 — Top lists hold 500 names

### Changed
- Top Clients and Top Servers return the top 500 names (was 100), plus the “(others)” row, ten or twelve to a page. Also applies to the cluster-wide totals.
- How many distinct names each time slot remembers is unchanged (it bounds memory), so a list can hold fewer than 500 when few names were seen.

### Verified
- Go test suite.

### Not verified
- Not run with real traffic; the larger reply is a few tens of KB more JSON per refresh.

## [v41] - 2026-10-15 — Top cards keep one size

### Changed
- The Top Clients and Top Servers cards are always the same height and the page buttons (“1–10 of n”, ‹ ›) always sit in the same place at the foot, whatever the number of results; a card with one page shows them disabled.
- Client rows (which can show a host name underneath) are taller than servers rows, so Top Servers lists 12 to a page against 10 for Top Clients, which makes the two lists equally tall.

### Verified
- Headless Chromium with 25 clients and 30 servers: both cards 697 px high, tables 546 px, footers at the same offset. The projects build.

### Not verified
- Not looked at with real host names under the client addresses, and the Go test suite was not re-run for this UI-only change (it passed on v40).

## [v40] - 2026-10-15 — Top cards: page controls at the bottom

### Changed
- The page controls of the Top Clients / Top Servers cards moved from the card header to a footer at the bottom of the card.

### Verified
- Headless Chromium with 25 clients: the footer shows "1–10 of 25", Page 1 of 3, and ‹ › step through the pages; a single page shows no footer. The project builds.

### Not verified
- The full Go test suite was not re-run for this UI-only change (it passed on v39).

## [v39] - 2026-10-15 — Top Clients / Top Servers paginate

### Changed
- The Top Clients / Top Servers cards no longer have More / Fewer buttons. They list every result the server returns (up to 100 names plus “(others)”), ten to a page, with ‹ › buttons and “1–10 of n” at the bottom of the card. A new filter, tile, pick or range starts again on page one.

### Verified
- Headless Chromium with 25 clients: ten rows a page, "1–10 of 25", Page 1 of 3, ‹ › step through, the last page holds 5, a new filter or pick returns to page one, no More/Fewer button left.

### Not verified
- Not run against a live daemon with real traffic.

## [v38] - 2026-10-15 — Card headings in title case; Statistics: "Top Clients: Answered"

### Changed
- Every card heading on every page is in title case: "Upload a Release", "Join an Existing Cluster", "Anycast Addresses", the Configure sections, the Statistics donuts and charts ("IP Family", "Clock Offset"), the Host charts, and so on. Short joining words stay small (a, an, of, on, per, the …) except first; a word with a capital inside it (BGP, NTS, GUI) and anything after a hyphen ("Kiss-o'-death", "Policy-Based") are left alone. Headings that are data (a user name, a gateway's own name) and dialog titles are unchanged. One helper, `tc()`, does it where the headings are built, so a new card is covered too. Ported from dnsdir v400.
- Statistics: with a tile picked, the two top lists are titled `Top Clients: Answered` and `Top Servers: Answered` (also Kiss-o'-death, Refused, Failed), not `Top clients — Answered`. The two donuts (Outcome, IP Family) and the chart keep the dash. The help and README say Top Clients / Top Servers too.

### Verified
- `node --check`, gofmt, vet, `go test -race -count=1`. `tc()` on sample headings. Headless Chromium against the real `app.js` with a mocked Statistics answer: clicking each of the four tiles gave exactly the eight list titles above, and the donuts read Outcome and IP Family.

### Not verified
- Every page was not opened in a browser: the other pages' headings follow from the code (every card-heading constructor goes through `tc()`), not from looking at them.

## [v37] - 2026-10-15 — The IPv6 controller is drawn in blue

### Changed
- Topology: when a dual-stack gateway has its IPv4 and IPv6 controllers on two different nodes, the dot of the node that is only the IPv6 controller is soft blue, and its tooltip says "Gateway controller (IPv6)". A node that is the IPv4 controller, or both, keeps the plain dot. Ported from dnsdir v398. New field `agc_afs` on a gateway member ("v4", "v6" or "v4+v6"), kept through the per-node merge of v35.

### Verified
- gofmt, vet, `go test` of the canvas and member tests (new: `TestMergeFamilyMembersKeepsControllerFamilies`: controllers on two nodes, and both on one); `node --check` of `app.js`.
- Headless Chromium (light and dark) against the real `app.js` and `style.css` with a mocked API: split controllers draw one plain and one blue dot, both on one node draws a single plain dot.

### Not verified
- A live dual-stack cluster. A node that sits in a gateway only by its IPv6 address is still not matched to its shape, as before.

## [v36] - 2026-10-15 — "New gateway" without the dots

### Changed
- The sidebar's **＋ New gateway**, the right-click menu entry on the empty drawing, the text on the empty Topology page, the help, README and QUICKSTART no longer end in "…". The other right-click entries are unchanged.

### Verified
- gofmt, build, vet, `go test -race -count=1`, CGO-off vet and test, cross-compiles for amd64, arm64, arm, 386 and riscv64, `node --check` of `app.js` and `help.js`.

### Not verified
- The page in a browser (a text change only).
- Flaky tests: in two full `-race` runs, `TestBGPOperateAPIAndStatus` (v35's run) and `TestLogServerFlips` (this one) each failed once and passed on their own and on a rerun. Neither is touched by these changes; the causes were not found.

## [v35] - 2026-10-15 — Help: a Find box; the circle's tooltip counts nodes, not nodes × families

### Added
- The help panel (the **?** at the top right) has a **Find** box above the text, ported from dnsdir v396. Typing marks every match in the page's help (not case sensitive) and shows `1 / 12`; Enter goes to the next match, Shift+Enter to the one before, and the current one has its own colour and is scrolled into view. Esc empties the box (a second Esc closes the panel). The word stays marked when the help changes to another page's. A match is found inside one piece of text, so a phrase that runs from plain text into bold or code is not found as one. The help code in `app.js` is the same as dnsdir's apart from the names.

### Fixed
- Topology: the gateway circle's tooltip said "Serving nodes: 8" for 4 nodes. A gateway with IPv4 and IPv6 runs one engine per address family on each node, each speaking from its own address, and the members were told apart by that address, so every node was counted once per family. `canvasGroups` now merges the members that belong to one node (by the node names the cluster already works out from the nodes' addresses, `nodeNamesByIP`): one member per node, listed by its IPv4 address with both families (`v4+v6`), local and controller kept. An address that belongs to no known node stays its own member.

### Verified
- gofmt, build, vet, `go test -race -count=1`, CGO-off vet and test, cross-compiles for amd64, arm64, arm, 386 and riscv64, `node --check` of `app.js` and `help.js`.
- New test `TestMergeFamilyMembersCountsNodes` (4 nodes × 2 families and an unknown address: 9 entries before, 5 after, IPv4 address and `v4+v6` kept, local and controller kept).
- Live, with a real daemon (real PAM, a throwaway user; user, group and `/etc/pam.d/ntpdir` removed afterwards), in headless Chromium against the real `app.js`, `style.css` and `help.js` (light and dark): typing marked the matches (89 for "gateway" on the Topology help) with the counter, Enter and Shift+Enter moved through them, upper case found the same matches, an unknown word marked nothing and said `0`, the word stayed marked on another page's help (102 for "the" on Statistics), Esc emptied the box and left the panel open, a second Esc closed it, and the help's text was the same after marking and unmarking. No page errors.

### Not verified
- A flaky test: in one of the full `go test -race` runs `TestBGPOperateAPIAndStatus` failed once (BGP code is untouched here). It then passed five times on its own with `-race` and in a second full run; the cause was not found.
- The member count on a real dual-stack cluster: the sandbox has no IPv6 and one node, so the fix is covered by the unit test only. It relies on the nodes' IPv6 gateway addresses being known to the cluster (`gw_ips`); a node that does not send them yet (an older version) keeps its IPv6 entry apart until it is updated.

## [v34] - 2026-10-15 — A new gateway starts with four public NTP servers

### Added
- A gateway you create now starts with the NTP servers `pool.ntp.org`, `time.nist.gov`, `time.google.com` and `time.cloudflare.com`. This is the GUI's **New gateway** form and `--canvas-add gateway`. They are ordinary servers of the gateway (probed, named and paused like any other), so a server you do not want is removed the usual way: right-click it ▸ **Delete**, or `--canvas-del server --group N --server ADDR`. A server named with `--server` at creation is added to them, and not twice when it is one of them. The CLI's reply lists the servers and how to remove one. The New gateway form checks a fallback server against the four, since a fallback may not also be a normal server.
- The same list is in `config.go` (`defaultGatewayServers`) and `webui/app.js` (`DEFAULT_SERVERS`); a test keeps the two equal.

### Changed
- QUICKSTART, README and the Topology help topic say that a new gateway comes with these servers (the quick start no longer says the circle is amber for lack of a server).
- Not changed on purpose: a gateway already in a config file, a gateway read from a file that lists no servers, the shared server list (Configure ▸ NTP ▸ Servers) and `defaultNTP`, so an upgrade and an existing config see no new servers. The first-start default gateway and `--configure` also stay as they were: they have no servers of their own.

### Verified
- gofmt, build, vet, `go test -race -count=1`, CGO-off vet and test, cross-compiles for amd64, arm64, arm, 386 and riscv64, `node --check` of `app.js` and `help.js`.
- Tests: `TestNewGatewayStartsWithDefaultServers` (the four servers, removing one, naming one of them at creation, a file read gets none), `TestDefaultServersMatchTheGUI`; `TestApplyCanvasEdit` and `TestCanvasDualStackAndStratumEdits` now expect the four first.
- Live, with a real daemon (`"groups": []`, real PAM, a throwaway user in the `ntpdir` group; user, group and `/etc/pam.d/ntpdir` removed afterwards): `--canvas-add gateway` wrote the four servers to the config file; the PAM login over HTTPS gave 200; in headless Chromium (light and dark) the New gateway form created gateways whose circle has the four squares and whose config file has the four servers; `--canvas-del gateway --yes` removed one.

### Not verified
- The four servers answering: the sandbox has no DNS, so they showed as down there. A deleted server and a second node in a cluster were not tried in the GUI (server delete is unchanged code, covered by `TestApplyCanvasEdit`).
- The other PAM cases (wrong password, a valid user outside the group, root): only the login of a member was checked, as nothing in the login code changed.

## [v33] - 2026-10-14 — Statistics: Top servers names the node that answered

### Changed
- Monitor ▸ Statistics: **Top servers** lists the node that answered, by its host name, instead of the fixed word "chrony". chrony answers the clients on every node, so "chrony" told the nodes apart from nothing; with the Node menu on **Cluster** the list now has one row per node, and picking a row filters Top clients to the clients that node answered. The name is read each time the counts are taken, so a renamed node counts under its new name; a node with no host name still counts as "chrony". Counts recorded before this version stay under "chrony" until they age out of the history (or **Clear**). Two nodes with the same host name count as one row.
- The Statistics help topic says so.

### Verified
- gofmt, build, vet, `go test -race -count=1`, CGO-off vet and test, cross-compiles for amd64, arm64, arm, 386 and riscv64, `node --check` of `app.js` and `help.js`.
- New test `TestSampleClientsNamesTheNode`.
- Live: a private `chronyd -x` as the node (sources and clients through `NTPDIR_CHRONY_SOURCEDIR`, `NTPDIR_CHRONY_CONFDIR` and `NTPDIR_CHRONYC_ARGS`), a second one as the upstream, and one real daemon with a gateway on `lo`. 30 NTP requests were answered and `--stats` listed 30 answered under Top servers as the host name (`vm`). Daemon, chronyds and the VIP removed afterwards.

### Not verified
- The Statistics page and the help panel in a browser, the Real PAM login check (only help text changed in `webui/`), and the Cluster view with more than one node (the per-node rows are the same host names the cluster view already adds up; not run with two daemons).

## [v32] - 2026-10-14 — Fix: the chart tooltip did not show

### Fixed
- Monitor ▸ Statistics: hovering the chart showed no tooltip since v31. The RPS row was added in the wrong chart's code (the server/gateway statistics chart) and left out of the Statistics chart, so the hover handler hit an undefined name. The row now lives only in the Statistics chart; the other chart's code is as in v30. Checked by diffing `app.js` against v30: the only differences are the Now button and the RPS row.

### Verified
- gofmt, build, vet, `go test -race -count=1`, CGO-off vet and test, cross-compiles for amd64, arm64, arm, 386 and riscv64, `node --check`, diff of `app.js` against v30.

### Not verified
- In a browser. The v31 mistake got through because the page was never opened; this fix was found by reading the code and the diff.

## [v31] - 2026-10-14 — Statistics: a "Now" range, RPS in the chart tooltip

### Added
- **Now** button before **Last Hour** on the Statistics page; CLI `--stats --stats-range now`. It covers the current 10-minute period so far, and reaches back one more period when fewer than 5 minutes of it have passed (so 5 to 15 minutes). The top lists are stored in 10-minute slots, so this is the closest they can come to the present; starting on a slot boundary makes the totals, the chart (one point per minute) and the top lists cover the same period. In a cluster the receiving node fixes the period once.
- Hovering the Statistics chart in the counts view shows an **RPS** line, with a black box in front of it, under the values (of the picked outcome when a tile is picked, otherwise of all requests).

### Verified
- gofmt, build, vet, `go test -race -count=1`, CGO-off vet and test, cross-compiles for amd64, arm64, arm, 386 and riscv64, `node --check`.

### Not verified
- In a browser, and on a live multi-node cluster.

## [v30] - 2026-10-14 — Stray dot on the statistics chart

### Fixed
- Monitor ▸ Statistics: a small coloured dot sat in the top-left corner of the chart. It was the hover marker of each line, drawn at (0, 0) and never hidden until the mouse was over the chart. The markers are hidden until hovered, and now hidden again when the mouse leaves (this also applies to the gateway and host charts, whose markers stayed where the mouse left them).

### Verified
- `node --check`, gofmt, vet, tests, cross-builds.

### Not verified
- The chart in a browser.

## [v29] - 2026-10-13 — README and screenshots brought up to date

### Changed
- README: the container install (`chronyd -x`), the FRR reload script and where it is looked for, "Serving only with the right time" (`serve_offset_ms`), the time and the Time zone picker, what the server boxes show (offset, name, address, `*`) and the blue links, the gateway clock offset and root delay charts, the Outcome donut, and the refusal to join at the same cluster address. The quick start has the same notes in short.
- Every screenshot under `snaps/` was taken again from the current build.

### Verified
- The screenshots come from a two-node demo cluster (network namespaces, stub NTP servers, generated client traffic) running this build.

### Verified (tests)
- gofmt, vet, `go test -count=1 ./...` and the five cross-builds pass. `TestAddVIPDoesNotStealOutboundRoute` fails while the demo network (198.51.100.0/24) exists on the same machine, so the full suite was run after it was removed.

### Not verified
- In that demo a small script stands in for `chronyc`, because chrony in the sandbox does not open its command socket; the numbers on the NTP, Statistics and clock pages are therefore simulated, not real chrony output.

## [v28] - 2026-10-13 — FRR reload script found on RPM-style paths

### Fixed
- FRR's `frr-reload.py` is also looked for in `/usr/libexec/frr` (where Ubuntu 26.04 and the RPM distributions put it); the "cannot reload" warning no longer appears when it is there, and the installer no longer tries `frr-pythontools` on RPM distributions.

## [v27] - 2026-10-13 — Name above the addresses

### Changed
- Topology: in the gateway circle and the server boxes the name now sits above the IP addresses.

## [v26] - 2026-10-13 — The star on the offset

### Changed
- The star that marks the source chrony has selected is after the offset (`-0.23 ms *`), no longer after the address.

### Verified
- `node --check`, gofmt, vet, tests, cross-builds.

## [v25] - 2026-10-13 — Topology: addresses like the names

### Changed
- The IP addresses in the gateway circle and in the server boxes are drawn like the names: the same size and the same muted colour. The circle is sized for the clock line.

### Verified
- `node --check`, gofmt, vet, tests, cross-builds.

## [v24] - 2026-10-13 — Topology: lines reordered

### Changed
- Gateway circle: the time is the top line, then the IPv4 and IPv6 addresses (no longer bold), then the name.
- Server boxes: the offset is the top line, in bold, then the address (no longer bold), then the name. The round trip stays in the tooltip.

### Verified
- Both shapes rendered with the real stylesheet in Chromium; `node --check`, gofmt, vet, tests, cross-builds.

## [v23] - 2026-10-13 — Type in the Time zone box

### Changed
- The Time zone picker is a box you can type in: it shows the whole list when you click it and narrows as you type (the browser filters the list; each entry shows its UTC offset). Picking an entry, or typing a full zone name, applies it; anything else you typed is put back to the zone in use when you leave the box.

### Verified
- The box's focus, typing and blur logic in headless Chromium; `node --check`, gofmt, vet, tests, cross-builds.

### Not verified
- How the narrowing list looks in Firefox and Safari (it is the browser's own list).

## [v22] - 2026-10-13 — Pickers stay open while the page refreshes

### Fixed
- The Time zone and Node pickers closed themselves when the node list refreshed (every 6 s), because the whole bar was redrawn each time. It is now redrawn only when what it shows changes (page, node picked, node list), and never while one of its pickers has the focus.

### Verified
- `node --check`, gofmt, vet, tests, cross-builds.

### Not verified
- In a browser with a list held open across a refresh.

## [v21] - 2026-10-13 — Time zone picker beside the node picker

### Changed
- The Time zone picker is on the same line as the node picker, at the left of the Topology page (the node picker stays at the right), instead of in a second row under it.

### Verified
- `node --check`, gofmt, vet, tests, cross-builds. The layout was agreed from a mockup.

### Not verified
- The layout in the real page.

## [v20] - 2026-10-13 — Time zone picker

### Added
- Topology: a **Time zone** picker under the node picker (the bar is also shown on a single node). It lists UTC and every zone the browser knows (`Intl.supportedValuesOf`), each with its current UTC offset; picking one changes the zone of the time in the gateway circle at once. The choice is stored in the cookie `ntpdir_tz` (one year, `SameSite=Strict`, `Secure` over HTTPS; a plain cookie the page reads, holding only the zone name), so each person's browser keeps the zone they last chose. UTC until one is chosen. The node's time itself is unchanged: only its display.

### Verified
- `node --check`, gofmt, vet, tests, cross-builds.

### Not verified
- The picker and the cookie in a browser (layout of the two rows, light and dark; a cookie that is refused falls back to UTC).

## [v19] - 2026-10-13 — Serve only with a good clock; offset on the server boxes

### Added
- `serve_offset_ms` (Configure ▸ NTP ▸ Health, "Serve only within (ms, 0 = off)", default 50): a node serves, and keeps the gateway address and anycast addresses, only while its clock is within that of what chrony measures against the servers. Beyond it chrony is told to answer nobody and the node leaves like one whose chrony is down; it comes back once within 80% of the limit (no flapping at the edge). In a container this is the host's clock against the servers, which `-x` chrony measures but cannot correct. The gateway's tooltip says why a node is not serving.

### Changed
- The third line of a server box on the Topology page is the server's clock offset (`+1.25 ms`), no longer the round trip; the round trip stays in the tooltip.

### Verified
- A test for the limit (edge, hysteresis, off), gofmt, vet, tests, cross-builds.

### Not verified
- Against a real chronyd with a skewed clock, and the drawing in a browser.

## [v18] - 2026-10-13 — The time in the gateway circle

### Added
- The gateway circle on the Topology page shows the time of the node being looked at (UTC, to the second); the tooltip gives the date and chrony's stratum, reference and offset. It is asked of the node every 15 s (`GET /api/time`, relayed to the picked node) and counted locally in between. `ntpdir --show-ntp` prints the time too. The circle is a little taller to fit the extra line.

### Verified
- gofmt, vet, tests, `node --check`, cross-builds.

### Not verified
- The drawing in a browser (circle size with the extra line, light and dark).

## [v17] - 2026-10-12 — Topology: a star on the selected source

### Added
- A server box shows a star after its address when it is the source chrony has selected (`*` in `chronyc sources`); the blue links still mark every source the time comes from. The tooltip says "the selected source".

### Verified
- `node --check`, gofmt, vet, tests, cross-builds.

### Not verified
- The drawing in a browser.

## [v16] - 2026-10-12 — Topology: the servers chrony uses are blue

### Fixed
- The links from the gateway to its servers were never blue any more: the highlight belonged to the old relay and nothing set it after chrony replaced it. A link is now blue (with a "used for time" entry in the legend) when chrony on the node being viewed has that server as its selected (`*`) or combined (`+`) source, and the server's tooltip says so. Servers chrony has but does not use (not combined, falseticker, unreachable) stay grey.

### Verified
- `node --check`, gofmt, vet, tests, cross-builds.

### Not verified
- The drawing in a browser, and against a real chronyd (the marks come from `chronyc sources` as before).

## [v15] - 2026-10-12 — Statistics: outcome card

### Changed
- Monitor ▸ Statistics: the "NTP versions" card always read 100% Other, because chrony reports a client's address and packet counts but not the NTP version. It is replaced by an **Outcome** card (answered, refused, kiss-o'-death, failed). The screenshots under `snaps/` are still the old ones.

### Verified
- `node --check`, gofmt, vet, tests, cross-builds.

### Not verified
- The card in a browser (checked by reading the code only).

## [v14] - 2026-10-12 — A red gateway answers nobody

### Changed
- When no server is in service and no fallback is configured (every server down or paused), the gateway is red, and the node now also stops answering clients: chrony is told `deny all` live and the `allow` lines are left out of its file (so a restart does not bring them back). The allowed clients return, without a restart, as soon as a server passes. Before, chrony kept answering from its holdover while the gateway showed red.

### Added
- A gateway's Statistics dialog (right-click ▸ Statistics…) now shows the time itself, not only availability: **Clock offset** (this node's clock against what chrony believes; with chrony `-x` in a container, the host's error) and **Root delay** (average and worst), one point a minute, all nodes of the cluster together. Recorded from chrony's tracking while the gateway is up and chrony is synchronised.

### Verified
- A test for the mute and the restore (file, live rules, no restart), gofmt, vet, tests, cross-builds.

### Not verified
- A live run against a real chronyd (the live rule is the same `deny all` that was checked in v8).

## [v13] - 2026-10-12 — Chrony in containers, corrected

### Fixed
- v12's chrony drop-in did not work: Ubuntu starts chronyd with `ExecStart=!…` (full privileges), the drop-in dropped the `!`, and chronyd then failed with "Not superuser". The drop-in keeps the `!` and also clears `ConditionVirtualization`.
- v12 decided "container" only from the installer's own capabilities. The installer now also reads PID 1's capabilities and, after starting chrony, asks systemd whether the unit was skipped (`ConditionResult=no`); if so it writes the drop-in and restarts chrony.

### Added
- The troubleshooting bundle has `system/chrony-service.txt`: `systemctl status` and `systemctl cat` of the chrony unit (drop-ins included), its last 100 journal lines, who holds UDP 123, and `chronyc tracking`.

### Verified
- `bash -n`, shellcheck, the drop-in function with the skipped/not-skipped answers forced, gofmt, vet, tests, cross-builds. The `!` fix follows a real failure log from an Ubuntu 26.04 LXC node.

### Not verified
- A full installer run in a container (the manual drop-in with `!` was given to the owner to try).

## [v13] - 2026-10-12 — Detect a skipped chrony unit

### Fixed
- v12 decided whether the machine was a container from the installer's own capabilities; on some LXC setups systemd still skipped the chrony unit and no drop-in was written. The installer now also reads PID 1's capabilities and, after starting chrony, asks systemd whether the unit was skipped (`ConditionResult=no`); if so it writes the `chronyd -x` drop-in and restarts chrony.

### Verified
- `bash -n`, shellcheck, the drop-in function with the skipped/not-skipped answers forced, gofmt, vet, tests, cross-builds.

### Not verified
- A real install in a container.

## [v12] - 2026-10-12 — Chrony in containers

### Fixed
- In an LXC or other container without `CAP_SYS_TIME`, Ubuntu's chrony unit is skipped by systemd ("start condition unmet"), so no node ever answered NTP and the gateways stayed amber. The installer now detects a machine that cannot set the clock and writes a drop-in (`/etc/systemd/system/<chrony unit>.d/ntpdir.conf`) that removes the condition and runs `chronyd -x`: chrony tracks the servers and answers clients, and the clock comes from the host. The uninstaller removes the drop-in. The chrony-not-running message now says what to do.

### Verified
- `bash -n`, shellcheck, the drop-in function in isolation (written only when the clock cannot be set), gofmt, vet, `go test -race -count=1 ./...`, the five cross-builds, `CGO_ENABLED=0` vet and test.

### Not verified
- A full install in a real container; the generated unit text matches Ubuntu's chrony unit (`ExecStart=!/usr/sbin/chronyd $DAEMON_OPTS`) and the Red Hat family's (`$OPTIONS`) but was not run under systemd here.

## [v11] - 2026-10-12 — Host lookup fix

### Fixed
- Add NTP server: filling in a name or an address showed "Lookup failed: unknown command: ntp.lookup". The route `/api/hostlookup` named an operation that does not exist; it now calls `host.lookup`. A test checks that every operation a web route names is handled.

### Verified
- gofmt, `go vet`, `go test -race -count=1 ./...`, the five cross-builds, `CGO_ENABLED=0` vet and test.

## [v10] - 2026-10-12

### Removed
- The cluster **Failover** drop-down (Auto/On/Off), `--cluster-failover`, `POST /api/cluster/failover` and the `cluster.failover` operation. Failover is always automatic: on from three members, off with two (promote by hand). Old files that carry a `failover` value are accepted and ignored.

### Fixed
- A node whose saved state said it was a replica of its own address showed "the primary … is not reachable" and "Last sync failed: the primary … is not a known peer" while it was in fact alone. It now becomes the primary at start and on the next sync (no epoch change), and the warning is never shown for one's own address.

## [v9] - 2026-10-13 — Clean re-release of v8

No code change. The v8 tag on GitHub contained files that v8 had deleted (`ntpfront.go`, `fwdfail.go`, `upstreamudp.go` and others from the old relay), so `get.sh` and `install.sh` failed to build it with "dialUDP redeclared" and "undefined: ntpVersion". This archive is the v8 tree, built from an empty directory, with the version raised so that a new tag is unambiguous.

### Packaging fix
- When publishing, replace the repository's tree instead of copying over it (`git rm -rf . && tar xzf ntpdir_v9.tgz --strip-components=1 && git add -A`), and tag that commit. Files removed by a release must be deleted from the repository, or the web installer builds a mixture of old and new source.

### Verified
- gofmt, `go build`, `go vet`, `go test -race -count=1 ./...`, the five cross-builds and `CGO_ENABLED=0` vet and test; the archive contains none of the removed relay files.

### Not verified
- The GitHub tag and `curl | bash` path (the sandbox cannot reach the repository).

## [v9] - 2026-10-13 — Clean re-release of v8

No code change. The v8 tag on GitHub contained files v8 had deleted (`ntpfront.go`, `fwdfail.go`, `upstreamudp.go`), so the web installer failed to build it. This archive is the v8 tree with the version raised, so a new tag is unambiguous.

### Packaging fix
- Publish by replacing the repository's tree (`git rm -rf .`, extract, `git add -A`), so files removed by a release are deleted from the repository.

## [v8] - 2026-10-13 — chrony answers the clients; AnyTime keeps its sources healthy

The forwarding NTP relay is gone. Each node's chrony answers clients, and AnyTime decides which upstream servers chrony may use: servers that test good are chrony's sources on every node, and a server that fails, is a falseticker, is too far out of sync or is too slow is removed from them within seconds and added again when it recovers.

### Added
- `chrony` source management (`chronysrc.go`, `chronyloop.go`): every 2 seconds AnyTime writes the healthy servers to `<sourcedir>/ntpdir.sources` (chrony's `sourcedir`) and runs `chronyc reload sources`. If no normal server passes, chrony keeps what it has and the fallback servers become sources only for that time; with everything paused the file is emptied. A write that chrony was not there to receive is retried.
- **Rolling chrony restart** (`chronyroll.go`): a changed port or rate limit is applied by restarting chrony node by node. Each node pauses itself, restarts chrony, waits (up to 3 minutes) until it is synchronised, and resumes; nodes go in order of address, and nobody starts while another is restarting, has failed, or is updating. A node that cannot be paused (alone, or the last one serving a gateway) restarts without pausing. A node that fails to synchronise resumes anyway, shows `failed`, and holds the others for 10 minutes. The state is in the cluster status (`chrony_roll`), the NTP page tile and `--show-ntp`; a roll cut short by a daemon stop resumes the node afterwards (`chrony-roll.json`).
- Client settings go to `<confdir>/ntpdir.conf` (`port`, `allow`, `ratelimit`); a new `allowed_clients` list is applied to the running chrony with `chronyc deny all` / `allow all NET` (verified against a real chronyd with `accheck`) and chrony is restarted only when the port or the rate limit changes, since chrony has no command for those. `allowed_clients` is `allow`; `client_rate`, `client_burst` and `client_action` are `ratelimit` (interval from the rate rounded to a power of two, burst, leak 4 for drop and 2 for kod).
- `max_rtt_ms` (default 500, 0 = off): a server whose round trip is longer counts as down ("too slow"). Configure ▸ NTP ▸ Health.
- The NTP page and `--show-ntp` show chrony's state (synchronised, stratum, offset, synchronised to, requests handled and dropped) and an **In chrony** column per server. `chrony.json`, `chrony-sources.txt` and `chrony-sourcestats.txt` are in the troubleshooting bundle.
- Statistics are read from `chronyc clients` every 10 seconds (answered = packets minus drops, refused = drops).
- Installer: requires chrony 4.0 or newer; adds `sourcedir` and `confdir` to chrony's marked block, creates both directories, and switches off chrony's own servers (`pool`/`server`/`peer` lines marked `#ntpdir-off#`, distribution `sources.d/*.sources` renamed `*.ntpdir-off`). The uninstaller puts them back; `--purge` also removes the two directories.

### Changed
- A gateway or anycast address counts as healthy only while chrony runs and is synchronised, as well as a server passing.
- Pools are kept for paused gateways and paused nodes too (a paused node still needs its time sources); two tests that expected no pool were changed.
- With no gateway there is no pool, so chrony gets no sources: draw a gateway first.
- Configure ▸ NTP is now Servers, Health and Clients tabs; per-gateway "Load balancing" is "Health checks".
- A node's sources are only the servers of the topology: each gateway's own servers, or the shared list for a gateway without its own, from gateways that are not paused; the same on every node. A shared list that no gateway uses is not given to chrony. chrony has one set of sources, so with several gateways the node uses all their healthy servers together.
- Test floor in `TestHelpCoversEveryField` lowered from 70 to 55 labelled fields, because the spread/attempts/alpha/timeout/limit fields were removed.

### Removed
- The relay (`ntpfront.go`, `upstreamudp.go`, `udpreply.go`, `loopguard.go`, `fwdfail.go`), the in-process client limiter, ranking, spread and the `NTPDIR_CHRONY_IFACE` / `bindaddress` logic. `spread`, `spread_band`, `max_attempts`, `latency_alpha`, `query_timeout_ms`, `client_exempt` and `client_limits` are still accepted in a file but do nothing. Their CLI flags and GUI fields are gone.
- Recorded per-gateway answer time, errors and request rate, and a server's failed requests: chrony does not report them. The topology gateway/server statistics windows show availability, round trip, offset and failed probes only. Statistics show "Failed" and "Kiss-o'-death" as 0, the top-servers list as one `chrony` entry and the NTP version as "Other".

### Fixed
- The NTP page and `--show-ntp` showed the default port and client settings instead of the configured ones.
- The Topology legend is hidden until a gateway exists.

### Verified
- gofmt, `go build`, `go vet`, `go test -race -count=1 ./...` pass, with new tests for the sources file, client config, state parsing and statistics sampling; cross-builds and `CGO_ENABLED=0` vet/test as listed below.
- Live, with a real chronyd 4.5 (private instance, `-x`), three stub NTP servers and the daemon: the three servers appear as sources; a dead server, a server 0.6 s slow (limit 300 ms) and a server 5 s off are each removed from `chronyc sources` within about 10 s and added back on recovery; with all servers dead chrony keeps its sources; a node started before chronyd got its sources once chronyd came up; a gateway on `lo` answered on the VIP through chrony; allowed clients and rate limit reached `ntpdir.conf`, and the allowed-clients rules applied to a real running chronyd (`accheck`).
- Installer: dry-run, a real install with a shim `systemctl` against a fake `chrony.conf` and `sources.d`, an idempotent re-run, and an uninstall with `--purge` that restored `chrony.conf` byte for byte.
- Live, two real daemons clustered, each with its own real chronyd and shim `systemctl`: a shared rate-limit change rolled through the nodes in order: the first node paused, chrony restarted, resumed when synchronised (about 12 s), and only then the second; the primary role was handed over on each pause; a fresh node started with a non-default port restarted chrony once.
- GUI in headless Chromium, light and dark: NTP page, Configure ▸ NTP, Statistics, Topology.

### Not verified
- The failure path of the roll (chrony never synchronising) and the recovery after a daemon stop mid-roll were run only in unit tests, not live; three or more nodes; a real systemd restart.
- A real cluster of several nodes with chrony (each node's chrony run by systemd), a real `chronyd` restart through systemd, chrony older than 4.5, and the installer on a distribution other than a sandbox with a fake Ubuntu `os-release` (no real apt/dnf chrony install, no shellcheck-clean run on other families beyond `shellcheck -S warning`).
- chrony's own `clientloglimit` caps the clients it counts, so the statistics undercount on a very busy node.
- The screenshots under `snaps/` were not retaken: `ntp.png`, `topology.png` and `statistics.png` show the old relay pages. `ntp-relay.png` was removed.
- Cross-platform builds use the PAM stub (see v1); only the native amd64 build is verified with PAM.

## [v7] - 2026-10-12 — Updates: "Downloading…"; Controller greyed with several gateways

Taken from the Anyname DNS Director v379. Its other recent changes (server names registered in DNS, Rename registering in DNS, policy-based resolution) are DNS-only; its v369-v374 changes were already here.

### Changed
- Fetching an update from online says "Downloading…" while it works, not "Downloading from GitHub…".

### Fixed
- With more than one gateway, a node that was already the controller (and primary) still offered **Controller** in its menu, because the check also counted gateways the node is not a member of (another subnet, removed from it), where it can never hold the role. It now counts only the gateways the node is a member of. A paused node still shows "Paused: resume it first".

### Verified
- gofmt, build, vet, `go test -race -count=1`, CGO-off vet and test, cross-compiles for amd64, arm64, arm, 386 and riscv64, `node --check`.

### Not verified
- The failure path of the roll (chrony never synchronising) and the recovery after a daemon stop mid-roll were run only in unit tests, not live; three or more nodes; a real systemd restart.
- In a browser; the multi-gateway case was reasoned from the code, not reproduced.

## [v6] - 2026-10-12 — README and screenshots refreshed for NTP

### Changed
- All 18 screenshots in `snaps/` regenerated from a live two-node NTP cluster (anycast, capture, cluster, gateway-stats, gateways, history, host, log, login, node, ntp-relay, ntp, statistics, topology-menu, topology, upgrade, users, web-certificate).
- README gained two images: `snaps/ntp.png` (Monitor ▸ NTP) and `snaps/ntp-relay.png` (Configure ▸ NTP relay).

### Fixed
- Leftover DNS wording: the cluster-join prompts in `cli.go` ("NTP block" not "DNS block"), two README sentences ("NTP servers", "NTP pool"), the capture filter and anycast address placeholders in `app.js`, and the capture examples in `help.js` (`port 123` not `port 53`).

### Verified
- Screenshots taken in Chromium (dark, 1280x760) against a two-node cluster with stub NTP servers, generated client traffic, real PAM users and a real update push.
- gofmt, build, vet, `go test -race -count=1`, cross-compile amd64/arm64/arm/386/riscv64, `CGO_ENABLED=0` vet and test, `node --check` on `app.js` and `help.js`.

### Not verified
- The failure path of the roll (chrony never synchronising) and the recovery after a daemon stop mid-roll were run only in unit tests, not live; three or more nodes; a real systemd restart.
- The screenshots were taken from a build with the `cli.go` fix but before the final `app.js`/`help.js` placeholder edits.
- The Upgrade shot's newest event is a "cancelled" entry from a mistaken demo command; History shows setup BGP entries; the NTP page's right-hand columns clip at 1280px.
- The first `go test -race` run failed once (failing test not captured); the rerun passed. Timing-sensitive tests have been flaky before (`TestLogServerFlips`, `TestSpreadSharesRealQueries`).
- dnsdir on a real host.

## [v5] - 2026-10-12 — Fix: pausing a server could pause the whole node; controller mark on a paused node

### Fixed
- Pausing or resuming a server (or anything else) in the Topology saved the page's copy of the whole configuration, which still carried the node's pause flag from before the node was last paused or resumed from its menu. The save then paused the node (its history read "Groups changed … ; Node: paused — this node is out of service" and its gateways stopped). Whether the node is paused is now changed only by pausing or resuming the node (node menu, Operate ▸ Node, `--node-pause`/`--node-resume`): a saved configuration from the web page, an import and a restored version all keep the node's live state. The same fix as dnsdir v374, where a real node showed it.
- Topology on a paused node (or one that does not serve a gateway): the picture of a serving node was borrowed with that node's own member still marked "local", so the controller dot and the star landed on the paused node instead of the real controller. Borrowed members are no longer marked local (dnsdir v369).

### Verified
- gofmt, build, vet, `go test -race -count=1` (new `TestConfigSaveNeverChangesTheNodePause`, `TestTakeFromClearsLocalOnMembers`; one run failed once with the output not captured and passed on three reruns, so it is treated as a flaky timing test), CGO-off vet and test, cross-compiles for amd64, arm64, arm, 386 and riscv64, `node --check`.

### Not verified
- The failure path of the roll (chrony never synchronising) and the recovery after a daemon stop mid-roll were run only in unit tests, not live; three or more nodes; a real systemd restart.
- In a browser or on a live cluster. A node paused by this bug stays paused until it is resumed from its menu.

## [v4] - 2026-10-12 — A gateway can answer NTP on dnsdir's anycast addresses

### Added
- **dnsdir addresses.** With the Anyname DNS Director installed on the same host, a gateway can also answer NTP on anycast addresses dnsdir announces (`groups[].dnsdir_vips`, shared by the cluster). The addresses on offer are read from dnsdir's configuration (`/var/lib/dnsdir/dnsdir.conf`, `extra_vips` of its gateways). ntpdir **only listens** (freebind, the gateway's NTP port, the gateway's pool): it never adds the address to `lo`, takes it off, renews it or announces it, and never touches FRR, so it cannot interfere with dnsdir's BGP. Every 3 s it checks whether dnsdir is still installed, still announces the address and has it on `lo`; the listener follows (no restart needed when dnsdir is installed or removed).
- GUI: right-click the gateway ▸ *Add dnsdir address* (only while dnsdir is installed; a choice of the addresses it announces that are free). Each shows as a pill under the anycast pills: green answering, amber when dnsdir holds it but no NTP server answers (dnsdir still announces it), grey when dnsdir does not hold it, no longer announces it, or is gone. Right-click a pill ▸ Delete, or the Delete key. CLI: `--canvas-add dnsdirvip --group N --address ADDR`, `--canvas-del dnsdirvip ...`; `--canvas` lists them. `GET /api/canvas` carries `dnsdir` (`present`, `offered`).
- `AnycastState.external` marks them; they are left out of the cluster's anycast report and of the BGP colouring.

### Changed
- Adding a dnsdir address is refused unless dnsdir is installed here and announces it (GUI, CLI and API: `PUT /api/config` and the canvas edits). Addresses already saved are not re-checked, so a config stays loadable while dnsdir is away, and the listener returns when it comes back. Validation: a dnsdir address cannot equal a gateway's shared address or an anycast address of ntpdir, cannot be listed twice, and only one gateway may answer on it.
- The settings form carries `dnsdir_vips` through like `extra_vips`; the loop guard counts them as this host's own addresses.
- BGP stays unavailable in ntpdir while dnsdir is installed (v3); standalone, ntpdir runs BGP and its own anycast as before.

### Verified
- New tests (`dnsdir_vips_test.go`): reading dnsdir's offered list (junk, unreadable file, dnsdir absent); config rules; the cluster hash and merge; the check on add (not installed, not announced, announced, already saved); canvas add/delete; the listener follows dnsdir (not on `lo` yet, held, dead pool, dropped from dnsdir's list, dnsdir removed) and `lo` is never touched (no adds, no deletes, also on stop).
- Live run of the real daemon with a stub NTP server, a fake dnsdir marker and configuration: an address dnsdir does not announce is refused; an announced one is added and reports "not announcing it right now" until it is put on `lo`, then an NTP request to it is answered (origin timestamp echoed) from the gateway's pool; it is still on `lo` afterwards (ntpdir never removes it); removing the marker stops the listener and bringing it back restarts it; deleting works. The sandbox was restored.
- Chromium (light and dark), signed in through real PAM: the menu item appears, the form offers only free addresses, the pill is drawn with its label and tooltip, Delete removes it.
- `gofmt -l` empty, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, `node --check`; cross-compiles for linux/amd64, arm64, arm, 386 and riscv64.

### Not verified
- The failure path of the roll (chrony never synchronising) and the recovery after a daemon stop mid-roll were run only in unit tests, not live; three or more nodes; a real systemd restart.
- Two flaky tests: one full `-race` run reported a race in `TestLogServerFlips`, and one non-race run missed a timing bound in `TestSpreadSharesRealQueries`. Neither recurred in 40 isolated race runs, 3 isolated runs and the full runs that followed (all green), and neither touches this change, but the race report was not investigated.
- A real dnsdir install: dnsdir was simulated by a marker file, a configuration file and an address added to `lo` by hand. BGP announcements, and what dnsdir does with the address when its own DNS is unhealthy, were not exercised.
- More than one node: the shared list is covered by tests of the hash and merge, not by a live cluster run.
- IPv6 dnsdir addresses (the sandbox has no IPv6).

## [v3] - 2026-10-12 — BGP is switched off while dnsdir is installed on the host

### Changed
- ntpdir looks for the Anyname DNS Director (`/usr/local/sbin/dnsdir`, `/usr/local/share/dnsdir`, `/etc/systemd/system/dnsdir.service`) at start-up and each time BGP is applied or changed. While one is present, BGP is unavailable: ntpdir does not touch `/etc/frr/frr.conf`, `/etc/frr/daemons`, its marker or the FRR service (even if it managed FRR before dnsdir was installed, so it cannot wipe dnsdir's BGP section), treats BGP as inactive (the drawing shows no BGP colouring), and refuses to set it up or enable it from the GUI, the API (`PUT /api/bgp`, `POST /api/bgp/operate`) and the CLI (`--asn`, `--bgp-neighbor-add`, `--bgp-enable`). Clearing the settings and disabling still work; settings already in the config are kept and have no effect. Removing dnsdir lifts the block without a restart.
- `GET /api/bgp` has a new `blocked` field; the three Anycast pages and `--bgp` say BGP is unavailable. The README, the Anycast help topic and the v2 note on running both products are updated.
- Anycast addresses are unaffected: without BGP they are plain addresses on `lo`.

### Verified
- New tests: the check follows the marker files; with dnsdir present `applyNow` leaves `frr.conf`, `daemons`, the marker and the FRR calls untouched, for BGP on and off, after ntpdir had managed FRR; setting an AS or neighbor and enabling BGP are refused over the API while clearing and disabling work; `blocked` is in the status.
- Live run of the real daemon with a scratch config: `--asn 64512` works, then with a marker file at `/usr/local/sbin/dnsdir` `--bgp` reports BGP unavailable, `--asn 64513` and `--bgp-enable` are refused, `--asn off` is accepted; after removing the marker `--asn` works again. The marker and test state were removed afterwards.
- `gofmt -l` empty, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`, `node --check webui/app.js`; cross-compiles for linux/amd64, arm64, arm, 386 and riscv64.

### Not verified
- The failure path of the roll (chrony never synchronising) and the recovery after a daemon stop mid-roll were run only in unit tests, not live; three or more nodes; a real systemd restart.
- The three Anycast pages in Chromium with the block shown (only `node --check` and the API/CLI were run).
- A real dnsdir install on the same host; the check is by file presence only, so a dnsdir that was removed by hand but left its unit file behind keeps BGP blocked.
- dnsdir v373 was not changed and has no matching check for ntpdir, so it would still take over `frr.conf` on its own; only ntpdir backs off.

## [v2] - 2026-10-12 — Own gateway port and multicast addresses, so ntpdir can share a host with dnsdir

### Changed
- The gateway protocol (election, heartbeats, hand-overs) now uses **UDP 12382** and the multicast groups **224.1.3.123** and **ff02::1:123**. They were 4729, 224.1.3.7 and ff02::1:307, the same as the Anyname DNS Director's. Both daemons open that socket with `SO_REUSEPORT`, so on one host the kernel split unicast packets between them and each saw the other's multicast (rejected by the HMAC, but the lost packets broke elections). The packet format and magic are unchanged.
- Upgrade note: the new port is not compatible with v1, so **every node of a gateway must run v2**. A rolling update leaves the nodes unable to see each other until all have restarted, and each may then briefly claim the controller role.
- The installer's firewall hints say `12382/udp`; the README describes the port and the multicast groups next to the cluster settings.

### Still to watch when running both products on one host
- Only one of them may manage BGP: each owns `/etc/frr/frr.conf` and rewrites it.
- Their gateway ids must differ (dnsdir defaults to 1, ntpdir to 100): the virtual MAC is derived from the group id and slot only.

### Verified
- `gofmt -l` empty, `go build`, `go vet`, `go test -race -count=1 ./...`, `CGO_ENABLED=0 go vet` and `go test`; cross-compiles for linux/amd64, arm64, arm, 386 and riscv64; `bash -n install.sh`.

### Not verified
- The failure path of the roll (chrony never synchronising) and the recovery after a daemon stop mid-roll were run only in unit tests, not live; three or more nodes; a real systemd restart.
- Running ntpdir and dnsdir together on one host: the conflict was found by reading both sources, and the fix was not tried against a running dnsdir.
- A rolling v1 to v2 update on a live multi-node cluster.

## [v1] - 2026-10-12 — AnyTime NTP Director: the DNS gateway becomes an NTP relay

The project is now **AnyTime NTP Director** (`ntpdir`), built from the Anyname DNS Director v365 code base. The numbering restarts at 1 and the earlier changelog was removed on purpose.

### Added
- **NTP relay** in place of the DNS proxy. Each gateway forwards a client's NTP packet (RFC 5905) unchanged to the fastest healthy upstream server and returns the answer, accepted only if it echoes the client's transmit timestamp. Modes 6 and 7 are never relayed. A loop guard never forwards to the asker or to this host's own addresses.
- **NTP health checks** with real NTP requests: highest stratum (default 15), largest root distance (default 1500 ms), kiss-o'-death and unsynchronised-clock detection, and **falseticker** detection against the median offset (default 128 ms, needs three or more servers). Ranking by smoothed round trip, spread over servers within a band, fallback servers, per-server pause, per-client allow list and rate limits (`drop` or `kod`).
- **chrony as a prerequisite.** The installer installs it (apt, dnf, pacman), enables it and writes a marked block into its configuration: `bindaddress` for the first IPv4 and the first IPv6 address of the first Ethernet interface, `allow ::/0` and `allow 0.0.0.0/0`. chrony is restarted when the block changes. The uninstaller removes only the block and leaves chrony installed.
- **Statistics, Topology, NTP page, Capture and help** rewritten for NTP: outcomes (answered, failed, kiss-o'-death, refused), NTP versions and IP families, top clients and top servers, NTP packet decoding in Capture, `--show-ntp`, `--stats-outcome`, `--stats-server`, `--host-lookup`.
- **Rename a node** (Topology ▸ right-click a node ▸ Rename, or `--node-rename NAME`): sets the operating system host name (`hostnamectl`, or `hostname` plus `/etc/hostname` without systemd) and rewrites the old name in `/etc/hosts` (a `127.0.1.1` line is added when none names the host). The name is validated before it reaches a command, files are replaced atomically with their mode kept, and `/etc/hosts` is restored if the host name cannot be set. It works on any cluster member through the node picker.
- **Pausing a node moves the roles.** The primary role is handed to a reachable node that is not paused, and the gateway controller moves because the paused node's gateways resign. A paused node cannot be made primary or controller (CLI, GUI and menu items are refused or greyed). The Topology no longer shows the controller dot on a paused node.

### Changed
- Name, binary, service, group, PAM service, state directory (`/var/lib/ntpdir`), Go module and config keys are `ntpdir` / `ntp`; the brand is written "AnyTime" everywhere. Web GUI port **12380** and cluster port **12381** (were 53853 and 53854); the relay listens on UDP 123 by default.
- New gateways are numbered from **100** (101, 102, …); `--group N` still picks another number (1 to 255).
- Cluster strings were renamed, so nodes of the old DNS Director cannot join an ntpdir cluster. The wire protocol and packet magic are unchanged. The default HMAC key is now `ntpdir` (was `dgw`): a gateway with no explicit `key` must have the same default on every node, and a config that sets `key` keeps working as before.
- The installer no longer aborts when a service restart itself returns an error: the active check decides, and the rollback runs.
- The default update repository is `micush/ntpdir`; the GitHub repository must be renamed to match.
- README, QUICKSTART, CLAUDE.md, the example config and `help.js` were rewritten for NTP. The screenshots in `snaps/` still show the DNS pages (the DNS and policy pictures were removed), so most of them are out of date.

### Verified
- `gofmt -l` empty, `go build`, `go vet`, `go test -race -count=1 ./...`, and `CGO_ENABLED=0 go vet` plus `go test`. Cross-compiles for linux/amd64, arm64, arm, 386 and riscv64.
- New and ported tests cover the NTP wire format, probing, falseticker, spread, fallback, loop guard, client limits, canvas edits, group numbering from 100 and primary hand-over skipping paused nodes.
- Smoke run with three stub NTP servers on `lo`: a client request through the VIP is answered by the fastest server; killing it fails over to the next; an atomic config rename hot-reloads; `--show-ntp` shows the ranking.
- Real PAM check: a group member signs in; a wrong password and a valid user outside the group get the same message; repeated failures lock out the source (root was then refused too).
- Chromium, light and dark: Topology (servers, controller dot), NTP, Statistics and the help panel.
- Live cluster run with two real daemons: join, a shared edit on the replica reaching both files, pausing the primary (the role moved to the other node), a paused node refusing promotion, and an update pushed from the replica (both nodes built v2, re-exec'd and were confirmed by the boot guard; the second needed `--update-apply --yes` because the soak gate held it back).
- Rename: unit tests for name validation, the `/etc/hosts` rewrite, the command sequence and the restore on failure; a live run renamed the sandbox host through the CLI (host name, `/etc/hostname` and `/etc/hosts` changed, then were restored) and through the Chromium dialog (a bad name shows the reason, a valid one is applied).
- Installer: `bash -n` and `shellcheck -x -S warning` clean; dry runs for ubuntu, debian, linuxmint, fedora, rocky, almalinux, centos, arch, manjaro and endeavouros (alpine refused); a real run with a shim `systemctl`: fresh install, no-op, upgrade, forced-failure rollback, downgrade refusal, uninstall with and without `--purge`, a customised PAM file kept, and chrony's configuration restored byte for byte.

### Not verified
- The failure path of the roll (chrony never synchronising) and the recovery after a daemon stop mid-roll were run only in unit tests, not live; three or more nodes; a real systemd restart.
- The IPv6 branch of the chrony block (the sandbox has no IPv6) and a real chrony package install and restart; only the configuration edit with a shim was run.
- The installer's Go download against a local server was not re-run for this release (that code is unchanged).
- Real multi-host behaviour: election on a real wire, ARP/NS steering to virtual MACs, an AFN answering through `lo` and `arp_ignore`, real public NTP servers, and relay behaviour behind rate-limiting upstreams. Upstream servers see the relay's address for every client.
- The certificate, history restore and users flows of the cluster were not exercised again in this release.
- Binaries cross-compiled with cgo off use the fail-closed PAM stub; only the native amd64 build was run with PAM.

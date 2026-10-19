# AnyTime NTP Director quick start (using the web GUI)

AnyTime gives a group of machines one shared NTP address (a **gateway**). Clients point at that address; every node answers through chrony, and chrony takes its time from the upstream NTP servers you list that pass AnyTime's health checks. This guide takes you from the tarball to a working gateway using only the browser. The full reference is `README.md`.

## What you need

- One Linux machine to start with (Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch or Manjaro), with root access and internet access for the installer.
- A **free IP address** on the machine's network to use as the shared address (the VIP). It must not be in use by anything else. The machine itself keeps its own address.
- The address of at least one upstream NTP server (for example `10.0.0.124`, or a public one such as `time.cloudflare.com`).

## 1. Install

From GitHub, the latest tagged release:

```
curl -fsSL https://raw.githubusercontent.com/micush/ntpdir/HEAD/get.sh | sudo bash
```

Or from a tarball:

```
tar xzf ntpdir_v*.tgz
cd ntpdir
sudo ./install.sh
```

The user running the installer (you, behind `sudo`) can log in to the GUI; add others with `--add-user NAME` or later on the Users page. The installer installs what is missing (including **chrony** 4.0 or newer, which answers NTP clients and keeps the machine's clock; the installer switches off the servers chrony came with, so the machine has no time source until you add NTP servers in the next steps), builds AnyTime, creates the `ntpdir` group and the PAM login file, and starts the `ntpdir` service. Add `--dry-run` first if you want to see what it will do. Re-running it on a newer tarball upgrades in place and keeps your settings.

Who can log in: a user whose Linux password PAM accepts **and** who is in the `ntpdir` group. `root` is not special; add it to the group only if you want it to log in (Configure ▸ Users ▸ **Add existing user** adds an existing account to the group later).

## 2. Open the GUI

Browse to **https://&lt;this machine's address&gt;:12380** and sign in with that Linux user and password.

- Your browser will warn about the certificate: AnyTime made a self-signed one. Continue for now; you will replace it in step 6.
- No sign-in possible? Check `groups alice` lists `ntpdir`, and that `/etc/pam.d/ntpdir` exists. A failed login shows one generic message on purpose.
- The page follows your light/dark setting. The **?** at the top right of every page opens help for that page.

## 3. Draw your first gateway (Topology)

A new install has no gateways. Topology is the first page.

1. **Right-click** the empty drawing and choose **New gateway**
2. Fill in the form:
   - **Group number**: leave the suggestion (100: group numbers start at 100).
   - **Name (optional)**: a label such as "Office NTP".
   - **Shared IPv4 address / prefix**: the free address with its prefix, for example `192.168.1.123/24`.
   - **Network interface**: the interface that is on that network (for example `eth0`).
3. Save. A **circle** appears: that is the gateway, with four **squares** under it, the servers it starts with: `pool.ntp.org`, `time.nist.gov`, `time.google.com` and `time.cloudflare.com`. Everything you change is saved at once; there is no Apply button.
4. Right-click a square and choose **Delete** for any server you do not want. To add your own, **right-click the circle** and choose **Add NTP server…**
   - **IP address or host name**: for example `10.0.0.124` (add `:port` for a port other than 123). AnyTime checks a server by sending it real NTP requests.
5. When the gateway is working the circle and the servers turn **green**.

These servers need the node to reach the internet. Add your own servers the same way for redundancy. Hover any shape for its status and uptime ("Online for 1m 1s - 0 failures").

Colours: **green** working, **yellow** degraded (the gateway runs but something is down), **red** down, **grey** not known yet. A server is taken out of service when it stops answering, reports a stratum or root distance above the limits, or its clock disagrees with the others or answers too slowly (change the limits on Configure ▸ NTP ▸ Health). It is then removed from chrony's sources on every node, and added again when it recovers.

The circle shows the time (pick the zone with the Time zone box at the top left), and each server box shows its clock offset in bold; a blue line is a server chrony takes the time from, and the `*` marks the selected one. A node whose clock is more than 50 ms off the servers stops serving until it is back in step (Configure ▸ NTP ▸ Health ▸ Serve only within).

## 4. Try it

From another machine on the network, ask the shared address for the time:

```
chronyc -h 127.0.0.1 sources   # on a node, or:
ntpdate -q 192.168.1.123
```

Then open **Monitor ▸ NTP** to see chrony's state and each server's health, round trip, offset, stratum and whether chrony uses it. **Monitor ▸ Statistics** shows requests over time and top clients.

Point your clients (or your DHCP server) at the shared address when you are happy with it.

Running in an LXC container? chrony cannot set the clock there, so the installer starts it with `-x` and the node serves the host's clock. Use a virtual machine if the node must set its own.

## 5. Add more nodes (optional, for redundancy)

Install AnyTime on a second machine the same way (step 1 and 2), then:

1. On the first node: **Operate ▸ Cluster** ▸ **Create join code** and copy it. It works once and expires in an hour.
2. On the new node: **Operate ▸ Cluster** ▸ paste the code ▸ **Join**.
3. The new node takes over the shared settings (the drawing); only its interface, priority and similar per-node settings stay local. Check the **Network interface** for the gateway on that node (Topology ▸ right-click the circle ▸ **Edit gateway…**).

Both nodes now answer on the shared address and one of them is the controller (see **Monitor ▸ Gateways**). Open TCP port 12381 between the nodes. With a cluster, a drop-down at the top right lets you look at and configure any node from the one you are logged in to.

## 6. Replace the certificate

**Configure ▸ Web GUI** shows the certificate the GUI uses. Install your own (paste the certificate and key, or generate a signing request and paste the signed result) so your browser stops warning.

## 7. Worth knowing

- **General, Gateway groups, NTP, Web GUI and Cluster** (all under Configure) hold everything else, and every field saves on its own: probe timing, stratum, root-distance and round-trip limits, falseticker offset, allowed clients, client rate limits, and more. Each page's **?** help lists the command-line equivalent.
- **History** keeps every saved change as a version. You can compare a version with the live one and restore any of them.
- **Operate ▸ Upgrade**: upload a newer AnyTime tarball, tick the nodes to update and press the button in the Nodes card (none ticked = this node). A bad update rolls back by itself.
- **Operate ▸ Anycast**: switch BGP, or a single neighbor, off and on without losing the settings (set them under **Configure ▸ Anycast**).
- **Operate ▸ Node**: make this node the gateway controller, put it in maintenance (pause; the controller and primary roles move to another node), or restart or shut down the host, now or later.
- Bind the GUI to a management address or firewall port 12380: it can reconfigure a daemon that runs as root.
- To start over on a node: stop the service, `sudo rm -rf /var/lib/ntpdir/*`, start it again.
- To remove ntpdir: `sudo ntpdir-uninstall` (add `--purge` to delete its settings too).

## If something looks wrong

- **Circle stays grey or amber**: the node has no address on the gateway's subnet, or no server answers. Hover it: the tooltip says why.
- **Server red**: hover it (or look at the last error on **Monitor ▸ NTP**). A typo in the address, a blocked UDP port 123, a server that is not synchronised (stratum 16) or one that rate-limits your nodes are the usual causes.
- **Log**: **Monitor ▸ Log** shows what the daemon is doing, filtered by level.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// pickSuccessor chooses the member that should take the primary role from a node that is about to go away on purpose: the
// reachable replica with the newest shared settings (the highest revision), one that is not itself installing an update or
// failed one, and not a paused node (it is out of service); the same version as this node first, then the lowest address, so the choice is the same every time.
// "" when there is none.
func pickSuccessor(peers []PeerView, myVersion string) string {
	return pickSuccessorPrefer(peers, myVersion, "")
}

// pickSuccessorPrefer is pickSuccessor, except that prefer (the primary's home, see primaryHome) is chosen whenever it is a
// candidate at all.
func pickSuccessorPrefer(peers []PeerView, myVersion, prefer string) string {
	var c []PeerView
	for _, p := range peers {
		if p.Self || !p.Reachable || p.NodePaused || p.Updating || p.UpdateFailed != "" || p.IsPrimary {
			continue
		}
		c = append(c, p)
	}
	if len(c) == 0 {
		return ""
	}
	for _, p := range c {
		if prefer != "" && p.Addr == prefer {
			return p.Addr
		}
	}
	sort.Slice(c, func(i, j int) bool {
		if c[i].SharedRev != c[j].SharedRev {
			return c[i].SharedRev > c[j].SharedRev
		}
		si, sj := c[i].Version == myVersion, c[j].Version == myVersion
		if si != sj {
			return si
		}
		return c[i].Addr < c[j].Addr
	})
	return c[0].Addr
}

// HandOverPrimary gives the primary role to the best other member before this node is shut down, restarted or updated on
// purpose, and says who got it ("" when this node is not the primary or nobody can take it: then nothing changes).  The role
// then stays where it lands: this node comes back as a replica.  A node that goes offline unexpectedly never gets here; its
// role stays put until an administrator promotes another node.
func (c *Cluster) HandOverPrimary(by, why string) (string, error) {
	return c.handOverPrimary(by, why, false)
}

// HandOverPrimaryForUpdate is HandOverPrimary for a node that restarts into an update: the primary also remembers its home, the
// node that was primary when the update began, and the role goes back there once the update is over (returnPrimaryHome).
func (c *Cluster) HandOverPrimaryForUpdate(by, why string) (string, error) {
	return c.handOverPrimary(by, why, true)
}

func (c *Cluster) handOverPrimary(by, why string, forUpdate bool) (string, error) {
	if c == nil || !c.Enabled() {
		return "", nil
	}
	snap := c.node.Snapshot()
	if snap.Role != RolePrimary {
		return "", nil
	}
	home := ""
	if forUpdate {
		if home = c.primaryHome(); home == "" {
			home = snap.SelfAddr
		}
	}
	target := pickSuccessorPrefer(c.View().Peers, version(), home)
	if target == "" {
		return "", nil
	}
	return c.handOverTo(target, by, why, home)
}

// handOverTo gives the primary role to target (a member that was picked as able to take it), telling it the home to go back to
// ("" for none), and says who got it.
func (c *Cluster) handOverTo(target, by, why, home string) (string, error) {
	snap := c.node.Snapshot()
	var tp *ClusterPeer
	for i := range snap.Peers {
		if snap.Peers[i].Addr == target {
			tp = &snap.Peers[i]
		}
	}
	if tp == nil {
		return "", nil
	}
	epoch := snap.Epoch + 1
	ctx, cancel := context.WithTimeout(context.Background(), peerTimeout)
	defer cancel()
	// the successor first: if it does not take the role, nothing has changed here
	if err := c.call(ctx, *tp, "POST", "/cluster/announce", announceMsg{Epoch: epoch, PrimaryAddr: target, Home: home}, nil, peerTimeout); err != nil {
		return "", fmt.Errorf("%s did not take over as primary: %v", target, err)
	}
	if _, err := c.node.AdoptAnnounce(epoch, target); err != nil {
		return "", err
	}
	c.setPrimaryHome("")
	warnf("cluster: primary role handed to %s (epoch %d) before %s, by %s", target, epoch, why, by)
	c.announce(c.node.Snapshot())
	return target, nil
}

// ── the primary goes back home after an update ──────────────────────────────

// primaryReturnAfter is how long everything must have looked finished before the primary role goes back to its home.
var primaryReturnAfter = 30 * time.Second

// primaryHomeExpires is how long a home is remembered: a rolling update that has not finished by then is not going to.
const primaryHomeExpires = 12 * time.Hour

func (c *Cluster) homePath() string {
	return filepath.Join(c.mg.stateDir, "update", "primary_home")
}

// primaryHome is the node the primary role goes back to when the update is over: the primary at the time the first node handed
// the role over to update.  "" when there is none.  It is kept only by the node that holds the role (the announcement that
// hands it over carries it) and is dropped by any other change of primary.
func (c *Cluster) primaryHome() string {
	st, err := os.Stat(c.homePath())
	if err != nil {
		return ""
	}
	if time.Since(st.ModTime()) > primaryHomeExpires {
		os.Remove(c.homePath())
		return ""
	}
	b, _ := os.ReadFile(c.homePath())
	return strings.TrimSpace(string(b))
}

func (c *Cluster) setPrimaryHome(addr string) {
	if c == nil || c.mg == nil || c.mg.stateDir == "" {
		return
	}
	if addr == "" {
		os.Remove(c.homePath())
		return
	}
	if os.MkdirAll(filepath.Dir(c.homePath()), 0o700) == nil {
		_ = os.WriteFile(c.homePath(), []byte(addr+"\n"), 0o600)
	}
}

// primaryReturnTarget says whether the primary (this node) may give the role back to home now: nobody is installing an update or
// restarting into one, nothing is queued, with auto-update on every reachable member runs this node's version (or has failed
// its update), and home itself is up, not paused and not failed.  drop is true when home cannot come back at all (it is gone, or
// its update failed) and should be forgotten.
func primaryReturnTarget(peers []PeerView, home string, intent UpdateIntent, selfBusy bool) (ready, drop bool, why string) {
	var self *PeerView
	var hp *PeerView
	for i := range peers {
		if peers[i].Self {
			self = &peers[i]
		}
		if peers[i].Addr == home {
			hp = &peers[i]
		}
	}
	switch {
	case hp == nil:
		return false, true, "it is no longer a member"
	case hp.UpdateFailed != "":
		return false, true, "its update failed"
	case selfBusy:
		return false, false, "this node is installing an update"
	case len(intent.Pending) > 0:
		return false, false, "an update is still queued"
	case !hp.Reachable || hp.NodePaused:
		return false, false, "it is not available"
	}
	for _, p := range peers {
		if p.Updating || p.Restarting {
			return false, false, p.Addr + " is installing an update"
		}
		if intent.AutoAll && !p.Self && p.Reachable && p.UpdateFailed == "" && self != nil && p.Version != self.Version {
			return false, false, p.Addr + " runs another version"
		}
	}
	return true, false, ""
}

// returnPrimaryHome runs on every sync of every node: the primary, when it holds a home that is not itself and the update is over
// (primaryReturnTarget for primaryReturnAfter in a row), gives the role back to it.
func (m *Mgmt) returnPrimaryHome() {
	c := m.cl
	if c == nil || !c.Enabled() {
		return
	}
	home := c.primaryHome()
	if home == "" {
		return
	}
	snap := c.node.Snapshot()
	if snap.Role != RolePrimary || home == snap.SelfAddr {
		c.setPrimaryHome("")
		c.mu.Lock()
		c.returnSince = time.Time{}
		c.mu.Unlock()
		return
	}
	ready, drop, why := primaryReturnTarget(c.View().Peers, home, m.upd.Intent(), m.upd.Busy())
	if drop {
		warnf("cluster: the primary role stays here: %s cannot take it back (%s)", home, why)
		c.setPrimaryHome("")
		return
	}
	c.mu.Lock()
	if !ready {
		c.returnSince = time.Time{}
		c.mu.Unlock()
		return
	}
	if c.returnSince.IsZero() {
		c.returnSince = time.Now()
	}
	wait := time.Since(c.returnSince) < primaryReturnAfter
	c.mu.Unlock()
	if wait {
		return
	}
	if _, err := c.handOverTo(home, "update", "the update is over", ""); err != nil {
		warnf("cluster: could not give the primary role back to %s: %v", home, err)
		return
	}
	infof("cluster: the update is over: the primary role is back at %s", home)
	c.mu.Lock()
	c.returnSince = time.Time{}
	c.mu.Unlock()
}

// handOver is the daemon's side of it: the primary role moves before a restart, shut down or update, and a failure is logged,
// never a reason to stop (the administrator asked for the restart).
func (m *Mgmt) handOver(by, why string) {
	if m == nil || m.cl == nil {
		return
	}
	if _, err := m.cl.HandOverPrimary(by, why); err != nil {
		warnf("cluster: could not hand the primary role over before %s: %v", why, err)
	}
}

// handOverForUpdate is handOver for a node about to restart into an update: the role goes back to its home afterwards.
func (m *Mgmt) handOverForUpdate(by, why string) {
	if m == nil || m.cl == nil {
		return
	}
	if _, err := m.cl.HandOverPrimaryForUpdate(by, why); err != nil {
		warnf("cluster: could not hand the primary role over before %s: %v", why, err)
	}
}

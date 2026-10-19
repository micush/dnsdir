package main

import (
	"context"
	"sort"
	"time"
)

// chronyEvery is how often the pools' health is looked at and chrony's sources brought in line with it.
var chronyEvery = 2 * time.Second

// chronySources is what chrony should use now: every server that tests good among the servers of the topology (each
// gateway's own servers, or the shared list for a gateway that has none of its own; paused gateways count for nothing).  Fallback servers count only while no ordinary server tests good anywhere.  empty is true when no
// ordinary server is defined at all (none listed or every one paused) and there is no fallback either: chrony then
// has no source, because that is what the administrator asked for.  With servers defined but none good, the list is
// empty and empty is false: chrony keeps the sources it has.
func (s *Supervisor) chronySources() (servers []string, empty bool) {
	s.poolMu.RLock()
	defer s.poolMu.RUnlock()
	good, fb := map[string]bool{}, map[string]bool{}
	defined := 0
	for _, p := range s.pools {
		for _, sv := range p.servers {
			if !sv.Fallback {
				defined++
			}
			sv.mu.Lock()
			h := sv.healthy
			sv.mu.Unlock()
			switch {
			case sv.Fallback:
				fb[sv.Addr] = true
			case h:
				good[sv.Addr] = true
			}
		}
	}
	set := good
	if len(good) == 0 {
		set = fb
	}
	for a := range set {
		servers = append(servers, a)
	}
	sort.Strings(servers)
	return servers, len(servers) == 0 && defined == 0
}

// syncChrony does one round: read chrony, write the sources.
func (s *Supervisor) syncChrony() {
	st := chrony.readState()
	if !st.Running && st.Err != "" {
		chrony.warnEvery("down", "chrony: "+st.Err+" (this node cannot serve NTP to clients until chrony runs; in a container run the installer again so chrony starts with -x, or check systemctl status chrony)")
	}
	if !chrony.allowedOK() { // chrony was not there when the allow rules were first sent
		_ = chrony.applyClients(s.sharedNTP())
	}
	servers, empty := s.chronySources()
	nd := s.sharedNTP()
	chrony.setOffsetLimit(nd.ServeOffsetMS)
	chrony.setServing(len(servers) > 0 && !chrony.tooFar(st), nd)
	if auth, err := parseServerAuth(nd.ServerAuth, nil); err == nil {
		chrony.setAuth(auth)
	}
	if nd.NTSServer { // the certificate may have been renewed: the copy chrony reads follows it
		s.applyChronyClients()
	}
	if err := chrony.applySources(servers, empty); err != nil {
		chrony.warnEvery("sources", err.Error())
	}
}

func (s *Supervisor) startChronyLoop() {
	if s.chronyCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	s.chronyCancel = cancel
	s.chronyDone = make(chan struct{})
	s.applyChronyClients()
	go func() {
		defer close(s.chronyDone)
		t := time.NewTicker(chronyEvery)
		defer t.Stop()
		for n := 0; ; n++ {
			s.syncChrony()
			if n%5 == 4 { // every ten seconds
				chrony.sampleClients(qstats)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (s *Supervisor) stopChronyLoop() {
	if s.chronyCancel == nil {
		return
	}
	s.chronyCancel()
	<-s.chronyDone
	s.chronyCancel, s.chronyDone = nil, nil
}

// applyChronyClients writes who may ask and how often (the shared ntp block) where chrony reads it.
func (s *Supervisor) applyChronyClients() {
	s.mu.Lock()
	d := s.dc.NTP
	s.mu.Unlock()
	if err := chrony.applyClients(d); err != nil {
		chrony.warnEvery("clients", err.Error())
	}
}

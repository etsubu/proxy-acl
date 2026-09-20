package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"proxy-acl/internal/acl"
)

// Client-supplied fields are clipped before they are logged or kept for
// log summaries: a request line can carry a 60 KB "host" or "method".
const (
	maxLogHost   = 253 // the longest valid hostname
	maxLogMethod = 32
	maxLogPort   = 16
)

// clip bounds s for logging, noting how long it really was.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(" + strconv.Itoa(len(s)) + " bytes)"
}

func (p *Proxy) logDecision(r *http.Request, client netip.Addr, host, port string, d acl.Decision) {
	action, msg, ev := "deny", "denied", log.Warn()
	if d.Allow {
		action, msg, ev = "allow", "allowed", log.Info()
	}
	host = clip(host, maxLogHost)
	// Invalid hosts are counted under one key in summaries.
	key := host
	if strings.HasPrefix(d.Reason, "invalid host") {
		key = "(invalid host)"
	}
	if !p.sample(ev, client, action, key) {
		return
	}
	ev = ev.Str("action", action).
		Str("client", client.String()).
		Str("subnet", d.Subnet).
		Str("method", clip(r.Method, maxLogMethod)).
		Str("host", host).
		Str("port", clip(port, maxLogPort)).
		Str("reason", d.Reason)
	if d.Rule != "" {
		ev = ev.Str("rule", d.Rule)
	}
	ev.Msg(msg)
}

func (p *Proxy) logRejected(client netip.Addr, subnet, reason string) {
	ev := log.Warn()
	if !ev.Enabled() {
		return
	}
	// Clients outside every subnet share one log budget and aren't tracked
	// individually, so they can't fill the per-client table.
	var ok bool
	if subnet == "" {
		ok = p.clients.LogUnknown(client)
	} else {
		ok = p.clients.Log(client, "deny", "(connection)")
	}
	if !ok {
		ev.Discard()
		return
	}
	ev.Str("action", "deny").Str("client", client.String()).Str("subnet", subnet).Str("reason", reason).Msg("connection rejected")
}

func (p *Proxy) logUpstreamError(r *http.Request, host string, err error) {
	ev := log.Warn()
	if errors.Is(err, context.Canceled) {
		ev = log.Debug() // the client went away
	}
	client := clientAddr(r)
	host = clip(host, maxLogHost)
	if p.sample(ev, client, "error", host) {
		ev.Err(err).Str("client", client.String()).Str("method", clip(r.Method, maxLogMethod)).Str("host", host).Msg("upstream connection failed")
	}
}

// sample reports whether ev should be written. Lines at a disabled level
// don't count against the client's log budget; lines over budget are
// discarded and summarized later by sweep.
func (p *Proxy) sample(ev *zerolog.Event, client netip.Addr, action, host string) bool {
	if !ev.Enabled() {
		return false
	}
	if !p.clients.Log(client, action, host) {
		ev.Discard()
		return false
	}
	return true
}

// sweep writes one summary line per client whose access log lines were
// counted instead of written.
func (p *Proxy) sweep() {
	cfg := p.config()
	subnetOf := func(a netip.Addr) string {
		if s := cfg.Policy.SubnetOf(a); s != nil {
			return s.Name()
		}
		return ""
	}
	for _, s := range p.clients.Sweep() {
		byAction := map[string]*zerolog.Event{}
		total := s.Other
		for k, n := range s.Counts {
			if byAction[k.Action] == nil {
				byAction[k.Action] = zerolog.Dict()
			}
			byAction[k.Action].Int(k.Host, n)
			total += n
		}
		ev := log.Info()
		if byAction["deny"] != nil || byAction["error"] != nil {
			ev = log.Warn()
		}
		switch {
		case s.Unknown:
			// Keys are client addresses here: which unconfigured devices knock.
			ev = ev.Int("suppressed", total)
			if clients := byAction["deny"]; clients != nil {
				ev = ev.Dict("clients", clients)
			}
			if s.Other > 0 {
				ev = ev.Int("other", s.Other)
			}
			ev.Msg("connections from unknown clients suppressed")
			continue
		case s.Prefix.IsValid():
			ev = ev.Str("network", s.Prefix.String()).Str("subnet", subnetOf(s.Prefix.Addr()))
		default:
			ev = ev.Str("client", s.Client.String()).Str("subnet", subnetOf(s.Client))
		}
		ev = ev.Int("suppressed", total)
		for action, hosts := range byAction {
			ev = ev.Dict(action, hosts)
		}
		if s.Other > 0 {
			ev = ev.Int("other", s.Other)
		}
		ev.Msg("access log lines suppressed")
	}
}

// Package proxy wires the ACL and per-client limits into a goproxy forward
// proxy.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"proxy-acl/internal/acl"
	"proxy-acl/internal/config"
	"proxy-acl/internal/dnscache"
	"proxy-acl/internal/limits"
)

const (
	maxResponseHeaderBytes = 1 << 20
	sweepInterval          = 10 * time.Second
	// Sent when an allowed destination can't be reached. It deliberately
	// carries no detail: dial errors contain the resolved addresses.
	badGatewayConnect = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)

// Proxy is the HTTP handler; serve it on a listener wrapped by Listener.
type Proxy struct {
	*goproxy.ProxyHttpServer
	config   func() *config.Config
	resolver acl.Resolver
	clients  *limits.Tracker
	upstream *upstreamPools
}

// New returns a forward proxy that checks every plain HTTP request and
// every CONNECT tunnel against the config returned by cfg().
func New(cfg func() *config.Config, resolver acl.Resolver) *Proxy {
	gp := goproxy.NewProxyHttpServer()
	gp.Logger = goproxyLogger{}

	// Approved plain HTTP requests go through upstreamPools. gp.Tr is only
	// a backstop for anything that bypasses them: it dials through
	// dialVetted, which fails closed without an ACL-approved destination,
	// and never pools. It also replaces goproxy's default transport, which
	// skips TLS verification.
	gp.Tr = &http.Transport{
		DialContext:            dialVetted,
		DisableKeepAlives:      true,
		TLSHandshakeTimeout:    10 * time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		DisableCompression:     true,
	}
	// Pass the client's Accept-Encoding through. By default goproxy drops
	// it, has the transport ask for gzip and decompresses responses itself,
	// which costs CPU and sends clients uncompressed bodies.
	gp.KeepAcceptEncoding = true
	// No upstream proxy from the environment: dials must go to vetted addresses.
	gp.ConnectDial = nil
	gp.ConnectDialWithReq = nil
	// Tunnels are handled by Proxy.tunnel; this only covers goproxy's own
	// CONNECT paths, so they can't echo dial errors either.
	gp.ConnectionErrHandler = func(w io.Writer, _ *goproxy.ProxyCtx, _ error) {
		io.WriteString(w, badGatewayConnect)
	}

	p := &Proxy{ProxyHttpServer: gp, config: cfg, resolver: resolver, clients: limits.NewTracker(), upstream: newUpstreamPools()}
	gp.OnRequest().HandleConnectFunc(p.connect)
	gp.OnRequest().DoFunc(p.request)
	gp.OnResponse().DoFunc(p.response)
	return p
}

// Maintain periodically writes summaries of rate-limited log lines, forgets
// idle clients and closes idle upstream connection pools, until ctx is
// cancelled.
func (p *Proxy) Maintain(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.sweep()
			p.upstream.sweep()
		}
	}
}

// connect handles CONNECT tunnels (HTTPS and any other TCP). Only the
// target host:port is visible; the TLS session itself is end to end.
func (p *Proxy) connect(hostport string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, ""
	}
	v, refusal := p.check(ctx.Req, host, port)
	if v == nil {
		ctx.Resp = refusal
		return goproxy.RejectConnect, hostport
	}
	return &goproxy.ConnectAction{
		Action: goproxy.ConnectHijack,
		Hijack: func(r *http.Request, client net.Conn, _ *goproxy.ProxyCtx) { p.tunnel(r, client, v) },
	}, hostport
}

// tunnel runs an approved CONNECT on the hijacked client connection. It
// dials and answers the client, then copies in a new goroutine so the HTTP
// server's connection goroutine, and the buffers it holds, can go away.
func (p *Proxy) tunnel(r *http.Request, client net.Conn, v *vetted) {
	start := time.Now()
	upstream, err := v.dial(r.Context(), "tcp", net.JoinHostPort(v.host, strconv.Itoa(int(v.port))))
	if err != nil {
		p.logUpstreamError(r, v.host, err)
		io.WriteString(client, badGatewayConnect)
		client.Close()
		return
	}
	major, minor := r.ProtoMajor, r.ProtoMinor
	if major == 0 {
		major, minor = 1, 1
	}
	if _, err := fmt.Fprintf(client, "HTTP/%d.%d 200 Connection established\r\n\r\n", major, minor); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	clientIP := clientAddr(r).String()
	go func() {
		defer client.Close() // frees the client's connection slot
		sent, received, err := tunnelCopy(unwrap(client), upstream, v.idle)
		ev := log.Debug()
		if err != nil {
			ev = ev.Err(err)
		}
		ev.Str("client", clientIP).Str("host", v.host).Uint16("port", v.port).
			Int64("sent", sent).Int64("received", received).Dur("duration", time.Since(start)).Msg("tunnel closed")
	}()
}

// request handles plain proxy requests (absolute-form URLs). Each request on
// a keep-alive client connection passes through here separately.
func (p *Proxy) request(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	host, port := r.URL.Hostname(), r.URL.Port()
	switch r.URL.Scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	default:
		p.logDecision(r, clientAddr(r), host, port, acl.Decision{Reason: "unsupported scheme " + strconv.Quote(clip(r.URL.Scheme, 16))})
		return r, forbidden(r)
	}
	v, refusal := p.check(r, host, port)
	if v == nil {
		return r, refusal
	}
	ctx.RoundTripper = p.upstream
	return r.WithContext(context.WithValue(r.Context(), vettedKey{}, v)), nil
}

// response replaces goproxy's upstream error responses, which include the
// dial error and with it the resolved addresses, with a generic 502.
func (p *Proxy) response(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp != nil || ctx.Error == nil {
		return resp
	}
	p.logUpstreamError(ctx.Req, ctx.Req.URL.Hostname(), ctx.Error)
	return goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusBadGateway, "Bad gateway\n")
}

// check applies the rate limit and the ACL, and logs the decision. It
// returns the vetted destination, or the response to refuse with.
func (p *Proxy) check(r *http.Request, host, port string) (*vetted, *http.Response) {
	client := clientAddr(r)
	cfg := p.config()
	subnet, _ := cfg.Policy.SubnetOf(client)
	lim := cfg.ClientLimits(subnet)
	if !p.clients.Allow(client, lim) {
		p.logDecision(r, client, host, port, acl.Decision{Subnet: subnet, Reason: "rate limited"})
		resp := goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusTooManyRequests, "Too many requests\n")
		resp.Header.Set("Retry-After", "1")
		return nil, resp
	}
	d := cfg.Policy.Check(dnscache.WithClient(r.Context(), client), p.resolver, client, host, port)
	p.logDecision(r, client, host, port, d)
	if !d.Allow {
		return nil, forbidden(r)
	}
	return &vetted{host: host, port: d.Port, addrs: d.Addrs, idle: lim.TunnelIdleTimeout}, nil
}

// clientAddr returns the client's IP, or the zero Addr (which matches no
// subnet) if it can't be parsed.
func clientAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// forbidden deliberately gives no detail; the reason is in the proxy's log.
// It also closes the connection so denied clients don't linger.
func forbidden(r *http.Request) *http.Response {
	resp := goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by proxy ACL\n")
	resp.Header.Set("Connection", "close")
	return resp
}

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

func (p *Proxy) sweep() {
	cfg := p.config()
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
			ev = ev.Int("suppressed", total).Dict("clients", byAction["deny"])
			if s.Other > 0 {
				ev = ev.Int("other", s.Other)
			}
			ev.Msg("connections from unknown clients suppressed")
			continue
		case s.Prefix.IsValid():
			subnet, _ := cfg.Policy.SubnetOf(s.Prefix.Addr())
			ev = ev.Str("network", s.Prefix.String()).Str("subnet", subnet)
		default:
			subnet, _ := cfg.Policy.SubnetOf(s.Client)
			ev = ev.Str("client", s.Client.String()).Str("subnet", subnet)
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

// goproxyLogger routes goproxy's internal messages (mostly connection
// errors) to zerolog at debug level so they don't drown out access logs.
type goproxyLogger struct{}

func (goproxyLogger) Printf(format string, v ...any) {
	log.Debug().Str("component", "goproxy").Msg(strings.TrimSpace(fmt.Sprintf(format, v...)))
}

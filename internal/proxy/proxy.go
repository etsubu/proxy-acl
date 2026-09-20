// Package proxy implements a forward HTTP/HTTPS proxy that only ever
// connects to destinations the ACL has approved.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"proxy-acl/internal/acl"
	"proxy-acl/internal/config"
	"proxy-acl/internal/dnscache"
	"proxy-acl/internal/limits"
)

const (
	sweepInterval = 10 * time.Second
	shutdownGrace = 5 * time.Second
	// Sent when an allowed destination can't be reached over a tunnel, where
	// there is no ResponseWriter left to use. It deliberately carries no
	// detail: dial errors contain the resolved addresses.
	badGatewayConnect = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)

var errUpgradeNotSupported = errors.New("upstream answered 101 to a request with no Upgrade header")

// Proxy checks every plain HTTP request and every CONNECT tunnel against
// the config returned by cfg(). It is driven by Serve; the HTTP handler is
// deliberately not exported, so it cannot be served without the connection
// vetting and per-client limits that Serve installs.
type Proxy struct {
	config   func() *config.Config
	resolver acl.Resolver
	clients  *limits.Tracker
	upstream *upstreamPools
}

// New returns a proxy that enforces the policy in the config returned by
// cfg() and resolves hostnames with resolver.
func New(cfg func() *config.Config, resolver acl.Resolver) *Proxy {
	return &Proxy{config: cfg, resolver: resolver, clients: limits.NewTracker(), upstream: newUpstreamPools()}
}

// Serve proxies connections accepted on ln until ctx is cancelled, then
// shuts down and returns. Established tunnels are hijacked connections and
// are cut at shutdown rather than waited for.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler: handler{p},
		// No read/write timeouts: a proxy can't know how long a legitimate
		// upload or download takes. Tunnels are hijacked and have their own
		// idle timeout.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          stdlog.New(serverLog{}, "", 0),
	}
	go p.maintain(ctx)
	go func() {
		<-ctx.Done()
		// Detached from ctx, which is already cancelled, but still tied to
		// it for any values it carries.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(p.listener(ln)); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// maintain periodically writes summaries of rate-limited log lines, forgets
// idle clients and closes idle upstream connection pools.
func (p *Proxy) maintain(ctx context.Context) {
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

type handler struct{ p *Proxy }

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		h.p.serveConnect(w, r)
	case r.URL.IsAbs():
		h.p.serveRequest(w, r)
	default:
		// An origin-form request: the client isn't using us as a proxy.
		h.p.logDecision(r, clientAddr(r), r.Host, "", acl.Decision{Reason: "not a proxy request"})
		http.Error(w, "This is a forward proxy; requests must use an absolute URL.", http.StatusBadRequest)
	}
}

// serveConnect handles CONNECT tunnels (HTTPS and any other TCP). Only the
// target host:port is visible; the TLS session itself is end to end.
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		host, port = r.URL.Host, ""
	}
	v := p.check(w, r, host, port)
	if v == nil {
		return
	}
	client, early, err := hijack(w)
	if err != nil {
		log.Debug().Err(err).Msg("cannot hijack the client connection for a tunnel")
		return
	}
	p.tunnel(r, client, early, v)
}

// hijack takes the client connection away from the HTTP server, along with
// any bytes already read past the request: a client that sends its first
// payload without waiting for the 200 would otherwise lose it.
func hijack(w http.ResponseWriter) (net.Conn, []byte, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("connection does not support hijacking")
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	var early []byte
	if n := brw.Reader.Buffered(); n > 0 {
		early = make([]byte, n)
		if _, err := io.ReadFull(brw.Reader, early); err != nil {
			_ = c.Close()
			return nil, nil, err
		}
	}
	return c, early, nil
}

// tunnel runs an approved CONNECT on the hijacked client connection. It
// dials and answers the client, then copies in a new goroutine so the HTTP
// server's connection goroutine, and the buffers it holds, can go away.
func (p *Proxy) tunnel(r *http.Request, client net.Conn, early []byte, v *vetted) {
	start := time.Now()
	upstream, err := v.dial(r.Context(), "tcp", net.JoinHostPort(v.host, strconv.Itoa(int(v.port))))
	if err != nil {
		p.logUpstreamError(r, v.host, err)
		_, _ = io.WriteString(client, badGatewayConnect)
		_ = client.Close()
		return
	}
	major, minor := r.ProtoMajor, r.ProtoMinor
	if major == 0 {
		major, minor = 1, 1
	}
	_, err = fmt.Fprintf(client, "HTTP/%d.%d 200 Connection established\r\n\r\n", major, minor)
	if err == nil && len(early) > 0 {
		_, err = upstream.Write(early)
	}
	if err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	clientIP := clientAddr(r).String()
	go func() {
		defer func() { _ = client.Close() }() // frees the client's connection slot
		sent, received, err := tunnelCopy(unwrap(client), upstream, v.idle)
		ev := log.Debug()
		if err != nil {
			ev = ev.Err(err)
		}
		ev.Str("client", clientIP).Str("host", v.host).Uint16("port", v.port).
			Int64("sent", sent).Int64("received", received).Dur("duration", time.Since(start)).Msg("tunnel closed")
	}()
}

// serveRequest handles plain proxy requests (absolute-form URLs). Each
// request on a keep-alive client connection passes through here separately.
func (p *Proxy) serveRequest(w http.ResponseWriter, r *http.Request) {
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
		deny(w)
		return
	}
	v := p.check(w, r, host, port)
	if v == nil {
		return
	}

	resp, err := p.upstream.roundTrip(outbound(r), v)
	if err != nil {
		p.badGateway(w, r, host, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// outbound strips Upgrade, so this is a server switching protocols
		// unasked. Forwarding it would mean handing over the client
		// connection, which this path neither owns nor can time out.
		p.badGateway(w, r, host, errUpgradeNotSupported)
		return
	}

	removeHopByHop(resp.Header)
	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(bodyWriter(w, resp), resp.Body); err != nil {
		// The status and headers have already gone out, so there is nothing
		// left to tell the client; net/http drops the connection when the
		// body turns out shorter than its Content-Length.
		log.Debug().Err(err).Str("host", host).Msg("response body truncated")
	}
	// Trailers arrive only once the body has been read. The prefix tells
	// net/http to send them as trailers without a prior announcement.
	for k, vs := range resp.Trailer {
		w.Header()[http.TrailerPrefix+k] = vs
	}
}

// badGateway answers with no detail; the error, which contains the resolved
// addresses, goes to the log instead.
func (p *Proxy) badGateway(w http.ResponseWriter, r *http.Request, host string, err error) {
	p.logUpstreamError(r, host, err)
	http.Error(w, "Bad gateway", http.StatusBadGateway)
}

// check applies the rate limit and the ACL, and logs the decision. It
// returns the vetted destination, or nil after answering the refusal.
func (p *Proxy) check(w http.ResponseWriter, r *http.Request, host, port string) *vetted {
	client := clientAddr(r)
	cfg := p.config()
	subnet := cfg.Policy.SubnetOf(client)
	lim := cfg.ClientLimits(subnet)

	if !p.clients.Allow(client, lim) {
		d := acl.Decision{Reason: "rate limited"}
		if subnet != nil {
			d.Subnet = subnet.Name()
		}
		p.logDecision(r, client, host, port, d)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return nil
	}
	// The listener drops these at accept; a config reload can still leave an
	// established connection without a subnet.
	if subnet == nil {
		p.logDecision(r, client, host, port, acl.Decision{Reason: "client not in any subnet"})
		deny(w)
		return nil
	}

	d := subnet.Check(dnscache.WithClient(r.Context(), client), p.resolver, host, port)
	p.logDecision(r, client, host, port, d)
	if !d.Allow {
		deny(w)
		return nil
	}
	return &vetted{host: host, port: d.Port, addrs: d.Addrs, idle: lim.TunnelIdleTimeout}
}

// deny deliberately gives no detail; the reason is in the proxy's log. It
// also closes the connection so denied clients don't linger.
func deny(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	http.Error(w, "Blocked by proxy ACL", http.StatusForbidden)
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

// hopByHop are the headers that apply to a single connection only and must
// not be forwarded by an intermediary (RFC 9110 §7.6.1). Upgrade is among
// them: this proxy tunnels protocol switches through CONNECT, not by
// handing over a plain HTTP connection.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopByHop(h http.Header) {
	for _, field := range h.Values("Connection") {
		for name := range strings.SplitSeq(field, ",") {
			if name = textproto.TrimString(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// outbound returns the request to send upstream: a copy without the
// hop-by-hop and proxy-only headers, and without the client's wish to close
// its own connection, which says nothing about the upstream one.
func outbound(r *http.Request) *http.Request {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Close = false
	removeHopByHop(out.Header)
	return out
}

// bodyWriter returns the writer to copy a response body to. Responses of
// unknown length are streams (chunked bodies, server-sent events): flush
// every chunk, or a slow trickle would sit in net/http's buffer instead of
// reaching the client.
func bodyWriter(w http.ResponseWriter, resp *http.Response) io.Writer {
	if resp.ContentLength >= 0 {
		return w // lets io.Copy use the ReaderFrom fast path
	}
	return flushWriter{w, http.NewResponseController(w)}
}

type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (f flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if err == nil {
		_ = f.rc.Flush() // not supported on every writer; harmless if it isn't
	}
	return n, err
}

// serverLog routes net/http's own connection-level complaints to zerolog at
// debug level, so they don't drown out access logs.
type serverLog struct{}

func (serverLog) Write(b []byte) (int, error) {
	log.Debug().Str("component", "http").Msg(strings.TrimSpace(string(b)))
	return len(b), nil
}

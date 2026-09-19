package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxy-acl/internal/dnscache"
)

var loopback = netip.MustParseAddr("127.0.0.1")

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// dialProxy opens a raw connection to the proxy from src (default 127.0.0.1).
func (e *env) dialProxy(t *testing.T, src string) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	if src != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}
	c, err := d.Dial("tcp", e.proxy.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// assertClosedByProxy checks that the proxy closes c without answering.
func assertClosedByProxy(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected the proxy to close the connection, got n=%d err=%v", n, err)
	}
}

// openTunnel sends CONNECT and returns the connection once the proxy answers.
func (e *env) openTunnel(t *testing.T, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	c := e.dialProxy(t, "")
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return c, br, resp
}

// startTCP runs a TCP backend and allows its port through the proxy.
func (e *env) startTCP(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	p := port("tcp://" + l.Addr().String())
	e.ports = append(e.ports, p)
	return p
}

func (e *env) connections() int {
	n, _ := e.p.clients.Connections(loopback)
	return n
}

func TestUnknownClientDroppedAtAccept(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	c := e.dialProxy(t, "127.0.0.2")
	fmt.Fprintf(c, "GET http://allowed.test:%s/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n", e.plainPort)
	assertClosedByProxy(t, c)
	if e.hits.Load() != 0 || e.res.lookups() != 0 {
		t.Error("request from an unknown client was processed")
	}
}

func TestClientConnectionLimit(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	e.setConfig(t, defaultAllow, nil, map[string]any{"client_connections": 3})

	var held []net.Conn
	for range 3 {
		held = append(held, e.dialProxy(t, ""))
	}
	waitFor(t, "3 connections", func() bool { return e.connections() == 3 })
	assertClosedByProxy(t, e.dialProxy(t, ""))

	held[0].Close()
	waitFor(t, "a free slot", func() bool { return e.connections() == 2 })
	if code, err := e.get("http://allowed.test:" + e.plainPort + "/"); err != nil || code != 200 {
		t.Fatalf("after freeing a slot: %d, %v", code, err)
	}
}

// Every way a client connection can end must free its slot, or clients
// would slowly lock themselves out.
func TestConnectionSlotsAreReleased(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	hangup := e.startTCP(t, func(net.Conn) {})
	e.setConfig(t, defaultAllow, nil, map[string]any{"client_connections": 2})

	for i := range 15 {
		c, _, resp := e.openTunnel(t, "allowed.test:"+e.tlsPort) // tunnel, closed by the client
		if resp.StatusCode != 200 {
			t.Fatalf("round %d: tunnel status %d", i, resp.StatusCode)
		}
		c.Close()
		c, _, resp = e.openTunnel(t, "denied.test:"+e.tlsPort) // CONNECT refused
		if resp.StatusCode != 403 {
			t.Fatalf("round %d: denied CONNECT status %d", i, resp.StatusCode)
		}
		c.Close()
		c, _, _ = e.openTunnel(t, "allowed.test:"+hangup) // upstream hangs up at once
		io.Copy(io.Discard, c)
		c.Close()
		if code, _ := e.get("http://denied.test:" + e.plainPort + "/"); code != 403 {
			t.Fatalf("round %d: denied GET status %d", i, code)
		}
		if code, _ := e.get("http://allowed.test:" + e.plainPort + "/"); code != 200 {
			t.Fatalf("round %d: allowed GET status %d", i, code)
		}
	}
	waitFor(t, "all slots to be released", func() bool { return e.connections() == 0 })
}

func TestTotalConnectionLimit(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	e.setConfig(t, defaultAllow, nil, map[string]any{"total_connections": 2})
	e.dialProxy(t, "")
	e.dialProxy(t, "")
	waitFor(t, "2 connections", func() bool { return e.connections() == 2 })
	assertClosedByProxy(t, e.dialProxy(t, ""))
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	e.setConfig(t, defaultAllow, nil, map[string]any{"client_requests_per_second": 0.5, "client_request_burst": 3})
	for i := range 3 {
		if code, err := e.get("http://allowed.test:" + e.plainPort + "/"); err != nil || code != 200 {
			t.Fatalf("request %d within burst: %d, %v", i, code, err)
		}
	}
	client := e.client()
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://allowed.test:" + e.plainPort + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("over the rate: %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if _, _, resp := e.openTunnel(t, "allowed.test:"+e.tlsPort); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("CONNECT over the rate: %d", resp.StatusCode)
	}
	if n := e.hits.Load(); n != 3 {
		t.Errorf("backend hits = %d, want 3", n)
	}
	// Rate-limited requests never reach the ACL, so they cost no DNS lookups.
	if n := e.res.lookups(); n != 3 {
		t.Errorf("lookups = %d, want 3", n)
	}
}

func TestUpstreamErrorsAreGeneric(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := port("tcp://" + l.Addr().String())
	l.Close()
	e.ports = append(e.ports, closedPort)
	e.setConfig(t, defaultAllow, nil, nil)
	logs := captureLogs(t)

	client := e.client()
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://allowed.test:" + closedPort + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || string(body) != "Bad gateway\n" {
		t.Errorf("http: %d %q", resp.StatusCode, body)
	}

	c, br, resp := e.openTunnel(t, "allowed.test:"+closedPort)
	body, _ = io.ReadAll(resp.Body)
	rest, _ := io.ReadAll(br)
	c.Close()
	if resp.StatusCode != http.StatusBadGateway || len(body) != 0 || len(rest) != 0 {
		t.Errorf("connect: %d %q %q", resp.StatusCode, body, rest)
	}

	// The details go to the log instead.
	if out := logs(); strings.Count(out, `"message":"upstream connection failed"`) != 2 || !strings.Contains(out, "refused") {
		t.Errorf("expected two logged upstream failures with details:\n%s", out)
	}
}

func TestTunnelIdleTimeout(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	echo := e.startTCP(t, func(c net.Conn) { io.Copy(c, c) })
	ticker := e.startTCP(t, func(c net.Conn) { // server-to-client traffic only, then silence
		for range 12 {
			if _, err := c.Write([]byte("t")); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		io.Copy(io.Discard, c)
	})
	e.setConfig(t, defaultAllow, nil, map[string]any{"tunnel_idle_timeout": "300ms"})

	// closedAfterIdle waits for the proxy to close the tunnel and returns
	// how long after the last traffic that happened.
	closedAfterIdle := func(c net.Conn, br *bufio.Reader, lastTraffic time.Time) time.Duration {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := br.ReadByte()
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("tunnel not closed when idle: %v", err)
		}
		return time.Since(lastTraffic)
	}

	t.Run("activity keeps it open", func(t *testing.T) {
		c, br, resp := e.openTunnel(t, "allowed.test:"+echo)
		if resp.StatusCode != 200 {
			t.Fatal(resp.Status)
		}
		var last time.Time
		for i := range 12 { // 1.2s of traffic, 100ms apart
			time.Sleep(100 * time.Millisecond)
			c.Write([]byte{byte(i)})
			c.SetReadDeadline(time.Now().Add(time.Second))
			if b, err := br.ReadByte(); err != nil || b != byte(i) {
				t.Fatalf("echo %d: %v", i, err)
			}
			last = time.Now()
		}
		if d := closedAfterIdle(c, br, last); d < 300*time.Millisecond || d > 2*time.Second {
			t.Errorf("closed %v after the last traffic, want 300ms plus up to a quarter", d)
		}
	})
	t.Run("one-way traffic counts", func(t *testing.T) {
		c, br, _ := e.openTunnel(t, "allowed.test:"+ticker)
		var last time.Time
		for i := range 12 {
			c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := br.ReadByte(); err != nil {
				t.Fatalf("tick %d: tunnel closed during one-way traffic: %v", i, err)
			}
			last = time.Now()
		}
		closedAfterIdle(c, br, last)
	})
}

func TestTunnelHalfCloseAndIntegrity(t *testing.T) {
	for _, idle := range []string{"0s", "1h"} { // plain copy and chunked copy
		t.Run("idle="+idle, func(t *testing.T) {
			e := newEnv(t, defaultAllow, nil)
			counter := e.startTCP(t, func(c net.Conn) { // reads to EOF, then replies
				n, _ := io.Copy(io.Discard, c)
				fmt.Fprintf(c, "got %d", n)
			})
			echo := e.startTCP(t, func(c net.Conn) { io.Copy(c, c) })
			e.setConfig(t, defaultAllow, nil, map[string]any{"tunnel_idle_timeout": idle})

			c, br, _ := e.openTunnel(t, "allowed.test:"+counter)
			c.Write(make([]byte, 100_000))
			c.(*net.TCPConn).CloseWrite()
			if reply, _ := io.ReadAll(br); string(reply) != "got 100000" {
				t.Errorf("half-close: reply %q", reply)
			}

			// 5 MB both ways at once, across several copy chunks.
			data := make([]byte, 5<<20)
			rand.Read(data)
			c, br, _ = e.openTunnel(t, "allowed.test:"+echo)
			go func() { c.Write(data); c.(*net.TCPConn).CloseWrite() }()
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			if got, err := io.ReadAll(br); err != nil || !bytes.Equal(got, data) {
				t.Errorf("echo: %d of %d bytes, equal=%v, err=%v", len(got), len(data), bytes.Equal(got, data), err)
			}
		})
	}
}

func TestLogSampling(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	logs := captureLogs(t)
	const n = 300
	for range n {
		e.get("http://denied.test:" + e.plainPort + "/")
	}
	e.p.sweep()
	out := logs()
	lines := strings.Count(out, `"message":"denied"`)
	if lines >= n || lines < 150 {
		t.Errorf("%d of %d denials logged individually; want roughly the burst of 200", lines, n)
	}
	want := fmt.Sprintf(`"suppressed":%d,"deny":{"denied.test":%d}`, n-lines, n-lines)
	if !strings.Contains(out, want) || !strings.Contains(out, `"message":"access log lines suppressed"`) {
		t.Errorf("missing summary %s in:\n%s", want, out[max(0, len(out)-2000):])
	}
}

// fakeConn records whether it was closed.
type fakeConn struct {
	net.Conn
	name   string
	closed atomic.Bool
}

func (c *fakeConn) Close() error { c.closed.Store(true); return nil }

func withDialer(t *testing.T, budget, fallback time.Duration, dial func(ctx context.Context, addr string) (net.Conn, error)) {
	t.Helper()
	oldDial, oldBudget, oldFallback := dialAddr, dialBudget, fallbackDelay
	dialAddr = func(ctx context.Context, _, addr string) (net.Conn, error) { return dial(ctx, addr) }
	dialBudget, fallbackDelay = budget, fallback
	t.Cleanup(func() { dialAddr, dialBudget, fallbackDelay = oldDial, oldBudget, oldFallback })
}

func vettedFor(addrs ...string) *vetted {
	v := &vetted{host: "example.test", port: 443}
	for _, a := range addrs {
		v.addrs = append(v.addrs, netip.MustParseAddr(a))
	}
	return v
}

func TestDialFallsBackToOtherFamily(t *testing.T) {
	withDialer(t, 5*time.Second, 50*time.Millisecond, func(ctx context.Context, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "[") { // IPv6 is blackholed
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &fakeConn{name: addr}, nil
	})
	start := time.Now()
	c, err := vettedFor("2001:db8::1", "198.51.100.1").dial(context.Background(), "tcp", "example.test:443")
	if err != nil || c.(*fakeConn).name != "198.51.100.1:443" {
		t.Fatalf("got %v, %v", c, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("fallback took %v", d)
	}
}

func TestDialFallsBackAtOnceOnFailure(t *testing.T) {
	withDialer(t, 5*time.Second, time.Hour, func(ctx context.Context, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "[") {
			return nil, errors.New("unreachable")
		}
		return &fakeConn{name: addr}, nil
	})
	start := time.Now()
	if _, err := vettedFor("2001:db8::1", "198.51.100.1").dial(context.Background(), "tcp", "example.test:443"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("waited %v for the fallback after the first family failed", d)
	}
}

func TestDialLimitsAttemptsAndTime(t *testing.T) {
	var mu sync.Mutex
	var attempts []string
	withDialer(t, 200*time.Millisecond, 50*time.Millisecond, func(ctx context.Context, addr string) (net.Conn, error) {
		mu.Lock()
		attempts = append(attempts, addr)
		mu.Unlock()
		if strings.HasPrefix(addr, "198.51.100.") {
			return nil, errors.New("refused")
		}
		<-ctx.Done() // blackholed
		return nil, ctx.Err()
	})
	var ten []string
	for i := range 10 {
		ten = append(ten, fmt.Sprintf("198.51.100.%d", i))
	}
	if _, err := vettedFor(ten...).dial(context.Background(), "tcp", "example.test:443"); err == nil {
		t.Fatal("expected an error")
	}
	if len(attempts) != maxAddrsPerFamily {
		t.Errorf("%d attempts for 10 addresses, want %d", len(attempts), maxAddrsPerFamily)
	}

	start := time.Now()
	if _, err := vettedFor("203.0.113.1", "203.0.113.2", "2001:db8::1").dial(context.Background(), "tcp", "example.test:443"); err == nil {
		t.Fatal("expected an error")
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > time.Second {
		t.Errorf("gave up after %v, want the 200ms budget", d)
	}
}

func TestDialClosesLosingConnection(t *testing.T) {
	loser := &fakeConn{name: "loser"}
	withDialer(t, 5*time.Second, 20*time.Millisecond, func(ctx context.Context, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "[") {
			time.Sleep(100 * time.Millisecond) // connects late, ignoring cancellation
			return loser, nil
		}
		return &fakeConn{name: addr}, nil
	})
	c, err := vettedFor("2001:db8::1", "198.51.100.1").dial(context.Background(), "tcp", "example.test:443")
	if err != nil || c.(*fakeConn).name == "loser" {
		t.Fatalf("got %v, %v", c, err)
	}
	waitFor(t, "the losing connection to be closed", loser.closed.Load)
}

func TestDialWithoutAddresses(t *testing.T) {
	if _, err := vettedFor().dial(context.Background(), "tcp", "example.test:443"); !errors.Is(err, errNotVetted) {
		t.Errorf("got %v, want errNotVetted", err)
	}
}

func TestClientConnKeepsTCPFeatures(t *testing.T) {
	var c net.Conn = &clientConn{Conn: &net.TCPConn{}, release: func() {}}
	if _, ok := c.(interface{ CloseWrite() error }); !ok {
		t.Error("CloseWrite hidden from the HTTP server")
	}
	if _, ok := c.(io.ReaderFrom); !ok {
		t.Error("ReadFrom hidden from the HTTP server")
	}
}

func TestLoggedFieldsAreClipped(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	logs := captureLogs(t)
	c := e.dialProxy(t, "")
	fmt.Fprintf(c, "%s http://denied.test:%s/ HTTP/1.1\r\nHost: denied.test\r\n\r\n", strings.Repeat("M", 50_000), e.plainPort)
	http.ReadResponse(bufio.NewReader(c), nil)
	if !strings.Contains(logs(), `"method":"MMMM`) {
		t.Fatal("long-method request wasn't logged")
	}
	huge := strings.Repeat("a", 60_000) + ".example"
	for i := range logBurstForTest + 30 { // past the log budget, so some are only counted
		c := e.dialProxy(t, "")
		fmt.Fprintf(c, "CONNECT %s%d:443%s HTTP/1.1\r\nHost: x\r\n\r\n", huge, i, strings.Repeat("9", 1000))
		http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
		c.Close()
	}

	e.p.sweep()
	for _, line := range strings.Split(strings.TrimSpace(logs()), "\n") {
		if len(line) > 2000 {
			t.Errorf("log line of %d bytes: %.200s...", len(line), line)
		}
	}
	if out := logs(); !regexp.MustCompile(`"deny":\{"\(invalid host\)":\d+`).MatchString(out) {
		t.Errorf("invalid hosts not summarized under one key:\n%.2000s", out[max(0, len(out)-2000):])
	}
}

// logBurstForTest mirrors limits.logBurst.
const logBurstForTest = 200

func TestUnknownClientsAreNotTracked(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	logs := captureLogs(t)
	for i := range 210 {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, byte(2+i%3))}, Timeout: time.Second}
		c, err := d.Dial("tcp", e.proxy.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		assertClosedByProxy(t, c)
		c.Close()
	}
	if n := e.p.clients.Tracked(); n != 0 {
		t.Errorf("rejected clients created %d tracker entries", n)
	}
	e.p.sweep()
	if out := logs(); !strings.Contains(out, `"suppressed":10,"clients":{`) || !strings.Contains(out, "connections from unknown clients suppressed") {
		t.Errorf("missing unknown-client summary:\n%.1500s", out[max(0, len(out)-1500):])
	}
}

func TestDNSCacheWiredEndToEnd(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	p := New(e.cfg.Load, dnscache.New(e.res)) // as in main
	srv := httptest.NewUnstartedServer(p)
	srv.Listener = p.Listener(srv.Listener)
	srv.Start()
	defer srv.Close()
	e.proxy = srv
	for _, u := range []string{"http://allowed.test:" + e.plainPort + "/", "https://allowed.test:" + e.tlsPort + "/"} {
		for range 2 {
			if code, err := e.get(u); err != nil || code != 200 {
				t.Fatalf("%s: %d, %v", u, code, err)
			}
		}
	}
	if n := e.res.lookups(); n != 1 {
		t.Errorf("%d lookups for 4 requests to one host, want 1", n)
	}
}

// slowResolver never answers names starting with "slow".
type slowResolver struct{ *fakeResolver }

func (s slowResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if strings.HasPrefix(host, "slow") {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.fakeResolver.LookupNetIP(ctx, network, host)
}

func TestSlowDNSClientDoesNotStallOthers(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	e.cidrs = []string{"127.0.0.1/32", "127.0.0.3/32"}
	e.setConfig(t, []string{"*", "127.0.0.1"}, nil, nil)
	p := New(e.cfg.Load, dnscache.New(slowResolver{e.res}))
	srv := httptest.NewUnstartedServer(p)
	srv.Listener = p.Listener(srv.Listener)
	srv.Start()
	defer srv.Close()
	e.proxy = srv

	// A device at 127.0.0.3 retries names whose DNS never answers, more
	// of them at once than the proxy's total lookup capacity.
	var mu sync.Mutex
	var stuck []net.Conn
	defer func() { // hang up so the stuck requests end before the server closes
		mu.Lock()
		defer mu.Unlock()
		for _, c := range stuck {
			c.Close()
		}
	}()
	for i := range 300 {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 3)}}
		c, err := d.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		stuck = append(stuck, c)
		mu.Unlock()
		fmt.Fprintf(c, "CONNECT slow-%d.example:%s HTTP/1.1\r\nHost: x\r\n\r\n", i, e.tlsPort)
	}
	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	if code, err := e.get("http://allowed.test:" + e.plainPort + "/"); err != nil || code != 200 {
		t.Fatalf("other client: %d, %v", code, err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("other client's request took %v while one device's DNS lookups hung", d)
	}
}

// startHTTP runs an HTTP backend and allows its port through the proxy.
func (e *env) startHTTP(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	p := port(srv.URL)
	e.ports = append(e.ports, p)
	return p
}

// A pooled connection must not serve a request whose check approved other
// addresses, even for the same host (here: the DNS answer changed).
func TestPoolNotReusedForOtherAddresses(t *testing.T) {
	allow := []string{"allowed.test", "127.0.0.0/8"}
	e := newEnv(t, allow, nil)
	e.setConfig(t, allow, nil, nil)
	u := "http://allowed.test:" + e.plainPort + "/"
	if code, err := e.get(u); err != nil || code != 200 {
		t.Fatalf("first request: %d, %v", code, err)
	}
	e.res.mu.Lock()
	e.res.table["allowed.test"] = netip.MustParseAddr("127.0.0.2") // nothing listens there
	e.res.mu.Unlock()
	if code, err := e.get(u); err != nil || code != http.StatusBadGateway {
		t.Errorf("after the address changed: %d, %v; want 502, not the pooled connection", code, err)
	}
	if n := e.hits.Load(); n != 1 {
		t.Errorf("backend hits = %d, want 1", n)
	}
}

func TestPoolFailsClosedWithoutVetting(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	req, _ := http.NewRequest(http.MethodGet, e.plain.URL, nil)
	if _, err := e.p.upstream.RoundTrip(req, nil); !errors.Is(err, errNotVetted) {
		t.Errorf("unvetted request: %v, want errNotVetted", err)
	}
	if e.hits.Load() != 0 {
		t.Error("backend reached")
	}
}

func TestContentEncodingPassesThrough(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	gzipped := []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	backend := e.startHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Accept-Encoding", r.Header.Get("Accept-Encoding"))
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(gzipped)
		}
	})
	e.setConfig(t, defaultAllow, nil, nil)
	for _, ae := range []string{"", "br", "gzip"} {
		c := e.dialProxy(t, "")
		fmt.Fprintf(c, "GET http://allowed.test:%s/ HTTP/1.1\r\nHost: allowed.test\r\n", backend)
		if ae != "" {
			fmt.Fprintf(c, "Accept-Encoding: %s\r\n", ae)
		}
		io.WriteString(c, "\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		if got := resp.Header.Get("X-Seen-Accept-Encoding"); got != ae {
			t.Errorf("client sent Accept-Encoding %q, server saw %q", ae, got)
		}
		if ae == "gzip" && (resp.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(body, gzipped)) {
			t.Errorf("gzip response altered: Content-Encoding %q, %d bytes", resp.Header.Get("Content-Encoding"), len(body))
		}
	}
}

func TestPoolsAreBounded(t *testing.T) {
	u := newUpstreamPools()
	for i := range maxUpstreamPools + 50 {
		u.transport("http", vettedFor(fmt.Sprintf("198.51.100.%d", i%250), fmt.Sprintf("203.0.113.%d", i/250)))
	}
	if n := len(u.pools); n != maxUpstreamPools {
		t.Errorf("%d pools, want %d", n, maxUpstreamPools)
	}
	for _, p := range u.pools {
		p.used = time.Now().Add(-2 * upstreamIdleTimeout)
	}
	u.transport("http", vettedFor("192.0.2.1"))
	u.sweep()
	if n := len(u.pools); n != 1 {
		t.Errorf("%d pools after sweeping idle ones, want 1", n)
	}
}

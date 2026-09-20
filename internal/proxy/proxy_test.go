package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"go.yaml.in/yaml/v3"

	"proxy-acl/internal/config"
)

// testLog receives all log output. Tests capture it with captureLogs; the
// logger itself is never swapped, since goroutines from earlier tests may
// still be logging.
var testLog = &switchWriter{}

func TestMain(m *testing.M) {
	log.Logger = zerolog.New(testLog)
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

type switchWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (w *switchWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf == nil {
		return len(p), nil
	}
	return w.buf.Write(p)
}

// captureLogs records log output at info level until the test ends.
func captureLogs(t *testing.T) func() string {
	t.Helper()
	testLog.mu.Lock()
	testLog.buf = &bytes.Buffer{}
	testLog.mu.Unlock()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	t.Cleanup(func() {
		zerolog.SetGlobalLevel(zerolog.Disabled)
		testLog.mu.Lock()
		testLog.buf = nil
		testLog.mu.Unlock()
	})
	return func() string {
		testLog.mu.Lock()
		defer testLog.mu.Unlock()
		return testLog.buf.String()
	}
}

// fakeResolver resolves every name in the table to loopback, where the
// test backends run. None of these names exist in real DNS, so a request
// that succeeds proves the proxy dialed the vetted address instead of
// resolving the name again.
type fakeResolver struct {
	mu    sync.Mutex
	table map[string]netip.Addr
	calls int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if a, ok := f.table[host]; ok {
		return []netip.Addr{a}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f *fakeResolver) lookups() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type env struct {
	addr      string // the proxy's listen address
	p         *Proxy
	plain     *httptest.Server // allowed port
	secure    *httptest.Server // allowed port, TLS
	other     *httptest.Server // port not in the allow list
	hits      atomic.Int64     // requests that reached any backend
	conns     atomic.Int64     // TCP connections accepted by the plain backend
	res       *fakeResolver
	cfg       atomic.Pointer[config.Config]
	plainPort string
	tlsPort   string
	otherPort string
	ports     []string // allowed ports: plainPort, tlsPort and any added by tests
	cidrs     []string // the test subnet; default 127.0.0.1/32 and ::1
}

// newEnv starts the backends and a proxy for a single subnet containing
// 127.0.0.1 (so 127.0.0.2 is an unknown client). allow and deny are the
// subnet's rules; every name here resolves to 127.0.0.1, which, being
// non-public, needs an explicit IP allow rule. Limits are off unless a
// test sets them with setConfig.
func newEnv(t *testing.T, allow, deny []string) *env {
	t.Helper()
	e := &env{res: &fakeResolver{table: map[string]netip.Addr{}}}
	for _, name := range []string{"allowed.test", "denied.test", "blocked.allowed.test"} {
		e.res.table[name] = netip.MustParseAddr("127.0.0.1")
	}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		e.hits.Add(1)
		io.WriteString(w, "backend")
	})
	e.plain = httptest.NewUnstartedServer(backend)
	e.plain.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			e.conns.Add(1)
		}
	}
	e.plain.Start()
	e.secure = httptest.NewUnstartedServer(backend)
	e.secure.Config.ErrorLog = stdlog.New(io.Discard, "", 0) // raw CONNECT tests hang up before the handshake
	e.secure.StartTLS()
	e.other = httptest.NewServer(backend)
	t.Cleanup(func() { e.plain.Close(); e.secure.Close(); e.other.Close() })
	e.plainPort = port(e.plain.URL)
	e.tlsPort = port(e.secure.URL)
	e.otherPort = port(e.other.URL)
	e.ports = []string{e.plainPort, e.tlsPort}

	e.setConfig(t, allow, deny, nil)
	e.p = New(e.cfg.Load, e.res)
	e.addr = serve(t, e.p)
	return e
}

// serve runs p on a loopback listener until the test ends, exactly as main
// does, and returns its address. Going through Serve means the tests
// exercise the connection vetting and the real HTTP server settings.
func serve(t *testing.T, p *Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := p.Serve(ctx, ln); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String()
}

// setConfig installs a config for the test subnet. limits overrides the
// top-level limits, which are otherwise all disabled.
func (e *env) setConfig(t *testing.T, allow, deny []string, limits map[string]any) {
	t.Helper()
	cidrs := e.cidrs
	if cidrs == nil {
		cidrs = []string{"127.0.0.1/32", "::1"}
	}
	lim := map[string]any{
		"total_connections":          0,
		"client_connections":         0,
		"client_requests_per_second": 0,
		"client_request_burst":       0,
		"tunnel_idle_timeout":        "0s",
	}
	maps.Copy(lim, limits)
	doc, err := yaml.Marshal(map[string]any{
		"limits": lim,
		"subnets": []map[string]any{{
			"name":  "loopback",
			"cidrs": cidrs,
			"ports": e.ports,
			"allow": allow,
			"deny":  deny,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(doc)
	if err != nil {
		t.Fatalf("config: %v\n%s", err, doc)
	}
	e.cfg.Store(cfg)
}

func port(rawURL string) string {
	u, _ := url.Parse(rawURL)
	return u.Port()
}

func (e *env) client() *http.Client {
	proxyURL, _ := url.Parse("http://" + e.addr)
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test cert isn't for these names
	}}
}

// get fetches rawURL through the proxy.
func (e *env) get(rawURL string) (int, error) {
	client := e.client()
	defer client.CloseIdleConnections()
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// raw sends hand-written requests over one connection to the proxy and
// returns the status code of each response (0 once the connection fails).
func (e *env) raw(t *testing.T, reqs ...string) []int {
	t.Helper()
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	codes := make([]int, len(reqs))
	for i, req := range reqs {
		if _, err := io.WriteString(conn, req); err != nil {
			break
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			break
		}
		codes[i] = resp.StatusCode
		if strings.HasPrefix(req, "CONNECT") {
			break // the connection is a tunnel (or closed) now
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return codes
}

var defaultAllow = []string{"allowed.test", "127.0.0.1"}

func TestHTTPAndHTTPS(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	tests := []struct {
		name, url string
		want      int // 0: the request must fail (CONNECT refused)
		reached   bool
	}{
		{"http allowed", "http://allowed.test:" + e.plainPort + "/", 200, true},
		{"http denied", "http://denied.test:" + e.plainPort + "/", 403, false},
		{"http port not allowed", "http://allowed.test:" + e.otherPort + "/", 403, false},
		{"https allowed", "https://allowed.test:" + e.tlsPort + "/", 200, true},
		{"https denied", "https://denied.test:" + e.tlsPort + "/", 0, false},
		{"https port not allowed", "https://allowed.test:" + e.otherPort + "/", 0, false},
		{"http ip literal allowed", "http://127.0.0.1:" + e.plainPort + "/", 200, true},
		{"http ipv6 loopback denied", "http://[::1]:" + e.plainPort + "/", 403, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := e.hits.Load()
			code, err := e.get(tt.url)
			if tt.want == 0 {
				if err == nil || !strings.Contains(err.Error(), "Forbidden") {
					t.Fatalf("expected CONNECT to be refused with 403, got %d, %v", code, err)
				}
			} else if err != nil || code != tt.want {
				t.Fatalf("got %d, %v; want %d", code, err, tt.want)
			}
			if reached := e.hits.Load() > before; reached != tt.reached {
				t.Errorf("backend reached=%v, want %v", reached, tt.reached)
			}
		})
	}
}

func TestResolvedLoopbackNeedsExplicitAllow(t *testing.T) {
	// "*" allows the name, but it resolves to loopback, which only an IP
	// rule can allow. Covers DNS rebinding and names like localhost.
	e := newEnv(t, []string{"*"}, nil)
	if code, err := e.get("http://allowed.test:" + e.plainPort + "/"); err != nil || code != 403 {
		t.Errorf("http: got %d, %v; want 403", code, err)
	}
	if _, err := e.get("https://allowed.test:" + e.tlsPort + "/"); err == nil {
		t.Error("https: CONNECT to a name resolving to loopback succeeded")
	}
	if e.hits.Load() != 0 {
		t.Error("backend reached")
	}
}

func TestNameResolvedOncePerRequest(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	for i := 0; i < 3; i++ {
		if code, err := e.get("http://allowed.test:" + e.plainPort + "/"); err != nil || code != 200 {
			t.Fatalf("got %d, %v", code, err)
		}
	}
	if code, err := e.get("https://allowed.test:" + e.tlsPort + "/"); err != nil || code != 200 {
		t.Fatalf("https: got %d, %v", code, err)
	}
	if n := e.res.lookups(); n != 4 {
		t.Errorf("lookups = %d, want 4 (one per request)", n)
	}
	// The three plain HTTP requests were approved for the same addresses,
	// so they share one pooled upstream connection.
	if n := e.conns.Load(); n != 1 {
		t.Errorf("backend connections = %d, want 1", n)
	}
}

func TestRawRequestTricks(t *testing.T) {
	e := newEnv(t, []string{".allowed.test", "127.0.0.1"}, []string{"blocked.allowed.test"})
	p, tp := e.plainPort, e.tlsPort
	get := func(target, host string) string {
		return fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, host)
	}
	connect := func(authority string) string {
		return fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	}
	tests := []struct {
		name  string
		req   string
		allow bool // true: 200 expected; false: anything but 2xx, backend untouched
	}{
		{"baseline allowed", get("http://allowed.test:"+p+"/", "allowed.test:"+p), true},
		{"uppercase host", get("http://ALLOWED.TEST:"+p+"/", "ALLOWED.TEST:"+p), true},
		{"trailing dot", get("http://allowed.test.:"+p+"/", "allowed.test.:"+p), true},

		{"denied url, allowed Host header", get("http://denied.test:"+p+"/", "allowed.test:"+p), false},
		{"userinfo lookalike", get("http://allowed.test@denied.test:"+p+"/", "denied.test:"+p), false},
		{"userinfo with port lookalike", get("http://allowed.test:"+p+"@denied.test:"+p+"/", "denied.test:"+p), false},
		{"percent-encoded host", get("http://%64enied.test:"+p+"/", "denied.test:"+p), false},
		{"percent-encoded dot", get("http://denied%2etest:"+p+"/", "denied.test:"+p), false},
		{"deny rule with case and dot", get("http://BLOCKED.allowed.test.:"+p+"/", "x"), false},
		{"origin-form request is not proxied", get("/", "allowed.test:"+p), false},
		{"empty host", get("http://:"+p+"/", "allowed.test:"+p), false},
		{"unsupported scheme", get("ftp://allowed.test:"+p+"/", "allowed.test:"+p), false},
		{"websocket scheme", get("ws://allowed.test:"+p+"/", "allowed.test:"+p), false},
		{"port not allowed", get("http://allowed.test:"+e.otherPort+"/", "allowed.test"), false},
		{"zero-padded port", get("http://allowed.test:0"+p+"/", "allowed.test"), false},
		{"decimal ip", get("http://2130706433:"+p+"/", "x"), false},
		{"short ip", get("http://127.1:"+p+"/", "x"), false},
		{"mapped ipv6 loopback", get("http://[::ffff:127.0.0.2]:"+p+"/", "x"), false},

		{"connect allowed", connect("allowed.test:" + tp), true},
		{"connect denied", connect("denied.test:" + tp), false},
		{"connect deny rule", connect("blocked.allowed.test:" + tp), false},
		{"connect without port", connect("allowed.test"), false},
		{"connect port not allowed", connect("allowed.test:" + e.otherPort), false},
		{"connect userinfo lookalike", connect("allowed.test@denied.test:" + tp), false},
		{"connect ipv6 loopback", connect("[::1]:" + tp), false},
		{"connect decimal ip", connect("2130706433:" + tp), false},
		{"connect zone", connect("[fe80::1%25lo]:" + tp), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := e.hits.Load()
			code := e.raw(t, tt.req)[0]
			if tt.allow && code != 200 {
				t.Errorf("status %d, want 200", code)
			}
			if !tt.allow && code >= 200 && code < 300 {
				t.Errorf("status %d, want a refusal", code)
			}
			if !tt.allow && e.hits.Load() != before {
				t.Error("backend reached")
			}
		})
	}

	// net/http answers "OPTIONS *" itself (with 200); it must not be forwarded.
	before := e.hits.Load()
	e.raw(t, "OPTIONS * HTTP/1.1\r\nHost: allowed.test:"+p+"\r\n\r\n")
	if e.hits.Load() != before {
		t.Error("OPTIONS * reached the backend")
	}
}

func TestEveryKeepAliveRequestIsChecked(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	req := func(host string) string {
		return fmt.Sprintf("GET http://%s:%s/ HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, e.plainPort, host, e.plainPort)
	}
	// A deny also closes the connection, so the third request never runs.
	codes := e.raw(t, req("allowed.test"), req("allowed.test"), req("denied.test"), req("allowed.test"))
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 403 || codes[3] != 0 {
		t.Errorf("codes = %v, want [200 200 403 0]", codes)
	}
	if n := e.hits.Load(); n != 2 {
		t.Errorf("backend hits = %d, want 2", n)
	}
}

func TestPolicyChangesApplyToNextRequest(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	u := "http://allowed.test:" + e.plainPort + "/"
	if code, _ := e.get(u); code != 200 {
		t.Fatalf("before: %d", code)
	}
	e.setConfig(t, []string{"other.test"}, nil, nil)
	if code, _ := e.get(u); code != 403 {
		t.Errorf("after reload: %d, want 403", code)
	}
}

func TestDialerFailsClosed(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)

	// A vetted destination only dials the exact host:port that was checked.
	v := &vetted{host: "allowed.test", port: 443, addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	for _, addr := range []string{"other.test:443", "allowed.test:80", "allowed.test:0443", "ALLOWED.test:443", "127.0.0.1:443", "allowed.test"} {
		if _, err := v.dial(context.Background(), "tcp", addr); !errors.Is(err, errNotVetted) {
			t.Errorf("dial %q: %v, want errNotVetted", addr, err)
		}
	}
	// Upstream requests go through that same guard: a pooled transport can
	// only reach the destination its vetted approved. Sending a request
	// without one doesn't compile, so there is no unvetted path to test.
	req, _ := http.NewRequest(http.MethodGet, "http://other.test:443/", nil)
	if _, err := newUpstreamPools().roundTrip(req, v); !errors.Is(err, errNotVetted) {
		t.Errorf("roundTrip to a host the vetted doesn't cover: %v, want errNotVetted", err)
	}
	if e.hits.Load() != 0 {
		t.Error("backend reached")
	}
}

func TestIgnoresUpstreamProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	e := newEnv(t, defaultAllow, nil)
	// The upstream transports are built here rather than taken from
	// net/http's defaults, so nothing chains to the environment's proxy.
	if tr := newUpstreamTransport(nil); tr.Proxy != nil {
		t.Error("upstream transport reads the environment's proxy settings")
	}
	if code, err := e.get("http://allowed.test:" + e.plainPort + "/"); err != nil || code != 200 {
		t.Fatalf("request did not go straight to the vetted address: %d, %v", code, err)
	}
}

func TestAccessLog(t *testing.T) {
	e := newEnv(t, defaultAllow, nil)
	logs := captureLogs(t)
	e.get("http://allowed.test:" + e.plainPort + "/")
	e.get("https://denied.test:" + e.tlsPort + "/")

	out := logs()
	for _, want := range []string{
		`"level":"info","action":"allow","client":"127.0.0.1","subnet":"loopback","method":"GET","host":"allowed.test","port":"` + e.plainPort + `","reason":"allow rule matched","rule":"allowed.test","message":"allowed"`,
		`"level":"warn","action":"deny","client":"127.0.0.1","subnet":"loopback","method":"CONNECT","host":"denied.test","port":"` + e.tlsPort + `","reason":"no allow rule matched","message":"denied"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s\n--- log:\n%s", want, out)
		}
	}
}

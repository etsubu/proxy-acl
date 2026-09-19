package proxy

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

const (
	maxUpstreamPools      = 1024
	upstreamIdleTimeout   = 30 * time.Second
	maxIdlePerDestination = 32
)

// upstreamPools reuses plain-HTTP upstream connections, but only between
// requests whose ACL check approved exactly the same destination: each pool
// is keyed by scheme, host, port and the vetted addresses, and its dialer
// can only reach those addresses. Every request is checked before it is
// matched to a pool, so a pooled connection never serves a request that
// wasn't approved for where it leads.
type upstreamPools struct {
	mu    sync.Mutex
	pools map[string]*upstreamPool
}

type upstreamPool struct {
	tr   *http.Transport
	used time.Time
}

func newUpstreamPools() *upstreamPools {
	return &upstreamPools{pools: map[string]*upstreamPool{}}
}

// RoundTrip implements goproxy.RoundTripper.
func (u *upstreamPools) RoundTrip(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
	v, _ := req.Context().Value(vettedKey{}).(*vetted)
	if v == nil {
		return nil, errNotVetted
	}
	return u.transport(req.URL.Scheme, v).RoundTrip(req)
}

func (u *upstreamPools) transport(scheme string, v *vetted) *http.Transport {
	key := poolKey(scheme, v)
	now := time.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	if p := u.pools[key]; p != nil {
		p.used = now
		return p.tr
	}
	if len(u.pools) >= maxUpstreamPools {
		u.evictLocked(now, 0)
	}
	tr := newUpstreamTransport(v.dial)
	u.pools[key] = &upstreamPool{tr: tr, used: now}
	return tr
}

// sweep drops pools unused for longer than their connections may idle.
func (u *upstreamPools) sweep() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.evictLocked(time.Now(), upstreamIdleTimeout)
}

// evictLocked drops pools unused for longer than maxIdle, or with maxIdle
// 0, the least recently used one. u.mu must be held.
func (u *upstreamPools) evictLocked(now time.Time, maxIdle time.Duration) {
	var oldest string
	for k, p := range u.pools {
		if maxIdle > 0 && now.Sub(p.used) > maxIdle {
			p.tr.CloseIdleConnections()
			delete(u.pools, k)
		} else if oldest == "" || p.used.Before(u.pools[oldest].used) {
			oldest = k
		}
	}
	if maxIdle == 0 && oldest != "" {
		u.pools[oldest].tr.CloseIdleConnections()
		delete(u.pools, oldest)
	}
}

func poolKey(scheme string, v *vetted) string {
	addrs := make([]string, len(v.addrs))
	for i, a := range v.addrs {
		addrs[i] = a.String()
	}
	slices.Sort(addrs)
	return scheme + "|" + v.host + "|" + strconv.Itoa(int(v.port)) + "|" + strings.Join(addrs, ",")
}

// newUpstreamTransport returns an HTTP/1.1 transport that dials with dial.
// Compression is left to the client and server: the proxy neither asks for
// gzip nor decompresses.
func newUpstreamTransport(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DialContext:            dial,
		MaxIdleConnsPerHost:    maxIdlePerDestination,
		IdleConnTimeout:        upstreamIdleTimeout,
		TLSHandshakeTimeout:    10 * time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		DisableCompression:     true,
	}
}

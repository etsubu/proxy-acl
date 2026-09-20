// Package limits tracks per-client resource use, so one misbehaving device
// can't starve the others, and rate-limits access logging per client.
package limits

import (
	"errors"
	"net/netip"
	"sync"
	"time"
)

// Client holds the limits applied to each client IP. Zero disables a limit.
type Client struct {
	MaxConnections    int           // concurrent connections, including tunnels
	RequestsPerSecond float64       // sustained rate of new requests and tunnels
	RequestBurst      int           // requests allowed at once before the rate applies
	TunnelIdleTimeout time.Duration // close tunnels with no data in either direction
}

// Acquire returns these when a connection can't be admitted.
var (
	ErrTotalConnections  = errors.New("proxy connection limit reached")
	ErrClientConnections = errors.New("client connection limit reached")
)

const (
	// Access log lines per client: a flooding device gets summarized
	// instead of drowning out everyone else's log lines.
	logRate  = 20
	logBurst = 200
	// Distinct (action, host) pairs counted per client between summaries.
	maxSuppressedKeys = 16
	// Past this many tracked addresses, new ones share a single entry.
	maxClients = 100_000
	// Entries with no connections are forgotten after this long.
	forgetAfter = 5 * time.Minute
)

// Tracker holds per-client state. It is safe for concurrent use.
type Tracker struct {
	mu       sync.Mutex
	now      func() time.Time
	clients  map[netip.Addr]*client
	overflow map[netip.Prefix]*client // clients past maxClients, shared per network
	unknown  client                   // log budget shared by clients outside every subnet
	total    int
}

type client struct {
	conns      int
	seen       time.Time
	requests   bucket
	logs       bucket
	suppressed map[SuppressedKey]int
	other      int
}

// SuppressedKey identifies access log lines that were counted, not written.
type SuppressedKey struct{ Action, Host string }

// Suppressed summarizes unwritten access log lines. It is for one client
// address, one overflow network (Prefix set), or all clients outside every
// subnet (Unknown set; the keys' Host is then the client address).
type Suppressed struct {
	Client  netip.Addr
	Prefix  netip.Prefix
	Unknown bool
	Counts  map[SuppressedKey]int
	Other   int // lines beyond the distinct keys that are counted individually
}

// NewTracker returns an empty Tracker.
func NewTracker() *Tracker {
	return &Tracker{now: time.Now, clients: map[netip.Addr]*client{}, overflow: map[netip.Prefix]*client{}}
}

// get returns ip's entry, creating it if needed. t.mu must be held.
func (t *Tracker) get(ip netip.Addr, now time.Time) *client {
	c := t.clients[ip]
	if c == nil {
		if len(t.clients) < maxClients {
			c = &client{}
			t.clients[ip] = c
		} else {
			// Too many addresses to track one by one (say, a device rotating
			// IPv6 addresses): share per network, so they can't starve
			// clients elsewhere.
			p := overflowPrefix(ip)
			if c = t.overflow[p]; c == nil {
				c = &client{}
				t.overflow[p] = c
			}
		}
	}
	c.seen = now
	return c
}

func overflowPrefix(ip netip.Addr) netip.Prefix {
	bits := 24
	if ip.Is6() {
		bits = 64
	}
	p, _ := ip.Prefix(bits)
	return p
}

// Acquire reserves a connection slot for ip. The returned release func must
// be called when the connection closes; extra calls are ignored.
func (t *Tracker) Acquire(ip netip.Addr, lim Client, maxTotal int) (release func(), err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if maxTotal > 0 && t.total >= maxTotal {
		return nil, ErrTotalConnections
	}
	c := t.get(ip, t.now())
	if lim.MaxConnections > 0 && c.conns >= lim.MaxConnections {
		return nil, ErrClientConnections
	}
	c.conns++
	t.total++
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			c.conns--
			t.total--
			c.seen = t.now()
			t.mu.Unlock()
		})
	}, nil
}

// Allow takes one request token for ip.
func (t *Tracker) Allow(ip netip.Addr, lim Client) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	return t.get(ip, now).requests.take(now, lim.RequestsPerSecond, lim.RequestBurst)
}

// Log reports whether an access log line for ip may be written now. If not,
// the line is counted for the next Sweep summary. host must be bounded in
// length; it is kept until then.
func (t *Tracker) Log(ip netip.Addr, action, host string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	return t.get(ip, now).log(now, SuppressedKey{action, host})
}

// LogUnknown is Log for clients outside every subnet. They share one
// budget and aren't tracked individually, so they can't fill the tracker.
func (t *Tracker) LogUnknown(ip netip.Addr) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unknown.log(t.now(), SuppressedKey{"deny", ip.String()})
}

func (c *client) log(now time.Time, k SuppressedKey) bool {
	if c.logs.take(now, logRate, logBurst) {
		return true
	}
	if _, ok := c.suppressed[k]; ok || len(c.suppressed) < maxSuppressedKeys {
		if c.suppressed == nil {
			c.suppressed = map[SuppressedKey]int{}
		}
		c.suppressed[k]++
	} else {
		c.other++
	}
	return false
}

// Sweep returns and resets the suppressed log counts, and forgets clients
// that have been idle for a while.
func (t *Tracker) Sweep() []Suppressed {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var out []Suppressed
	take := func(c *client, s Suppressed) {
		if len(c.suppressed) > 0 || c.other > 0 {
			s.Counts, s.Other = c.suppressed, c.other
			out = append(out, s)
			c.suppressed, c.other = nil, 0
		}
	}
	for ip, c := range t.clients {
		take(c, Suppressed{Client: ip})
		if c.conns == 0 && now.Sub(c.seen) > forgetAfter {
			delete(t.clients, ip)
		}
	}
	for p, c := range t.overflow {
		take(c, Suppressed{Prefix: p})
		if c.conns == 0 && now.Sub(c.seen) > forgetAfter {
			delete(t.overflow, p)
		}
	}
	take(&t.unknown, Suppressed{Unknown: true})
	return out
}

// Connections returns the number of connections held by ip and in total.
func (t *Tracker) Connections(ip netip.Addr) (client, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.clients[ip]
	if c == nil {
		c = t.overflow[overflowPrefix(ip)]
	}
	if c != nil {
		client = c.conns
	}
	return client, t.total
}

// Tracked returns the number of client addresses tracked individually.
func (t *Tracker) Tracked() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.clients)
}

// bucket is a token bucket that starts full.
type bucket struct {
	tokens float64
	last   time.Time
	primed bool
}

func (b *bucket) take(now time.Time, rate float64, burst int) bool {
	if rate <= 0 {
		return true
	}
	capacity := float64(max(burst, 1))
	if !b.primed {
		b.tokens, b.primed = capacity, true
	} else {
		b.tokens = min(capacity, b.tokens+now.Sub(b.last).Seconds()*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

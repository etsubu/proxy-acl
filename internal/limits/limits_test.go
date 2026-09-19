package limits

import (
	"net/netip"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestTracker() (*Tracker, *clock) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	tr := NewTracker()
	tr.now = c.now
	return tr, c
}

var (
	ipA = netip.MustParseAddr("10.0.0.1")
	ipB = netip.MustParseAddr("10.0.0.2")
)

func TestConnectionLimits(t *testing.T) {
	tr, _ := newTestTracker()
	lim := Client{MaxConnections: 2}

	r1, err1 := tr.Acquire(ipA, lim, 3)
	r2, err2 := tr.Acquire(ipA, lim, 3)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if _, err := tr.Acquire(ipA, lim, 3); err != ErrClientConnections {
		t.Errorf("third connection for A: %v", err)
	}
	rb, err := tr.Acquire(ipB, lim, 3) // B has its own allowance
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Acquire(ipB, lim, 3); err != ErrTotalConnections {
		t.Errorf("fourth connection overall: %v", err)
	}

	r1()
	r1() // releasing twice must not free a second slot
	if n, total := tr.Connections(ipA); n != 1 || total != 2 {
		t.Errorf("after release: client %d total %d", n, total)
	}
	if _, err := tr.Acquire(ipA, lim, 3); err != nil {
		t.Errorf("slot not freed: %v", err)
	}
	r2()
	rb()

	unlimited := Client{}
	for range 1000 {
		if _, err := tr.Acquire(ipA, unlimited, 0); err != nil {
			t.Fatal("zero limits must not limit:", err)
		}
	}
}

func TestRequestRate(t *testing.T) {
	tr, clk := newTestTracker()
	lim := Client{RequestsPerSecond: 10, RequestBurst: 5}
	allowed := func(n int) (ok int) {
		for range n {
			if tr.Allow(ipA, lim) {
				ok++
			}
		}
		return ok
	}
	if n := allowed(20); n != 5 {
		t.Errorf("burst: %d allowed, want 5", n)
	}
	clk.advance(300 * time.Millisecond) // refills 3 tokens
	if n := allowed(20); n != 3 {
		t.Errorf("after 300ms: %d allowed, want 3", n)
	}
	clk.advance(time.Hour) // refills to the burst, no further
	if n := allowed(20); n != 5 {
		t.Errorf("after an hour: %d allowed, want 5", n)
	}
	if n := func() (ok int) {
		for range 5 {
			if tr.Allow(ipB, lim) {
				ok++
			}
		}
		return ok
	}(); n != 5 {
		t.Errorf("other client affected: %d allowed", n)
	}
	if !tr.Allow(ipA, Client{}) {
		t.Error("zero rate must not limit")
	}
}

func TestLogSamplingAndSweep(t *testing.T) {
	tr, clk := newTestTracker()
	written := 0
	for i := range logBurst + 50 {
		host := "flood.example"
		if i%2 == 0 {
			host = "other.example"
		}
		if tr.Log(ipA, "deny", host) {
			written++
		}
	}
	if written != logBurst {
		t.Errorf("%d lines written, want the burst of %d", written, logBurst)
	}
	// Past maxSuppressedKeys distinct hosts, lines are only counted.
	for i := range maxSuppressedKeys + 5 {
		tr.Log(ipA, "allow", string(rune('a'+i))+".example")
	}

	sums := tr.Sweep()
	if len(sums) != 1 || sums[0].Client != ipA {
		t.Fatalf("summaries: %+v", sums)
	}
	s := sums[0]
	if s.Counts[SuppressedKey{"deny", "flood.example"}] != 25 || s.Counts[SuppressedKey{"deny", "other.example"}] != 25 {
		t.Errorf("counts: %v", s.Counts)
	}
	if len(s.Counts) != maxSuppressedKeys || s.Other != 7 {
		t.Errorf("%d keys, other %d; want %d keys, other 7", len(s.Counts), s.Other, maxSuppressedKeys)
	}
	if len(tr.Sweep()) != 0 {
		t.Error("summary not reset after sweep")
	}

	// Idle clients without connections are forgotten; others are kept.
	release, _ := tr.Acquire(ipB, Client{}, 0)
	clk.advance(forgetAfter + time.Second)
	tr.Sweep()
	if _, ok := tr.clients[ipA]; ok {
		t.Error("idle client not forgotten")
	}
	if _, ok := tr.clients[ipB]; !ok {
		t.Error("client with an open connection forgotten")
	}
	release()
}

func TestTrackedClientsAreBounded(t *testing.T) {
	tr, _ := newTestTracker()
	base := netip.MustParseAddr("2001:db8:1::").As16()
	for i := range maxClients + 100 {
		a := base
		a[12], a[13], a[14], a[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		tr.Allow(netip.AddrFrom16(a), Client{})
	}
	if n := tr.Tracked(); n != maxClients {
		t.Errorf("%d tracked clients, want %d", n, maxClients)
	}
	if n := len(tr.overflow); n != 1 {
		t.Errorf("%d overflow networks, want 1", n)
	}

	// Past the limit, clients share per network, not all together.
	lim := Client{MaxConnections: 1}
	if _, err := tr.Acquire(netip.MustParseAddr("2001:db8:2::1"), lim, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Acquire(netip.MustParseAddr("2001:db8:2::2"), lim, 0); err != ErrClientConnections {
		t.Errorf("same /64 should share a budget: %v", err)
	}
	if _, err := tr.Acquire(netip.MustParseAddr("2001:db8:3::1"), lim, 0); err != nil {
		t.Errorf("another /64 was starved: %v", err)
	}
	if _, err := tr.Acquire(netip.MustParseAddr("192.0.2.1"), lim, 0); err != nil {
		t.Errorf("an IPv4 client was starved: %v", err)
	}
}

func TestUnknownClientsShareOneLogBudget(t *testing.T) {
	tr, _ := newTestTracker()
	written := 0
	for i := range logBurst + 30 {
		if tr.LogUnknown(netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 3)})) {
			written++
		}
	}
	if written != logBurst {
		t.Errorf("%d lines written, want %d", written, logBurst)
	}
	if n := tr.Tracked(); n != 0 {
		t.Errorf("unknown clients created %d tracker entries", n)
	}
	sums := tr.Sweep()
	if len(sums) != 1 || !sums[0].Unknown || len(sums[0].Counts) != 3 {
		t.Fatalf("summary: %+v", sums)
	}
	if n := sums[0].Counts[SuppressedKey{"deny", "192.0.2.0"}]; n != 10 {
		t.Errorf("192.0.2.0: %d suppressed, want 10", n)
	}
}

package dnscache

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLookup struct {
	calls   atomic.Int64
	answers map[string][]netip.Addr
	err     error
	block   chan struct{} // if set, lookups wait for it
}

func (f *fakeLookup) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTest(f *fakeLookup) (*Resolver, *clock) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	r := New(f)
	r.now = c.now
	return r, c
}

func TestCachesAnswersForTTL(t *testing.T) {
	f := &fakeLookup{answers: map[string][]netip.Addr{"a.example": {netip.MustParseAddr("198.51.100.1")}}}
	r, clk := newTest(f)
	ctx := context.Background()
	for range 5 {
		if a, err := r.LookupNetIP(ctx, "ip", "a.example"); err != nil || len(a) != 1 {
			t.Fatal(a, err)
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("%d upstream lookups within the TTL, want 1", n)
	}
	clk.t = clk.t.Add(ttl)
	r.LookupNetIP(ctx, "ip", "a.example")
	if n := f.calls.Load(); n != 2 {
		t.Errorf("%d upstream lookups after the TTL, want 2", n)
	}

	// Callers get their own copy.
	a, _ := r.LookupNetIP(ctx, "ip", "a.example")
	a[0] = netip.MustParseAddr("10.0.0.1")
	if b, _ := r.LookupNetIP(ctx, "ip", "a.example"); b[0] != netip.MustParseAddr("198.51.100.1") {
		t.Error("cached answer was modified through a returned slice")
	}
}

func TestNegativeAndFailedLookups(t *testing.T) {
	f := &fakeLookup{}
	r, clk := newTest(f)
	ctx := context.Background()
	for range 3 {
		if _, err := r.LookupNetIP(ctx, "ip", "missing.example"); err == nil {
			t.Fatal("expected NXDOMAIN")
		}
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("NXDOMAIN looked up %d times, want 1 (cached)", n)
	}
	clk.t = clk.t.Add(negativeTTL)
	r.LookupNetIP(ctx, "ip", "missing.example")
	if n := f.calls.Load(); n != 2 {
		t.Errorf("NXDOMAIN cached past its TTL")
	}

	// Timeouts and server failures are cached only briefly.
	f.err = &net.DNSError{Err: "server misbehaving", Name: "flaky.example", IsTemporary: true}
	r.LookupNetIP(ctx, "ip", "flaky.example")
	r.LookupNetIP(ctx, "ip", "flaky.example")
	if n := f.calls.Load(); n != 3 {
		t.Errorf("server failure looked up again within %v", failureTTL)
	}
	clk.t = clk.t.Add(failureTTL)
	r.LookupNetIP(ctx, "ip", "flaky.example")
	if n := f.calls.Load(); n != 4 {
		t.Errorf("server failure cached past %v", failureTTL)
	}
}

func TestMergesConcurrentLookupsOfOneName(t *testing.T) {
	f := &fakeLookup{block: make(chan struct{}), answers: map[string][]netip.Addr{"same.example": {netip.MustParseAddr("198.51.100.1")}}}
	r, _ := newTest(f)
	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := WithClient(context.Background(), netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}))
			if a, err := r.LookupNetIP(ctx, "ip", "same.example"); err == nil && len(a) == 1 {
				ok.Add(1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(f.block)
	wg.Wait()
	if n := f.calls.Load(); n != 1 || ok.Load() != 64 {
		t.Errorf("64 concurrent misses: %d lookups, %d answers; want 1 and 64", n, ok.Load())
	}
}

func TestLookupSurvivesTheCallerThatStartedIt(t *testing.T) {
	f := &fakeLookup{block: make(chan struct{}), answers: map[string][]netip.Addr{"a.example": {netip.MustParseAddr("198.51.100.1")}}}
	r, _ := newTest(f)
	first, cancel := context.WithCancel(context.Background())
	go r.LookupNetIP(first, "ip", "a.example")
	for f.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	done := make(chan error)
	go func() { _, err := r.LookupNetIP(context.Background(), "ip", "a.example"); done <- err }()
	cancel() // the first caller gives up
	time.Sleep(20 * time.Millisecond)
	close(f.block)
	if err := <-done; err != nil {
		t.Errorf("second caller got %v after the first gave up", err)
	}
}

// slowFake never answers names starting with "slow"; others answer at once.
type slowFake struct{ slow atomic.Int64 }

func (s *slowFake) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	if strings.HasPrefix(host, "slow") {
		s.slow.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
}

func TestSlowClientCannotStarveOthers(t *testing.T) {
	f := &slowFake{}
	r, _ := newTest(&fakeLookup{})
	r.next = f
	bad := WithClient(context.Background(), netip.MustParseAddr("10.0.0.66"))
	for i := range maxConcurrent + 50 { // more than the global cap
		go func() {
			ctx, cancel := context.WithTimeout(bad, 2*time.Second)
			defer cancel()
			r.LookupNetIP(ctx, "ip", fmt.Sprintf("slow-%d.example", i))
		}()
	}
	time.Sleep(100 * time.Millisecond)
	if n := f.slow.Load(); n != maxPerClient {
		t.Errorf("one client has %d lookups in flight, want %d", n, maxPerClient)
	}

	good := WithClient(context.Background(), netip.MustParseAddr("10.0.0.7"))
	ctx, cancel := context.WithTimeout(good, time.Second)
	defer cancel()
	start := time.Now()
	if _, err := r.LookupNetIP(ctx, "ip", "deb.debian.org"); err != nil || time.Since(start) > 100*time.Millisecond {
		t.Errorf("other client's lookup: %v after %v", err, time.Since(start))
	}
}

func TestClientSlotHeldUntilLookupEnds(t *testing.T) {
	f := &slowFake{}
	r, _ := newTest(&fakeLookup{})
	r.next = f
	bad := WithClient(context.Background(), netip.MustParseAddr("10.0.0.66"))
	for i := range maxPerClient {
		ctx, cancel := context.WithTimeout(bad, 20*time.Millisecond) // gives up at once
		go func() { defer cancel(); r.LookupNetIP(ctx, "ip", fmt.Sprintf("slow-%d.example", i)) }()
	}
	time.Sleep(100 * time.Millisecond) // callers are gone, their lookups aren't
	ctx, cancel := context.WithTimeout(bad, 50*time.Millisecond)
	defer cancel()
	if _, err := r.LookupNetIP(ctx, "ip", "slow-new.example"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("abandoned lookups freed the client's slots early: %v", err)
	}
	if n := f.slow.Load(); n != maxPerClient {
		t.Errorf("%d lookups started, want %d", n, maxPerClient)
	}
}

func TestConcurrencyCap(t *testing.T) {
	f := &fakeLookup{block: make(chan struct{}), answers: map[string][]netip.Addr{}}
	r, _ := newTest(f)
	var wg sync.WaitGroup
	for i := range maxConcurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.LookupNetIP(context.Background(), "ip", fmt.Sprintf("n%d.example", i))
		}()
	}
	for f.calls.Load() < maxConcurrent {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := r.LookupNetIP(ctx, "ip", "one-more.example"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("lookup past the cap: %v, want it to wait", err)
	}
	if n := f.calls.Load(); n != maxConcurrent {
		t.Errorf("%d lookups in flight, want %d", n, maxConcurrent)
	}
	close(f.block)
	wg.Wait()
}

func TestCacheIsBounded(t *testing.T) {
	f := &fakeLookup{answers: map[string][]netip.Addr{}}
	for i := range maxEntries + 500 {
		f.answers[fmt.Sprintf("n%d.example", i)] = []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	}
	r, _ := newTest(f)
	for name := range f.answers {
		r.LookupNetIP(context.Background(), "ip", name)
	}
	if n := len(r.entries); n > maxEntries {
		t.Errorf("%d entries, want at most %d", n, maxEntries)
	}
}

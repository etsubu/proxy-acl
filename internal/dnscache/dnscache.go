// Package dnscache puts a small, short-lived cache in front of a resolver,
// merges concurrent lookups of the same name, and shares lookup capacity
// fairly between clients.
//
// Caching can't weaken the ACL: every request's addresses are still checked
// by the policy; only the lookup is skipped.
package dnscache

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const (
	// Go's resolver doesn't expose record TTLs, so entries live for a fixed
	// time, short enough that DNS-based failover still works.
	ttl         = 30 * time.Second
	negativeTTL = 5 * time.Second // names that don't exist
	// Timeouts and server failures are cached briefly too, so a device
	// retrying a name whose DNS is broken costs one lookup every few
	// seconds instead of one per request.
	failureTTL    = 3 * time.Second
	lookupTimeout = 5 * time.Second
	maxEntries    = 10_000
	// Lookups in flight at once, in total and per client. The per-client
	// cap keeps one device retrying names whose DNS never answers from
	// taking every slot and stalling everyone else's lookups.
	maxConcurrent = 256
	maxPerClient  = 32
)

// Lookuper is the resolver being cached. *net.Resolver implements it.
type Lookuper interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Resolver struct {
	next   Lookuper
	now    func() time.Time
	global chan struct{}

	mu      sync.Mutex
	entries map[string]entry
	flights map[string]*flight
	clients map[netip.Addr]*clientSlots
}

type entry struct {
	addrs   []netip.Addr
	err     error
	expires time.Time
}

// flight is a lookup in progress, shared by everyone asking for its name.
type flight struct {
	done  chan struct{}
	addrs []netip.Addr
	err   error
}

type clientSlots struct {
	sem   chan struct{}
	users int // holders and waiters; the entry is dropped at zero
}

type clientKey struct{}

// WithClient tags ctx with the client a lookup is made for, so it counts
// against that client's share of lookup capacity. Untagged lookups only
// count against the total.
func WithClient(ctx context.Context, client netip.Addr) context.Context {
	return context.WithValue(ctx, clientKey{}, client)
}

func New(next Lookuper) *Resolver {
	return &Resolver{
		next:    next,
		now:     time.Now,
		global:  make(chan struct{}, maxConcurrent),
		entries: map[string]entry{},
		flights: map[string]*flight{},
		clients: map[netip.Addr]*clientSlots{},
	}
}

func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	key := network + "|" + host
	r.mu.Lock()
	f, addrs, err, ok := r.findLocked(key)
	r.mu.Unlock()
	if ok {
		if f != nil {
			return r.wait(ctx, f)
		}
		return addrs, err
	}

	// Starting a new lookup takes one of the client's slots, held until
	// the lookup finishes even if this caller gives up earlier.
	release, err := r.acquireClient(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if f, addrs, err, ok := r.findLocked(key); ok { // done or started while we waited
		r.mu.Unlock()
		release()
		if f != nil {
			return r.wait(ctx, f)
		}
		return addrs, err
	}
	f = &flight{done: make(chan struct{})}
	r.flights[key] = f
	r.mu.Unlock()

	go r.run(ctx, key, network, host, f, release)
	return r.wait(ctx, f)
}

// findLocked returns a fresh cache entry or the lookup in flight for key.
// r.mu must be held.
func (r *Resolver) findLocked(key string) (*flight, []netip.Addr, error, bool) {
	if e, ok := r.entries[key]; ok && r.now().Before(e.expires) {
		return nil, slices.Clone(e.addrs), e.err, true
	}
	if f, ok := r.flights[key]; ok {
		return f, nil, nil, true
	}
	return nil, nil, nil, false
}

func (r *Resolver) wait(ctx context.Context, f *flight) ([]netip.Addr, error) {
	select {
	case <-f.done:
		return slices.Clone(f.addrs), f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// run performs a lookup for everyone waiting on f. It isn't tied to the
// caller that started it: others may be waiting for the same name.
func (r *Resolver) run(ctx context.Context, key, network, host string, f *flight, release func()) {
	defer release()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lookupTimeout)
	defer cancel()
	select {
	case r.global <- struct{}{}:
		f.addrs, f.err = r.next.LookupNetIP(ctx, network, host)
		<-r.global
		r.store(key, f.addrs, f.err)
	case <-ctx.Done():
		f.err = ctx.Err() // no free slot: local congestion, not the name's fault, so not cached
	}
	r.mu.Lock()
	delete(r.flights, key)
	r.mu.Unlock()
	close(f.done)
}

func (r *Resolver) acquireClient(ctx context.Context) (release func(), err error) {
	client, ok := ctx.Value(clientKey{}).(netip.Addr)
	if !ok {
		return func() {}, nil
	}
	r.mu.Lock()
	cs := r.clients[client]
	if cs == nil {
		cs = &clientSlots{sem: make(chan struct{}, maxPerClient)}
		r.clients[client] = cs
	}
	cs.users++
	r.mu.Unlock()
	leave := func() {
		r.mu.Lock()
		if cs.users--; cs.users == 0 {
			delete(r.clients, client)
		}
		r.mu.Unlock()
	}
	select {
	case cs.sem <- struct{}{}:
		var once sync.Once
		return func() { once.Do(func() { <-cs.sem; leave() }) }, nil
	case <-ctx.Done():
		leave()
		return nil, ctx.Err()
	}
}

func (r *Resolver) store(key string, addrs []netip.Addr, err error) {
	var e entry
	var dnsErr *net.DNSError
	switch {
	case err == nil && len(addrs) > 0:
		e = entry{addrs: slices.Clone(addrs), expires: r.now().Add(ttl)}
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		e = entry{err: err, expires: r.now().Add(negativeTTL)}
	case err != nil:
		e = entry{err: err, expires: r.now().Add(failureTTL)}
	default:
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) >= maxEntries {
		now := r.now()
		for k, old := range r.entries {
			if !now.Before(old.expires) {
				delete(r.entries, k)
			}
		}
		// Still full of live entries: evict an arbitrary one.
		for k := range r.entries {
			if len(r.entries) < maxEntries {
				break
			}
			delete(r.entries, k)
		}
	}
	r.entries[key] = e
}

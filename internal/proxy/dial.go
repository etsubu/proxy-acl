package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"
)

var errNotVetted = errors.New("proxy-acl: refusing to dial a destination the ACL did not approve")

// Variables so tests can shorten them.
var (
	// dialBudget bounds the whole dial, whatever the client does; once a
	// CONNECT is hijacked, a client hanging up no longer cancels it.
	dialBudget = 30 * time.Second
	// fallbackDelay is how long the preferred address family gets before
	// the other one is tried in parallel (Happy Eyeballs, RFC 8305).
	fallbackDelay = 300 * time.Millisecond
	// dialAddr dials one address.
	dialAddr = (&net.Dialer{}).DialContext
)

const (
	maxAddrsPerFamily = 3
	minAttemptTimeout = 2 * time.Second
)

type vettedKey struct{}

// vetted is an ACL-approved destination: the requested host and port, and
// the addresses the ACL checked for it.
type vetted struct {
	host  string
	port  uint16
	addrs []netip.Addr
	idle  time.Duration // tunnel idle timeout
}

func dialVetted(ctx context.Context, network, addr string) (net.Conn, error) {
	v, _ := ctx.Value(vettedKey{}).(*vetted)
	if v == nil {
		return nil, errNotVetted
	}
	return v.dial(ctx, network, addr)
}

// dial connects to the vetted addresses only. addr must be the host:port
// that was checked; its host is never resolved again.
func (v *vetted) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != v.host || port != strconv.Itoa(int(v.port)) || len(v.addrs) == 0 {
		return nil, errNotVetted
	}
	ctx, cancel := context.WithTimeout(ctx, dialBudget)
	defer cancel()
	return dialParallel(ctx, network, v.addrs, v.port)
}

// dialParallel tries the first address's family, starting the other family
// in parallel after fallbackDelay or as soon as the first family fails.
// The first connection to succeed wins.
func dialParallel(ctx context.Context, network string, addrs []netip.Addr, port uint16) (net.Conn, error) {
	var primary, fallback []netip.Addr
	for _, a := range addrs {
		if a.Is4() == addrs[0].Is4() {
			if len(primary) < maxAddrsPerFamily {
				primary = append(primary, a)
			}
		} else if len(fallback) < maxAddrsPerFamily {
			fallback = append(fallback, a)
		}
	}
	if len(fallback) == 0 {
		return dialSerial(ctx, network, primary, port)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	results := make(chan result, 2)
	race := func(list []netip.Addr) {
		c, err := dialSerial(ctx, network, list, port)
		results <- result{c, err}
	}
	go race(primary)
	pending, fallbackStarted := 1, false
	startFallback := func() {
		if !fallbackStarted {
			fallbackStarted = true
			pending++
			go race(fallback)
		}
	}
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()

	var errs []error
	for {
		select {
		case <-timer.C:
			startFallback()
		case r := <-results:
			pending--
			if r.err == nil {
				if pending > 0 {
					// The loser is cancelled, but may connect anyway.
					go func() {
						if l := <-results; l.c != nil {
							l.c.Close()
						}
					}()
				}
				return r.c, nil
			}
			errs = append(errs, r.err)
			startFallback()
			if pending == 0 {
				return nil, errors.Join(errs...)
			}
		}
	}
}

// dialSerial tries addrs in order, splitting the remaining time between
// them so one unreachable address can't use up the whole budget.
func dialSerial(ctx context.Context, network string, addrs []netip.Addr, port uint16) (net.Conn, error) {
	var errs []error
	for i, a := range addrs {
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok {
			share := time.Until(deadline) / time.Duration(len(addrs)-i)
			attemptCtx, cancel = context.WithTimeout(ctx, max(share, minAttemptTimeout))
		}
		c, err := dialAddr(attemptCtx, network, netip.AddrPortFrom(a, port).String())
		cancel()
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, errNotVetted
	}
	return nil, errors.Join(errs...)
}

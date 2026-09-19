package acl

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// publicAddr is what fakeResolver returns for names without a record.
var publicAddr = netip.MustParseAddr("198.51.100.10")

// fakeResolver resolves from a fixed table and records every lookup.
type fakeResolver struct {
	mu      sync.Mutex
	records map[string][]netip.Addr
	calls   []string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, host)
	if addrs, ok := f.records[host]; ok {
		if addrs == nil {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return addrs, nil
	}
	return []netip.Addr{publicAddr}, nil
}

func (f *fakeResolver) lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func mustPolicy(t testing.TB, specs ...SubnetSpec) *Policy {
	t.Helper()
	p, err := New(specs)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

const testClient = "10.0.1.10"

// ruleCase is one request against a single-subnet policy.
type ruleCase struct {
	host  string
	port  string // defaults to 443
	allow bool
}

// runRuleCases checks each case from testClient against a subnet with the
// given allow/deny rules. Names resolve to a public address unless res has
// a record for them.
func runRuleCases(t *testing.T, allow, deny []string, res *fakeResolver, cases []ruleCase) {
	t.Helper()
	p := mustPolicy(t, SubnetSpec{Name: "test", CIDRs: []string{"10.0.1.0/24"}, Allow: allow, Deny: deny})
	if res == nil {
		res = &fakeResolver{}
	}
	for _, c := range cases {
		port := c.port
		if port == "" {
			port = "443"
		}
		d := p.Check(context.Background(), res, netip.MustParseAddr(testClient), c.host, port)
		if d.Allow != c.allow {
			t.Errorf("allow=%q deny=%q: %q:%s allowed=%v, want %v (reason %q, rule %q)",
				allow, deny, c.host, port, d.Allow, c.allow, d.Reason, d.Rule)
		}
		if d.Reason == "" {
			t.Errorf("%q: decision without a reason", c.host)
		}
		if d.Allow && len(d.Addrs) == 0 {
			t.Errorf("%q: allowed without vetted addresses", c.host)
		}
		if !d.Allow && (d.Addrs != nil || d.Port != 0) {
			t.Errorf("%q: denied decision carries dial targets", c.host)
		}
	}
}

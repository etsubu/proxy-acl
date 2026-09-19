package acl

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// Config mistakes must be rejected at load time rather than silently
// widening (or pointlessly narrowing) access.
func TestNewRejectsInvalidConfig(t *testing.T) {
	sub := func(mod func(*SubnetSpec)) []SubnetSpec {
		s := SubnetSpec{Name: "a", CIDRs: []string{"10.0.0.0/24"}}
		mod(&s)
		return []SubnetSpec{s}
	}
	tests := map[string][]SubnetSpec{
		"no subnets":      nil,
		"no cidrs":        sub(func(s *SubnetSpec) { s.CIDRs = nil }),
		"bad cidr":        sub(func(s *SubnetSpec) { s.CIDRs = []string{"10.0.0.0/33"} }),
		"host bits set":   sub(func(s *SubnetSpec) { s.CIDRs = []string{"10.0.1.50/24"} }),
		"mapped cidr":     sub(func(s *SubnetSpec) { s.CIDRs = []string{"::ffff:10.0.0.0/104"} }),
		"zoned cidr":      sub(func(s *SubnetSpec) { s.CIDRs = []string{"fe80::1%eth0"} }),
		"hostname cidr":   sub(func(s *SubnetSpec) { s.CIDRs = []string{"lan.example"} }),
		"duplicate cidr":  {{Name: "a", CIDRs: []string{"10.0.0.0/24"}}, {Name: "b", CIDRs: []string{"10.0.0.0/24"}}},
		"duplicate host":  {{Name: "a", CIDRs: []string{"10.0.0.5"}}, {Name: "b", CIDRs: []string{"10.0.0.5/32"}}},
		"duplicate name":  {{Name: "a", CIDRs: []string{"10.0.0.0/24"}}, {Name: "a", CIDRs: []string{"10.0.1.0/24"}}},
		"port zero":       sub(func(s *SubnetSpec) { s.Ports = []string{"0"} }),
		"port too big":    sub(func(s *SubnetSpec) { s.Ports = []string{"65536"} }),
		"port text":       sub(func(s *SubnetSpec) { s.Ports = []string{"https"} }),
		"port star":       sub(func(s *SubnetSpec) { s.Ports = []string{"*"} }),
		"port empty":      sub(func(s *SubnetSpec) { s.Ports = []string{""} }),
		"port open range": sub(func(s *SubnetSpec) { s.Ports = []string{"80-"} }),
		"port neg":        sub(func(s *SubnetSpec) { s.Ports = []string{"-80"} }),
		"port reversed":   sub(func(s *SubnetSpec) { s.Ports = []string{"90-80"} }),
		"port zero pad":   sub(func(s *SubnetSpec) { s.Ports = []string{"0443"} }),
	}
	for _, p := range []string{
		"", "  ", "~", "~(", "~[a-", // empty / bad regex
		"https://example.com", "example.com:443", "example.com/path", "//example.com", // not hostnames
		"user@example.com", "example.com?x", "example.com#x", "ex ample.com", "exämple.com",
		"example..com", ".", "..example.com", ".*", ".*.example.com", // bad structure
		"*example.com", "**.example.com", "*-cdn.example.com", // leading * not followed by "."
		"192.168.1.*", "10.*", "*.1", // IP wildcards
		"example.123", "127.1", "2130706433", // numeric TLD
		strings.Repeat("a", 64) + ".com",
		"10.0.0.1/24", "::ffff:1.2.3.4", "fe80::1%eth0", "10.0.0.0/33", // bad addresses
	} {
		tests["allow "+p] = sub(func(s *SubnetSpec) { s.Allow = []string{p} })
		tests["deny "+p] = sub(func(s *SubnetSpec) { s.Deny = []string{p} })
	}
	for name, specs := range tests {
		if _, err := New(specs); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestNewAcceptsValidForms(t *testing.T) {
	p, err := New([]SubnetSpec{{
		Name:  "a",
		CIDRs: []string{"10.0.0.5", "fd00::/64", " 10.1.0.0/16 "},
		Ports: []string{"443", "8000-8100", "1-65535"},
		Allow: []string{"example.com", "EXAMPLE.ORG", "fqdn.example.", ".suffix.example", "*.wild.example", "api-*.example.net",
			"example.*", `~re\.example`, "203.0.113.0/24", "2001:db8::1", "_srv.example", "xn--80ak6aa92e.com", " spaced.example ", "*"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// A bare address in cidrs is a single host.
	res := &fakeResolver{}
	if d := p.Check(context.Background(), res, netip.MustParseAddr("10.0.0.5"), "example.com", "443"); !d.Allow {
		t.Errorf("10.0.0.5: %s", d.Reason)
	}
	if d := p.Check(context.Background(), res, netip.MustParseAddr("10.0.0.6"), "example.com", "443"); d.Allow {
		t.Error("10.0.0.6 matched a bare-address subnet")
	}
	// Uppercase and trailing-dot patterns are normalized.
	for _, h := range []string{"example.org", "fqdn.example", "spaced.example"} {
		if d := p.Check(context.Background(), res, netip.MustParseAddr("10.0.0.5"), h, "443"); d.Rule == "*" {
			t.Errorf("%s matched only by \"*\", its own rule was not normalized", h)
		}
	}
}

package acl

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestDenyByDefault(t *testing.T) {
	ctx := context.Background()
	res := &fakeResolver{}
	p := mustPolicy(t,
		SubnetSpec{Name: "empty", CIDRs: []string{"10.0.1.0/24"}},
		SubnetSpec{Name: "denyonly", CIDRs: []string{"10.0.2.0/24"}, Deny: []string{"evil.example"}},
		SubnetSpec{Name: "open", CIDRs: []string{"10.0.3.0/24"}, Allow: []string{"*"}},
	)
	hosts := []string{"example.com", "evil.example", "localhost", "198.51.100.10", "2001:db8::1", "::1", "127.0.0.1", "0.0.0.0", ""}

	// A subnet without allow rules allows nothing.
	for _, client := range []string{"10.0.1.10", "10.0.2.10"} {
		for _, h := range hosts {
			if d := p.Check(ctx, res, netip.MustParseAddr(client), h, "443"); d.Allow {
				t.Errorf("client %s host %q allowed without an allow rule", client, h)
			}
		}
	}
	// Clients outside every subnet are denied, whatever they ask for.
	for _, client := range []netip.Addr{
		netip.MustParseAddr("10.0.4.10"),
		netip.MustParseAddr("192.168.1.10"),
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("0.0.0.0"),
		netip.MustParseAddr("::"),
		{}, // unparseable RemoteAddr
	} {
		for _, h := range hosts {
			d := p.Check(ctx, res, client, h, "443")
			if d.Allow || d.Subnet != "" || d.Reason != "client not in any subnet" {
				t.Errorf("client %v host %q: %+v", client, h, d)
			}
		}
	}
	if calls := res.lookups(); len(calls) != 0 {
		t.Errorf("denied requests caused DNS lookups: %q", calls)
	}
}

func TestPorts(t *testing.T) {
	t.Run("default is 80 and 443 only", func(t *testing.T) {
		cases := []ruleCase{{host: "example.com", port: "80", allow: true}, {host: "example.com", port: "443", allow: true}}
		for _, port := range []string{"22", "25", "8080", "8443", "1", "65535", "0", "65536", "99999",
			"abc", "-1", "+443", " 443", "443 ", "4 43", "0443", "00443", "0x1bb", "443.0", "1e3", "４４３"} {
			cases = append(cases, ruleCase{host: "example.com", port: port})
		}
		runRuleCases(t, []string{"example.com"}, nil, nil, cases)

		p := mustPolicy(t, SubnetSpec{CIDRs: []string{"10.0.1.0/24"}, Allow: []string{"example.com"}})
		if d := p.Check(context.Background(), &fakeResolver{}, netip.MustParseAddr(testClient), "example.com", ""); d.Allow {
			t.Error("missing port allowed")
		}
	})
	t.Run("explicit list replaces the default", func(t *testing.T) {
		p := mustPolicy(t, SubnetSpec{CIDRs: []string{"10.0.1.0/24"}, Ports: []string{"22", "8000-8100"}, Allow: []string{"example.com"}})
		for port, want := range map[string]bool{"22": true, "8000": true, "8050": true, "8100": true,
			"80": false, "443": false, "7999": false, "8101": false} {
			d := p.Check(context.Background(), &fakeResolver{}, netip.MustParseAddr(testClient), "example.com", port)
			if d.Allow != want {
				t.Errorf("port %s: allowed=%v, want %v (%s)", port, d.Allow, want, d.Reason)
			}
		}
	})
	t.Run("allowed decision carries the checked port", func(t *testing.T) {
		p := mustPolicy(t, SubnetSpec{CIDRs: []string{"10.0.1.0/24"}, Allow: []string{"example.com"}})
		if d := p.Check(context.Background(), &fakeResolver{}, netip.MustParseAddr(testClient), "example.com", "80"); d.Port != 80 {
			t.Errorf("Port = %d, want 80", d.Port)
		}
	})
}

func TestSubnetSelection(t *testing.T) {
	p := mustPolicy(t,
		SubnetSpec{Name: "default", CIDRs: []string{"0.0.0.0/0"}},
		SubnetSpec{Name: "lan", CIDRs: []string{"10.0.1.0/24", "fd00:1::/64"}, Allow: []string{"*"}},
		SubnetSpec{Name: "printer", CIDRs: []string{"10.0.1.50"}},
		SubnetSpec{Name: "iot", CIDRs: []string{"10.0.20.0/24"}, Allow: []string{".netflix.com"}},
	)
	tests := []struct {
		client, host string
		subnet       string
		allow        bool
	}{
		{"10.0.1.10", "github.com", "lan", true},
		{"10.0.1.0", "github.com", "lan", true},
		{"10.0.1.255", "github.com", "lan", true},
		{"::ffff:10.0.1.10", "github.com", "lan", true},
		{"fd00:1::5", "github.com", "lan", true},
		{"10.0.1.50", "github.com", "printer", false}, // /32 beats /24
		{"10.0.1.49", "github.com", "lan", true},
		{"10.0.20.5", "www.netflix.com", "iot", true},
		{"10.0.20.5", "github.com", "iot", false}, // iot doesn't inherit lan rules
		{"10.0.2.1", "github.com", "default", false},
		{"192.168.1.1", "github.com", "default", false},
		{"fd00:2::5", "github.com", "", false}, // 0.0.0.0/0 doesn't cover IPv6
	}
	for _, tt := range tests {
		d := p.Check(context.Background(), &fakeResolver{}, netip.MustParseAddr(tt.client), tt.host, "443")
		if d.Subnet != tt.subnet || d.Allow != tt.allow {
			t.Errorf("%s -> %s: subnet=%q allow=%v, want subnet=%q allow=%v", tt.client, tt.host, d.Subnet, d.Allow, tt.subnet, tt.allow)
		}
	}
}

func TestResolvedAddresses(t *testing.T) {
	res := &fakeResolver{records: map[string][]netip.Addr{
		"public.test":     addrs("198.51.100.1", "2001:db8::1"),
		"nas.test":        addrs("10.0.1.5"),
		"private.test":    addrs("10.0.0.7"),
		"private172.test": addrs("172.16.5.5"),
		"private192.test": addrs("192.168.1.1"),
		"loopback.test":   addrs("127.0.0.1"),
		"loopback2.test":  addrs("127.8.9.10"),
		"loopback6.test":  addrs("::1"),
		"zero.test":       addrs("0.0.0.0"),
		"zero6.test":      addrs("::"),
		"mapped.test":     addrs("::ffff:10.0.0.7"),
		"mappedlo.test":   addrs("::ffff:127.0.0.1"),
		"metadata.test":   addrs("169.254.169.254"),
		"cgnat.test":      addrs("100.100.100.100"),
		"ula.test":        addrs("fd00::1"),
		"linklocal6.test": addrs("fe80::1"),
		"nat64.test":      addrs("64:ff9b::a00:1"),
		"multicast.test":  addrs("224.0.0.1"),
		"broadcast.test":  addrs("255.255.255.255"),
		"mixed.test":      addrs("198.51.100.1", "10.0.0.7"),
		"mixed6.test":     addrs("198.51.100.1", "fd00::1"),
		"6to4.test":       addrs("2002:a00:1::1"), // embeds 10.0.0.1
		"teredo.test":     addrs("2001:0:4136:e378:8000:63bf:3fff:fdd2"),
		"denied-ip.test":  addrs("203.0.113.9"),
		"nxdomain.test":   nil,
		"empty.test":      {},
	}}
	runRuleCases(t, []string{"*", "10.0.1.5"}, []string{"203.0.113.0/24"}, res, []ruleCase{
		{host: "public.test", allow: true},
		{host: "nas.test", allow: true}, // private, but explicitly allowed by IP

		{host: "private.test"},
		{host: "private172.test"},
		{host: "private192.test"},
		{host: "loopback.test"},
		{host: "loopback2.test"},
		{host: "loopback6.test"},
		{host: "zero.test"},
		{host: "zero6.test"},
		{host: "mapped.test"},
		{host: "mappedlo.test"},
		{host: "metadata.test"},
		{host: "cgnat.test"},
		{host: "ula.test"},
		{host: "linklocal6.test"},
		{host: "nat64.test"},
		{host: "multicast.test"},
		{host: "broadcast.test"},
		{host: "mixed.test"},  // one bad address denies the whole request
		{host: "mixed6.test"}, // same for IPv6
		{host: "6to4.test"},
		{host: "teredo.test"},
		{host: "denied-ip.test"},
		{host: "nxdomain.test"},
		{host: "empty.test"},
		// IP literals get the same address checks.
		{host: "127.0.0.1"},
		{host: "10.0.1.5", allow: true},
	})

	p := mustPolicy(t, SubnetSpec{CIDRs: []string{"10.0.1.0/24"}, Allow: []string{"*"}, Deny: []string{"203.0.113.0/24"}})
	client := netip.MustParseAddr(testClient)

	d := p.Check(context.Background(), res, client, "public.test", "443")
	if !slices.Equal(d.Addrs, addrs("198.51.100.1", "2001:db8::1")) {
		t.Errorf("Addrs = %v, want exactly the resolved addresses", d.Addrs)
	}
	d = p.Check(context.Background(), res, client, "denied-ip.test", "443")
	if d.Rule != "203.0.113.0/24" || !strings.Contains(d.Reason, "203.0.113.9") {
		t.Errorf("deny by resolved address: rule=%q reason=%q", d.Rule, d.Reason)
	}
	d = p.Check(context.Background(), res, client, "::ffff:198.51.100.1", "443")
	if d.Allow {
		t.Error("IPv4-mapped literal allowed without an IP allow rule")
	}
}

// Names that fail the name rules must never reach DNS: otherwise the proxy
// would let a locked-down client leak data through lookups of hostnames
// like <data>.attacker.example.
func TestNoDNSLookupForDeniedRequests(t *testing.T) {
	res := &fakeResolver{}
	p := mustPolicy(t, SubnetSpec{CIDRs: []string{"10.0.1.0/24"}, Allow: []string{".example.com"}, Deny: []string{"bad.example.com"}})
	client := netip.MustParseAddr(testClient)
	ctx := context.Background()

	for _, req := range []struct{ client, host, port string }{
		{testClient, "c2VjcmV0.attacker.example", "443"}, // not allowed
		{testClient, "bad.example.com", "443"},           // deny rule
		{testClient, "www.example.com", "22"},            // port not allowed
		{testClient, "www.example.com", "bogus"},         // invalid port
		{testClient, "www.example..com", "443"},          // invalid host
		{"10.9.9.9", "www.example.com", "443"},           // unknown client
	} {
		if d := p.Check(ctx, res, netip.MustParseAddr(req.client), req.host, req.port); d.Allow {
			t.Errorf("%+v allowed", req)
		}
	}
	if calls := res.lookups(); len(calls) != 0 {
		t.Fatalf("denied requests caused DNS lookups: %q", calls)
	}

	// Allowed names are looked up once, in normalized form.
	if d := p.Check(ctx, res, client, "WWW.Example.com.", "443"); !d.Allow {
		t.Fatalf("allowed name denied: %s", d.Reason)
	}
	if calls := res.lookups(); !slices.Equal(calls, []string{"www.example.com"}) {
		t.Errorf("lookups = %q, want exactly [www.example.com]", calls)
	}
}

func TestIsPublic(t *testing.T) {
	for _, s := range []string{"198.51.100.1", "8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "100.63.255.255", "100.128.0.0", "172.32.0.1", "11.0.0.1"} {
		if !isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range []string{"0.0.0.0", "0.1.2.3", "10.255.255.255", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1",
		"172.31.255.255", "192.0.0.1", "192.168.0.1", "198.18.0.1", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::a00:1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1", "ff02::1",
		"192.88.99.1", "2002:a00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"} {
		if isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should not be public", s)
		}
	}
}

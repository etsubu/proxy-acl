package acl

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// Each pattern type is tested with what it must match and with lookalike
// hosts that must not slip through.

func TestExactHostname(t *testing.T) {
	runRuleCases(t, []string{"example.com"}, nil, nil, []ruleCase{
		{host: "example.com", allow: true},
		{host: "EXAMPLE.COM", allow: true},
		{host: "Example.Com", allow: true},
		{host: "example.com.", allow: true}, // FQDN form

		{host: "www.example.com"},
		{host: "a.b.example.com"},
		{host: "example.com.evil.net"},
		{host: "evil-example.com"},
		{host: "evilexample.com"},
		{host: "examplee.com"},
		{host: "xample.com"},
		{host: "example.co"},
		{host: "example.comm"},
		{host: "example"},
		{host: "com"},
		{host: "example.com.."},
		{host: ".example.com"},
		{host: "example..com"},
		{host: "*.example.com"},
		{host: "example.com "},
		{host: " example.com"},
		{host: "example.com\x00"},
		{host: "example.com\x00.evil.net"},
		{host: "example.com\n"},
		{host: "example.com\r\nX: y"},
		{host: "example.com/"},
		{host: "example.com:443"},
		{host: "example.com%00"},
		{host: "example%2ecom"},
		{host: "user@example.com"},
		{host: "evil.net#example.com"},
		{host: "evil.net\\example.com"},
		{host: "exаmple.com"}, // Cyrillic "а"
		{host: "example。com"}, // ideographic full stop, which IDNA maps to "."
		{host: ""},
	})
}

func TestDomainSuffix(t *testing.T) {
	runRuleCases(t, []string{".example.com"}, nil, nil, []ruleCase{
		{host: "example.com", allow: true},
		{host: "www.example.com", allow: true},
		{host: "a.b.c.example.com", allow: true},
		{host: "WWW.EXAMPLE.COM", allow: true},
		{host: "www.example.com.", allow: true},
		{host: "_srv.example.com", allow: true},

		{host: "badexample.com"},
		{host: "wwwexample.com"},
		{host: "example.com.evil.net"},
		{host: "www.example.com.evil.net"},
		{host: "example.comx"},
		{host: "xexample.com"},
		{host: "example.co"},
		{host: "com"},
		{host: "."},
		{host: ".example.com"},
		{host: "www..example.com"},
		{host: "www.example.com.."},
		{host: "*.example.com"},
		{host: "evil.net/.example.com"},
		{host: "evil.net?.example.com"},
	})
}

func TestWildcardSubdomains(t *testing.T) {
	runRuleCases(t, []string{"*.example.com"}, nil, nil, []ruleCase{
		{host: "www.example.com", allow: true},
		{host: "a.b.example.com", allow: true},
		{host: "x-y_z.example.com", allow: true},
		{host: "WWW.Example.COM.", allow: true},

		{host: "example.com"}, // subdomains only
		{host: "badexample.com"},
		{host: "wwwexample.com"},
		{host: "www.example.com.evil.net"},
		{host: "example.com.example.org"},
		{host: ".example.com"},
		{host: "*.example.com"},
		{host: "a..example.com"},
	})
}

func TestWildcardInsideLabel(t *testing.T) {
	// "*" inside a label never crosses a dot.
	runRuleCases(t, []string{"api-*.example.com"}, nil, nil, []ruleCase{
		{host: "api-eu.example.com", allow: true},
		{host: "API-US.example.com", allow: true},

		{host: "api.example.com"},
		{host: "api-eu.evil.example.com"},
		{host: "xapi-eu.example.com"},
		{host: "api-eu.example.com.evil.net"},
		{host: "api-eu.example.co"},
	})
	runRuleCases(t, []string{"example.*"}, nil, nil, []ruleCase{
		{host: "example.com", allow: true},
		{host: "example.org", allow: true},

		{host: "example.com.evil.net"},
		{host: "www.example.com"},
		{host: "example"},
	})
}

func TestStarMatchesHostnamesOnly(t *testing.T) {
	runRuleCases(t, []string{"*"}, nil, nil, []ruleCase{
		{host: "example.com", allow: true},
		{host: "a.b.c.d.example", allow: true},
		{host: "intranet", allow: true},
		{host: "xn--80ak6aa92e.com", allow: true}, // punycode is fine

		// IP literals need an IP/CIDR allow rule, even under "*".
		{host: "198.51.100.10"},
		{host: "::ffff:198.51.100.10"},
		{host: "2001:db8::1"},
		// Alternative IPv4 notations some resolvers accept.
		{host: "127.1"},
		{host: "2130706433"},
		{host: "0x7f000001"},
		{host: "0x7f.0.0.1"},
		{host: "0177.0.0.1"},
		{host: "127.0.0.1."},
		{host: "1.2.3.4.5"},
		{host: "198.51.100.010"},
		// Malformed.
		{host: ""},
		{host: "."},
		{host: ".."},
		{host: "-"},
		{host: "-example.com"},
		{host: "example-.com"},
		{host: "example.com-"},
		{host: "[::1]"},
		{host: "fe80::1%eth0"},
		{host: "exa mple.com"},
		{host: "example.com\t"},
		{host: strings.Repeat("a", 64) + ".com"},
		{host: strings.Repeat("a.", 126) + "com"}, // 255 chars
	})
	runRuleCases(t, []string{"*"}, nil, nil, []ruleCase{
		{host: strings.Repeat("a", 63) + ".com", allow: true},
		{host: strings.Repeat("a.", 125) + "com", allow: true}, // 253 chars
	})
}

func TestRegex(t *testing.T) {
	runRuleCases(t, []string{`~cdn[0-9]+\.example\.net`}, nil, nil, []ruleCase{
		{host: "cdn1.example.net", allow: true},
		{host: "CDN22.EXAMPLE.NET", allow: true},

		{host: "cdn.example.net"},
		{host: "xcdn1.example.net"},
		{host: "a.cdn1.example.net"},
		{host: "cdn1.example.net.evil.org"},
		{host: "cdn1.example.netx"},
		{host: "cdn1-example.net"},
		{host: "cdn1.example.net\n"},
	})
	// Alternation must be anchored as a whole, not just its outer branches.
	runRuleCases(t, []string{`~foo\.com|bar\.com`}, nil, nil, []ruleCase{
		{host: "foo.com", allow: true},
		{host: "bar.com", allow: true},

		{host: "foo.com.evil.net"},
		{host: "evil.bar.com"},
		{host: "xfoo.com"},
		{host: "bar.com.evil"},
	})
	runRuleCases(t, []string{`~^(www\.)?example\.com$`}, nil, nil, []ruleCase{
		{host: "example.com", allow: true},
		{host: "www.example.com", allow: true},
		{host: "ww.example.com"},
	})
	// Regexes are for hostnames; they never match IP literals.
	runRuleCases(t, []string{`~.*`}, nil, nil, []ruleCase{
		{host: "anything.example", allow: true},
		{host: "198.51.100.10"},
		{host: "2001:db8::1"},
	})
}

func TestIPRules(t *testing.T) {
	runRuleCases(t, []string{"203.0.113.0/24", "2001:db8::/32", "192.0.2.1"}, nil, nil, []ruleCase{
		{host: "203.0.113.7", allow: true},
		{host: "::ffff:203.0.113.7", allow: true}, // IPv4-mapped form of the same address
		{host: "2001:db8::1", allow: true},
		{host: "2001:DB8:0:0:0:0:0:1", allow: true},
		{host: "192.0.2.1", allow: true},

		{host: "203.0.114.1"},
		{host: "192.0.2.2"},
		{host: "2001:db9::1"},
		{host: "2001:db8::1%eth0"},
		{host: "203.0.113.7."},
		{host: "0203.0.113.7"},
		// IP allow rules don't allow hostnames, even ones resolving into the range.
		{host: "in-range.example"},
	})
}

func TestDenyWinsOverAllow(t *testing.T) {
	runRuleCases(t, []string{"*"}, []string{".ads.example"}, nil, []ruleCase{
		{host: "ads.example"},
		{host: "x.ads.example"},
		{host: "X.ADS.EXAMPLE"},
		{host: "x.ads.example."},
		{host: "ads.example.org", allow: true},
		{host: "badads.example", allow: true},
	})
	// A more specific allow rule doesn't beat a deny rule.
	runRuleCases(t, []string{"tracker.ads.example", ".ads.example"}, []string{".ads.example"}, nil, []ruleCase{
		{host: "tracker.ads.example"},
		{host: "ads.example"},
	})
	runRuleCases(t, []string{"*"}, []string{`~.*telemetry.*`}, nil, []ruleCase{
		{host: "telemetry.vendor.example"},
		{host: "eu-telemetry-1.vendor.example"},
		{host: "TELEMETRY.vendor.example"},
		{host: "vendor.example", allow: true},
	})
	runRuleCases(t, []string{"203.0.113.0/24"}, []string{"203.0.113.66"}, nil, []ruleCase{
		{host: "203.0.113.66"},
		{host: "::ffff:203.0.113.66"},
		{host: "203.0.113.65", allow: true},
	})
	// Deny "*" means everything: hostnames, IP literals, even explicitly
	// allowed ones.
	runRuleCases(t, []string{"*", "203.0.113.0/24", "10.0.1.5", "nas.example"}, []string{"*"}, nil, []ruleCase{
		{host: "example.com"},
		{host: "nas.example"},
		{host: "203.0.113.1"},
		{host: "10.0.1.5"},
		{host: "2001:db8::1"},
		{host: "::ffff:203.0.113.1"},
	})
}

// The logged rule is the most specific match, whatever the config order.
func TestReportedRuleIsMostSpecific(t *testing.T) {
	p := mustPolicy(t, SubnetSpec{CIDRs: []string{"10.0.1.0/24"}, Allow: []string{
		"*", `~.*\.example\.com`, "*.example.com", ".example.com", ".www.example.com", "www.example.com",
	}})
	for host, want := range map[string]string{
		"www.example.com":   "www.example.com",
		"a.www.example.com": ".www.example.com",
		"b.example.com":     ".example.com",
		"example.com":       ".example.com",
		"other.example":     "*",
	} {
		d := p.Check(context.Background(), &fakeResolver{}, netip.MustParseAddr(testClient), host, "443")
		if d.Rule != want {
			t.Errorf("%s: rule %q, want %q", host, d.Rule, want)
		}
	}
}

func TestUnicodeCaseFoldingCannotForgeASCII(t *testing.T) {
	// strings.ToLower maps U+212A KELVIN SIGN to "k"; such hosts must be
	// rejected, not folded into an allowed ASCII name.
	runRuleCases(t, []string{"keep.example.com"}, nil, nil, []ruleCase{
		{host: "Keep.example.com"},
		{host: "keep.example.com", allow: true},
	})
	runRuleCases(t, []string{"*"}, []string{".kitten.example"}, nil, []ruleCase{
		{host: "Kitten.example"},
		{host: "ſtuff.example"}, // U+017F LATIN SMALL LETTER LONG S
	})
}

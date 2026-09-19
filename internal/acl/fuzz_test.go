package acl

import (
	"context"
	"net/netip"
	"regexp"
	"strings"
	"testing"
)

// FuzzCheck checks that nothing outside a strict policy is ever allowed,
// whatever client, host and port strings come in. Every allowed decision is
// re-verified against an independent, deliberately simple reference.
//
// The seed corpus runs as part of go test; CI also fuzzes for a while:
//
//	go test ./internal/acl -run '^$' -fuzz '^FuzzCheck$' -fuzztime 30s
func FuzzCheck(f *testing.F) {
	p := mustPolicy(f,
		SubnetSpec{
			Name:  "strict",
			CIDRs: []string{"10.0.0.0/24"},
			Allow: []string{"example.com", ".allowed.org", "*.wild.net", "api-*.inner.io", `~cdn[0-9]+\.regex\.io`, "203.0.113.0/24"},
			Deny:  []string{"blocked.allowed.org", "203.0.113.66"},
		},
		SubnetSpec{Name: "closed", CIDRs: []string{"10.0.1.0/24"}},
	)
	res := &fakeResolver{}
	for _, s := range [][3]string{
		{"10.0.0.1", "example.com", "443"},
		{"10.0.0.1", "EXAMPLE.COM.", "80"},
		{"10.0.0.1", "www.example.com", "443"},
		{"10.0.0.1", "x.allowed.org", "443"},
		{"10.0.0.1", "blocked.allowed.org", "443"},
		{"10.0.0.1", "BLOCKED.allowed.org.", "443"},
		{"10.0.0.1", "a.b.wild.net", "443"},
		{"10.0.0.1", "wild.net", "443"},
		{"10.0.0.1", "api-x.inner.io", "443"},
		{"10.0.0.1", "api-x.y.inner.io", "443"},
		{"10.0.0.1", "cdn7.regex.io", "443"},
		{"10.0.0.1", "cdn7.regex.io.evil", "443"},
		{"10.0.0.1", "203.0.113.5", "443"},
		{"10.0.0.1", "203.0.113.66", "443"},
		{"10.0.0.1", "::ffff:203.0.113.66", "443"},
		{"10.0.0.1", "Kexample.com", "443"},
		{"10.0.0.1", "example.com", "0443"},
		{"::ffff:10.0.0.1", "example.com", "443"},
		{"10.0.1.1", "example.com", "443"},
		{"", "example.com", "443"},
	} {
		f.Add(s[0], s[1], s[2])
	}

	wildRe := regexp.MustCompile(`^cdn[0-9]+\.regex\.io$`)
	strict := netip.MustParsePrefix("10.0.0.0/24")
	allowedIPs := netip.MustParsePrefix("203.0.113.0/24")

	f.Fuzz(func(t *testing.T, clientStr, host, port string) {
		client, _ := netip.ParseAddr(clientStr)
		d := p.Check(context.Background(), res, client, host, port)
		if !d.Allow {
			if d.Addrs != nil || d.Port != 0 {
				t.Fatalf("denied decision carries dial targets: %+v", d)
			}
			return
		}

		if !client.IsValid() || !strict.Contains(client.Unmap()) {
			t.Fatalf("client %q allowed outside the strict subnet", clientStr)
		}
		if port != "80" && port != "443" {
			t.Fatalf("port %q allowed", port)
		}
		if len(d.Addrs) == 0 {
			t.Fatal("allowed without vetted addresses")
		}
		for _, a := range d.Addrs {
			if !isPublic(a) && !allowedIPs.Contains(a) {
				t.Fatalf("non-public address %s allowed", a)
			}
		}

		if a, err := netip.ParseAddr(host); err == nil {
			a = a.Unmap()
			if a.Zone() != "" || !allowedIPs.Contains(a) || a == netip.MustParseAddr("203.0.113.66") {
				t.Fatalf("IP %q allowed", host)
			}
			return
		}
		for i := 0; i < len(host); i++ {
			c := host[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.') {
				t.Fatalf("host %q with byte %q allowed", host, c)
			}
		}
		n := strings.ToLower(strings.TrimSuffix(host, "."))
		if n == "" || strings.HasPrefix(n, ".") || strings.Contains(n, "..") {
			t.Fatalf("malformed host %q allowed", host)
		}
		sub := func(parent string) bool { return strings.HasSuffix(n, "."+parent) }
		inner, innerOK := strings.CutPrefix(n, "api-")
		inner, innerOK2 := strings.CutSuffix(inner, ".inner.io")
		ok := n == "example.com" ||
			(n == "allowed.org" || sub("allowed.org")) && n != "blocked.allowed.org" ||
			sub("wild.net") ||
			innerOK && innerOK2 && !strings.Contains(inner, ".") ||
			wildRe.MatchString(n)
		if !ok {
			t.Fatalf("host %q allowed by rule %q but not by the reference", host, d.Rule)
		}
	})
}

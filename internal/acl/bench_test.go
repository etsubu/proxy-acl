package acl

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
)

type staticResolver []netip.Addr

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}

func BenchmarkCheck(b *testing.B) {
	res := staticResolver{publicAddr}
	homelab := mustPolicy(b,
		SubnetSpec{Name: "proxmox", CIDRs: []string{"10.0.10.0/24"}, Allow: []string{".debian.org", "download.proxmox.com", "enterprise.proxmox.com"}},
		SubnetSpec{Name: "iot", CIDRs: []string{"10.0.20.0/24"}, Allow: []string{".netflix.com", ".netflix.net", ".nflxvideo.net", ".nflximg.net", ".nflxext.com", ".nflxso.net"}},
		SubnetSpec{Name: "lan", CIDRs: []string{"10.0.1.0/24", "fd00:1::/64"}, Allow: []string{"*", "10.0.1.5"},
			Deny: []string{".doubleclick.net", `~(.+\.)?telemetry\..+`, "203.0.113.0/24"}},
	)
	big := func(n int) *Policy {
		var deny []string
		for i := range n {
			deny = append(deny, fmt.Sprintf(".blocked-%d.example", i))
		}
		return mustPolicy(b, SubnetSpec{CIDRs: []string{"10.0.1.0/24"}, Allow: []string{"*"}, Deny: deny})
	}

	for _, bc := range []struct {
		name   string
		p      *Policy
		client string
		host   string
	}{
		{"iot/allowed-suffix", homelab, "10.0.20.5", "ipv4-c001-hel001-ix.1.oca.nflxvideo.net"},
		{"iot/denied", homelab, "10.0.20.5", "telemetry.vendor.example"},
		{"proxmox/allowed", homelab, "10.0.10.5", "deb.debian.org"},
		{"lan/star-with-regex-deny", homelab, "10.0.1.7", "github.com"},
		{"unknown-client", homelab, "192.168.99.1", "github.com"},
		{"invalid-host", homelab, "10.0.1.7", "exa mple.com"},
		{"denylist-1k/miss", big(1000), "10.0.1.7", "github.com"},
		{"denylist-10k/miss", big(10000), "10.0.1.7", "github.com"},
	} {
		client := netip.MustParseAddr(bc.client)
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				bc.p.Check(context.Background(), res, client, bc.host, "443")
			}
		})
	}
}

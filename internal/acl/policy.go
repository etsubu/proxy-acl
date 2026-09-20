// Package acl implements the per-subnet destination policy. Anything not
// explicitly allowed is denied.
package acl

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Ports allowed when a subnet doesn't list any.
var defaultPorts = []portRange{{80, 80}, {443, 443}}

const resolveTimeout = 5 * time.Second

// SubnetSpec is the uncompiled rule set of one client subnet.
type SubnetSpec struct {
	Name  string
	CIDRs []string
	Ports []string
	Allow []string
	Deny  []string
}

// Resolver looks up the addresses of a hostname. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Policy is a compiled, immutable ACL. It is safe for concurrent use.
type Policy struct {
	subnets []*Subnet
}

// Subnet is one client subnet's compiled rules, and the handle SubnetOf
// returns. Callers that need more than the decision itself (per-subnet
// limits, log fields) look the subnet up once and pass it on, so a request
// costs a single scan over the configured prefixes.
type Subnet struct {
	name     string
	prefixes []netip.Prefix
	ports    []portRange
	allow    ruleSet
	deny     ruleSet
}

// Name returns the subnet's name from the config.
func (s *Subnet) Name() string { return s.name }

// Decision is the outcome of a policy check.
type Decision struct {
	Allow  bool
	Subnet string // the client's subnet, empty if it matched none
	Rule   string // the rule that decided, if any
	Reason string
	// When allowed: the only addresses and port the proxy may connect to.
	Addrs []netip.Addr
	Port  uint16
}

// New compiles and validates subnet specs into a Policy.
func New(specs []SubnetSpec) (*Policy, error) {
	if len(specs) == 0 {
		return nil, errors.New("no subnets defined")
	}
	p := &Policy{}
	names := map[string]bool{}
	owner := map[netip.Prefix]string{}
	for i, spec := range specs {
		if spec.Name == "" {
			spec.Name = fmt.Sprintf("subnet[%d]", i)
		}
		if names[spec.Name] {
			return nil, fmt.Errorf("duplicate subnet name %q", spec.Name)
		}
		names[spec.Name] = true

		s, err := compileSubnet(spec)
		if err != nil {
			return nil, fmt.Errorf("subnet %q: %w", spec.Name, err)
		}
		for _, pfx := range s.prefixes {
			if other, dup := owner[pfx]; dup {
				return nil, fmt.Errorf("subnet %q: cidr %s already used by subnet %q", s.name, pfx, other)
			}
			owner[pfx] = s.name
		}
		p.subnets = append(p.subnets, s)
	}
	return p, nil
}

func compileSubnet(spec SubnetSpec) (*Subnet, error) {
	s := &Subnet{name: spec.Name, ports: defaultPorts}
	if len(spec.CIDRs) == 0 {
		return nil, errors.New("no cidrs defined")
	}
	for _, c := range spec.CIDRs {
		pfx, err := parsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("cidr %q: %w", c, err)
		}
		s.prefixes = append(s.prefixes, pfx)
	}
	if len(spec.Ports) > 0 {
		s.ports = nil
		for _, p := range spec.Ports {
			r, err := parsePortRange(p)
			if err != nil {
				return nil, fmt.Errorf("port %q: %w", p, err)
			}
			s.ports = append(s.ports, r)
		}
	}
	var err error
	if s.allow, err = compileRules(spec.Allow); err != nil {
		return nil, fmt.Errorf("allow: %w", err)
	}
	if s.deny, err = compileRules(spec.Deny); err != nil {
		return nil, fmt.Errorf("deny: %w", err)
	}
	// In a deny list "*" means everything, IP addresses included. (In an
	// allow list it only means any hostname; IPs need their own rules.)
	if s.deny.any != "" {
		s.deny.addrs = append(s.deny.addrs,
			addrRule{s.deny.any, netip.MustParsePrefix("0.0.0.0/0")},
			addrRule{s.deny.any, netip.MustParsePrefix("::/0")})
	}
	return s, nil
}

// Subnets returns the compiled subnets in config order.
func (p *Policy) Subnets() []*Subnet { return p.subnets }

// SubnetOf returns the subnet client belongs to, or nil. The longest
// matching prefix wins, so a /32 entry can override the /24 it belongs to.
func (p *Policy) SubnetOf(client netip.Addr) *Subnet {
	client = client.Unmap()
	var best *Subnet
	bestBits := -1
	for _, s := range p.subnets {
		for _, pfx := range s.prefixes {
			if pfx.Bits() > bestBits && pfx.Contains(client) {
				best, bestBits = s, pfx.Bits()
			}
		}
	}
	return best
}

// Check looks up the client's subnet and checks the request against it.
// Callers that already hold the subnet should use Subnet.Check instead.
func (p *Policy) Check(ctx context.Context, res Resolver, client netip.Addr, host, port string) Decision {
	s := p.SubnetOf(client)
	if s == nil {
		return Decision{Reason: "client not in any subnet"}
	}
	return s.Check(ctx, res, host, port)
}

// Check decides whether a client of this subnet may connect to host:port.
// In order:
//
//   - the host must be a valid hostname or IP literal, and the port a valid
//     number;
//   - deny rules win over allow rules; an allow rule must match; the port
//     must be in the subnet's port list;
//   - an allowed hostname is resolved (only then, so denied names never
//     cause DNS lookups). Every resolved address is checked again: one
//     matching an IP/CIDR deny rule denies the request, and a non-public
//     one (loopback, private, link-local, ...) needs an IP/CIDR allow rule.
//
// The caller must connect only to Decision.Addrs, never re-resolve the
// name, or DNS rebinding could swap in an address that was never checked.
func (s *Subnet) Check(ctx context.Context, res Resolver, host, port string) Decision {
	d := Decision{Subnet: s.name}
	deny := func(reason, rule string) Decision {
		d.Reason, d.Rule = reason, rule
		return d
	}

	dst, err := parseHost(host)
	if err != nil {
		return deny("invalid host: "+err.Error(), "")
	}
	portNum, err := parsePort(port)
	if err != nil {
		return deny("invalid port", "")
	}
	if r, ok := s.deny.match(dst); ok {
		return deny("deny rule matched", r)
	}
	allowRule, ok := s.allow.match(dst)
	if !ok {
		return deny("no allow rule matched", "")
	}
	if !s.allowsPort(portNum) {
		return deny("port not allowed", "")
	}

	addrs := []netip.Addr{dst.addr}
	if dst.name != "" {
		if addrs, err = resolve(ctx, res, dst.name); err != nil {
			return deny("dns lookup failed: "+err.Error(), "")
		}
	}
	for _, a := range addrs {
		if r, ok := s.deny.matchAddr(a); ok {
			return deny(fmt.Sprintf("address %s matched deny rule", a), r)
		}
		if !isPublic(a) {
			if _, ok := s.allow.matchAddr(a); !ok {
				return deny(fmt.Sprintf("non-public address %s not explicitly allowed", a), "")
			}
		}
	}

	d.Allow, d.Rule, d.Reason = true, allowRule, "allow rule matched"
	d.Addrs, d.Port = addrs, portNum
	return d
}

func (s *Subnet) allowsPort(port uint16) bool {
	for _, r := range s.ports {
		if r.contains(port) {
			return true
		}
	}
	return false
}

func resolve(ctx context.Context, res Resolver, name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	found, err := res.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, errors.New("no addresses")
	}
	addrs := make([]netip.Addr, 0, len(found))
	for _, a := range found {
		a = a.Unmap()
		if !a.IsValid() || a.Zone() != "" {
			return nil, fmt.Errorf("unusable address %q", a)
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}

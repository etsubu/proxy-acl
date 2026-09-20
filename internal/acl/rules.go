package acl

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// destination is a validated, normalized request target: either a hostname
// or an IP literal, never both.
type destination struct {
	name string     // lowercase hostname without trailing dot
	addr netip.Addr // unmapped IP literal
}

type nameRule struct {
	pattern string
	match   func(name string) bool
}

type addrRule struct {
	pattern string
	prefix  netip.Prefix
}

// ruleSet keeps hostname and address rules apart: hostname patterns
// (including "*") never match IP literals, and address rules never match
// hostnames directly, only the addresses they resolve to.
//
// Exact and domain-suffix rules, the kind long blocklists are made of, are
// looked up in maps, so their number doesn't slow down matching.
type ruleSet struct {
	exact  map[string]string // hostname -> pattern
	suffix map[string]string // domain -> pattern, for ".example.com" rules
	names  []nameRule        // wildcards and regexes, in config order
	any    string            // the "*" pattern, if present
	addrs  []addrRule
}

func (rs *ruleSet) match(d destination) (string, bool) {
	if d.addr.IsValid() {
		return rs.matchAddr(d.addr)
	}
	return rs.matchName(d.name)
}

// matchName reports the most specific matching rule: an exact name, then
// the longest matching domain suffix, then wildcards and regexes in order,
// then "*".
func (rs *ruleSet) matchName(n string) (string, bool) {
	if p, ok := rs.exact[n]; ok {
		return p, true
	}
	if len(rs.suffix) > 0 {
		for d := n; ; {
			if p, ok := rs.suffix[d]; ok {
				return p, true
			}
			i := strings.IndexByte(d, '.')
			if i < 0 {
				break
			}
			d = d[i+1:]
		}
	}
	for _, r := range rs.names {
		if r.match(n) {
			return r.pattern, true
		}
	}
	return rs.any, rs.any != ""
}

func (rs *ruleSet) matchAddr(a netip.Addr) (string, bool) {
	for _, r := range rs.addrs {
		if r.prefix.Contains(a) {
			return r.pattern, true
		}
	}
	return "", false
}

func compileRules(patterns []string) (ruleSet, error) {
	var rs ruleSet
	for _, p := range patterns {
		if err := rs.add(p); err != nil {
			return ruleSet{}, fmt.Errorf("%q: %w", p, err)
		}
	}
	return rs, nil
}

// add compiles one pattern. Supported forms:
//
//	example.com     exact hostname
//	.example.com    example.com and any subdomain
//	*.example.com   any subdomain at any depth, not example.com itself
//	api-*.example.com  "*" inside a label matches within that label only
//	*               any hostname (not IP literals)
//	~regex          regular expression over the whole hostname
//	10.0.0.0/8      IP range
//	10.0.0.1        single IP
func (rs *ruleSet) add(pattern string) error {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return errors.New("empty pattern")
	}

	if expr, ok := strings.CutPrefix(p, "~"); ok {
		if expr == "" {
			return errors.New("empty regex")
		}
		// Anchored as a whole so neither "~a\.com" nor "~a\.com|b\.com"
		// can match "a.com.evil.net".
		re, err := regexp.Compile(`(?i)^(?:` + expr + `)$`)
		if err != nil {
			return err
		}
		rs.names = append(rs.names, nameRule{p, re.MatchString})
		return nil
	}

	if strings.ContainsAny(p, ":/") || isIPLike(p) {
		pfx, err := parsePrefix(p)
		if err != nil {
			return fmt.Errorf("not a valid IP or CIDR (hostname patterns can't include a scheme, port or path): %w", err)
		}
		rs.addrs = append(rs.addrs, addrRule{p, pfx})
		return nil
	}

	kind, name, match, err := compileNamePattern(p)
	if err != nil {
		return err
	}
	switch kind {
	case exactName:
		if rs.exact == nil {
			rs.exact = map[string]string{}
		}
		if _, dup := rs.exact[name]; !dup {
			rs.exact[name] = p
		}
	case domainSuffix:
		if rs.suffix == nil {
			rs.suffix = map[string]string{}
		}
		if _, dup := rs.suffix[name]; !dup {
			rs.suffix[name] = p
		}
	case anyName:
		if rs.any == "" {
			rs.any = p
		}
	default:
		rs.names = append(rs.names, nameRule{p, match})
	}
	return nil
}

type patternKind int

const (
	exactName    patternKind = iota // example.com
	domainSuffix                    // .example.com
	anyName                         // *
	wildcard                        // *.example.com, api-*.example.com
)

// compileNamePattern validates a hostname pattern and returns its kind and
// normalized name (the domain for suffix rules), or a matcher for wildcards.
func compileNamePattern(p string) (patternKind, string, func(string) bool, error) {
	if err := checkHostChars(p, true); err != nil {
		return 0, "", nil, err
	}
	p = strings.ToLower(strings.TrimSuffix(p, "."))

	if p == "*" {
		return anyName, "", nil, nil
	}

	if base, ok := strings.CutPrefix(p, "."); ok {
		if err := validateHostname(base, false); err != nil {
			return 0, "", nil, err
		}
		return domainSuffix, base, nil, nil
	}

	if !strings.Contains(p, "*") {
		if err := validateHostname(p, false); err != nil {
			return 0, "", nil, err
		}
		return exactName, p, nil, nil
	}

	// A leading "*" must be its own label; "*example.com" is almost
	// certainly a typo and would also match "evilexample.com".
	if p[0] == '*' && !strings.HasPrefix(p, "*.") {
		return 0, "", nil, errors.New(`a leading "*" must be followed by "." (did you mean "*.` + strings.TrimLeft(p, "*") + `"?)`)
	}
	if err := validateHostname(p, true); err != nil {
		return 0, "", nil, err
	}
	expr := "^"
	rest := p
	if r, ok := strings.CutPrefix(p, "*."); ok {
		expr, rest = `^(?:[^.]+\.)+`, r
	}
	expr += strings.ReplaceAll(regexp.QuoteMeta(rest), `\*`, `[^.]*`) + "$"
	return wildcard, "", regexp.MustCompile(expr).MatchString, nil
}

// parseHost validates and normalizes a requested host.
func parseHost(h string) (destination, error) {
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return destination{}, errors.New("zoned address")
		}
		return destination{addr: a.Unmap()}, nil
	}
	// Validate before lowercasing: strings.ToLower maps some non-ASCII
	// runes (e.g. the Kelvin sign) onto ASCII letters.
	if err := checkHostChars(h, false); err != nil {
		return destination{}, err
	}
	name := strings.ToLower(strings.TrimSuffix(h, "."))
	if err := validateHostname(name, false); err != nil {
		return destination{}, err
	}
	return destination{name: name}, nil
}

func checkHostChars(s string, wildcard bool) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_', c == '.':
		case c == '*' && wildcard:
		default:
			return fmt.Errorf("invalid character %q", c)
		}
	}
	return nil
}

// validateHostname checks the structure of a lowercase hostname (or
// hostname pattern when wildcard is set).
func validateHostname(name string, wildcard bool) error {
	if name == "" {
		return errors.New("empty hostname")
	}
	if len(name) > 253 {
		return errors.New("hostname too long")
	}
	labels := strings.Split(name, ".")
	allNumeric := true
	for _, l := range labels {
		if l == "" {
			return errors.New("empty label")
		}
		if len(l) > 63 {
			return errors.New("label too long")
		}
		if strings.Contains(l, "*") && !wildcard {
			return errors.New(`"*" not allowed here`)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("label starts or ends with a hyphen")
		}
		if !isNumeric(l) && l != "*" {
			allNumeric = false
		}
	}
	// No real TLD is numeric. Names like "127.1", "2130706433" or
	// "0x7f000001" are alternative IP notations some resolvers accept.
	if isNumeric(labels[len(labels)-1]) {
		return errors.New("numeric top-level label (IP addresses must be in standard notation)")
	}
	if wildcard && allNumeric {
		return errors.New("looks like an IP wildcard; use CIDR notation such as 192.168.1.0/24")
	}
	return nil
}

// isNumeric reports whether a label is a decimal, octal or hex number.
func isNumeric(l string) bool {
	if h, ok := strings.CutPrefix(l, "0x"); ok {
		l = h
		if l == "" {
			return true
		}
		for i := 0; i < len(l); i++ {
			switch c := l[i]; {
			case '0' <= c && c <= '9', 'a' <= c && c <= 'f':
			default:
				return false
			}
		}
		return true
	}
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return l != ""
}

func isIPLike(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// parsePrefix parses a CIDR or a bare address (as a single-host prefix).
// Host bits must be zero so a typo like 10.0.1.50/24 can't silently open
// up a whole /24.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var pfx netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if pfx, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, err
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if a.Zone() != "" {
			return netip.Prefix{}, errors.New("zoned addresses are not supported")
		}
		pfx = netip.PrefixFrom(a, a.BitLen())
	}
	if pfx.Addr().Is4In6() {
		return netip.Prefix{}, errors.New("use plain IPv4 notation instead of IPv4-mapped IPv6")
	}
	if pfx != pfx.Masked() {
		return netip.Prefix{}, fmt.Errorf("host bits set (did you mean %s or %s/%d?)", pfx.Masked(), pfx.Addr(), pfx.Addr().BitLen())
	}
	return pfx, nil
}

type portRange struct{ lo, hi uint16 }

func (r portRange) contains(p uint16) bool { return r.lo <= p && p <= r.hi }

// parsePort accepts canonical decimal ports only ("443", not "0443"), so the
// port that was checked is exactly the one that gets dialed.
func parsePort(s string) (uint16, error) {
	if s == "" || len(s) > 5 || s[0] == '0' {
		return 0, errors.New("invalid port")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("invalid port")
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("port out of range")
	}
	return uint16(n), nil
}

// parsePortRange parses "443" or "8000-8100".
func parsePortRange(s string) (portRange, error) {
	s = strings.TrimSpace(s)
	loS, hiS, isRange := strings.Cut(s, "-")
	lo, err := parsePort(loS)
	if err != nil {
		return portRange{}, err
	}
	hi := lo
	if isRange {
		if hi, err = parsePort(hiS); err != nil {
			return portRange{}, err
		}
		if hi < lo {
			return portRange{}, errors.New("range end before start")
		}
	}
	return portRange{lo, hi}, nil
}

// nonPublic lists address ranges that must never be reached through a
// hostname unless an IP/CIDR allow rule covers them. This keeps the proxy
// from bridging clients into the LAN, other VLANs or the proxy host itself.
var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",      // "this network"; 0.0.0.0 reaches the local host
		"10.0.0.0/8",     // private
		"100.64.0.0/10",  // carrier-grade NAT (also Tailscale)
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local, cloud metadata
		"172.16.0.0/12",  // private
		"192.0.0.0/24",   // IETF protocol assignments
		"192.88.99.0/24", // 6to4 relay anycast (deprecated)
		"192.168.0.0/16", // private
		"198.18.0.0/15",  // benchmarking
		"224.0.0.0/4",    // multicast
		"240.0.0.0/4",    // reserved, broadcast
		"::/96",          // unspecified, loopback, IPv4-compatible
		"::ffff:0:0/96",  // IPv4-mapped (addresses are unmapped first; kept as a backstop)
		"64:ff9b::/96",   // NAT64, embeds an IPv4 address
		"64:ff9b:1::/48", // local-use NAT64
		"2001::/32",      // Teredo, embeds IPv4 addresses
		"2002::/16",      // 6to4, embeds an IPv4 address
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"fec0::/10",      // deprecated site-local
		"ff00::/8",       // multicast
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func isPublic(a netip.Addr) bool {
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

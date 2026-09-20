// Package config loads the YAML config file and keeps it hot-reloaded.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/rs/zerolog"
	"go.yaml.in/yaml/v3"

	"proxy-acl/internal/acl"
	"proxy-acl/internal/limits"
)

// DefaultTotalConnections and DefaultClientLimits are deliberately
// generous: they are meant to contain a misbehaving device, not to throttle
// normal use.
const DefaultTotalConnections = 20_000

// DefaultClientLimits is the per-client limit set a config starts from.
var DefaultClientLimits = limits.Client{
	MaxConnections:    512,
	RequestsPerSecond: 200,
	RequestBurst:      1000,
	TunnelIdleTimeout: time.Hour,
}

// Config is a parsed and validated config file.
type Config struct {
	LogLevel         zerolog.Level
	Policy           *acl.Policy
	TotalConnections int // 0: unlimited

	clientLimits limits.Client
	subnetLimits map[*acl.Subnet]limits.Client
}

// ClientLimits returns the per-client limits for a subnet, or the top-level
// limits for a nil subnet (a client outside every subnet).
func (c *Config) ClientLimits(subnet *acl.Subnet) limits.Client {
	if l, ok := c.subnetLimits[subnet]; ok {
		return l
	}
	return c.clientLimits
}

type file struct {
	LogLevel string       `yaml:"log_level"`
	Limits   fileLimits   `yaml:"limits"`
	Subnets  []fileSubnet `yaml:"subnets"`
}

type fileClientLimits struct {
	ClientConnections *int      `yaml:"client_connections"`
	RequestsPerSecond *float64  `yaml:"client_requests_per_second"`
	RequestBurst      *int      `yaml:"client_request_burst"`
	TunnelIdleTimeout *duration `yaml:"tunnel_idle_timeout"`
}

type fileLimits struct {
	TotalConnections *int `yaml:"total_connections"`
	fileClientLimits `yaml:",inline"`
}

type fileSubnet struct {
	Name   string           `yaml:"name"`
	CIDRs  list             `yaml:"cidrs"`
	Ports  list             `yaml:"ports"`
	Allow  list             `yaml:"allow"`
	Deny   list             `yaml:"deny"`
	Limits fileClientLimits `yaml:"limits"`
}

// list is a YAML list of scalars that rejects empty entries such as a bare
// "-", which yaml.v3 would otherwise drop silently.
type list []string

func (l *list) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: expected a list", n.Line)
	}
	for _, c := range n.Content {
		if c.Kind == yaml.AliasNode {
			c = c.Alias
		}
		if c.Kind != yaml.ScalarNode || c.ShortTag() == "!!null" {
			return fmt.Errorf("line %d: list entries must be plain non-empty values", c.Line)
		}
		*l = append(*l, c.Value)
	}
	return nil
}

// duration requires a unit ("90s", "10m", "1h"), so a bare number can't be
// silently read as nanoseconds. "0" is accepted and disables the timeout.
type duration time.Duration

func (d *duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if n.Kind != yaml.ScalarNode || err != nil {
		return fmt.Errorf("line %d: expected a duration such as 30s, 10m or 1h", n.Line)
	}
	*d = duration(v)
	return nil
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	// G304: reading the file the operator names is what this program is
	// for; the path comes from a flag, never from a proxied request.
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse validates a config file's contents. It is strict: unknown keys,
// duplicate keys and extra YAML documents are errors, so a typo can't
// silently drop rules.
func Parse(data []byte) (*Config, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config must be a single YAML document")
	}

	cfg := &Config{LogLevel: zerolog.InfoLevel, TotalConnections: DefaultTotalConnections, subnetLimits: map[*acl.Subnet]limits.Client{}}
	if f.LogLevel != "" {
		lvl, err := zerolog.ParseLevel(f.LogLevel)
		if err != nil {
			return nil, fmt.Errorf("log_level: %w", err)
		}
		cfg.LogLevel = lvl
	}
	if f.Limits.TotalConnections != nil {
		if *f.Limits.TotalConnections < 0 {
			return nil, errors.New("limits: total_connections must not be negative")
		}
		cfg.TotalConnections = *f.Limits.TotalConnections
	}
	var err error
	if cfg.clientLimits, err = f.Limits.apply(DefaultClientLimits); err != nil {
		return nil, fmt.Errorf("limits: %w", err)
	}

	specs := make([]acl.SubnetSpec, len(f.Subnets))
	for i, s := range f.Subnets {
		specs[i] = acl.SubnetSpec{Name: s.Name, CIDRs: s.CIDRs, Ports: s.Ports, Allow: s.Allow, Deny: s.Deny}
	}
	if cfg.Policy, err = acl.New(specs); err != nil {
		return nil, err
	}
	// acl.New names unnamed subnets and keeps them in config order, so the
	// limits are attached to the compiled subnets rather than to a name.
	for i, s := range cfg.Policy.Subnets() {
		l, err := f.Subnets[i].Limits.apply(cfg.clientLimits)
		if err != nil {
			return nil, fmt.Errorf("subnet %q: limits: %w", s.Name(), err)
		}
		cfg.subnetLimits[s] = l
	}
	return cfg, nil
}

// apply overrides the fields of base that are set in f.
func (f fileClientLimits) apply(base limits.Client) (limits.Client, error) {
	l := base
	if f.ClientConnections != nil {
		l.MaxConnections = *f.ClientConnections
	}
	if f.RequestsPerSecond != nil {
		l.RequestsPerSecond = *f.RequestsPerSecond
	}
	if f.RequestBurst != nil {
		l.RequestBurst = *f.RequestBurst
	}
	if f.TunnelIdleTimeout != nil {
		l.TunnelIdleTimeout = time.Duration(*f.TunnelIdleTimeout)
	}
	switch {
	case math.IsNaN(l.RequestsPerSecond) || math.IsInf(l.RequestsPerSecond, 0):
		return l, errors.New("client_requests_per_second must be a finite number")
	case l.MaxConnections < 0, l.RequestsPerSecond < 0, l.RequestBurst < 0, l.TunnelIdleTimeout < 0:
		return l, errors.New("values must not be negative")
	case l.RequestsPerSecond > 0 && l.RequestBurst < 1:
		return l, errors.New("client_request_burst must be at least 1 when client_requests_per_second is set")
	}
	return l, nil
}

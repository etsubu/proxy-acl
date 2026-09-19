package config

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"proxy-acl/internal/limits"
)

func TestMain(m *testing.M) {
	log.Logger = zerolog.Nop() // reloads reset the global level, so silence the logger itself
	os.Exit(m.Run())
}

type publicResolver struct{ records map[string]string }

func (r publicResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r.records[host]; ok {
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	return []netip.Addr{netip.MustParseAddr("198.51.100.10")}, nil
}

func TestParseRejects(t *testing.T) {
	const sub = "subnets:\n  - cidrs: [10.0.0.0/24]\n"
	tests := map[string]string{
		"empty":            "",
		"only comments":    "# nothing\n",
		"no subnets":       "log_level: info\n",
		"null subnets":     "subnets:\n",
		"unknown top key":  sub + "defaults: {}\n",
		"typo in subnet":   sub + "    alow: [x.com]\n",
		"typo deny":        sub + "    deny_: [x.com]\n",
		"duplicate key":    sub + "    deny: [a.com]\n    deny: [b.com]\n",
		"scalar allow":     sub + "    allow: x.com\n",
		"null rule":        sub + "    allow: [~]\n",
		"null among rules": sub + "    deny: [a.com, null, b.com]\n",
		"bare dash":        sub + "    deny:\n      -\n      - b.com\n",
		"null cidr":        "subnets:\n  - cidrs: [~, 10.0.0.0/24]\n",
		"empty rule":       sub + "    allow: ['']\n",
		"nested list":      sub + "    allow: [[x.com]]\n",
		"map rule":         sub + "    allow: [{x: y}]\n",
		"bad level":        "log_level: loud\n" + sub,
		"two documents":    sub + "---\n" + sub,
		"not a mapping":    "- a\n- b\n",
		"invalid yaml":     "subnets: [",
		"bad pattern":      sub + "    allow: ['*example.com']\n",
		"bad port":         sub + "    ports: [0]\n",
		"bad cidr":         "subnets:\n  - cidrs: [10.0.0.5/24]\n",
		"tab indentation":  "subnets:\n\t- cidrs: [10.0.0.0/24]\n",
		"alias to nothing": sub + "    allow: *missing\n",
	}
	for name, content := range tests {
		if _, err := Parse([]byte(content)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParse(t *testing.T) {
	cfg, err := Parse([]byte(`
log_level: warn
subnets:
  - name: a
    cidrs: [10.0.0.0/24]
    ports: [443, "8000-8100"]
    allow: &common [.example.com]
  - name: b
    cidrs: [10.0.1.0/24]
    allow: *common
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != zerolog.WarnLevel {
		t.Errorf("LogLevel = %v", cfg.LogLevel)
	}
	res := publicResolver{}
	for _, tt := range []struct {
		client, host, port string
		want               bool
	}{
		{"10.0.0.1", "www.example.com", "443", true},
		{"10.0.0.1", "www.example.com", "8050", true},
		{"10.0.0.1", "www.example.com", "80", false}, // explicit ports replace the default
		{"10.0.1.1", "www.example.com", "443", true}, // YAML anchors work
		{"10.0.1.1", "www.example.com", "8050", false},
	} {
		d := cfg.Policy.Check(context.Background(), res, netip.MustParseAddr(tt.client), tt.host, tt.port)
		if d.Allow != tt.want {
			t.Errorf("%+v: allowed=%v (%s)", tt, d.Allow, d.Reason)
		}
	}
}

func TestExampleConfig(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	res := publicResolver{records: map[string]string{
		"nas.home.arpa":      "10.0.1.5",
		"router.home.arpa":   "10.0.1.1",
		"sneaky.example":     "127.0.0.1",
		"blocked-ip.example": "203.0.113.20",
	}}
	for _, tt := range []struct {
		client, host, port string
		want               bool
	}{
		{"10.0.10.2", "deb.debian.org", "80", true},
		{"10.0.10.2", "security.debian.org", "443", true},
		{"10.0.10.2", "download.proxmox.com", "443", true},
		{"10.0.10.2", "github.com", "443", false},
		{"10.0.10.2", "deb.debian.org", "22", false},
		{"10.0.10.2", "debian.org.evil.net", "443", false},

		{"10.0.20.2", "www.netflix.com", "443", true},
		{"10.0.20.2", "ipv4-c001-hel001-ix.1.oca.nflxvideo.net", "443", true},
		{"10.0.20.2", "deb.debian.org", "443", false},
		{"10.0.20.2", "netflix.com.evil.net", "443", false},
		{"10.0.20.2", "nas.home.arpa", "443", false},

		{"10.0.1.2", "github.com", "443", true},
		{"10.0.1.2", "github.com", "22", true},
		{"10.0.1.2", "github.com", "8080", true},
		{"10.0.1.2", "github.com", "25", false},
		{"10.0.1.2", "nas.home.arpa", "443", true},
		{"10.0.1.2", "10.0.1.5", "443", true},
		{"10.0.1.2", "router.home.arpa", "443", false}, // private and not allowed by IP
		{"10.0.1.2", "10.0.1.1", "443", false},
		{"10.0.1.2", "sneaky.example", "443", false},
		{"10.0.1.2", "198.51.100.10", "443", false}, // "*" doesn't cover IP literals
		{"10.0.1.2", "ad.doubleclick.net", "443", false},
		{"10.0.1.2", "eu.telemetry.example.com", "443", false},
		{"10.0.1.2", "blocked-ip.example", "443", false},
		{"10.0.1.2", "203.0.113.20", "443", false},
		{"fd00:1::2", "github.com", "443", true},

		{"10.0.1.50", "github.com", "443", false},
		{"10.0.30.2", "github.com", "443", false},
	} {
		d := cfg.Policy.Check(context.Background(), res, netip.MustParseAddr(tt.client), tt.host, tt.port)
		if d.Allow != tt.want {
			t.Errorf("%s -> %s:%s allowed=%v, want %v (subnet %q, %s)", tt.client, tt.host, tt.port, d.Allow, tt.want, d.Subnet, d.Reason)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	// Write-then-rename, like most editors and config management tools.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

const reloadConfig = `
subnets:
  - cidrs: [10.0.0.0/24]
    allow: [a.example]
`

func TestStoreHotReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, reloadConfig)
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := store.Watch(ctx); err != nil {
		t.Fatal(err)
	}

	client := netip.MustParseAddr("10.0.0.1")
	allowed := func(host string) bool {
		return store.Current().Policy.Check(context.Background(), publicResolver{}, client, host, "443").Allow
	}
	waitFor := func(host string, want bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for allowed(host) != want {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s allowed=%v", host, want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	waitFor("b.example", false)
	writeFile(t, path, strings.Replace(reloadConfig, "[a.example]", "[a.example, b.example]", 1))
	waitFor("b.example", true)

	// Broken, empty or truncated files leave the last good config in place.
	for _, bad := range []string{"subnets: [", "", "subnets:\n  - cidrs: [10.0.0.0/24]\n    alow: [x]\n"} {
		writeFile(t, path, bad)
		time.Sleep(3 * reloadDebounce)
		if !allowed("b.example") || !allowed("a.example") {
			t.Fatalf("invalid config %q replaced the active one", bad)
		}
	}

	// In-place writes (no rename) are picked up too.
	if err := os.WriteFile(path, []byte(reloadConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	waitFor("b.example", false)

	// A deleted file keeps the last config; recreating it reloads.
	os.Remove(path)
	time.Sleep(3 * reloadDebounce)
	if !allowed("a.example") {
		t.Fatal("deleting the config file changed the active policy")
	}
	writeFile(t, path, strings.Replace(reloadConfig, "[a.example]", "[c.example]", 1))
	waitFor("c.example", true)
	waitFor("a.example", false)
}

func TestNewStoreFailsOnInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, "subnets: [")
	if _, err := NewStore(path); err == nil {
		t.Error("expected an error")
	}
	if _, err := NewStore(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestLimits(t *testing.T) {
	cfg, err := Parse([]byte(`
limits:
  total_connections: 5000
  client_requests_per_second: 50
  tunnel_idle_timeout: 90s
subnets:
  - name: lan
    cidrs: [10.0.1.0/24]
  - name: iot
    cidrs: [10.0.20.0/24]
    limits:
      client_connections: 64
      tunnel_idle_timeout: 0
  - cidrs: [10.0.30.0/24]
    limits:
      client_request_burst: 20
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TotalConnections != 5000 {
		t.Errorf("TotalConnections = %d", cfg.TotalConnections)
	}
	lan := limits.Client{MaxConnections: 512, RequestsPerSecond: 50, RequestBurst: 1000, TunnelIdleTimeout: 90 * time.Second}
	for subnet, want := range map[string]limits.Client{
		"lan":        lan,
		"iot":        {MaxConnections: 64, RequestsPerSecond: 50, RequestBurst: 1000, TunnelIdleTimeout: 0},
		"subnet[2]":  {MaxConnections: 512, RequestsPerSecond: 50, RequestBurst: 20, TunnelIdleTimeout: 90 * time.Second},
		"":           lan, // clients outside every subnet
		"not-listed": lan,
	} {
		if got := cfg.ClientLimits(subnet); got != want {
			t.Errorf("%q: %+v, want %+v", subnet, got, want)
		}
	}

	def, err := Parse([]byte("subnets:\n  - cidrs: [10.0.0.0/24]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if def.TotalConnections != DefaultTotalConnections || def.ClientLimits("subnet[0]") != DefaultClientLimits {
		t.Errorf("defaults: %d %+v", def.TotalConnections, def.ClientLimits("subnet[0]"))
	}
}

func TestLimitsRejects(t *testing.T) {
	const sub = "subnets:\n  - cidrs: [10.0.0.0/24]\n"
	for name, content := range map[string]string{
		"unit-less duration":      "limits:\n  tunnel_idle_timeout: 3600\n" + sub,
		"bad duration":            "limits:\n  tunnel_idle_timeout: soon\n" + sub,
		"negative connections":    "limits:\n  client_connections: -1\n" + sub,
		"negative total":          "limits:\n  total_connections: -1\n" + sub,
		"negative duration":       "limits:\n  tunnel_idle_timeout: -1s\n" + sub,
		"rate without burst":      "limits:\n  client_requests_per_second: 10\n  client_request_burst: 0\n" + sub,
		"unknown limit":           "limits:\n  client_conections: 10\n" + sub,
		"total in subnet":         sub + "    limits:\n      total_connections: 10\n",
		"text for number":         "limits:\n  client_connections: many\n" + sub,
		"negative rate in subnet": sub + "    limits:\n      client_requests_per_second: -5\n",
		"subnet limits not a map": sub + "    limits: 5\n",
		"NaN rate":                "limits:\n  client_requests_per_second: .nan\n" + sub,
		"infinite rate":           "limits:\n  client_requests_per_second: .inf\n" + sub,
	} {
		if _, err := Parse([]byte(content)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

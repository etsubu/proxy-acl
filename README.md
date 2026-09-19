# proxy-acl

A forward HTTP/HTTPS proxy built on [goproxy](https://github.com/elazarl/goproxy)
that enforces per-subnet destination rules. The YAML config reloads live when
you edit it. **Everything is denied unless a rule explicitly allows it.**

- **HTTP**: every plain proxy request (`GET http://…`) is checked separately,
  including each request on a keep-alive connection.
- **HTTPS**: `CONNECT host:port` tunnels are checked by hostname and port. TLS
  stays end to end (no MITM), so rules work per host, not per URL path.

## How a request is decided

1. The client IP must fall in a configured subnet. The most specific CIDR
   wins, so a `/32` can override its `/24`.
2. The host must be a valid hostname or standard-notation IP, and the port a
   valid number. Anything else (`127.1`, `2130706433`, Unicode lookalikes,
   zone IDs, …) is rejected.
3. Deny rules are checked first and always win.
4. An allow rule must match. Hostname rules (including `*`) match hostnames
   only; IP/CIDR rules match IP addresses. The exception is `deny: ["*"]`,
   which denies everything, IP addresses included.
5. The port must be in the subnet's `ports` list (default: 80 and 443).
6. The hostname is resolved, and only now: names that fail the rules never
   cause a DNS lookup. Every resolved address is checked. One matching a
   deny CIDR denies the request. A non-public one (LAN, loopback, link-local,
   CGNAT, …) needs an IP/CIDR allow rule. This stops DNS rebinding and
   `*.nip.io`-style tricks from turning the proxy into a bridge between your
   VLANs.
7. The proxy connects **only to the addresses it checked**. It never
   resolves the name again. Plain-HTTP upstream connections are kept alive
   and reused, but only between requests whose checks approved exactly the
   same destination (host, port and addresses).

See [`config.example.yaml`](config.example.yaml) for the full rule syntax.

**Network requirement:** clients are identified only by source IP. That's
only meaningful if a device can't give itself an address from another
subnet's range, so each subnet should be its own VLAN (not just a different
IP range on a shared network or Wi-Fi SSID). On the proxy host, set strict
reverse-path filtering on the VLAN interfaces (`net.ipv4.conf.<if>.rp_filter=1`,
see [host settings](#host-settings)) so packets can't claim a source address
from another interface's subnet. Also firewall the proxy port so only your
internal VLANs can reach it.

## Limits and misbehaving devices

All subnets share one process, so per-client limits keep one runaway device
from degrading the proxy for the others. The defaults are generous and meant
to contain a misbehaving device, not to throttle normal use. They can be
changed in the config's `limits` block and per subnet, live.

| limit | default | when exceeded |
|---|---|---|
| `total_connections` | 20000 | new connections are closed |
| `client_connections` (per client IP, incl. tunnels) | 512 | new connections are closed |
| `client_requests_per_second` / `client_request_burst` | 200/s, burst 1000 | `429 Too Many Requests` |
| `tunnel_idle_timeout` (no data either way) | 1h | tunnel is closed |

The proxy also:

- drops connections from clients outside every subnet as soon as they're
  accepted, without reading or answering anything;
- closes the client connection after a denied request;
- answers with a generic `502` when an allowed destination can't be reached,
  and logs the actual error (which contains resolved addresses) instead;
- caps request headers at 64 KB and upstream response headers at 1 MB;
- dials at most 3 addresses per IP family, IPv4 and IPv6 in parallel
  ("happy eyeballs"), within 30 s in total;
- caches DNS answers for 30 s (5 s for names that don't exist, 3 s for
  timeouts and server failures) and merges concurrent lookups of the same
  name. At most 256 lookups run at once, and at most 32 per client, so a
  device retrying names whose DNS never answers can't stall everyone else's
  lookups. Resolved addresses are still checked on every request.

## Running

Download a binary for linux amd64, arm64 or armv7 from the
[releases](https://github.com/etsubu/proxy-acl/releases) (see
[verifying a download](#verifying-a-download)), or build it:

```sh
go build -o proxy-acl ./cmd/proxy-acl
./proxy-acl -config config.yaml -listen :3128 -log-format console
```

| flag          | default       |                                              |
|---------------|---------------|----------------------------------------------|
| `-config`     | `config.yaml` | ACL file; reloaded on change and on `SIGHUP` |
| `-listen`     | `:3128`       | listen address (`:3128` = all interfaces)    |
| `-log-format` | `json`        | `json` or `console`                          |
| `-version`    |               | print the version and exit                   |

If the config file is invalid at startup, the proxy won't start. If a later
edit is invalid (bad YAML, unknown key, bad pattern…), the error is logged
and the previous config stays active.

### Docker

Images for linux/amd64, linux/arm64 and linux/arm/v7 are published to
`ghcr.io/etsubu/proxy-acl`: `:1.2.3`, `:1.2`, `:1` and `:latest` for
releases, `:main` for the latest commit on main. The image is distroless
and runs as a non-root user. The proxy needs no capabilities and writes no
files:

```sh
docker run -d --name proxy-acl --restart unless-stopped \
  --network host \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 1g --pids-limit 512 --ulimit nofile=262144:262144 \
  -v /etc/proxy-acl:/etc/proxy-acl:ro \
  ghcr.io/etsubu/proxy-acl:1
```

To build it yourself: `docker build -t proxy-acl .`

- **Use `--network host`.** The rules depend on the real client IP. With
  Docker's port publishing, clients can show up as the bridge gateway
  (e.g. `172.17.0.1`), which matches no subnet, so everything is denied.
- **Mount the directory, not the file.** Most editors save by replacing the
  file, and a single-file bind mount would keep pointing at the old one, so
  hot reload wouldn't see the change.

### systemd

[`deploy/proxy-acl.service`](deploy/proxy-acl.service) runs the proxy as a
throwaway user with no capabilities, a read-only view of the system, a
system-call filter and memory, task and file-descriptor limits, and
restarts it if it ever exits:

```sh
install -m 755 proxy-acl /usr/local/bin/
install -D -m 644 config.yaml /etc/proxy-acl/config.yaml
cp deploy/proxy-acl.service /etc/systemd/system/
systemctl enable --now proxy-acl
systemctl reload proxy-acl   # same as editing the config: reloads it
```

The memory limit (1 GB) is a backstop behind the proxy's own limits; lower
it on a small VM or container if you like.

### Host settings

[`deploy/90-proxy-acl.conf`](deploy/90-proxy-acl.conf) (copy to
`/etc/sysctl.d/`, apply with `sysctl --system`) sets:

- `net.ipv4.tcp_tw_reuse = 1` and a wider `ip_local_port_range`: after each
  tunnel the proxy's side of the upstream connection waits a minute in
  `TIME_WAIT`, which otherwise limits it to about 470 new connections per
  second to any one destination;
- strict reverse-path filtering (`rp_filter = 1`), see the network
  requirement above;
- optionally, `fs.pipe-user-pages-soft = 0`, which only matters with 10 GbE
  and many tunnels open at once.

## Finding blocked traffic

Allowed requests are logged at `info` and denied ones at `warn`, with
`client`, `subnet`, `host`, `port`, `reason` and the matching `rule`. Set
`log_level: warn` to see only blocks. Failed connections to allowed
destinations are logged at `warn` as `upstream connection failed`.

Each client may write about 20 access log lines per second (burst 200). A
device over that is summarized every 10 s instead, with counts per host, so a
flood can't push everyone else's log lines out of the journal. Clients
outside every subnet share one such budget, summarized by client address.
Client-supplied fields are clipped (hosts to 253 bytes), so a request can't
produce huge log lines:

```json
{"level":"warn","client":"10.0.20.7","subnet":"iot","suppressed":8412,"deny":{"telemetry.vendor.example":8400,"(connection)":12},"message":"access log lines suppressed"}
```

```sh
journalctl -u proxy-acl -o cat | jq -c 'select(.action=="deny") | {subnet, client, host, port, reason}'
# most-blocked hosts per subnet
journalctl -u proxy-acl -o cat | jq -r 'select(.action=="deny") | "\(.subnet) \(.host):\(.port)"' | sort | uniq -c | sort -rn
# devices being summarized
journalctl -u proxy-acl -o cat | jq -c 'select(.message=="access log lines suppressed")'
```

## Releases

To release, run the **Release** workflow (Actions → Release → Run workflow,
on `main`) and choose `patch`, `minor` or `major`. It:

1. runs all the checks;
2. tags exactly the commit that passed them with the next version: one
   patch, minor or major step above the highest existing `vX.Y.Z` tag
   (`v0.0.1`, `v0.1.0` or `v1.0.0` for the first release). Versions live only
   in git tags; there's no version file to bump;
3. starts the **Publish** workflow on the tag, which builds and publishes:
   - binaries and `.tar.gz` archives (with the README, example config and
     `deploy/` files) for linux amd64, arm64 and armv7, plus a SHA-256
     checksum file;
   - the multi-platform image, tagged `X.Y.Z`, `X.Y`, `X` and `latest`;
   - a signed provenance attestation for every file and the image;
   - the GitHub release, uploaded as a draft and published once complete.

If Publish fails, fix the cause and run Publish by hand on the tag (Use
workflow from → Tags → `vX.Y.Z`); it doesn't create a new version.

Repository settings this relies on:

- If a ruleset restricts creating `v*` tags, let GitHub Actions create them
  (for example, add the GitHub Actions app as a bypass actor).
- Enable immutable releases, so a published release and its tag can't be
  changed.
- After the first publish, check the `proxy-acl` package's visibility
  (Packages → proxy-acl → Package settings) if the image should be public.
- Optionally require actions to be pinned to full commit SHAs (Settings →
  Actions → General); the workflows already comply.

### Verifying a download

Every release file and image carries a provenance attestation, signed
through GitHub, recording the repository, workflow, tag and commit it was
built from:

```sh
gh attestation verify proxy-acl_1.2.3_linux_amd64.tar.gz \
  --repo etsubu/proxy-acl --source-ref refs/tags/v1.2.3
gh attestation verify oci://ghcr.io/etsubu/proxy-acl:1.2.3 \
  --repo etsubu/proxy-acl --source-ref refs/tags/v1.2.3
sha256sum -c proxy-acl_1.2.3_checksums.txt --ignore-missing
```

Builds are reproducible: with the Go version from `go.mod`,
`git checkout v1.2.3 && make release` produces the same checksums.

### Supply chain

- Every action is GitHub's own and pinned to a commit SHA; reusable
  workflows are referenced with `$/` (same repository, same commit).
- The Docker base images and the BuildKit builder image are pinned by
  digest, and `govulncheck` by `go.sum`. Dependabot proposes weekly updates
  for Go modules, base images and actions; the BuildKit image in
  `image.yml` is updated by hand.
- Jobs get only the permissions they need, never keep git credentials, and
  release builds use no caches.

## Layout

```
cmd/proxy-acl/     main: flags, logging, server
internal/acl/      policy compilation and evaluation (stdlib only)
internal/config/   YAML parsing and hot reload
internal/limits/   per-client connection, request-rate and log budgets
internal/dnscache/ short-lived DNS cache with a concurrency cap
internal/proxy/    goproxy wiring, the vetting listener, the vetted-address
                   dialer, upstream connection pools and the tunnel copy loop
deploy/            systemd unit and host sysctl settings
scripts/           versions from git tags and the release build, used by the
                   workflows and the Makefile
```

## Development

```sh
make build        # bin/proxy-acl
make run          # dev mode, see below
make test         # tests with the race detector
make fuzz         # fuzz the ACL (FUZZTIME=60s)
make vulncheck    # known vulnerabilities in dependencies
make check        # everything CI checks: formatting, vet, vulncheck, tests
make release      # release binaries and archives into dist/, as CI builds them
make              # list all targets
```

Local builds take their version from git tags: `1.2.3` on a release tag,
`1.2.3-4-gabc1234` four commits later, `-dirty` with uncommitted changes
(`scripts/version.sh`).

`make run` starts the proxy on `127.0.0.1:3128` with the race detector,
console logs and [`config.dev.yaml`](config.dev.yaml), which lets this
machine through to anything and logs every decision at debug level. Edits
to the config apply live. Point a client at it with
`curl -x http://127.0.0.1:3128 https://example.com`, or override
`CONFIG=...` and `LISTEN=...`.

- `internal/acl` has the security tests: lookalike hosts for each pattern
  type, deny precedence, ports, subnet selection, DNS results pointing at
  private/loopback/deny-listed addresses, and making sure denied names
  never reach DNS. It also has a fuzz target that re-checks every allowed
  decision against a simple, independent model of the policy.
- `internal/proxy` tests the proxy end to end with raw requests: Host header
  and userinfo tricks, unsupported schemes, missing ports, alternative IP
  notations, and keep-alive reuse. It also checks that the dialer refuses
  anything the ACL didn't approve.

`internal/proxy` also covers the limits end to end (unknown clients, slot
release on every close path, rate limiting, tunnel idle timeout and
half-close, dial fallback and budget, generic upstream errors, log
sampling).

CI runs formatting, vet, `govulncheck`, race tests and a fuzz pass, builds
the release binaries for every platform and the Docker image, and
smoke-tests the image (`checks.yml`). Pushes to `main` also publish the
`:main` image (`ci.yml`, `image.yml`).

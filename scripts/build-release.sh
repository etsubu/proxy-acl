#!/usr/bin/env bash
# Builds the release binaries and archives for every platform into dist/,
# with a SHA-256 checksum file. Builds are reproducible: the same commit and
# Go version give byte-identical files.
# Usage: scripts/build-release.sh VERSION
set -euo pipefail
umask 022 # file modes in the archives must not depend on the machine

version=${1:-}
# A release version, or a development one from scripts/version.sh.
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
	echo "usage: $0 MAJOR.MINOR.PATCH[-SUFFIX]" >&2
	exit 1
fi
platforms=(linux/amd64 linux/arm64 linux/arm/v7)
out=dist

rm -rf "$out"
mkdir -p "$out"
export CGO_ENABLED=0
# Archive timestamps come from the commit (or are fixed, outside a git
# checkout), never from the build time.
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

for platform in "${platforms[@]}"; do
	IFS=/ read -r os arch variant <<<"$platform"
	name=proxy-acl_${version}_${os}_${arch}${variant}
	GOOS=$os GOARCH=$arch GOARM=${variant#v} go build -trimpath \
		-ldflags "-s -w -buildid= -X main.version=$version" \
		-o "$out/$name" ./cmd/proxy-acl

	mkdir -p "$stage/$name/deploy"
	install -m 0755 "$out/$name" "$stage/$name/proxy-acl"
	install -m 0644 README.md config.example.yaml "$stage/$name/"
	install -m 0644 deploy/* "$stage/$name/deploy/"
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" --format=gnu \
		-C "$stage" -cf - "$name" | gzip -9n >"$out/$name.tar.gz"
done

(cd "$out" && sha256sum proxy-acl_* >"proxy-acl_${version}_checksums.txt")
ls -l "$out"

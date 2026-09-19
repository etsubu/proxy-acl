#!/usr/bin/env bash
# Prints the version that follows the highest vMAJOR.MINOR.PATCH git tag
# (0.0.0 if there is none yet). Tags that aren't plain release versions,
# such as v1.2 or v1.2.3-rc1, are ignored.
# Usage: scripts/next-version.sh patch|minor|major
set -euo pipefail

bump=${1:-}
current=$(git tag --list 'v*' |
	{ grep -E '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || true; } |
	sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
IFS=. read -r major minor patch <<<"${current:-0.0.0}"
case $bump in
major) echo "$((major + 1)).0.0" ;;
minor) echo "$major.$((minor + 1)).0" ;;
patch) echo "$major.$minor.$((patch + 1))" ;;
*)
	echo "usage: $0 patch|minor|major" >&2
	exit 1
	;;
esac

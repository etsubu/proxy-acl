#!/usr/bin/env bash
# Prints the version of the checked-out code, from git tags: 1.2.3 on a
# release tag, 1.2.3-4-gabc1234 four commits after it, with -dirty for
# uncommitted changes. Before the first release: 0.0.0-dev+abc1234.
set -uo pipefail

if v=$(git describe --tags --match 'v[0-9]*.[0-9]*.[0-9]*' --dirty 2>/dev/null); then
	echo "${v#v}"
elif sha=$(git rev-parse --short HEAD 2>/dev/null); then
	echo "0.0.0-dev+$sha"
else
	echo "0.0.0-dev"
fi

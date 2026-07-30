#!/usr/bin/env bash
# Copyright © 2026 @sudocelestia. All rights reserved.
#
# PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
#
# No licence, permission or authorisation is granted to use, copy, modify,
# compile, execute, distribute, publish, sublicense or otherwise exploit this
# file, except to the limited extent unavoidably permitted by applicable law
# or GitHub's Terms of Service.
#
# See the LICENSE file at the repository root for the complete terms.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
target=${1:-"$root"}
lint=$(cd "$root" && go tool -n golangci-lint)
if [[ "$target" != "$root" ]] &&
  ! cmp -s -- "$root/.golangci.yml" "$target/.golangci.yml"; then
  printf 'External lint target must contain the governed configuration\n' >&2
  exit 1
fi
targets='linux amd64
aix ppc64
plan9 amd64'

while read -r goos goarch; do
  (
    cd "$target"
    env GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
      "$lint" run ./...
  )
done <<<"$targets"

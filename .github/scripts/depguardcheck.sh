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
export GOWORK=off

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/celestia-depguard.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

lint=$(cd "$root" && go tool -n golangci-lint)
go_version=$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")
mkdir -p "$work/internal/execution/example" "$work/internal/operation/example"
printf 'module celestia.research/celestia\n\ngo %s\n' "$go_version" >"$work/go.mod"
printf 'package example\n' >"$work/internal/operation/example/example.go"

awk '
  !changed && $0 == "            - \"internal/execution/**/*.go\"" {
    print "            - \"$all\""
    changed=1
    next
  }
  { print }
  END { if (!changed) exit 1 }
' "$root/.golangci.yml" >"$work/.golangci.yml"

(cd "$work" && "$lint" run --enable-only=depguard --config .golangci.yml ./...)
cat >"$work/internal/execution/example/example.go" <<'EOF'
package example

import _ "celestia.research/celestia/internal/operation/example"
EOF

set +e
output=$(cd "$work" && "$lint" run --enable-only=depguard --config .golangci.yml ./... 2>&1)
status=$?
set -e
if [[ "$status" -eq 0 ]] ||
  [[ "$output" != *"execution packages must not import operations"* ]]; then
  printf 'depguard accepted a forbidden execution import:\n%s\n' "$output" >&2
  exit 1
fi

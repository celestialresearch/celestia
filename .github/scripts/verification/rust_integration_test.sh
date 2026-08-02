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

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=.github/scripts/verification/fixture.sh
source "$script_dir/fixture.sh"

main() (
root=$(cd -- "$script_dir/../../.." && pwd)
work_dir=$(new_verification_work verification-rust-integration)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-rust-integration failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

repo_dir="$work_dir/repo"
mkdir -p "$repo_dir"
tar -cf - -C "$root" \
  .github/codeql .github/scripts .github/workflows \
  .github/.coverage .github/.currency .github/dependabot.yml \
  docs internal policies tools worker \
  .editorconfig .gitattributes .gitignore .golangci.yml \
  AGENTS.md Cargo.lock Cargo.toml deny.toml go.mod go.sum LICENSE README.md \
  rust-toolchain.toml | tar -xf - -C "$repo_dir"
git -C "$repo_dir" init -q
git -C "$repo_dir" config core.autocrlf false
git -C "$repo_dir" add -A
rm -- "$repo_dir/rust-toolchain.toml"
set +e
output=$(
  cd "$repo_dir" &&
    DEVCHECK_PROFILE=config bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'devcheck accepted incomplete Rust configuration\n' >&2
  return 1
}
if ! grep -Fq 'Config' <<<"$output" ||
  ! grep -Fq 'Incomplete Rust configuration' <<<"$output"; then
  printf 'devcheck omitted the incomplete Rust diagnostic:\n%s\n' \
    "$output" >&2
  return 1
fi
cp "$root/rust-toolchain.toml" "$repo_dir/rust-toolchain.toml"

mkdir -p "$work_dir/ambient/actionlint/cmd/actionlint"
cat >"$work_dir/ambient/go.work" <<'EOF'
go 1.26.5

use ../repo

replace github.com/rhysd/actionlint => ./actionlint
EOF
cat >"$work_dir/ambient/actionlint/go.mod" <<'EOF'
module github.com/rhysd/actionlint

go 1.26.5
EOF
cat >"$work_dir/ambient/actionlint/cmd/actionlint/main.go" <<'EOF'
package main

import (
	"os"
)

func main() {
	if err := os.WriteFile(os.Getenv("CELESTIA_WORKSPACE_MARKER"), nil, 0o600); err != nil {
		panic(err)
	}
}
EOF
CELESTIA_WORKSPACE_MARKER="$work_dir/workspace-tool-invoked" \
  GOWORK="$work_dir/ambient/go.work" go tool actionlint
[[ -e "$work_dir/workspace-tool-invoked" ]] || {
  printf 'ambient Go workspace fixture did not replace the pinned tool\n' >&2
  return 1
}
rm -- "$work_dir/workspace-tool-invoked"
output=$(
  cd "$repo_dir" &&
    CELESTIA_WORKSPACE_MARKER="$work_dir/workspace-tool-invoked" \
    GOWORK="$work_dir/ambient/go.work" DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
[[ ! -e "$work_dir/workspace-tool-invoked" ]] || {
  printf 'devcheck allowed an ambient Go workspace to replace a pinned tool\n' >&2
  return 1
}
if grep -Fq 'Verification Scripts' <<<"$output" ||
  ! grep -Fq '0 skipped, 0 failed' <<<"$output"; then
  printf 'devcheck config profile did not stop after configuration:\n%s\n' \
    "$output" >&2
  return 1
fi
rm -rf -- "$work_dir/ambient"
fake_bin="$work_dir/config-bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
if [ "$1" = tool ] && [ "$2" = actionlint ]; then
: >"$CELESTIA_ACTIONLINT_MARKER"
exit
fi
exec "$CELESTIA_REAL_GO" "$@"
EOF
chmod +x "$fake_bin/go"
)

main

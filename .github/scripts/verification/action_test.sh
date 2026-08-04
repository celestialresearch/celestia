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
  local devcheck_profile
  local fake_bin
  local output
  local real_bash
  local real_go
  local repo_dir
  local root
  local status
  local work_dir

  root=${CELESTIA_VERIFICATION_ROOT:-$(cd -- "$script_dir/../../.." && pwd)}
  work_dir=$(new_verification_work verification-action)
  trap 'cleanup_verification "$work_dir"' EXIT
  trap 'exit 1' HUP INT TERM

  CELESTIA_VERIFICATION_FAMILY_DIR="$root/.github/scripts/actioncheck" \
    CELESTIA_VERIFICATION_FAMILY_REPO="$root" \
    CELESTIA_VERIFICATION_FAMILY_PREFIX=.github/scripts/actioncheck \
    CELESTIA_VERIFICATION_FAMILY_KIND=action \
    bash "$root/.github/scripts/verification_test.sh" --fixture

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

  fake_bin="$work_dir/config-bin"
  mkdir -p "$fake_bin"
  real_bash=$(command -v bash)
  real_go=$(command -v go)
  cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
if [ "$1" = tool ] && [ "$2" = actionlint ]; then
  : >"$CELESTIA_ACTIONLINT_MARKER"
  exit
fi
exec "$CELESTIA_REAL_GO" "$@"
EOF
  chmod +x "$fake_bin/go"
  cat >"$fake_bin/bash" <<'EOF'
#!/bin/sh
case "$1" in
*.github/scripts/actioncheck.sh | *.github/scripts/rustcheck.sh)
  exec "$CELESTIA_REAL_BASH" "$@"
  ;;
*)
  : >"$CELESTIA_LATER_CONTROL_MARKER"
  exit 99
  ;;
esac
EOF
  chmod +x "$fake_bin/bash"
  cat >"$repo_dir/.github/workflows/alias-bomb.yml" <<'EOF'
name: Alias Bomb
permissions: read-all
on: push
jobs:
  check:
    strategy:
      matrix:
        level0: &level0 [x, x, x, x, x, x, x, x, x, x]
        level1: &level1 [*level0, *level0, *level0, *level0, *level0, *level0, *level0, *level0, *level0, *level0]
        level2: &level2 [*level1, *level1, *level1, *level1, *level1, *level1, *level1, *level1, *level1, *level1]
        level3: &level3 [*level2, *level2, *level2, *level2, *level2, *level2, *level2, *level2, *level2, *level2]
        level4: &level4 [*level3, *level3, *level3, *level3, *level3, *level3, *level3, *level3, *level3, *level3]
        level5: &level5 [*level4, *level4, *level4, *level4, *level4, *level4, *level4, *level4, *level4, *level4]
        level6: &level6 [*level5, *level5, *level5, *level5, *level5, *level5, *level5, *level5, *level5, *level5]
        level7: [*level6, *level6, *level6, *level6, *level6, *level6, *level6, *level6, *level6, *level6]
    runs-on: ubuntu-latest
    steps: []
EOF
  for devcheck_profile in config quick full; do
    rm -f -- "$work_dir/actionlint-invoked" "$work_dir/later-control"
    set +e
    output=$(
      cd "$repo_dir" &&
        CELESTIA_ACTIONLINT_MARKER="$work_dir/actionlint-invoked" \
        CELESTIA_LATER_CONTROL_MARKER="$work_dir/later-control" \
        CELESTIA_REAL_BASH="$real_bash" \
        CELESTIA_REAL_GO="$real_go" \
        PATH="$fake_bin:$PATH" \
        DEVCHECK_PROFILE="$devcheck_profile" \
          "$real_bash" .github/scripts/devcheck.sh 2>&1
    )
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || {
      printf 'devcheck %s accepted exponential YAML aliases\n' \
        "$devcheck_profile" >&2
      return 1
    }
    if [[ -e "$work_dir/actionlint-invoked" ]] ||
      [[ -e "$work_dir/later-control" ]] ||
      ! grep -Fq 'traversal budget' <<<"$output"; then
      printf 'devcheck %s passed action failure to another control:\n%s\n' \
        "$devcheck_profile" "$output" >&2
      return 1
    fi
  done
)

main

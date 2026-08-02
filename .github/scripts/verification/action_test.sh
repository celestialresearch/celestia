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
work_dir=$(new_verification_work verification-action)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-action failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

real_go=$(command -v go)
bash "$root/.github/scripts/actioncheck_test.sh"
family_repo="$work_dir/action-families"
family_dir="$family_repo/families"
mkdir -p "$family_dir"
git -C "$family_repo" init -q
git -C "$family_repo" config core.autocrlf false
families='remote_release_test.sh
cache_test.sh
inventory_test.sh
permissions_test.sh'
while IFS= read -r family; do
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$family_dir/$family"
  chmod +x "$family_dir/$family"
done <<<"$families"
printf '%s\n' '#!/usr/bin/env bash' 'exit 9' \
  >"$family_dir/inventory_test.sh"
git -C "$family_repo" add -f families
while IFS= read -r family; do
  git -C "$family_repo" update-index --chmod=+x "families/$family"
done <<<"$families"
set +e
output=$(CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" 2>&1)
status=$?
set -e
if [[ "$status" -ne 2 ||
  "$output" != *"overrides require fixture mode"* ]]; then
  printf 'action test driver accepted an ambient family override:\n%s\n' \
    "$output" >&2
  return 1
fi
driver_temp="$work_dir/action-driver-temp"
mkdir -p "$driver_temp"
if require_empty_verification_directory "$work_dir/missing-driver-temp" \
  'action test driver temporary' \
  >/dev/null 2>&1; then
  printf 'action test driver accepted missing cleanup state\n' >&2
  return 1
fi
if TMPDIR="$driver_temp" CELESTIA_ACTION_FAMILY_DIR="$family_dir" \
  CELESTIA_ACTION_FAMILY_REPO="$family_repo" \
  CELESTIA_ACTION_FAMILY_PREFIX=families \
  bash "$root/.github/scripts/actioncheck_test.sh" --fixture \
  >/dev/null 2>&1; then
  printf 'action test driver accepted a failing family\n' >&2
  return 1
fi
require_empty_verification_directory "$driver_temp" \
  'action test driver temporary'
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
cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
if [ "$1" = tool ] && [ "$2" = actionlint ]; then
  : >"$CELESTIA_ACTIONLINT_MARKER"
  exit
fi
exec "$CELESTIA_REAL_GO" "$@"
EOF
chmod +x "$fake_bin/go"
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
set +e
output=$(
  cd "$repo_dir" &&
    CELESTIA_ACTIONLINT_MARKER="$work_dir/actionlint-invoked" \
    CELESTIA_REAL_GO="$real_go" \
    PATH="$fake_bin:$PATH" \
    DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
rm -- "$repo_dir/.github/workflows/alias-bomb.yml"
[[ "$status" -ne 0 ]] || {
  printf 'devcheck accepted exponential YAML aliases\n' >&2
  return 1
}
if [[ -e "$work_dir/actionlint-invoked" ]] ||
  ! grep -Fq 'traversal budget' <<<"$output"; then
  printf 'devcheck reached actionlint before bounded workflow validation:\n%s\n' \
    "$output" >&2
  return 1
fi

)

main

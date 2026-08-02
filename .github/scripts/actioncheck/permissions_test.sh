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

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=.github/scripts/actioncheck/fixture.sh
source "$script_dir/fixture.sh"
new_action_test_work
trap 'rm -rf -- "$work_dir"' EXIT
trap 'exit 130' HUP INT TERM

root=$action_test_root
action_file="$work_dir/main.yml"

action_files() {
  printf '%s\0' "$action_file"
}

cat >"$action_file" <<'EOF'
permissions:
  security-events: write
jobs:
  classify:
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check accepted workflow-scoped security write\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
permissions:
  "security-events": write
jobs:
  classify:
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check missed a quoted workflow permission\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
permissions: write-all
jobs:
  classify:
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check accepted workflow-wide write authority\n' >&2
  exit 1
fi

for permission in contents id-token; do
  cat >"$action_file" <<EOF
permissions:
  $permission: write
EOF
  if check_permissions >/dev/null 2>&1; then
    printf 'permission check accepted %s write authority\n' "$permission" >&2
    exit 1
  fi
done

cat >"$action_file" <<'EOF'
permissions:
  contents: read
jobs:
  classify:
    permissions:
      security-events: write
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check accepted unrelated security write\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
permissions:
  contents: read
jobs:
  classify:
    permissions:
      security-events: write # SARIF upload
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check missed an unrelated commented security write\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
permissions:
  contents: read
jobs:
  analyze:
    permissions: &security-write
      security-events: write
    steps:
      - uses: github/codeql-action/analyze@0000000000000000000000000000000000000001 # v1.0.0
  classify:
    permissions: *security-write
    steps:
      - run: true
EOF
if check_permissions >/dev/null 2>&1; then
  printf 'permission check missed aliased security write authority\n' >&2
  exit 1
fi

action_policy_dir="$work_dir/actionpolicy"
mkdir -p "$action_policy_dir"
cp -- "$root/tools/actionpolicy/main.go" "$action_policy_dir/main.go"
policy_files() {
  printf '%s\0' "$action_policy_dir/main.go"
}
first_key=$(cache_key)
printf '\n// cache mutation\n' >>"$action_policy_dir/main.go"
second_key=$(cache_key)
[[ "$first_key" != "$second_key" ]] || {
  printf 'action cache ignored the structural policy parser\n' >&2
  exit 1
}

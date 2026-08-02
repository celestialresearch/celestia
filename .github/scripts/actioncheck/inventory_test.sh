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

output_file="$work_dir/output"
error_file="$work_dir/error"
action_file="$work_dir/action.yml"
printf 'fixture\n' >"$currency_file"
printf '#!/usr/bin/env bash\nexit 1\n' >"$currency_script"
printf 'module\n' >"$module_file"
printf 'sum\n' >"$module_sum_file"

action_files() {
  printf '%s\0' "$action_file"
}

invalid_entry='.github/workflows/main.yml:1:actions/checkout@0000000000000000000000000000000000000001 # v01.0.0'
if parse_action "$invalid_entry" >/dev/null 2>&1; then
  printf 'action parser accepted a non-canonical semantic version\n' >&2
  exit 1
fi

if parse_action '.github/workflows/main.yml:1:./local-action' \
  >/dev/null 2>&1; then
  printf 'action parser accepted an unresolved local action\n' >&2
  exit 1
fi

linked_action="$work_dir/linked-action.yml"
if ln -s "$action_file" "$linked_action" 2>/dev/null &&
  [[ -L "$linked_action" ]]; then
  original_action_files=$(declare -f action_files)
  action_files() {
    printf '%s\0' "$linked_action"
  }
  if action_documents <(action_files) >/dev/null 2>&1; then
    printf 'action document reader followed linked metadata\n' >&2
    exit 1
  fi
  eval "$original_action_files"
fi

if parse_action '.github/workflows/main.yml:1:docker://alpine:latest' \
  >/dev/null 2>&1; then
  printf 'action parser accepted a floating container image\n' >&2
  exit 1
fi
docker_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
if ! parse_action \
  ".github/workflows/main.yml:1:docker://alpine@sha256:$docker_digest"; then
  printf 'action parser rejected a digest-pinned container image\n' >&2
  exit 1
fi
[[ "$ACTION_KIND" == docker ]] || {
  printf 'action parser did not classify a container image\n' >&2
  exit 1
}

printf 'runs:\n  using: composite\n  steps:\n    - uses : example/action@main\n' >"$action_file"
entry=$(remote_actions)
if [[ -z "$entry" ]]; then
  printf 'action inventory missed a spaced action key\n' >&2
  exit 1
fi
if parse_action "$entry" >/dev/null 2>&1; then
  printf 'action parser missed a spaced unpinned action\n' >&2
  exit 1
fi

printf 'runs:\n  using: composite\n  steps:\n    - "uses": example/action@main\n' >"$action_file"
entry=$(remote_actions)
if [[ -z "$entry" ]]; then
  printf 'action inventory missed a quoted action key\n' >&2
  exit 1
fi
if parse_action "$entry" >/dev/null 2>&1; then
  printf 'action parser missed a quoted unpinned action\n' >&2
  exit 1
fi

printf 'runs:\n  using: composite\n  steps:\n    - { uses: example/action@main }\n' >"$action_file"
entry=$(remote_actions)
if [[ -z "$entry" ]]; then
  printf 'action inventory missed a flow action mapping\n' >&2
  exit 1
fi
if parse_action "$entry" >/dev/null 2>&1; then
  printf 'action parser missed a flow-mapped unpinned action\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
runs:
  using: composite
  steps:
    - { uses: example/action@0000000000000000000000000000000000000001 } # v1.0.0
EOF
entry=$(remote_actions)
if ! parse_action "$entry"; then
  printf 'action parser rejected a flow-mapped pinned action\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
jobs:
  call:
    "uses": example/workflow/.github/workflows/check.yml@main
EOF
entry=$(remote_actions)
if [[ -z "$entry" ]]; then
  printf 'action inventory missed a reusable workflow\n' >&2
  exit 1
fi
if parse_action "$entry" >/dev/null 2>&1; then
  printf 'action parser missed an unpinned reusable workflow\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
jobs:
  check:
    steps:
      - "uses": example/action@0000000000000000000000000000000000000001 # v1.0.0
EOF
entry=$(remote_actions)
if ! parse_action "$entry"; then
  printf 'action parser rejected a quoted pinned action\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
jobs:
  check:
    container: alpine:latest
    services:
      database:
        image: postgres:latest
    steps:
      - uses: docker://busybox:latest
EOF
entries=$(remote_actions)
[[ "$(grep -Fc 'docker://' <<<"$entries")" -eq 3 ]] || {
  printf 'action inventory omitted a container reference\n' >&2
  exit 1
}
while IFS= read -r entry; do
  if parse_action "$entry" >/dev/null 2>&1; then
    printf 'action parser accepted an unpinned container reference\n' >&2
    exit 1
  fi
done <<<"$entries"

cat >"$action_file" <<EOF
runs:
  using: docker
  image: docker://alpine@sha256:$docker_digest
EOF
entry=$(remote_actions)
if ! parse_action "$entry"; then
  printf 'action parser rejected a digest-pinned Docker action\n' >&2
  exit 1
fi

cat >"$action_file" <<'EOF'
image: &image alpine:latest
action: &action example/action@main
jobs:
  check:
    container: *image
    steps:
      - uses: *action
EOF
entries=$(remote_actions)
[[ "$(grep -Fc 'docker://alpine:latest' <<<"$entries")" -eq 1 &&
  "$(grep -Fc 'example/action@main' <<<"$entries")" -eq 1 ]] || {
  printf 'action inventory omitted an aliased reference\n' >&2
  exit 1
}

{
  printf 'level0: &level0 [value, value, value, value, value, value, value, value, value, value]\n'
  for level in 1 2 3 4 5 6 7; do
    printf 'level%s: &level%s [' "$level" "$level"
    item=0
    while ((item < 10)); do
      if ((item > 0)); then
        printf ', '
      fi
      printf '*level%s' "$((level - 1))"
      item=$((item + 1))
    done
    printf ']\n'
  done
} >"$action_file"
if remote_actions >"$output_file" 2>"$error_file"; then
  printf 'action parser accepted an excessive alias expansion\n' >&2
  exit 1
fi
grep -Fq 'traversal budget' "$error_file" || {
  printf 'action parser did not report its traversal bound\n' >&2
  exit 1
}

action_file="$work_dir/main.yml"

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

main() (
work_dir=$2
output=
status=0
fake_bin="$work_dir/fake-bin"
real_git=$(command -v git)
mkdir -p "$fake_bin"
cat >"$fake_bin/git" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "${FAIL_GIT_COMMAND:-}" ]]; then
exit 2
fi
exec "$REAL_GIT" "$@"
EOF
chmod +x "$fake_bin/git"
set +e
output=$(
  cd "$work_dir" &&
    CELESTIA_GIT_BIN="$fake_bin/git" FAIL_GIT_COMMAND=grep \
      REAL_GIT="$real_git" \
      bash .github/scripts/policycheck.sh markers 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check ignored a failed scanner\n' >&2
  return 1
}
grep -Fq 'git grep failed while enforcing repository policy' <<<"$output" || {
  printf 'policy output omitted the scanner failure:\n%s\n' "$output" >&2
  return 1
}
set +e
output=$(
  cd "$work_dir" &&
    CELESTIA_GIT_BIN="$fake_bin/git" FAIL_GIT_COMMAND=ls-files \
      REAL_GIT="$real_git" \
      bash .github/scripts/modcheck.sh diff 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'module check ignored a failed source inventory\n' >&2
  return 1
}
grep -Fq 'Failed to inventory module inputs' <<<"$output" || {
  printf 'module output omitted the inventory failure:\n%s\n' \
    "$output" >&2
  return 1
}
)

main "$@"

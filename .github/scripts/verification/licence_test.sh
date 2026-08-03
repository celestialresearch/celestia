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
root=${CELESTIA_VERIFICATION_ROOT:-$(cd -- "$script_dir/../../.." && pwd)}
work_dir=$(new_verification_work verification-licence)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-licence failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

licence_dir="$work_dir/licence"
mkdir -p "$licence_dir/.github/scripts"
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
cp "$root/.github/scripts/licencecheck.sh" \
  "$licence_dir/.github/scripts/"
git -C "$licence_dir" init -q
git -C "$licence_dir" config core.autocrlf false
set +e
output=$(
  cd "$licence_dir" &&
    CELESTIA_GIT_BIN="$fake_bin/git" FAIL_GIT_COMMAND=ls-files \
      REAL_GIT="$real_git" \
      bash .github/scripts/licencecheck.sh verify 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'licence check ignored a failed file inventory\n' >&2
  return 1
}
printf '%s\n' '#!/usr/bin/env bash' >"$licence_dir/removed.sh"
git -C "$licence_dir" add removed.sh
rm -- "$licence_dir/removed.sh"
(cd "$licence_dir" &&
  bash .github/scripts/licencecheck.sh verify >/dev/null)
printf '%s\n' 'package fixture' >"$licence_dir/fixture.go"
(
  cd "$licence_dir" &&
    bash .github/scripts/licencecheck.sh apply >/dev/null &&
    bash .github/scripts/licencecheck.sh cached-diff >/dev/null
)
mv -- "$licence_dir/fixture.go" "$licence_dir/-fixture.sh"
set +e
output=$(
  cd "$licence_dir" &&
    bash .github/scripts/licencecheck.sh cached-diff 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'licence cache ignored a filename-dependent header change\n' >&2
  return 1
}
grep -Fq -- '-fixture.sh: missing or incorrect proprietary header' <<<"$output" || {
  printf 'licence cache did not report the renamed fixture\n' >&2
  return 1
}

for extension in s m f F for f90 swig swigcxx; do
  printf 'SOURCE\n' >"$licence_dir/fixture.$extension"
  git -C "$licence_dir" add "fixture.$extension"
  set +e
  output=$(cd "$licence_dir" &&
    bash .github/scripts/licencecheck.sh verify 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'licence check accepted .%s source without a header\n' "$extension" >&2
    return 1
  }
  grep -Fq "fixture.$extension: missing or incorrect proprietary header" \
    <<<"$output" || {
    printf 'licence check omitted the .%s source diagnostic\n' "$extension" >&2
    return 1
  }
  rm -- "$licence_dir/fixture.$extension"
  git -C "$licence_dir" rm --cached -q -- "fixture.$extension"
done
)

main

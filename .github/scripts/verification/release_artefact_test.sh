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
work_dir=$(new_verification_work verification-release-artefact)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-release-artefact failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

rust_dir="$work_dir/rust"
rust_bin="$rust_dir/bin"
mkdir -p "$rust_bin"
cp "$root/.github/scripts/rustcheck.sh" "$rust_dir/rustcheck.sh"
cat >"$rust_bin/cargo" <<'EOF'
#!/usr/bin/env bash
while (($#)); do
if [[ "$1" == --target-dir ]]; then
  shift
  target_dir=$1
fi
shift
done
mkdir -p "$target_dir/release"
case "$(uname -s 2>/dev/null)" in
CYGWIN* | MINGW* | MSYS*) suffix=.exe ;;
*) suffix= ;;
esac
: >"$target_dir/release/celestia-url-reference$suffix"
chmod +x "$target_dir/release/celestia-url-reference$suffix"
EOF
cat >"$rust_bin/find" <<'EOF'
#!/usr/bin/env bash
exit 2
EOF
chmod +x "$rust_bin/cargo" "$rust_bin/find"
set +e
output=$(
  cd "$rust_dir" &&
    CARGO_BIN="$rust_bin/cargo" PATH="$rust_bin:$PATH" \
      bash ./rustcheck.sh artefacts 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'Rust release check ignored a failed artefact inventory\n' >&2
  return 1
}
grep -Fq 'Failed to inventory release build outputs' <<<"$output" || {
  printf 'Rust release output omitted the inventory failure:\n%s\n' \
    "$output" >&2
  return 1
}
)

main

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
work=$(mktemp -d "${TMPDIR:-/tmp}/testcheck-test.XXXXXX")

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/bin"
cat >"$work/bin/go" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *" -list "* ]]; then
  printf '%s\n' \
    '{"Action":"output","Package":"fixture.invalid/test","Output":"TestMustRun\n"}'
  exit
fi
printf '%s\n' \
  '{"Action":"run","Package":"fixture.invalid/test","Test":"TestMustRun"}'
if [[ "${COMPLETE_TEST:-false}" == true ]]; then
  printf '%s\n' \
    '{"Action":"pass","Package":"fixture.invalid/test","Test":"TestMustRun"}'
fi
EOF
chmod +x "$work/bin/go"

cat >"$work/bin/cargo" <<'EOF'
#!/usr/bin/env bash
printf 'running 1 test\n'
if [[ "${COMPLETE_TEST:-false}" == true ]]; then
  printf 'test result: ok. 1 passed; 0 failed; 0 ignored\n'
fi
EOF
chmod +x "$work/bin/cargo"

if PATH="$work/bin:$PATH" \
  bash "$root/.github/scripts/testcheck.sh" go quick >/dev/null 2>&1; then
  printf 'Go completion check accepted a missing terminal outcome\n' >&2
  exit 1
fi
PATH="$work/bin:$PATH" COMPLETE_TEST=true \
  bash "$root/.github/scripts/testcheck.sh" go quick >/dev/null

if CARGO_BIN="$work/bin/cargo" \
  bash "$root/.github/scripts/testcheck.sh" rust >/dev/null 2>&1; then
  printf 'Rust completion check accepted a missing harness summary\n' >&2
  exit 1
fi
CARGO_BIN="$work/bin/cargo" COMPLETE_TEST=true \
  bash "$root/.github/scripts/testcheck.sh" rust >/dev/null

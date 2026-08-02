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
work_dir=$(new_verification_work verification-lint)
trap 'cleanup_verification "$work_dir" "$change_pid" "$currency_pid"' EXIT
trap '[[ $- != *e* ]] || printf "verification-lint failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0

go_version=$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")
if [[ ! "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'verification fixture requires a patch-level Go version\n' >&2
  return 1
fi
change_pid=
currency_pid=
golangci_lint=$(cd "$root" && go tool -n golangci-lint)
shellcheck_script="$root/.github/scripts/windows-shellcheck.ps1"

mkdir -p "$work_dir/module-policy/.github/scripts"
cp "$root/.github/scripts/policycheck.sh" \
  "$work_dir/module-policy/.github/scripts/"
printf 'module celestia.research/module-policy\n\ngo 1.26\n' \
  >"$work_dir/module-policy/go.mod"
git -C "$work_dir/module-policy" init -q
git -C "$work_dir/module-policy" add -- go.mod
if output=$(cd "$work_dir/module-policy" &&
  bash .github/scripts/policycheck.sh module 2>&1); then
  printf 'policy check accepted a Go directive without a patch version\n' >&2
  return 1
fi
if [[ "$output" != 'go.mod: Go version must be pinned at patch level' ]]; then
  printf 'policy check returned the wrong Go directive diagnostic:\n%s\n' \
    "$output" >&2
  return 1
fi

if grep -Fq '| head' "$shellcheck_script"; then
  printf 'Windows shell check uses an unowned output pipeline\n' >&2
  return 1
fi
if grep -Eq "find .*'-name '\\*\\.go'.*\\|.*grep" \
  "$root"/.github/workflows/*.yml; then
  printf 'workflow Go package detection masks inventory failures\n' >&2
  return 1
fi
if grep -Eq 'find .*-quit' "$root"/.github/workflows/*.yml; then
  printf 'workflow uses non-portable find options\n' >&2
  return 1
fi
grep -Fq 'sudo pkgin -y install go pkg_alternatives' \
  "$root/.github/workflows/compatibility.yml" || {
  printf 'NetBSD Go bootstrap is missing\n' >&2
  return 1
}
grep -Fq 'sudo pkg_add go' \
  "$root/.github/workflows/compatibility.yml" || {
  printf 'OpenBSD Go bootstrap is missing\n' >&2
  return 1
}
grep -Fq "https://pkg.dragonflybsd.org/pkg/\${ABI}/LATEST" \
  "$root/.github/scripts/dragonfly-bootstrap.sh" || {
  printf 'DragonFly package repository is missing\n' >&2
  return 1
}
grep -Fq 'mirror_type: "HTTP"' \
  "$root/.github/scripts/dragonfly-bootstrap.sh" || {
  printf 'DragonFly mirror mode is missing\n' >&2
  return 1
}
grep -Fq "if [[ \"\$attempts\" -ge 5 ]]" \
  "$root/.github/scripts/dragonfly-bootstrap.sh" || {
  printf 'DragonFly retry budget is missing\n' >&2
  return 1
}
grep -Fq "SSL_CA_CERT_FILE=\"\$ca_bundle\"" \
  "$root/.github/scripts/dragonfly-bootstrap.sh" || {
  printf 'DragonFly trusted CA handoff is missing\n' >&2
  return 1
}
grep -Fq 'pkg install -y go git' \
  "$root/.github/scripts/dragonfly-bootstrap.sh" || {
  printf 'DragonFly Git bootstrap is outside the trusted package path\n' >&2
  return 1
}
grep -Fq '.github/generated/dragonfly-ca.pem' \
  "$root/.github/workflows/compatibility.yml" || {
  printf 'DragonFly CA bundle staging is missing\n' >&2
  return 1
}
if grep -Eq 'url: "http://' \
  "$root/.github/scripts/dragonfly-bootstrap.sh"; then
  printf 'DragonFly bootstrap permits unauthenticated package transport\n' >&2
  return 1
fi
for variable in CELESTIA_SHELL_CACHE CELESTIA_SHELL_TARGET \
  CELESTIA_SHELL_TMP; do
  grep -Fq "\$start.Environment['$variable']" "$shellcheck_script" || {
    printf 'Windows shell check omits %s isolation\n' "$variable" >&2
    return 1
  }
done
grep -Fq 'exec /usr/bin/bash ./.github/scripts/devcheck.sh' \
  "$shellcheck_script" || {
  printf 'Windows shell check does not own devcheck\n' >&2
  return 1
}
[[ $(grep -Fc 'GIT_CONFIG_COUNT=3' "$shellcheck_script") -eq 1 &&
  $(grep -Fc 'GIT_CONFIG_KEY_0=safe.directory' "$shellcheck_script") -eq 1 &&
  $(grep -Fc "GIT_CONFIG_VALUE_0=\"\$GITHUB_WORKSPACE\"" \
    "$shellcheck_script") -eq 1 &&
  $(grep -Fc 'GIT_CONFIG_KEY_1=safe.directory' "$shellcheck_script") -eq 1 &&
  $(grep -Fc "GIT_CONFIG_VALUE_1=\"\$PWD\"" "$shellcheck_script") -eq 1 &&
  $(grep -Fc 'GIT_CONFIG_KEY_2=safe.directory' "$shellcheck_script") -eq 1 &&
  $(grep -Fc "GIT_CONFIG_VALUE_2=\"\$CELESTIA_CYGWIN_ROOT\"" \
    "$shellcheck_script") -eq 1 ]] || {
  printf 'Windows shell check omits command-scoped Git ownership\n' >&2
  return 1
}
grep -Fq '[System.IO.Path]::GetTempPath()' "$shellcheck_script" || {
  printf 'Windows shell check stores mutable data in the checkout\n' >&2
  return 1
}
grep -Fq "\$start.RedirectStandardOutput = \$true" \
  "$shellcheck_script" || {
  printf 'Windows shell check does not own standard output\n' >&2
  return 1
}
grep -Fq "\$start.RedirectStandardError = \$true" \
  "$shellcheck_script" || {
  printf 'Windows shell check does not own standard error\n' >&2
  return 1
}
grep -Fq "\$Stream.ReadAsync(" "$shellcheck_script" || {
  printf 'Windows shell check does not use bounded stream reads\n' >&2
  return 1
}
if grep -Eq 'Get-Content .*-(Raw|ReadCount)' "$shellcheck_script"; then
  printf 'Windows shell check reads captured output without a bound\n' >&2
  return 1
fi
grep -Fq "\$cleanupFailures = @(" "$shellcheck_script" || {
  printf 'Windows shell check does not retain cleanup failures as an array\n' >&2
  return 1
}
grep -Fq "CYGWIN*) go_profile=\$(cygpath -w \"\$profile\")" \
  "$root/.github/scripts/coveragecheck.sh" || {
  printf 'coverage check omits Cygwin Go-path conversion\n' >&2
  return 1
}
grep -Fq 'arguments=(-p=2 -count=1 -shuffle=on)' \
  "$root/.github/scripts/testcheck.sh" || {
  printf 'standard tests omit the package parallelism bound\n' >&2
  return 1
}
grep -Fq 'arguments=(-p=2 -race -count=1 -shuffle=on)' \
  "$root/.github/scripts/testcheck.sh" || {
  printf 'race tests omit the package parallelism bound\n' >&2
  return 1
}
grep -Fq 'config | full | quick | shell' \
  "$root/.github/scripts/devcheck.sh" || {
  printf 'devcheck omits the quick profile\n' >&2
  return 1
}
grep -Fq "\${DEVCHECK_SELF_TEST:-true}" \
  "$root/.github/scripts/devcheck.sh" || {
  printf 'verification self-tests are not explicitly owned\n' >&2
  return 1
}
grep -Fq "DEVCHECK_PROFILE: \${{ needs.classify.outputs.full == 'true' && 'full' || 'quick' }}" \
  "$root/.github/workflows/main.yml" || {
  printf 'main verification does not select quick conservatively\n' >&2
  return 1
}
[[ $(grep -Fc "self-test: 'true'" \
  "$root/.github/workflows/main.yml") -eq 1 ]] || {
  printf 'main verification has more than one self-test owner\n' >&2
  return 1
}
mkdir -p "$work_dir/type-assertion"
cp "$root/.golangci.yml" "$work_dir/.golangci.yml"
cp "$root/.golangci.yml" "$work_dir/type-assertion/.golangci.yml"
fake_bin="$work_dir/platform-bin"
platform_log="$work_dir/platform-targets"
mkdir -p "$fake_bin"
cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
if [ "$1" = tool ] && [ "$2" = -n ] && [ "$3" = golangci-lint ]; then
printf '%s\n' "$CELESTIA_FAKE_LINT"
exit
fi
exit 1
EOF
cat >"$fake_bin/golangci-lint" <<'EOF'
#!/bin/sh
printf '%s %s\n' "$GOOS" "$GOARCH" >>"$CELESTIA_PLATFORM_LOG"
EOF
chmod +x "$fake_bin/go" "$fake_bin/golangci-lint"
PATH="$fake_bin:$PATH" \
  CELESTIA_FAKE_LINT="$fake_bin/golangci-lint" \
  CELESTIA_PLATFORM_LOG="$platform_log" \
  bash "$root/.github/scripts/platformlint.sh" "$work_dir/type-assertion"
printf 'linux amd64\naix ppc64\nplan9 amd64\n' \
  >"$work_dir/platform-targets.expected"
if ! cmp -s "$work_dir/platform-targets.expected" "$platform_log"; then
  printf 'Go platform lint dispatched unexpected targets:\n' >&2
  cat "$platform_log" >&2
  return 1
fi
printf 'module celestia.research/type-assertion\n\ngo %s\n' "$go_version" \
  >"$work_dir/type-assertion/go.mod"
printf 'package typeassertion\n' \
  >"$work_dir/type-assertion/typeassertion.go"
cat >"$work_dir/type-assertion/assertion_linux.go" <<'EOF'
//go:build linux

package typeassertion

func assertion(value any) int {
	return value.(int)
}

var _ = assertion
EOF
set +e
output=$(
  cd "$work_dir/type-assertion" &&
    env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
      GOLANGCI_LINT_CACHE="$work_dir/lint-type-bad" \
      "$golangci_lint" run ./... 2>&1
)
status=$?
set -e
if [[ "$status" -eq 0 ]] || ! grep -Fq 'errcheck' <<<"$output"; then
  printf 'errcheck accepted an unchecked type assertion:\n%s\n' \
    "$output" >&2
  return 1
fi
cat >"$work_dir/type-assertion/assertion_linux.go" <<'EOF'
//go:build linux

package typeassertion

func assertion(value any) int {
	number, ok := value.(int)
	if !ok {
		return 0
	}
	return number
}

var _ = assertion
EOF
(
  cd "$work_dir/type-assertion"
  env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    GOLANGCI_LINT_CACHE="$work_dir/lint-type-good" \
    "$golangci_lint" run ./...
) || {
  printf 'errcheck rejected a checked type assertion\n' >&2
  return 1
}

mkdir -p "$work_dir/linter-policy"
printf 'module celestia.research/linterfixture\n\ngo %s\n' "$go_version" \
  >"$work_dir/linter-policy/go.mod"
cat >"$work_dir/linter-policy/fixture.go" <<'EOF'
package linterfixture

import (
	"context"
	"encoding/json"
)

type owner struct{}

func (*owner) mutate() {
}

func (owner) inspect() {
}

func consume(context.Context) {
}

func inherit(ctx context.Context) {
	consume(context.Background())
}

func maybe() (*int, error) {
	return nil, nil
}

func unused(value int) int {
	return 1
}

func encode() {
	_, _ = json.Marshal(make(chan int))
}

func café() {}

// TODO: unresolved work.
func Use() {
	var value owner
	value.mutate()
	value.inspect()
	inherit(context.Background())
	_, _ = maybe()
	_ = unused(1)
	encode()
	café()
}
EOF
cat >"$work_dir/linter-policy/fixture_test.go" <<'EOF'
package linterfixture

import "testing"

func TestParallel(t *testing.T) {
	t.Parallel()
	t.Run("child", func(t *testing.T) {})
}
EOF
set +e
output=$(
  cd "$work_dir/linter-policy" &&
    GOLANGCI_LINT_CACHE="$work_dir/lint-policy-bad" \
      "$golangci_lint" run ./... 2>&1
)
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
  printf 'admitted linters accepted defective fixtures\n' >&2
  return 1
fi
for linter in \
  asciicheck contextcheck errcheck godox nilnil recvcheck tparallel unparam; do
  if ! grep -Fq "($linter)" <<<"$output"; then
    printf '%s did not reject its defective fixture:\n%s\n' \
      "$linter" "$output" >&2
    return 1
  fi
done
set +e
output=$(
  cd "$work_dir/linter-policy" &&
    GOLANGCI_LINT_CACHE="$work_dir/lint-errchkjson" \
      "$golangci_lint" run \
      --enable-only=errchkjson ./... 2>&1
)
status=$?
set -e
if [[ "$status" -eq 0 ]] || ! grep -Fq '(errchkjson)' <<<"$output"; then
  printf 'errchkjson accepted its defective fixture:\n%s\n' \
    "$output" >&2
  return 1
fi
cat >"$work_dir/linter-policy/fixture.go" <<'EOF'
package linterfixture

import (
	"context"
	"encoding/json"
)

type owner struct{}

func (*owner) mutate() {
}

func (*owner) inspect() {
}

func consume(context.Context) {
}

func inherit(ctx context.Context) {
	consume(ctx)
}

func maybe() (*int, error) {
	value := 1
	return &value, nil
}

func used(value int) int {
	return value
}

func encode() error {
	_, err := json.Marshal(map[string]int{"value": 1})
	return err
}

func Use() error {
	var value owner
	value.mutate()
	value.inspect()
	inherit(context.Background())
	result, err := maybe()
	if err != nil {
		return err
	}
	_ = result
	_ = used(1)
	return encode()
}
EOF
cat >"$work_dir/linter-policy/fixture_test.go" <<'EOF'
package linterfixture

import "testing"

func TestParallel(t *testing.T) {
	t.Parallel()
	t.Run("child", func(t *testing.T) {
		t.Parallel()
	})
}
EOF
(
  cd "$work_dir/linter-policy"
  GOLANGCI_LINT_CACHE="$work_dir/lint-policy-good" \
    "$golangci_lint" run ./...
) || {
  printf 'admitted linters rejected correct fixtures\n' >&2
  return 1
}

sleep 60 &
change_pid=$!
terminate_child "$change_pid"
if kill -0 "$change_pid" 2>/dev/null; then
  printf 'verification cleanup retained an owned child\n' >&2
  return 1
fi
change_pid=

bash "$root/.github/scripts/changecheck_test.sh" &
change_pid=$!
bash "$root/.github/scripts/currencycheck_test.sh" &
currency_pid=$!
bash "$root/.github/scripts/testcheck_test.sh"

status=0
await_child Change "$change_pid" || status=1
change_pid=
await_child Currency "$currency_pid" || status=1
currency_pid=
return "$status"
)

main

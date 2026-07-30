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
cache_root=${CELESTIA_CACHE_DIR:-"$root/.cache"}

terminate_child() {
  local pid=$1

  kill -0 "$pid" 2>/dev/null || return 0
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

cleanup_verification() {
  local work_dir=$1
  shift

  for pid in "$@"; do
    if [[ -n "$pid" ]]; then
      terminate_child "$pid"
    fi
  done
  rm -rf -- "$work_dir"
}

await_child() {
  local name=$1
  local pid=$2
  local result

  set +e
  wait "$pid"
  result=$?
  set -e
  if ((result != 0)); then
    printf '%s self-test failed with status %d\n' "$name" "$result" >&2
    return 1
  fi
}

main() (
  local output
  local repo_dir
  local fake_bin
  local licence_dir
  local metadata_probe
  local real_git
  local real_go
  local rust_dir
  local shellcheck_script
  local status
  local work_dir
  local action_pid=
  local change_pid=
  local currency_pid=
  local go_version
  local golangci_lint
  local platform_log

  mkdir -p "$cache_root"
  work_dir=$(mktemp -d "$cache_root/verification-test.XXXXXX")
  case "$work_dir" in
  "$cache_root"/verification-test.*) ;;
  *)
    printf 'refusing unexpected temporary path %s\n' "$work_dir" >&2
    return 1
    ;;
  esac
  trap 'cleanup_verification "$work_dir" "$change_pid" "$currency_pid" "$action_pid"' EXIT
  trap '[[ $- != *e* ]] || printf "verification self-test failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
  trap 'exit 1' HUP INT TERM
  real_go=$(command -v go)
  go_version=$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")
  if [[ ! "$go_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf 'verification fixture requires a patch-level Go version\n' >&2
    return 1
  fi
  golangci_lint=$(cd "$root" && go tool -n golangci-lint)
  shellcheck_script="$root/.github/scripts/windows-shellcheck.ps1"
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
  grep -Fq "https://avalon.dragonflybsd.org/dports/\${ABI}/LATEST" \
    "$root/.github/scripts/dragonfly-bootstrap.sh" || {
    printf 'DragonFly direct repository is missing\n' >&2
    return 1
  }
  grep -Fq 'mirror_type: "NONE"' \
    "$root/.github/scripts/dragonfly-bootstrap.sh" || {
    printf 'DragonFly direct repository mode is missing\n' >&2
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
  grep -Fq 'go test -p=2 -count=1 -shuffle=on ./...' \
    "$root/.github/scripts/devcheck.sh" || {
    printf 'standard tests omit the package parallelism bound\n' >&2
    return 1
  }
  grep -Fq 'go test -p=2 -race -count=1 -shuffle=on ./...' \
    "$root/.github/scripts/devcheck.sh" || {
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
        "$golangci_lint" run --config "$root/.golangci.yml" ./... 2>&1
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
      "$golangci_lint" run --config "$root/.golangci.yml" ./...
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
        "$golangci_lint" run --config "$root/.golangci.yml" ./... 2>&1
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
        "$golangci_lint" run --config "$root/.golangci.yml" \
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
      "$golangci_lint" run --config "$root/.golangci.yml" ./...
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
  bash "$root/.github/scripts/actioncheck_test.sh" &
  action_pid=$!

  mkdir -p \
    "$work_dir/.github/scripts" \
    "$work_dir/a" \
    "$work_dir/b" \
    "$work_dir/tools/sourcepolicy"
  cp "$root/.github/scripts/coveragecheck.sh" \
    "$root/.github/scripts/modcheck.sh" \
    "$root/.github/scripts/policycheck.sh" \
    "$work_dir/.github/scripts/"
  cp \
    "$root/tools/sourcepolicy/goskip.go" \
    "$root/tools/sourcepolicy/main.go" \
    "$root/tools/sourcepolicy/suppression.go" \
    "$work_dir/tools/sourcepolicy/"
  printf 'default 90\ncache-max-age-minutes 0\npackage celestia.research/coverage/tools/sourcepolicy 0\n' \
    >"$work_dir/.github/.coverage"
  cat >"$work_dir/go.mod" <<'EOF'
module celestia.research/coverage

go 1.26.5

require (
	github.com/BurntSushi/toml v1.6.0
	golang.org/x/tools v0.48.0
)
EOF
  cp "$root/go.sum" "$work_dir/go.sum"
  git -C "$work_dir" init -q
  cat >"$work_dir/.git/info/exclude" <<'EOF'
/config-bin/
/lint-*/
/linter-policy/
/platform-bin/
/repo/
/rust/
/type-assertion/
EOF
  if git -C "$work_dir" ls-files -co --exclude-standard |
    grep -Eq '^((lint-|linter-policy|platform-bin|repo|rust|type-assertion)/)'; then
    printf 'coverage fixture inventory includes generated verifier state\n' >&2
    return 1
  fi

  set +e
  output=$(
    cd "$root" &&
      DEVCHECK_PROFILE=invalid bash .github/scripts/devcheck.sh 2>&1
  )
  status=$?
  set -e
  [[ "$status" -eq 2 ]] || {
    printf 'devcheck accepted an unknown profile\n' >&2
    return 1
  }
  grep -Fq 'Unknown verification profile: invalid' <<<"$output" || {
    printf 'devcheck omitted the unknown-profile diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }

  rust_dir="$work_dir/rust"
  mkdir -p "$rust_dir/.github/scripts" "$rust_dir/.github/workflows" \
    "$rust_dir/bin" "$rust_dir/worker/qualification-fixtures" \
    "$rust_dir/worker/url-reference"
  cp "$root/.github/scripts/rustcheck.sh" "$rust_dir/.github/scripts/"
  cat >"$rust_dir/Cargo.toml" <<'EOF'
[workspace]
resolver = "3"

[workspace.package]
rust-version = "1.94.1"

[workspace.lints.rust]
non_ascii_idents = "deny"
unsafe_code = "forbid"
EOF
  printf '%s\n' '[toolchain]' 'channel = "1.94.0"' \
    >"$rust_dir/rust-toolchain.toml"
  printf '%s\n' '[package]' 'rust-version = "1.94.1"' '' \
    '[lints.rust]' 'non_ascii_idents = "deny"' \
    >"$rust_dir/worker/qualification-fixtures/Cargo.toml"
  printf '%s\n' '[package]' 'name = "worker"' 'version = "0.0.0"' '' \
    '[lints]' 'workspace = true' \
    >"$rust_dir/worker/url-reference/Cargo.toml"
  cat >"$rust_dir/.github/workflows/main.yml" <<'EOF'
steps:
  - name: Unrelated
    with:
      tool: |
        rust@1.94.1 + ignored
  - name: Setup
    uses: taiki-e/install-action@0123456789012345678901234567890123456789
    with:
      tool: |
        rust@1.94.1 + rustfmt + clippy
        cargo-llvm-cov@0.8.7
        cargo-audit@0.22.2
        cargo-deny@0.20.2
EOF
  cp "$rust_dir/.github/workflows/main.yml" \
    "$rust_dir/.github/workflows/main.yml.base"
  cp "$rust_dir/.github/workflows/main.yml" \
    "$rust_dir/.github/workflows/nightly.yml"

  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted mismatched versions\n' >&2
    return 1
  }
  grep -Fq \
    'Rust version mismatch: manifest=1.94.1 fixture=1.94.1 toolchain=1.94.0 workflow=1.94.1' \
    <<<"$output" || {
    printf 'Rust config check omitted the mismatch diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }

  rm -- "$rust_dir/rust-toolchain.toml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted an incomplete workspace\n' >&2
    return 1
  }
  grep -Fq 'Incomplete Rust configuration' <<<"$output" || {
    printf 'Rust config check omitted the incomplete diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }

  printf '%s\n' '[toolchain]' 'channel = "1.94.1"' \
    >"$rust_dir/rust-toolchain.toml"
  (cd "$rust_dir" && bash .github/scripts/rustcheck.sh config)

  printf '%s\n' '[package]' 'rust-version = "1.94.0"' '' \
    '[lints.rust]' 'non_ascii_idents = "deny"' \
    >"$rust_dir/worker/qualification-fixtures/Cargo.toml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted fixture version drift\n' >&2
    return 1
  }
  grep -Fq 'fixture=1.94.0' <<<"$output" || {
    printf 'Rust config check omitted fixture drift:\n%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' '[package]' 'rust-version = "1.94.1"' '' \
    '[lints.rust]' 'non_ascii_idents = "deny"' \
    >"$rust_dir/worker/qualification-fixtures/Cargo.toml"

  cp "$rust_dir/Cargo.toml" "$rust_dir/Cargo.toml.lints"
  sed '/unsafe_code = "forbid"/d' "$rust_dir/Cargo.toml.lints" \
    >"$rust_dir/Cargo.toml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  mv "$rust_dir/Cargo.toml.lints" "$rust_dir/Cargo.toml"
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted a missing unsafe-code prohibition\n' >&2
    return 1
  }
  grep -Fq 'Rust lint policy mismatch' <<<"$output" || {
    printf 'Rust config check omitted the lint-policy diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }

  mv "$rust_dir/Cargo.toml" "$rust_dir/Cargo.toml.saved"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  mv "$rust_dir/Cargo.toml.saved" "$rust_dir/Cargo.toml"
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted workflow-only configuration\n' >&2
    return 1
  }

  {
    printf '%s\n' '# rust@1.94.1'
    sed 's/rust@1.94.1 +/rust@1.94.0 +/' \
      "$rust_dir/.github/workflows/main.yml.base"
  } >"$rust_dir/.github/workflows/main.yml.new"
  mv "$rust_dir/.github/workflows/main.yml.new" \
    "$rust_dir/.github/workflows/main.yml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted a matching commented version\n' >&2
    return 1
  }
  cp "$rust_dir/.github/workflows/main.yml.base" \
    "$rust_dir/.github/workflows/main.yml"

  sed 's/rust@1.94.1 +/rust@1.94.0 +/' \
    "$rust_dir/.github/workflows/main.yml.base" \
    >"$rust_dir/.github/workflows/nightly.yml"
  set +e
  output=$(cd "$rust_dir" && bash .github/scripts/rustcheck.sh config 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust config check accepted cross-workflow pin drift\n' >&2
    return 1
  }
  grep -Fq 'Expected one active workflow version for rust, found 2' \
    <<<"$output" || {
    printf 'Rust config check omitted the cross-workflow diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
  cp "$rust_dir/.github/workflows/main.yml.base" \
    "$rust_dir/.github/workflows/nightly.yml"

  cat >"$rust_dir/bin/cargo" <<'EOF'
#!/usr/bin/env bash
case "$1" in
build)
  shift
  target_dir=
  while [[ $# -gt 0 ]]; do
    case "$1" in
    --target-dir)
      shift
      target_dir=${1:-}
      ;;
    esac
    shift || exit 2
  done
  [[ -n "$target_dir" ]] || exit 2
  release_dir="$target_dir/release"
  mkdir -p "$release_dir"
  suffix=
  case "$(uname -s 2>/dev/null)" in
  CYGWIN* | MINGW* | MSYS*) suffix=.exe ;;
  esac
  : >"$release_dir/celestia-url-reference$suffix"
  chmod +x "$release_dir/celestia-url-reference$suffix"
  : >"$release_dir/celestia-url-reference.d"
  if [[ "${RUSTCHECK_EXECUTABLE_METADATA:-false}" == true ]]; then
    chmod +x "$release_dir/celestia-url-reference.d"
  fi
  if [[ -n "${RUSTCHECK_EXTRA_RELEASE_EXECUTABLE:-}" ]]; then
    : >"$release_dir/${RUSTCHECK_EXTRA_RELEASE_EXECUTABLE}${suffix}"
    chmod +x "$release_dir/${RUSTCHECK_EXTRA_RELEASE_EXECUTABLE}${suffix}"
  fi
  if [[ -n "${RUSTCHECK_EXTRA_RELEASE_ARTEFACT:-}" ]]; then
    : >"$release_dir/${RUSTCHECK_EXTRA_RELEASE_ARTEFACT}"
  fi
  if [[ -n "${RUSTCHECK_NESTED_RELEASE_ARTEFACT:-}" ]]; then
    mkdir -p "$release_dir/nested"
    : >"$release_dir/nested/${RUSTCHECK_NESTED_RELEASE_ARTEFACT}"
  fi
  ;;
llvm-cov) printf 'cargo-llvm-cov %s\n' "${LLVM_COV_VERSION:-0.8.7}" ;;
audit)
  [[ "${FAIL_SUPPLY_COMMANDS:-false}" == false ]] || exit 9
  printf 'cargo-audit %s\n' "${AUDIT_VERSION:-0.22.2}"
  ;;
deny)
  [[ "${FAIL_SUPPLY_COMMANDS:-false}" == false ]] || exit 9
  printf 'cargo-deny %s\n' "${DENY_VERSION:-0.20.2}"
  ;;
*) exit 2 ;;
esac
EOF
  chmod +x "$rust_dir/bin/cargo"
  cat >"$rust_dir/bin/rustc" <<'EOF'
#!/usr/bin/env bash
printf 'rustc %s\n' "${FIXTURE_RUSTC_VERSION:-1.94.1}"
EOF
  chmod +x "$rust_dir/bin/rustc"
  unset FIXTURE_RUSTC_VERSION

  (
    cd "$rust_dir" &&
      RUSTC_BIN="$rust_dir/bin/rustc" \
        CARGO_BIN="$rust_dir/bin/cargo" \
        bash .github/scripts/rustcheck.sh tools
  )
  set +e
  output=$(
    cd "$rust_dir" &&
      RUSTC_BIN="$rust_dir/bin/rustc" \
        CARGO_BIN="$rust_dir/bin/cargo" FIXTURE_RUSTC_VERSION=0 \
        bash .github/scripts/rustcheck.sh tools 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust tool check accepted a mismatched compiler version\n' >&2
    return 1
  }
  grep -Fq 'Rust compiler version mismatch: expected=1.94.1 actual=0' \
    <<<"$output" || {
    printf 'Rust tool check omitted the compiler mismatch diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
  (
    cd "$rust_dir" &&
      RUSTC_BIN="$rust_dir/bin/rustc" \
        CARGO_BIN="$rust_dir/bin/cargo" DEVCHECK_SUPPLY_CHAIN=false \
        FAIL_SUPPLY_COMMANDS=true bash .github/scripts/rustcheck.sh tools
  )

  for mismatch in llvm-cov audit deny; do
    set +e
    case "$mismatch" in
    llvm-cov)
      output=$(
        cd "$rust_dir" &&
          RUSTC_BIN="$rust_dir/bin/rustc" \
            CARGO_BIN="$rust_dir/bin/cargo" DEVCHECK_SUPPLY_CHAIN=true \
            LLVM_COV_VERSION=0 \
            bash .github/scripts/rustcheck.sh tools 2>&1
      )
      ;;
    audit)
      output=$(
        cd "$rust_dir" &&
          RUSTC_BIN="$rust_dir/bin/rustc" \
            CARGO_BIN="$rust_dir/bin/cargo" DEVCHECK_SUPPLY_CHAIN=true \
            AUDIT_VERSION=0 \
            bash .github/scripts/rustcheck.sh tools 2>&1
      )
      ;;
    deny)
      output=$(
        cd "$rust_dir" &&
          RUSTC_BIN="$rust_dir/bin/rustc" \
            CARGO_BIN="$rust_dir/bin/cargo" DEVCHECK_SUPPLY_CHAIN=true \
            DENY_VERSION=0 \
            bash .github/scripts/rustcheck.sh tools 2>&1
      )
      ;;
    esac
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || {
      printf 'Rust tool check accepted a mismatched %s version\n' \
        "$mismatch" >&2
      return 1
    }
    grep -Fq 'Rust helper version mismatch' <<<"$output" || {
      printf 'Rust tool check omitted the %s mismatch diagnostic:\n%s\n' \
        "$mismatch" "$output" >&2
      return 1
    }
  done

  (
    cd "$rust_dir" &&
      CARGO_BIN="$rust_dir/bin/cargo" \
        bash .github/scripts/rustcheck.sh artefacts
  )
  set +e
  output=$(
    cd "$rust_dir" &&
      CARGO_BIN="$rust_dir/bin/cargo" \
        RUSTCHECK_EXTRA_RELEASE_EXECUTABLE=celestia-hostile-worker \
        bash .github/scripts/rustcheck.sh artefacts 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust artefact check accepted an unexpected executable\n' >&2
    return 1
  }
  grep -Fq 'Unexpected release executable: celestia-hostile-worker' \
    <<<"$output" || {
    printf 'Rust artefact check omitted the unexpected executable:\n%s\n' \
      "$output" >&2
    return 1
  }
  set +e
  output=$(
    cd "$rust_dir" &&
      CARGO_BIN="$rust_dir/bin/cargo" \
        RUSTCHECK_EXTRA_RELEASE_ARTEFACT=unexpected.metadata \
        bash .github/scripts/rustcheck.sh artefacts 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust artefact check accepted an unexpected regular file\n' >&2
    return 1
  }
  grep -Fq 'Unexpected release build output: unexpected.metadata' \
    <<<"$output" || {
    printf 'Rust artefact check omitted the unexpected regular file:\n%s\n' \
      "$output" >&2
    return 1
  }
  set +e
  output=$(
    cd "$rust_dir" &&
      CARGO_BIN="$rust_dir/bin/cargo" \
        RUSTCHECK_NESTED_RELEASE_ARTEFACT=unexpected.nested \
        bash .github/scripts/rustcheck.sh artefacts 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Rust artefact check accepted a nested regular file\n' >&2
    return 1
  }
  grep -Fq 'Unexpected release directory: nested' \
    <<<"$output" || {
    printf 'Rust artefact check omitted the nested release directory:\n%s\n' \
      "$output" >&2
    return 1
  }
  metadata_probe="$rust_dir/executable.d"
  : >"$metadata_probe"
  chmod +x "$metadata_probe"
  if [[ -x "$metadata_probe" ]]; then
    set +e
    output=$(
      cd "$rust_dir" &&
        CARGO_BIN="$rust_dir/bin/cargo" RUSTCHECK_EXECUTABLE_METADATA=true \
          bash .github/scripts/rustcheck.sh artefacts 2>&1
    )
    status=$?
    set -e
    [[ "$status" -ne 0 ]] || {
      printf 'Rust artefact check accepted executable metadata\n' >&2
      return 1
    }
    grep -Fq 'Invalid release metadata: celestia-url-reference.d' \
      <<<"$output" || {
      printf 'Rust artefact check omitted executable metadata:\n%s\n' \
        "$output" >&2
      return 1
    }
  fi

  repo_dir="$work_dir/repo"
  mkdir -p "$repo_dir"
  tar -cf - -C "$root" \
    .github/codeql .github/scripts .github/workflows \
    .github/.coverage .github/.currency .github/dependabot.yml \
    docs internal policies tools worker \
    .editorconfig .gitattributes .gitignore .golangci.yml \
    AGENTS.md Cargo.lock Cargo.toml deny.toml go.mod go.sum LICENSE README.md \
    rust-toolchain.toml |
    tar -xf - -C "$repo_dir"
  git -C "$repo_dir" init -q
  git -C "$repo_dir" config core.autocrlf false
  if ! git -C "$repo_dir" add -A 2>"$work_dir/git-add-error"; then
    cat "$work_dir/git-add-error" >&2
    return 1
  fi
  rm -- "$repo_dir/rust-toolchain.toml"
  set +e
  output=$(
    cd "$repo_dir" &&
      DEVCHECK_PROFILE=config \
        bash .github/scripts/devcheck.sh 2>&1
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
  output=$(
    cd "$repo_dir" &&
      DEVCHECK_PROFILE=config \
        bash .github/scripts/devcheck.sh 2>&1
  )
  if grep -Fq 'Verification Scripts' <<<"$output" ||
    ! grep -Fq '0 skipped, 0 failed' <<<"$output"; then
    printf 'devcheck config profile did not stop after configuration:\n%s\n' \
      "$output" >&2
    return 1
  fi
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

  cat >"$work_dir/a/a.go" <<'EOF'
package a

func Value() bool { return true }
EOF
  cat >"$work_dir/a/a_test.go" <<'EOF'
package a

import "testing"

func TestValue(t *testing.T) {
	if !Value() {
		t.Fatal("value is false")
	}
}
EOF
  cat >"$work_dir/b/b.go" <<'EOF'
package b

func First() bool { return true }
func Second() bool { return true }
EOF
  cat >"$work_dir/b/b_test.go" <<'EOF'
package b

import "testing"

func TestFirst(t *testing.T) {
	if !First() {
		t.Fatal("first is false")
	}
}
EOF

  cat >"$work_dir/b/failure_test.go" <<'EOF'
package b

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestFailure(t *testing.T) {
	fmt.Fprintln(os.Stderr, strings.Repeat("x", 131072))
	t.Fatal("failed")
}

func TestMain(m *testing.M) {
	code := m.Run()
	fmt.Fprintln(os.Stderr, "fixture failure")
	os.Exit(code)
}
EOF
  set +e
  output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify 2>&1)
  status=$?
  set -e
  rm -- "$work_dir/b/failure_test.go"
  [[ "$status" -ne 0 ]] || {
    printf 'coverage check accepted a failing test\n' >&2
    return 1
  }
  if grep -Fq 'unbound variable' <<<"$output"; then
    printf 'coverage cleanup masked a failing test:\n%s\n' "$output" >&2
    return 1
  fi
  grep -Fq 'fixture failure' <<<"$output" || {
    printf 'coverage check discarded failing test output:\n%s\n' "$output" >&2
    return 1
  }
  ((${#output} <= 70000)) || {
    printf 'coverage check retained unbounded failing output\n' >&2
    return 1
  }

  set +e
  output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'coverage check accepted an under-covered package\n' >&2
    return 1
  }
  grep -Eq 'celestia\.research/coverage/a[[:space:]]+100\.00%' \
    <<<"$output" || {
    printf 'coverage output omitted the fully covered package:\n%s\n' \
      "$output" >&2
    return 1
  }
  grep -Eq 'celestia\.research/coverage/b[[:space:]]+50\.00%' \
    <<<"$output" || {
    printf 'coverage output omitted the under-covered package:\n%s\n' \
      "$output" >&2
    return 1
  }

  cat >>"$work_dir/b/b_test.go" <<'EOF'

func TestSecond(t *testing.T) {
	if !Second() {
		t.Fatal("second is false")
	}
}
EOF
  output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh verify 2>&1) || {
    printf 'coverage check rejected the fully covered fixture:\n%s\n' \
      "$output" >&2
    return 1
  }
  (
    cd "$work_dir" &&
      bash .github/scripts/coveragecheck.sh cached >/dev/null
  )
  mv -- "$work_dir/b/b_test.go" "$work_dir/b/b_plan9_test.go"
  set +e
  output=$(cd "$work_dir" && bash .github/scripts/coveragecheck.sh cached 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'coverage cache ignored a build-sensitive filename change\n' >&2
    return 1
  }
  mv -- "$work_dir/b/b_plan9_test.go" "$work_dir/b/b_test.go"
  {
    printf '%s\n' '// Code generated by fixture. DO NOT EDIT.'
    awk 'BEGIN { for (line = 0; line < 801; line++) print "// fixture" }'
  } >"$work_dir/-generated.go"
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh source-files 2>&1)
  status=$?
  set -e
  [[ "$status" -eq 0 ]] || {
    printf 'policy check rejected an option-like generated filename:\n%s\n' \
      "$output" >&2
    return 1
  }
  rm -- "$work_dir/-generated.go"

  printf '%s\n' '// probe' >"$work_dir/coverage_test.go"
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh source-files 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted coverage_test.go\n' >&2
    return 1
  }
  grep -Fq 'use an intent-named residual coverage file' <<<"$output" || {
    printf 'policy output omitted the rejected filename:\n%s\n' \
      "$output" >&2
    return 1
  }
  rm -- "$work_dir/coverage_test.go"

  cat >"$work_dir/skipped_test.go" <<'EOF'
package fixture

import "testing"

func TestSkipped(t *testing.T) {
	t.Skip("unverified")
}
EOF
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh test-skips 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted a skipped Go test\n' >&2
    return 1
  }
  grep -Fq 'Go tests must not skip cases' <<<"$output" || {
    printf 'policy output omitted the skipped-test failure:\n%s\n' \
      "$output" >&2
    return 1
  }
  rm -- "$work_dir/skipped_test.go"

  cat >"$work_dir/helper.go" <<'EOF'
package fixture

import "testing"

func testContext(t *testing.T) *testing.T {
	return t
}

type skipper interface {
	Skip(...any)
}

func hideSkip(value skipper) {
	value.Skip("unverified")
}
EOF
  cat >"$work_dir/skipped_test.go" <<'EOF'
package fixture

import "testing"

func TestSkipped(t *testing.T) {
	testContext(t).Skip("unverified")
	hideSkip(t)
}
EOF
  cat >"$work_dir/platform_linux.go" <<'EOF'
//go:build linux

package fixture

const platform = "linux"
EOF
  cat >"$work_dir/platform_windows.go" <<'EOF'
//go:build windows

package fixture

const platform = "windows"
EOF
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh test-skips 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted a cross-file Go skip\n' >&2
    return 1
  }
  rm -- \
    "$work_dir/helper.go" \
    "$work_dir/skipped_test.go" \
    "$work_dir/platform_linux.go" \
    "$work_dir/platform_windows.go"

  cat >"$work_dir/skipped_test.go" <<'EOF'
package fixture

import "testing"

func TestSkipped(t *testing.T) {
	(*testing.T).Skip(t, "unverified")
}
EOF
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh test-skips 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted a method-expression Go skip\n' >&2
    return 1
  }
  rm -- "$work_dir/skipped_test.go"

  cat >"$work_dir/ignored_test.rs" <<'EOF'
#[test]
#[ignore]
fn ignored() {}
EOF
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh test-skips 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted an ignored Rust test\n' >&2
    return 1
  }
  grep -Fq 'Rust tests must not ignore cases' <<<"$output" || {
    printf 'policy output omitted the ignored-test failure:\n%s\n' \
      "$output" >&2
    return 1
  }
  rm -- "$work_dir/ignored_test.rs"

  cat >"$work_dir/ignored_test.rs" <<'EOF'
#[test]
#[cfg_attr(all(), ignore)]
fn ignored() {}
EOF
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh test-skips 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted a conditionally ignored Rust test\n' >&2
    return 1
  }
  rm -- "$work_dir/ignored_test.rs"

  cat >"$work_dir/included_test.rs" <<'EOF'
use std::include as load;

load!("skipped.inc");
EOF
  cat >"$work_dir/path_test.rs" <<'EOF'
#[path = "skipped.inc"]
mod skipped;
EOF
  cat >"$work_dir/forwarded_test.rs" <<'EOF'
macro_rules! make_test {
	($attribute:meta) => {
		#[test]
		#[$attribute]
		fn generated() {}
	};
}

make_test!(ignore);
EOF
  cat >"$work_dir/skipped.inc" <<'EOF'
#[test]
#[ignore]
fn ignored() {}
EOF
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh test-skips 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted Rust source expansion\n' >&2
    return 1
  }
  grep -Fq 'Rust include! is prohibited' <<<"$output" || {
    printf 'policy output omitted the Rust include failure:\n%s\n' \
      "$output" >&2
    return 1
  }
  grep -Fq 'Rust path attributes are prohibited' <<<"$output" || {
    printf 'policy output omitted the Rust path failure:\n%s\n' \
      "$output" >&2
    return 1
  }
  rm -- \
    "$work_dir/included_test.rs" \
    "$work_dir/path_test.rs" \
    "$work_dir/forwarded_test.rs" \
    "$work_dir/skipped.inc"

  printf '%s%s\n' '// #no' 'sec -- broad' >"$work_dir/broad_suppression.go"
  printf '%s%s\n' '//no' 'lint -- broad' >"$work_dir/broad_nolint.go"
  printf '%s%s\n' '//no' 'lint:all -- reasoned blanket suppression' \
    >"$work_dir/reasoned_broad_nolint.go"
  printf '%s%s\n' '# shell' 'check disable=SC2329' \
    >"$work_dir/broad_shellcheck.sh"
  printf '%s%s\n' '#shell' 'check disable=SC2086' \
    >"$work_dir/compact_shellcheck.sh"
  printf '%s%s\n' '#[al' 'low(clippy::needless_pass_by_value)]' \
    >"$work_dir/broad_clippy.rs"
  printf '%s%s\n' '#[al' \
    'low(clippy::all, reason = "reasoned blanket suppression")]' \
    >"$work_dir/reasoned_broad_clippy.rs"
  printf '%s%s\n' '#![al' 'low(clippy::all)]' \
    >"$work_dir/inner_broad_clippy.rs"
  printf '%s%s\n' '#![ex' 'pect(clippy::all)]' \
    >"$work_dir/inner_broad_expect.rs"
  cat >"$work_dir/Cargo.toml" <<'EOF'
[workspace]

[patch.crates-io]
fixture = { path = "../fixture" }

[workspace.lints.rustdoc]
broken_intra_doc_links = "allow"
EOF
  mkdir -p "$work_dir/.cargo"
  cat >"$work_dir/.cargo/config.toml" <<'EOF'
include = ["hostile.toml"]
paths = ["../override"]

[alias]
clippy = "bypass"

[build]
rustflags = ["@args.txt"]
rustc-wrapper = "wrapper.exe"
EOF
  cat >"$work_dir/.cargo/hostile.toml" <<'EOF'
[build]
rustflags = ["--cap-lints=allow"]
EOF
  printf '%s\n' '--cap-lints' 'allow' >"$work_dir/args.txt"
  head -c 1048577 /dev/zero | tr '\0' x >"$work_dir/oversized.sh"
  {
    printf '%s%s\n' '#[al' 'low('
    printf '%s\n' '    clippy::all,'
    printf '%s\n' '    reason = "reasoned blanket suppression"'
    printf '%s\n' ')]'
  } >"$work_dir/reasoned_broad_multiline_clippy.rs"
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh suppressions 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted hostile suppression fixtures\n' >&2
    return 1
  }
  for diagnostic in \
    'invalid gosec suppression' \
    'invalid golangci-lint suppression' \
    'invalid ShellCheck suppression' \
    'invalid Clippy suppression' \
    'Cargo lint allowances are prohibited' \
    'Cargo source override is prohibited' \
    'Cargo rustflags are not approved' \
    'Cargo execution override is prohibited' \
    'source file exceeds 1048576 bytes'; do
    grep -Fq "$diagnostic" <<<"$output" || {
      printf 'policy output omitted %s:\n%s\n' "$diagnostic" "$output" >&2
      return 1
    }
  done
  rm -- \
    "$work_dir/broad_suppression.go" \
    "$work_dir/broad_nolint.go" \
    "$work_dir/reasoned_broad_nolint.go" \
    "$work_dir/broad_shellcheck.sh" \
    "$work_dir/compact_shellcheck.sh" \
    "$work_dir/broad_clippy.rs" \
    "$work_dir/reasoned_broad_clippy.rs" \
    "$work_dir/inner_broad_clippy.rs" \
    "$work_dir/inner_broad_expect.rs" \
    "$work_dir/reasoned_broad_multiline_clippy.rs" \
    "$work_dir/Cargo.toml" \
    "$work_dir/.cargo/config.toml" \
    "$work_dir/.cargo/hostile.toml" \
    "$work_dir/args.txt" \
    "$work_dir/oversized.sh"
  rmdir -- "$work_dir/.cargo"

  {
    printf '%s%s\n' '// #no' 'sec G103 -- narrow native boundary'
    printf '%s%s\n' '//no' 'lint:errcheck -- checked by an owning wrapper'
  } >"$work_dir/valid_suppressions.go"
  printf '%s%s\n' \
    '# shell' 'check disable=SC2329 # Invoked by a registered trap' \
    >"$work_dir/valid_suppressions.sh"
  printf '%s%s\n' \
    '#[al' 'low(clippy::needless_pass_by_value, reason = "FFI owns the value")]' \
    >"$work_dir/valid_suppressions.rs"
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh suppressions 2>&1) || {
    printf 'policy check rejected narrow suppressions:\n%s\n' "$output" >&2
    return 1
  }
  rm -- \
    "$work_dir/valid_suppressions.go" \
    "$work_dir/valid_suppressions.sh" \
    "$work_dir/valid_suppressions.rs"

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
        bash .github/scripts/coveragecheck.sh cached 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'coverage check ignored a failed source inventory\n' >&2
    return 1
  }
  grep -Fq 'Failed to inventory coverage inputs' <<<"$output" || {
    printf 'coverage output omitted the inventory failure:\n%s\n' \
      "$output" >&2
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

  licence_dir="$work_dir/licence"
  mkdir -p "$licence_dir/.github/scripts"
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

  status=0
  await_child Change "$change_pid" || status=1
  change_pid=
  await_child Currency "$currency_pid" || status=1
  currency_pid=
  await_child Action "$action_pid" || status=1
  action_pid=
  return "$status"
)

main

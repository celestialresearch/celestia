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
exec 5>&1

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

if [[ -n "${GOFLAGS:-}" &&
  ! "$GOFLAGS" =~ ^-p=[1-9][0-9]*$ ]]; then
  printf 'Uncontrolled Go test environment: GOFLAGS\n' >&2
  exit 1
fi
if [[ -n "${GOENV:-}" && "$GOENV" != off ]]; then
  printf 'Uncontrolled Go test environment: GOENV\n' >&2
  exit 1
fi
export GOENV=off

profile=${DEVCHECK_PROFILE:-full}
platform_lint=${DEVCHECK_PLATFORM_LINT:-true}
case "$profile" in
  config | full | quick | shell) ;;
  *)
    printf 'Unknown verification profile: %s\n' "$profile" >&2
    exit 2
    ;;
esac
case "$platform_lint" in
  false | true) ;;
  *)
    printf 'Invalid platform-lint selection: %s\n' "$platform_lint" >&2
    exit 2
    ;;
esac

check_names=()
check_statuses=()
check_outputs=()

section() {
  printf '\n==> %s\n' "$1"
}

record_result() {
  check_names+=("$1")
  check_statuses+=("$2")
  check_outputs+=("$3")
}

stop_failed() {
  record_result "$1" fail "$2"
  finish || true
  exit 1
}

skip_check() {
  printf '    %-42s[SKIP] %s\n' "$1" "$2"
  record_result "$1" skip "$2"
}

run_check() {
  local finished
  local output
  local started

  started=$(date +%s)
  printf '    %-42s' "$1"
  if output="$("${@:2}" 2>&1)"; then
    finished=$(date +%s)
    printf '[PASS] %ss\n' "$((finished - started))"
    record_result "$1" pass "$output"
    return
  fi

  finished=$(date +%s)
  printf '[FAIL] %ss\n' "$((finished - started))"
  stop_failed "$1" "$output"
}

run_no_output() {
  local finished
  local output
  local started

  started=$(date +%s)
  printf '    %-42s' "$1"
  if ! output="$("${@:2}" 2>&1)"; then
    finished=$(date +%s)
    printf '[FAIL] %ss\n' "$((finished - started))"
    stop_failed "$1" "$output"
  fi
  if [[ -n "$output" ]]; then
    finished=$(date +%s)
    printf '[FAIL] %ss\n' "$((finished - started))"
    stop_failed "$1" "$output"
  fi

  finished=$(date +%s)
  printf '[PASS] %ss\n' "$((finished - started))"
  record_result "$1" pass ''
}

run_subcheck() {
  local finished
  local output
  local started

  started=$(date +%s)
  if output="$("${@:2}" 2>&1)"; then
    finished=$(date +%s)
    printf '        %-34s[PASS] %ss\n' "$1" "$((finished - started))"
    [[ -z "$output" ]] || printf '%s\n' "$output"
    return
  fi

  finished=$(date +%s)
  printf '        %-34s[FAIL] %ss\n' "$1" "$((finished - started))"
  [[ -z "$output" ]] || printf '%s\n' "$output"
  return 1
}

go_packages() {
  go list -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' ./... 2>/dev/null |
    sed '/^[[:space:]]*$/d'
}

has_go_packages() {
  local packages

  packages=$(go_packages) || return 2
  [[ -n "$packages" ]]
}

check_config() {
  run_subcheck 'Go Lint Config' go tool golangci-lint config verify || return
  run_subcheck 'Action Policy' \
    bash ./.github/scripts/actioncheck.sh verify || return
  run_subcheck 'Workflow Syntax' go tool actionlint || return
  run_subcheck 'Rust Config' \
    bash ./.github/scripts/rustcheck.sh config || return
  run_subcheck 'Shell Syntax and Style' check_shell || return
}

check_shell() (
  local base=()
  local finished
  local output_dir
  local pid
  local pids=()
  local script_list
  local status=0
  local verification=()

  script_list=$(find .github/scripts -type f -name '*.sh' -print | sort) ||
    return
  while IFS= read -r script; do
    [[ -n "$script" ]] || continue
    case "$script" in
      .github/scripts/verification/*)
        verification+=("$script")
        ;;
      .github/scripts/actioncheck/* | .github/scripts/*.sh)
        base+=("$script")
        ;;
      *)
        printf 'Unassigned shell source: %s\n' "$script" >&2
        return 1
        ;;
    esac
  done <<<"$script_list"
  ((${#base[@]} > 0 && ${#verification[@]} > 0)) || return 1

  # Root tests source the verification fixture, so both analysis groups need it.
  base+=(.github/scripts/verification/fixture.sh)
  output_dir=$(mktemp -d "${TMPDIR:-/tmp}/celestia-shellcheck.XXXXXX") ||
    return 1
  trap 'rm -rf -- "$output_dir"' EXIT
  trap 'exit 1' HUP INT TERM

  go tool shellcheck --severity=style "${base[@]}" \
    >"$output_dir/base" 2>&1 &
  pids+=("$!")
  go tool shellcheck --severity=style "${verification[@]}" \
    >"$output_dir/verification" 2>&1 &
  pids+=("$!")

  for pid in "${pids[@]}"; do
    wait "$pid" || status=1
  done
  for finished in base verification; do
    [[ ! -s "$output_dir/$finished" ]] || cat -- "$output_dir/$finished"
  done
  return "$status"
)

discover_fuzz_targets() {
  go run ./tools/sourcepolicy go-fuzz-inventory
}

fuzz_smoke() {
  local count=0
  local discovery_output
  local discovery_started
  local finished
  local fuzz_time=${DEVCHECK_FUZZTIME:-1000x}
  local package
  local started
  local target
  local timeout=${DEVCHECK_FUZZ_TIMEOUT:-60s}

  discovery_started=$(date +%s)
  if ! discovery_output=$(discover_fuzz_targets); then
    printf 'Go fuzz-target discovery failed.\n'
    return 1
  fi
  finished=$(date +%s)
  printf '        %-34s[PASS] %ss\n' 'Fuzz Discovery' \
    "$((finished - discovery_started))"
  if [[ -z "$discovery_output" ]]; then
    printf 'No Go fuzz targets discovered.\n'
    return
  fi
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    count=$((count + 1))
    IFS=$'\t' read -r package target <<<"$entry"
    started=$(date +%s)
    if go test -run '^$' -fuzz "^${target}$" -fuzztime "$fuzz_time" \
      -timeout "$timeout" "$package"; then
      printf '        %-34s[PASS] %ss\n' "$target" \
        "$(($(date +%s) - started))"
    else
      printf '        %-34s[FAIL] %ss\n' "$target" \
        "$(($(date +%s) - started))"
      return 1
    fi
  done <<<"$discovery_output"
  printf 'Discovered %s Go fuzz target(s).\n' "$count"
}

finish() {
  local failed=0
  local index
  local output_label
  local passed=0
  local show_output=${DEVCHECK_OUTPUT:-failed}
  local skipped=0

  section 'Result'
  for index in "${!check_names[@]}"; do
    if [[ "${check_statuses[index]}" == pass ]]; then
      ((passed += 1))
    elif [[ "${check_statuses[index]}" == skip ]]; then
      ((skipped += 1))
    else
      ((failed += 1))
    fi
  done

  if ((failed == 0)); then
    printf '    [PASS] %s passed, %s skipped, 0 failed\n' "$passed" "$skipped"
  else
    printf '    [FAIL] %s passed, %s skipped, %s failed\n' \
      "$passed" "$skipped" "$failed"
  fi

  if [[ "$show_output" != none ]]; then
    for index in "${!check_names[@]}"; do
      if [[ "$show_output" != all && "${check_statuses[index]}" != fail ]]; then
        continue
      fi
      [[ -n "${check_outputs[index]}" ]] || continue
      output_label=$(printf '%s' "${check_statuses[index]}" | tr '[:lower:]' '[:upper:]')
      printf '\n----- BEGIN %s OUTPUT: %s -----\n' \
        "$output_label" "${check_names[index]}"
      printf '%s\n' "${check_outputs[index]}"
      printf '%s\n' "----- END $output_label OUTPUT: ${check_names[index]} -----"
    done
  fi

  ((failed == 0))
}

section 'Environment'
required_go_version=$(awk '$1 == "go" { print "go" $2; exit }' go.mod)
actual_go_version=$(go env GOVERSION)
printf '    %-16s %s\n' Go "$actual_go_version"
if [[ -n "$required_go_version" && "$actual_go_version" == "$required_go_version" ]]; then
  record_result 'Go Version' pass ''
else
  stop_failed 'Go Version' \
    "Go version mismatch: required $required_go_version, found $actual_go_version"
fi
printf '    %-16s %s/%s\n' Platform "$(go env GOOS)" "$(go env GOARCH)"
if [[ "$(go env CGO_ENABLED)" == 1 ]]; then
  printf '    %-16s %s (%s)\n' 'CGO (required)' true "$(go env CC)"
  record_result 'CGO (required)' pass ''
else
  printf '    %-16s %s\n' 'CGO (required)' 'false [FAIL]'
  stop_failed 'CGO (required)' \
    'CGO must be enabled for the required race-detector gate.'
fi
printf '    %-16s %s\n' golangci-lint \
  "$(go list -m -f '{{.Version}}' github.com/golangci/golangci-lint/v2)"
printf '    %-16s %s\n' govulncheck \
  "$(go list -m -f '{{.Version}}' golang.org/x/vuln)"
printf '    %-16s %s\n' shellcheck \
  "$(go list -m -f '{{.Version}}' github.com/wasilibs/go-shellcheck)"
if [[ "$profile" == full && -f rust-toolchain.toml ]]; then
  printf '    %-16s %s %s\n' Rust \
    "$(rustc --version | awk '{ print $1 }')" \
    "$(rustc --version | awk '{ print $2 }')"
  printf '    %-16s %s %s\n' Cargo \
    "$(cargo --version | awk '{ print $1 }')" \
    "$(cargo --version | awk '{ print $2 }')"
fi

section 'Project'
if [[ "$profile" == shell ]]; then
  run_check 'Policy' bash ./.github/scripts/policycheck.sh
  finish
  exit $?
fi
run_check 'Config' check_config
if [[ "$profile" == config ]]; then
  finish
  exit $?
fi
if [[ "$profile" != quick && "${DEVCHECK_SELF_TEST:-true}" == true ]]; then
  run_check 'Verification Scripts' env CELESTIA_PROGRESS_FD=5 \
    bash ./.github/scripts/verification_test.sh
else
  skip_check 'Verification Scripts' 'Full profile'
fi
run_check 'Policy' bash ./.github/scripts/policycheck.sh
run_check 'Modules' bash ./.github/scripts/modcheck.sh verify
run_check 'Currency Exceptions' bash ./.github/scripts/currencycheck.sh verify
run_check 'Licence Headers' bash ./.github/scripts/licencecheck.sh verify
if [[ "$profile" != quick && "${DEVCHECK_CURRENCY:-true}" == true ]]; then
  run_check 'Module Currency' bash ./.github/scripts/modcheck.sh cached-diff
  run_check 'Action Currency' bash ./.github/scripts/actioncheck.sh cached-currency
  run_check 'Version Currency' bash ./.github/scripts/currencycheck.sh currency
else
  skip_check 'Module Currency' 'Disabled for this platform job'
  skip_check 'Action Currency' 'Disabled for this platform job'
  skip_check 'Version Currency' 'Disabled for this platform job'
fi

if has_go_packages; then
  section 'Go'
  if [[ "$profile" == quick ]]; then
    skip_check 'Go Build' 'Covered by cached tests'
  else
    run_check 'Go Build' go build -trimpath -buildvcs=true ./...
  fi
  run_no_output 'Go Fix' go fix -diff ./...
  run_no_output 'Go Format' go tool golangci-lint fmt --diff
  run_check 'Go Vet' go vet ./...
  run_check 'Go Lint' go tool golangci-lint run
  if [[ "$profile" == quick ]]; then
    run_check 'Go Test' bash ./.github/scripts/testcheck.sh go quick
    skip_check 'Go Platform Lint' 'Full profile'
    skip_check 'Go Race' 'Full profile'
    skip_check 'Go Coverage' 'Full profile'
    skip_check 'Go Fuzz' 'Full profile'
    skip_check 'Go Vulnerabilities' 'Full profile'
  else
    if [[ "$platform_lint" == true ]]; then
      run_check 'Go Platform Lint' bash ./.github/scripts/platformlint.sh
    else
      skip_check 'Go Platform Lint' 'Owned by Linux AMD64'
    fi
    run_check 'Go Test' bash ./.github/scripts/testcheck.sh go standard
    run_check 'Go Race' bash ./.github/scripts/testcheck.sh go race
    run_check 'Go Coverage' bash ./.github/scripts/coveragecheck.sh verify
    run_check 'Go Fuzz' fuzz_smoke
    run_check 'Go Vulnerabilities' go tool govulncheck ./...
  fi
else
  package_discovery_status=$?
  if ((package_discovery_status == 2)); then
    stop_failed 'Go package discovery' \
      'go list failed while discovering Go source packages.'
  else
    skip_check 'Go Checks' 'No Go packages exist'
  fi
fi

section 'Rust'
if [[ -f Cargo.toml ]]; then
  run_check 'Rust Tools' bash ./.github/scripts/rustcheck.sh tools
  run_no_output 'Rust Format' cargo fmt --all -- --check
  run_check 'Rust Check' \
    cargo check --workspace --all-targets --locked
  run_check 'Rust Minimal Check' \
    cargo check --workspace --all-targets --no-default-features --locked
  run_check 'Rust Clippy' \
    cargo clippy --workspace --all-targets --locked -- -D warnings
  run_check 'Rust Test' bash ./.github/scripts/rustcheck.sh tests
  run_no_output 'Qualification Fixture Format' \
    cargo fmt --manifest-path worker/qualification-fixtures/Cargo.toml -- --check
  run_check 'Qualification Fixture Clippy' \
    cargo clippy --manifest-path worker/qualification-fixtures/Cargo.toml \
    --all-targets --locked -- -D warnings
  run_check 'Qualification Fixtures' \
    cargo test --manifest-path worker/qualification-fixtures/Cargo.toml --bins --locked
  if [[ "$profile" == quick ]]; then
    skip_check 'Qualification Fixture Docs' 'Full profile'
    skip_check 'Rust Docs' 'Full profile'
    skip_check 'Rust Coverage' 'Full profile'
    skip_check 'Rust Build Outputs' 'Full profile'
  else
    run_check 'Qualification Fixture Docs' env RUSTDOCFLAGS='-D warnings' \
      cargo doc --manifest-path worker/qualification-fixtures/Cargo.toml \
      --no-deps --locked
    run_check 'Rust Docs' env RUSTDOCFLAGS='-D warnings' \
      cargo doc --workspace --no-deps --locked
    run_check 'Rust Coverage' cargo llvm-cov --workspace --locked \
      --fail-under-lines 90
    run_check 'Rust Build Outputs' bash ./.github/scripts/rustcheck.sh artefacts
  fi
  if [[ "$profile" != quick && "${DEVCHECK_SUPPLY_CHAIN:-true}" == true ]]; then
    run_check 'Rust Advisories' cargo audit --deny warnings
    run_check 'Rust Dependencies' cargo deny check
    run_check 'Fixture Advisories' \
      cargo audit --deny warnings \
      --file worker/qualification-fixtures/Cargo.lock
    run_check 'Fixture Dependencies' \
      cargo deny --manifest-path worker/qualification-fixtures/Cargo.toml \
      check
  else
    skip_check 'Rust Advisories' 'Disabled for this platform job'
    skip_check 'Rust Dependencies' 'Disabled for this platform job'
    skip_check 'Fixture Advisories' 'Disabled for this platform job'
    skip_check 'Fixture Dependencies' 'Disabled for this platform job'
  fi
else
  skip_check 'Rust Checks' 'No Cargo workspace exists'
fi

finish

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

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

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
  record_result "$1" fail "$output"
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
    record_result "$1" fail "$output"
    return
  fi
  if [[ -n "$output" ]]; then
    finished=$(date +%s)
    printf '[FAIL] %ss\n' "$((finished - started))"
    record_result "$1" fail "$output"
    return
  fi

  finished=$(date +%s)
  printf '[PASS] %ss\n' "$((finished - started))"
  record_result "$1" pass ''
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
  local scripts=()

  go tool golangci-lint config verify
  go tool actionlint
  while IFS= read -r script; do
    scripts+=("$script")
  done < <(find .github/scripts -type f -name '*.sh' -print | sort)
  go tool shellcheck --severity=style "${scripts[@]}"
}

discover_fuzz_targets() {
  local list_output
  local package
  local packages

  packages=$(go list ./...) || return 1
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    list_output=$(go test -list '^Fuzz' "$package") || return 1
    awk -v package="$package" '/^Fuzz/ { print package "\t" $0 }' \
      <<<"$list_output"
  done <<<"$packages"
}

fuzz_smoke() {
  local count=0
  local discovery_output
  local fuzz_time=${DEVCHECK_FUZZTIME:-1000x}
  local package
  local status=0
  local target
  local timeout=${DEVCHECK_FUZZ_TIMEOUT:-60s}

  if ! discovery_output=$(discover_fuzz_targets); then
    printf 'Go fuzz-target discovery failed.\n'
    return 1
  fi
  if [[ -z "$discovery_output" ]]; then
    printf 'No Go fuzz targets discovered.\n'
    return
  fi
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    count=$((count + 1))
    IFS=$'\t' read -r package target <<<"$entry"
    printf 'Running %s in %s\n' "$target" "$package"
    go test -run '^$' -fuzz "^${target}$" -fuzztime "$fuzz_time" \
      -timeout "$timeout" "$package" || status=1
  done <<<"$discovery_output"
  printf 'Discovered %s Go fuzz target(s).\n' "$count"
  return "$status"
}

go_standard_tests() {
  go test -count=1 -shuffle=on ./...
}

go_race_tests() {
  go test -race -count=1 -shuffle=on ./...
}

rust_checks() {
  [[ -f Cargo.toml ]] || {
    printf 'No Cargo workspace exists; Rust checks are pending.\n'
    return
  }

  cargo fmt --all -- --check
  cargo check --workspace --all-targets --locked
  cargo test --workspace --all-targets --locked
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
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
  record_result 'Go Version' fail \
    "Go version mismatch: required $required_go_version, found $actual_go_version"
fi
printf '    %-16s %s/%s\n' Platform "$(go env GOOS)" "$(go env GOARCH)"
if [[ "$(go env CGO_ENABLED)" == 1 ]]; then
  printf '    %-16s %s (%s)\n' 'CGO (required)' true "$(go env CC)"
  record_result 'CGO (required)' pass ''
else
  printf '    %-16s %s\n' 'CGO (required)' 'false [FAIL]'
  record_result 'CGO (required)' fail \
    'CGO must be enabled for the required race-detector gate.'
fi
printf '    %-16s %s\n' golangci-lint \
  "$(go list -m -f '{{.Version}}' github.com/golangci/golangci-lint/v2)"
printf '    %-16s %s\n' govulncheck \
  "$(go list -m -f '{{.Version}}' golang.org/x/vuln)"
printf '    %-16s %s\n' shellcheck \
  "$(go list -m -f '{{.Version}}' github.com/wasilibs/go-shellcheck)"

section 'Project'
run_check 'Config' check_config
run_check 'Verification Scripts' bash ./.github/scripts/verification_test.sh
run_check 'Policy' bash ./.github/scripts/policycheck.sh
run_check 'Modules' bash ./.github/scripts/modcheck.sh verify
run_check 'Actions' bash ./.github/scripts/actioncheck.sh verify
run_check 'Licence Headers' bash ./.github/scripts/licencecheck.sh verify
if [[ "${DEVCHECK_CURRENCY:-true}" == true ]]; then
  run_check 'Module Currency' bash ./.github/scripts/modcheck.sh cached-diff
  run_check 'Action Currency' bash ./.github/scripts/actioncheck.sh cached-currency
else
  skip_check 'Module Currency' 'Disabled for this platform job'
  skip_check 'Action Currency' 'Disabled for this platform job'
fi

if has_go_packages; then
  run_check 'Compilation' go build -trimpath -buildvcs=true ./...

  section 'Code quality'
  run_no_output 'Modernisation (go fix)' go fix -diff ./...
  run_no_output 'Formatting' go tool golangci-lint fmt --diff
  run_check 'Go Vet' go vet ./...
  run_check 'Linting' go tool golangci-lint run

  section 'Tests'
  run_check 'Standard' go_standard_tests
  run_check 'Race Detection' go_race_tests
  run_check 'Coverage' bash ./.github/scripts/coveragecheck.sh cached
  run_check 'Fuzz Smoke' fuzz_smoke

  section 'Security'
  run_check 'Reachable Vulnerabilities' go tool govulncheck ./...
else
  package_discovery_status=$?
  if ((package_discovery_status == 2)); then
    record_result 'Go package discovery' fail \
      'go list failed while discovering Go source packages.'
  else
    skip_check 'Go Checks' 'No Go packages exist'
  fi
fi

section 'Rust'
if [[ -f Cargo.toml ]]; then
  run_check 'Rust Verification' rust_checks
else
  skip_check 'Rust Verification' 'No Cargo workspace exists'
fi

finish

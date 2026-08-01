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

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/celestia-depguard.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

lint=$(cd "$root" && go tool -n golangci-lint)
go_version=$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")

run_case() {
  name=$1
  importer=$2
  imported=$3
  want=$4
  message=$5
  case_root="$work/$name"
  mkdir -p "$case_root/$(dirname -- "$importer")"
  cp "$root/.golangci.yml" "$case_root/.golangci.yml"
  printf 'module celestia.research/celestia\n\ngo %s\n' "$go_version" >"$case_root/go.mod"

  case "$imported" in
    celestia.research/celestia/*)
      target=${imported#celestia.research/celestia/}
      mkdir -p "$case_root/$target"
      printf 'package target\n' >"$case_root/$target/target.go"
      ;;
  esac
  cat >"$case_root/$importer" <<EOF
package fixture

import _ "$imported"
EOF

  set +e
  output=$(cd "$case_root" && "$lint" run --enable-only=depguard --config .golangci.yml ./... 2>&1)
  status=$?
  set -e
  if [[ "$want" == pass && "$status" -ne 0 ]]; then
    printf '%s rejected an allowed import:\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  if [[ "$want" == reject ]] &&
    { [[ "$status" -eq 0 ]] || [[ "$output" != *"$message"* ]]; }; then
    printf '%s accepted a forbidden import:\n%s\n' "$name" "$output" >&2
    exit 1
  fi
}

run_case production-allow internal/example/example.go fmt pass ''
run_case production-reject internal/example/example.go \
  celestia.research/celestia/tools/sourcepolicy reject \
  'Production runtime must not import repository tools'
run_case execution-allow internal/processsupervision/example.go fmt pass ''
run_case execution-reject internal/processsupervision/example.go \
  celestia.research/celestia/internal/urloperation reject \
  'execution packages must not import legacy operations'
run_case execution-test-reject internal/processsupervision/rogue_test.go \
  celestia.research/celestia/internal/urloperation reject \
  'execution packages must not import legacy operations'
run_case execution-integration-allow \
  internal/processsupervision/supervisor_windows_test.go \
  celestia.research/celestia/internal/urladmission pass ''
run_case execution-integration-reject \
  internal/processsupervision/supervisor_windows_test.go \
  celestia.research/celestia/internal/urloperation reject \
  'legacy supervision integration test imports only declared dependencies'
run_case command-allow cmd/example/main.go \
  celestia.research/celestia/internal/operation/urlreference pass ''
run_case command-reject cmd/example/main.go \
  celestia.research/celestia/internal/operation/urlreference/transform reject \
  'commands import declared operation roots only'
run_case operation-allow internal/urloperation/example.go \
  celestia.research/celestia/internal/urladmission pass ''
run_case operation-reject internal/urloperation/example.go \
  celestia.research/celestia/internal/operation/other reject \
  'operation roots import only their own declared subpackages'
run_case attempt-allow internal/attemptstore/example.go \
  celestia.research/celestia/internal/workerprotocolv1 pass ''
run_case attempt-reject internal/attemptstore/example.go \
  celestia.research/celestia/internal/processsupervision reject \
  'attempt evidence imports only lower URL-reference owners'
run_case admission-allow internal/urladmission/example.go \
  celestia.research/celestia/internal/workerprotocolv1 pass ''
run_case admission-reject internal/urladmission/example.go \
  celestia.research/celestia/internal/attemptstore reject \
  'admission imports only protocol and transformation'
run_case protocol-allow internal/workerprotocolv1/example.go \
  celestia.research/celestia/internal/urlreferencev1 pass ''
run_case protocol-reject internal/workerprotocolv1/example.go \
  celestia.research/celestia/internal/urladmission reject \
  'protocol imports only transformation'
run_case transform-allow internal/urlreferencev1/example.go fmt pass ''
run_case transform-reject internal/urlreferencev1/example.go \
  celestia.research/celestia/internal/processsupervision reject \
  'transformation must not import other Production internals'

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
root=$1
work_dir=$2
governed_manifests=(
  docs/contracts/governed_url_reference_v1.json
  docs/contracts/cel_struct_001.json
  docs/contracts/cel_struct_003.json
  docs/contracts/cel_struct_004a.json
  docs/contracts/cel_struct_004b.json
  docs/contracts/cel_struct_004c.json
  docs/contracts/cel_struct_004d.json
  docs/contracts/cel_struct_004e.json
  docs/contracts/cel_struct_005.json
  docs/contracts/cel_split_001.json
  docs/contracts/cel_split_002.json
  docs/contracts/cel_split_003.json
  docs/contracts/cel_split_004.json
  docs/contracts/cel_split_005.json
  docs/contracts/cel_split_006.json
  docs/contracts/cel_split_007.json
  docs/contracts/cel_split_008.json
)
source_policy_files=(
  tools/sourcepolicy/architecture_action_policy.go
  tools/sourcepolicy/architecture_attempt_split.go
  tools/sourcepolicy/architecture_documentation.go
  tools/sourcepolicy/architecture_evaluation.go
  tools/sourcepolicy/architecture_imports.go
  tools/sourcepolicy/architecture_inventory.go
  tools/sourcepolicy/architecture_limits.go
  tools/sourcepolicy/architecture_operation_split.go
  tools/sourcepolicy/architecture_ownership.go
  tools/sourcepolicy/architecture_paths.go
  tools/sourcepolicy/architecture_policy.go
  tools/sourcepolicy/architecture_rust.go
  tools/sourcepolicy/architecture_scripts.go
  tools/sourcepolicy/architecture_source_policy.go
  tools/sourcepolicy/architecture_split.go
  tools/sourcepolicy/architecture_supervision_split.go
  tools/sourcepolicy/architecture_values.go
  tools/sourcepolicy/architecture.go
  tools/sourcepolicy/cargo.go
  tools/sourcepolicy/cargoconfig.go
  tools/sourcepolicy/doc.go
  tools/sourcepolicy/executable_inventory.go
  tools/sourcepolicy/gobuildtags.go
  tools/sourcepolicy/gocgo.go
  tools/sourcepolicy/goexit.go
  tools/sourcepolicy/gofallback.go
  tools/sourcepolicy/goinspect.go
  tools/sourcepolicy/golangci.go
  tools/sourcepolicy/goload.go
  tools/sourcepolicy/goskip.go
  tools/sourcepolicy/gotarget.go
  tools/sourcepolicy/gotestmain.go
  tools/sourcepolicy/inventory.go
  tools/sourcepolicy/main.go
  tools/sourcepolicy/manifest.go
  tools/sourcepolicy/module_replacement.go
  tools/sourcepolicy/rustpolicy.go
  tools/sourcepolicy/rustsyntax.go
  tools/sourcepolicy/scan.go
  tools/sourcepolicy/source_open_other.go
  tools/sourcepolicy/source_open_unix.go
  tools/sourcepolicy/source.go
  tools/sourcepolicy/suppression.go
  tools/sourcepolicy/testinventory.go
)
mkdir -p \
  "$work_dir/.github/scripts" \
  "$work_dir/a" \
  "$work_dir/b" \
  "$work_dir/docs/contracts" \
  "$work_dir/tools/sourcepolicy"
cp "$root/.github/scripts/coveragecheck.sh" \
  "$root/.github/scripts/modcheck.sh" \
  "$root/.github/scripts/policycheck.sh" \
  "$work_dir/.github/scripts/"
if ! diff -u \
  <(printf '%s\n' "${source_policy_files[@]}" | LC_ALL=C sort) \
  <(git -C "$root" ls-files -- 'tools/sourcepolicy/*.go' |
    grep -Ev '_test\.go$' | LC_ALL=C sort); then
  printf 'source-policy fixture inventory differs from tracked source\n' >&2
  return 1
fi
for source_policy_file in "${source_policy_files[@]}"; do
  cp -- "$root/$source_policy_file" "$work_dir/tools/sourcepolicy/"
done
printf '%s\n' "${governed_manifests[@]}" | LC_ALL=C sort \
  >"$work_dir/governed-manifests"
if ! git -C "$root" ls-files -- 'docs/contracts/*.json' \
  | LC_ALL=C sort >"$work_dir/tracked-governed-manifests"; then
  printf 'failed to inventory tracked governed manifests\n' >&2
  return 1
fi
if ! diff -u "$work_dir/governed-manifests" \
  "$work_dir/tracked-governed-manifests"; then
  printf 'governed manifest fixture inventory differs from tracked contracts\n' >&2
  return 1
fi
rm -- "$work_dir/tracked-governed-manifests"
for manifest in "${governed_manifests[@]}"; do
  cp -- "$root/$manifest" "$work_dir/$manifest"
done

)

main "$@"

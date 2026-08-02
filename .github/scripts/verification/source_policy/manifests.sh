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
output=
status=0
printf 'default 90\ncache-max-age-minutes 0\npackage celestia.research/coverage/tools/sourcepolicy 0\n' \
  >"$work_dir/.github/.coverage"
cat >"$work_dir/go.mod" <<'EOF'
module celestia.research/coverage

go 1.26.5

require (
	github.com/BurntSushi/toml v1.6.0
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.38.0
	golang.org/x/sys v0.47.0
	golang.org/x/tools v0.48.0
	mvdan.cc/sh/v3 v3.13.1
)

require golang.org/x/sync v0.22.0 // indirect
EOF
awk '
  $1 == "github.com/BurntSushi/toml" &&
    ($2 == "v1.6.0" || $2 == "v1.6.0/go.mod") ||
  $1 == "github.com/go-quicktest/qt" &&
    ($2 == "v1.101.0" || $2 == "v1.101.0/go.mod") ||
  $1 == "github.com/google/go-cmp" &&
    ($2 == "v0.7.0" || $2 == "v0.7.0/go.mod") ||
  $1 == "github.com/kr/pretty" &&
    ($2 == "v0.3.1" || $2 == "v0.3.1/go.mod") ||
  $1 == "github.com/kr/text" &&
    ($2 == "v0.2.0" || $2 == "v0.2.0/go.mod") ||
  $1 == "github.com/rogpeppe/go-internal" &&
    ($2 == "v1.14.1" || $2 == "v1.14.1/go.mod") ||
  $1 == "golang.org/x/mod" &&
    ($2 == "v0.38.0" || $2 == "v0.38.0/go.mod") ||
  $1 == "golang.org/x/sync" &&
    ($2 == "v0.22.0" || $2 == "v0.22.0/go.mod") ||
  $1 == "golang.org/x/sys" &&
    ($2 == "v0.47.0" || $2 == "v0.47.0/go.mod") ||
  $1 == "golang.org/x/tools" &&
    ($2 == "v0.48.0" || $2 == "v0.48.0/go.mod") ||
  $1 == "go.yaml.in/yaml/v3" &&
    ($2 == "v3.0.5" || $2 == "v3.0.5/go.mod") ||
  $1 == "mvdan.cc/sh/v3" &&
    ($2 == "v3.13.1" || $2 == "v3.13.1/go.mod")
' "$root/go.sum" >"$work_dir/go.sum"
LC_ALL=C sort "$work_dir/go.sum" >"$work_dir/go.sum.sorted"
mv "$work_dir/go.sum.sorted" "$work_dir/go.sum"
cat >"$work_dir/xsys_fixture_windows.go" <<'EOF'
// Copyright © 2026 @sudocelestia. All rights reserved.
//
// PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
//
// No licence, permission or authorisation is granted to use, copy, modify,
// compile, execute, distribute, publish, sublicense or otherwise exploit this
// file, except to the limited extent unavoidably permitted by applicable law
// or GitHub's Terms of Service.
//
// See the LICENSE file at the repository root for the complete terms.

//go:build windows

package fixture

import _ "golang.org/x/sys/windows"
EOF
git -C "$work_dir" init -q
for workspace_file in go.work go.work.sum; do
  printf 'fixture\n' >"$work_dir/$workspace_file"
  set +e
  output=$(cd "$work_dir" &&
    bash .github/scripts/policycheck.sh workspace 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted repository %s\n' "$workspace_file" >&2
    return 1
  }
  grep -Fq "$workspace_file: Go workspace files are prohibited" \
    <<<"$output" || {
    printf 'policy output omitted the Go workspace diagnostic:\n%s\n' \
      "$output" >&2
    return 1
  }
  rm -- "$work_dir/$workspace_file"
done
(
  cd "$work_dir"
  bash .github/scripts/policycheck.sh manifest
) || {
  printf 'policy check rejected the reviewed governed manifest\n' >&2
  return 1
}
mkdir -p "$work_dir/config-bin"
(
  cd "$work_dir"
  go build -o "$work_dir/config-bin/sourcepolicy" ./tools/sourcepolicy
)
for omission in \
  'gotarget.go|undefined: buildTarget' \
  'gocgo.go|undefined: cgoPolicyImporter' \
  'rustsyntax.go|undefined: rustPolicyToken'; do
  omitted_file=${omission%%|*}
  expected_diagnostic=${omission#*|}
  rm -- "$work_dir/tools/sourcepolicy/$omitted_file"
  set +e
  output=$(cd "$work_dir" && go build ./tools/sourcepolicy 2>&1)
  status=$?
  set -e
  cp -- "$root/tools/sourcepolicy/$omitted_file" \
    "$work_dir/tools/sourcepolicy/"
  [[ "$status" -ne 0 ]] || {
    printf 'source-policy fixture built without %s\n' "$omitted_file" >&2
    return 1
  }
  grep -Fq "$expected_diagnostic" <<<"$output" || {
    printf 'source-policy fixture omission of %s failed unexpectedly:\n%s\n' \
      "$omitted_file" "$output" >&2
    return 1
  }
done
while IFS= read -r manifest; do
  printf '\n' >>"$work_dir/$manifest"
  set +e
  output=$(cd "$work_dir" &&
    "$work_dir/config-bin/sourcepolicy" manifest 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted changed manifest %s\n' "$manifest" >&2
    return 1
  }
  grep -Fq 'governed manifest differs from its reviewed form' <<<"$output" || {
    printf 'policy output omitted manifest drift for %s:\n%s\n' \
      "$manifest" "$output" >&2
    return 1
  }
  cp -- "$root/$manifest" "$work_dir/$manifest"
  rm -- "$work_dir/$manifest"
  set +e
  output=$(cd "$work_dir" &&
    "$work_dir/config-bin/sourcepolicy" manifest 2>&1)
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'policy check accepted missing manifest %s\n' "$manifest" >&2
    return 1
  }
  cp -- "$root/$manifest" "$work_dir/$manifest"
done <"$work_dir/governed-manifests"
)

main "$@"

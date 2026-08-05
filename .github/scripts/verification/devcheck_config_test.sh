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

verify_module_cache() (
  local cache_root calls checksums checker first flags fourth key manifest
  local module_dir second third
  local root=$1
  local cache_work=$2

  module_dir=$cache_work/module-cache
  mkdir -p "$module_dir/.github/scripts"
  cp "$root/.github/scripts/modcheck.sh" "$module_dir/.github/scripts/"
  printf 'module fixture.invalid/cache\n\ngo 1.25.1\n' >"$module_dir/go.mod"
  printf 'fixture\n' >"$module_dir/go.sum"
  printf 'package cache\n\nconst Value = 1\n' >"$module_dir/cache.go"
  git -C "$module_dir" init -q
  git -C "$module_dir" config user.name Fixture
  git -C "$module_dir" config user.email fixture@example.invalid
  git -C "$module_dir" config commit.gpgsign false
  git -C "$module_dir" config core.autocrlf false
  git -C "$module_dir" add -A
  git -C "$module_dir" commit -q -m base

  cd "$module_dir"
  # shellcheck source=.github/scripts/modcheck.sh
  # shellcheck disable=SC1091 # The source is copied into the isolated fixture.
  source ./.github/scripts/modcheck.sh

  first=$(cache_key)
  printf '\n' >>cache.go
  second=$(cache_key)
  [[ "$first" != "$second" ]] || {
    printf 'module cache ignored Go source content\n' >&2
    return 1
  }
  git checkout -q -- cache.go

  git mv cache.go renamed.go
  third=$(cache_key)
  [[ "$first" != "$third" ]] || {
    printf 'module cache ignored a Go source path\n' >&2
    return 1
  }
  git reset -q --hard HEAD

  fourth=$(GOPROXY=https://proxy.invalid cache_key)
  [[ "$first" != "$fourth" ]] || {
    printf 'module cache ignored Go module resolution policy\n' >&2
    return 1
  }
  printf '\nrequire example.invalid/dependency v0.0.0\n' >>go.mod
  manifest=$(cache_key)
  [[ "$first" != "$manifest" ]] || {
    printf 'module cache ignored the module manifest\n' >&2
    return 1
  }
  git checkout -q -- go.mod
  printf 'changed\n' >go.sum
  checksums=$(cache_key)
  [[ "$first" != "$checksums" ]] || {
    printf 'module cache ignored the module checksum inventory\n' >&2
    return 1
  }
  git checkout -q -- go.sum
  printf '\n' >>.github/scripts/modcheck.sh
  checker=$(cache_key)
  [[ "$first" != "$checker" ]] || {
    printf 'module cache ignored its checker\n' >&2
    return 1
  }
  git checkout -q -- .github/scripts/modcheck.sh
  flags=$(GOFLAGS=-mod=readonly cache_key)
  [[ "$first" != "$flags" ]] || {
    printf 'module cache ignored Go build flags\n' >&2
    return 1
  }

  cache_root=$cache_work/module-result-cache
  key=$(cache_key)
  mkdir -p "$cache_root/modcheck"
  printf 'wrong-key\n' >"$cache_root/modcheck/$key"
  calls=0
  # shellcheck disable=SC2329 # Invoked indirectly by check_cached_update_diff.
  verify_modules() { calls=$((calls + 1)); }
  # shellcheck disable=SC2329 # Invoked indirectly by check_cached_update_diff.
  check_update_diff() { calls=$((calls + 1)); }
  MODCHECK_CACHE_MAX_AGE_MINUTES=1440 check_cached_update_diff >/dev/null
  [[ "$calls" -eq 2 && "$(<"$cache_root/modcheck/$key")" == "$key" ]] || {
    printf 'module cache trusted an invalid marker\n' >&2
    return 1
  }
  MODCHECK_CACHE_MAX_AGE_MINUTES=1440 check_cached_update_diff >/dev/null
  [[ "$calls" -eq 2 ]] || {
    printf 'module cache ignored a valid marker\n' >&2
    return 1
  }
)

main() (
root=${CELESTIA_VERIFICATION_ROOT:-$(cd -- "$script_dir/../../.." && pwd)}
work_dir=$(new_verification_work verification-devcheck-config)
trap 'cleanup_verification "$work_dir"' EXIT
trap '[[ $- != *e* ]] || printf "verification-devcheck-config failed at line %d: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
trap 'exit 1' HUP INT TERM
output=
status=0
fake_bin="$work_dir/bin"
real_bash=$(command -v bash)
mkdir -p -- "$fake_bin"

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

set +e
output=$(
  cd "$root" &&
    DEVCHECK_PLATFORM_LINT=invalid DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -eq 2 ]] || {
  printf 'devcheck accepted an invalid platform-lint selection\n' >&2
  return 1
}
grep -Fq 'Invalid platform-lint selection: invalid' <<<"$output" || {
  printf 'platform-lint selection rejection omitted the diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}

set +e
output=$(
  cd "$root" &&
    DEVCHECK_GO_CAMPAIGN=invalid DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -eq 2 ]] || {
  printf 'devcheck accepted an invalid Go campaign selection\n' >&2
  return 1
}
grep -Fq 'Invalid Go campaign selection: invalid' <<<"$output" || {
  printf 'Go campaign rejection omitted the diagnostic:\n%s\n' "$output" >&2
  return 1
}

set +e
output=$(
  cd "$root" &&
    GOFLAGS='-run=^$' DEVCHECK_PROFILE=config \
      bash .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'devcheck accepted an inherited Go test filter\n' >&2
  return 1
}
grep -Fq 'Uncontrolled Go test environment: GOFLAGS' <<<"$output" || {
  printf 'Go test filter rejection omitted the diagnostic:\n%s\n' \
    "$output" >&2
  return 1
}

cat >"$fake_bin/bash" <<'EOF'
#!/bin/sh
case "$1" in
*.github/scripts/policycheck.sh)
  : >"$CELESTIA_POLICY_MARKER"
  exit
  ;;
*)
  : >"$CELESTIA_UNEXPECTED_SCRIPT_MARKER"
  exit 99
  ;;
esac
EOF
chmod +x "$fake_bin/bash"
set +e
output=$(
  cd "$root" &&
    CELESTIA_POLICY_MARKER="$work_dir/policy" \
    CELESTIA_UNEXPECTED_SCRIPT_MARKER="$work_dir/unexpected" \
    PATH="$fake_bin:$PATH" DEVCHECK_PROFILE=shell \
      "$real_bash" .github/scripts/devcheck.sh 2>&1
)
status=$?
set -e
if [[ "$status" -ne 0 || ! -e "$work_dir/policy" ||
  -e "$work_dir/unexpected" ]]; then
  printf 'bounded devcheck did not run only policy:\n%s\n' "$output" >&2
  return 1
fi

rm -- "$fake_bin/bash"
real_go=$(command -v go)
cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
if [ "$1" = tool ] && [ "$2" = shellcheck ]; then
  shift 2
  printf '%s\n' "$*" >>"$CELESTIA_SHELLCHECK_LOG"
  case "$*" in
    *"$CELESTIA_SHELLCHECK_FAILURE"*)
      printf 'controlled ShellCheck failure: %s\n' \
        "$CELESTIA_SHELLCHECK_FAILURE" >&2
      exit 1
      ;;
  esac
  exit
fi
exec "$CELESTIA_REAL_GO" "$@"
EOF
chmod +x "$fake_bin/go"
for failed_path in \
  .github/scripts/actioncheck/cache_test.sh \
  .github/scripts/changecheck.sh \
  .github/scripts/verification/coverage_test.sh \
  .github/scripts/verification/source_policy/architecture.sh; do
  shellcheck_log="$work_dir/shellcheck.log"
  : >"$shellcheck_log"
  set +e
  output=$(
    cd "$root" &&
      CELESTIA_REAL_GO="$real_go" \
      CELESTIA_SHELLCHECK_FAILURE="$failed_path" \
      CELESTIA_SHELLCHECK_LOG="$shellcheck_log" \
      PATH="$fake_bin:$PATH" DEVCHECK_PROFILE=config \
        "$real_bash" .github/scripts/devcheck.sh 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || {
    printf 'Config accepted a failed ShellCheck group: %s\n' "$failed_path" >&2
    return 1
  }
  grep -Fq "controlled ShellCheck failure: $failed_path" <<<"$output" || {
    printf 'Config omitted the ShellCheck failure: %s\n%s\n' \
      "$failed_path" "$output" >&2
    return 1
  }
  [[ $(wc -l <"$shellcheck_log") -eq 4 ]] || {
    printf 'Config did not run all ShellCheck groups: %s\n' "$failed_path" >&2
    return 1
  }
done

cat >"$fake_bin/go" <<'EOF'
#!/bin/sh
case "$*" in
  'env GOVERSION') printf '%s\n' "$CELESTIA_FAKE_GO_VERSION" ;;
  'env GOOS') printf '%s\n' windows ;;
  'env GOARCH') printf '%s\n' amd64 ;;
  'env CGO_ENABLED') printf '%s\n' 1 ;;
  'env CC') printf '%s\n' gcc ;;
  'list -m -f {{.Version}} github.com/golangci/golangci-lint/v2') printf '%s\n' v2.12.2 ;;
  'list -m -f {{.Version}} golang.org/x/vuln') printf '%s\n' v1.6.0 ;;
  'list -m -f {{.Version}} github.com/wasilibs/go-shellcheck') printf '%s\n' v0.11.1 ;;
  'tool golangci-lint config verify' | 'tool actionlint' | tool\ shellcheck*) ;;
  'mod tidy -diff' | 'mod verify')
    printf '%s\n' "$*" >>"$CELESTIA_GO_COMMAND_LOG"
    ;;
  *) printf 'unexpected Go command: %s\n' "$*" >&2; exit 99 ;;
esac
EOF
cat >"$fake_bin/bash" <<'EOF'
#!/bin/sh
case "$1" in
  *.github/scripts/modcheck.sh)
    printf '%s\n' "$2" >"$CELESTIA_MODULE_MODE_LOG"
    exit 97
    ;;
  *.github/scripts/actioncheck.sh | *.github/scripts/rustcheck.sh | \
    *.github/scripts/policycheck.sh)
    exit
    ;;
  *)
    printf 'unexpected Bash command: %s\n' "$*" >&2
    exit 99
    ;;
esac
EOF
chmod +x "$fake_bin/go" "$fake_bin/bash"
fake_go_version=go$(awk '$1 == "go" { print $2; exit }' "$root/go.mod")
for module_mode in tidy verify; do
  : >"$work_dir/go-command"
  CELESTIA_FAKE_GO_VERSION="$fake_go_version" \
    CELESTIA_GO_COMMAND_LOG="$work_dir/go-command" PATH="$fake_bin:$PATH" \
    "$real_bash" "$root/.github/scripts/modcheck.sh" "$module_mode"
  if [[ "$module_mode" == tidy ]]; then
    expected_commands='mod tidy -diff'
  else
    expected_commands=$'mod verify\nmod tidy -diff'
  fi
  [[ "$(<"$work_dir/go-command")" == "$expected_commands" ]] || {
    printf 'modcheck %s selected the wrong Go commands\n' "$module_mode" >&2
    return 1
  }
done
for profile_mode in quick:tidy full:verify; do
  profile=${profile_mode%%:*}
  expected=${profile_mode#*:}
  set +e
  output=$(
    cd "$root" &&
      CELESTIA_MODULE_MODE_LOG="$work_dir/module-mode" \
      CELESTIA_FAKE_GO_VERSION="$fake_go_version" \
      CELESTIA_GO_COMMAND_LOG="$work_dir/go-command" \
      PATH="$fake_bin:$PATH" DEVCHECK_PROFILE="$profile" \
      DEVCHECK_SELF_TEST=false "$real_bash" .github/scripts/devcheck.sh 2>&1
  )
  status=$?
  set -e
  [[ "$status" -ne 0 && -f "$work_dir/module-mode" &&
    "$(<"$work_dir/module-mode")" == "$expected" ]] || {
    printf 'devcheck %s selected the wrong module mode:\n%s\n' \
      "$profile" "$output" >&2
    return 1
  }
done
verify_module_cache "$root" "$work_dir"
)

main

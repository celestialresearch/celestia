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

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/celestia-modcheck-cache.XXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

repo=$work/repo
mkdir -p "$repo/.github/scripts"
cp "$root/.github/scripts/modcheck.sh" "$repo/.github/scripts/modcheck.sh"
printf 'module fixture.invalid/cache\n\ngo 1.25.1\n' >"$repo/go.mod"
printf 'fixture\n' >"$repo/go.sum"
printf 'package cache\n\nconst Value = 1\n' >"$repo/cache.go"
git -C "$repo" init -q
git -C "$repo" config user.name Fixture
git -C "$repo" config user.email fixture@example.invalid
git -C "$repo" config commit.gpgsign false
git -C "$repo" config core.autocrlf false
git -C "$repo" add -A
git -C "$repo" commit -q -m base

cd "$repo"
# shellcheck source=.github/scripts/modcheck.sh
source ./.github/scripts/modcheck.sh

first=$(cache_key)
printf '\n' >>cache.go
second=$(cache_key)
[[ "$first" != "$second" ]] || {
  printf 'module cache ignored Go source content\n' >&2
  exit 1
}
git checkout -q -- cache.go

git mv cache.go renamed.go
third=$(cache_key)
[[ "$first" != "$third" ]] || {
  printf 'module cache ignored a Go source path\n' >&2
  exit 1
}
git reset -q --hard HEAD

fourth=$(GOPROXY=https://proxy.invalid cache_key)
[[ "$first" != "$fourth" ]] || {
  printf 'module cache ignored Go module resolution policy\n' >&2
  exit 1
}

printf '\nrequire example.invalid/dependency v0.0.0\n' >>go.mod
manifest=$(cache_key)
[[ "$first" != "$manifest" ]] || {
  printf 'module cache ignored the module manifest\n' >&2
  exit 1
}
git checkout -q -- go.mod

printf 'changed\n' >go.sum
checksums=$(cache_key)
[[ "$first" != "$checksums" ]] || {
  printf 'module cache ignored the module checksum inventory\n' >&2
  exit 1
}
git checkout -q -- go.sum

printf '\n' >>.github/scripts/modcheck.sh
checker=$(cache_key)
[[ "$first" != "$checker" ]] || {
  printf 'module cache ignored its checker\n' >&2
  exit 1
}
git checkout -q -- .github/scripts/modcheck.sh

flags=$(GOFLAGS=-mod=readonly cache_key)
[[ "$first" != "$flags" ]] || {
  printf 'module cache ignored Go build flags\n' >&2
  exit 1
}

cache_root=$work/cache
key=$(cache_key)
mkdir -p "$cache_root/modcheck"
printf 'wrong-key\n' >"$cache_root/modcheck/$key"
calls=0
verify_modules() { calls=$((calls + 1)); }
check_update_diff() { calls=$((calls + 1)); }
MODCHECK_CACHE_MAX_AGE_MINUTES=1440 check_cached_update_diff >/dev/null
[[ "$calls" -eq 2 && "$(<"$cache_root/modcheck/$key")" == "$key" ]] || {
  printf 'module cache trusted an invalid marker\n' >&2
  exit 1
}
MODCHECK_CACHE_MAX_AGE_MINUTES=1440 check_cached_update_diff >/dev/null
[[ "$calls" -eq 2 ]] || {
  printf 'module cache ignored a valid marker\n' >&2
  exit 1
}

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
work_dir=$2
output=
status=0
printf '%s%s\n' '// #no' 'sec -- broad' >"$work_dir/broad_suppression.go"
printf '%s%s\n' '//no' 'lint -- broad' >"$work_dir/broad_nolint.go"
printf '%s%s\n' '//no' 'lint:all -- reasoned blanket suppression' \
  >"$work_dir/reasoned_broad_nolint.go"
printf '%s%s\n' '# shell' 'check disable=SC2329' \
  >"$work_dir/broad_shellcheck.sh"
printf '%s%s\n' '#shell' 'check disable=SC2086' \
  >"$work_dir/compact_shellcheck.sh"
printf '%s\n' "printf '%s\\n' '# shellcheck disable=SC2086'" \
  >"$work_dir/shellcheck_literal.sh"
cat >"$work_dir/shellcheck_data.sh" <<'EOF'
cat <<'PAYLOAD'
# shellcheck disable=SC2086
PAYLOAD
printf '%s\n' "multiline
# shellcheck disable=SC2086"
EOF
printf '%s%s\n' '#[al' 'low(clippy::needless_pass_by_value)]' \
  >"$work_dir/broad_clippy.rs"
printf '%s%s\n' '#[al' \
  'low(clippy::all, reason = "reasoned blanket suppression")]' \
  >"$work_dir/reasoned_broad_clippy.rs"
printf '%s%s\n' '#![al' 'low(clippy::all)]' \
  >"$work_dir/inner_broad_clippy.rs"
printf '%s%s\n' '#![ex' 'pect(clippy::all)]' \
  >"$work_dir/inner_broad_expect.rs"
printf '%s\n' \
  "macro_rules! lint { (\$level:ident) => { #[\$level(clippy::all)] fn f() {} } }" \
  >"$work_dir/dynamic_attribute.rs"
cat >"$work_dir/Cargo.toml" <<'EOF'
[package]
name = "fixture"
version = "0.0.0"
edition = "2024"

[lib]
doctest = false

[profile.test]
debug-assertions = false

[dependencies]
fixture = { version = "1", optional = true }

[patch.crates-io]
fixture = { path = "../fixture" }

[lints.rustdoc]
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

[target.x86_64-pc-windows-msvc]
linker = "linker.exe"

[profile.test]
debug-assertions = false
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
if grep -Eq 'shellcheck_(literal|data)\.sh' <<<"$output"; then
  printf 'policy check treated a shell string as a suppression:\n%s\n' \
    "$output" >&2
  return 1
fi
for diagnostic in \
  'invalid gosec suppression' \
  'invalid golangci-lint suppression' \
  'invalid ShellCheck suppression' \
  'invalid Clippy suppression' \
  'dynamic Rust attributes are prohibited' \
  'Cargo library targets are prohibited' \
  'optional Cargo dependencies require an explicit test matrix' \
  'Cargo profile overrides are prohibited' \
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
  "$work_dir/dynamic_attribute.rs" \
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
cat >"$work_dir/Cargo.toml" <<'EOF'
[workspace]
members = ["worker/url-reference"]
exclude = ["worker/qualification-fixtures"]
EOF
cat >"$work_dir/worker/url-reference/Cargo.toml" <<'EOF'
[package]
name = "fixture"
version = "0.0.0"
edition = "2024"
EOF
cat >"$work_dir/worker/qualification-fixtures/Cargo.toml" <<'EOF'
[package]
name = "qualification-fixture"
version = "0.0.0"
edition = "2024"
EOF
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh suppressions 2>&1) || {
  printf 'policy check rejected narrow suppressions:\n%s\n' "$output" >&2
  return 1
}
rm -- \
  "$work_dir/valid_suppressions.go" \
  "$work_dir/valid_suppressions.sh" \
  "$work_dir/valid_suppressions.rs" \
  "$work_dir/Cargo.toml" \
  "$work_dir/worker/url-reference/Cargo.toml" \
  "$work_dir/worker/qualification-fixtures/Cargo.toml"

)

main "$@"

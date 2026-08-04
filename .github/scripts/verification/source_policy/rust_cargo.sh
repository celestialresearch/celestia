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
cat >"$work_dir/ignored_test.rs" <<'EOF'
#[test]
#[ignore]
fn ignored() {}
EOF
set +e
output=$(cd "$work_dir" &&
  "$work_dir/config-bin/sourcepolicy" test-skips 2>&1)
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

mkdir -p "$work_dir/worker/url-reference/src"
mkdir -p "$work_dir/worker/qualification-fixtures"
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
cat >"$work_dir/worker/url-reference/src/lib.rs" <<'EOF'
/// ```
/// use std::os::unix::process::CommandExt;
/// let _ = std::process::Command::new("true").exec();
/// assert!(false);
/// ```
pub fn documented() {}
EOF
set +e
output=$(cd "$work_dir" &&
  bash .github/scripts/policycheck.sh suppressions 2>&1)
status=$?
set -e
[[ "$status" -ne 0 ]] || {
  printf 'policy check accepted a Cargo library target\n' >&2
  return 1
}
grep -Fq 'Cargo library targets are prohibited' \
  <<<"$output" || {
  printf 'policy output omitted the Cargo library target:\n%s\n' \
    "$output" >&2
  return 1
}
rm -- \
  "$work_dir/Cargo.toml" \
  "$work_dir/worker/url-reference/Cargo.toml" \
  "$work_dir/worker/url-reference/src/lib.rs" \
  "$work_dir/worker/qualification-fixtures/Cargo.toml"

cat >"$work_dir/ignored_test.rs" <<'EOF'
#[test]
#[cfg_attr(all(), ignore)]
fn ignored() {}
EOF
set +e
output=$(cd "$work_dir" &&
  "$work_dir/config-bin/sourcepolicy" test-skips 2>&1)
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
  "$work_dir/config-bin/sourcepolicy" test-skips 2>&1)
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

)

main "$@"

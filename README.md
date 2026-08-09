# Governed Deterministic Operation

Celestia implementation repository. It contains internal governed URL-reference
and file-replacement operations for Windows AMD64. File replacement remains a
candidate until its exact-candidate gates pass. No public CLI exists and other
platforms fail closed.

The operation contracts are:
- [`docs/contracts/url_reference_v1.md`](docs/contracts/url_reference_v1.md);
- [`docs/contracts/file_replace_v1.md`](docs/contracts/file_replace_v1.md).

Repository history and push requirements are defined in
[`policies/commit.md`](policies/commit.md).

Source structure, naming and comment requirements are defined in
[`policies/programming.md`](policies/programming.md).

Static-analysis admission and suppression requirements are defined in
[`policies/linting.md`](policies/linting.md).

## Verification

Run the local gate:
```sh
bash ./.github/scripts/devcheck.sh
```

Rust verification requires `cargo-audit 0.22.2`, `cargo-deny 0.20.2` and
`cargo-llvm-cov 0.8.7`. CI installs those exact versions.

Optional output and fuzz controls:
```sh
DEVCHECK_OUTPUT=failed bash ./.github/scripts/devcheck.sh
DEVCHECK_FUZZTIME=60s DEVCHECK_FUZZ_TIMEOUT=90s bash ./.github/scripts/devcheck.sh
```

Module checks:
```sh
bash ./.github/scripts/modcheck.sh verify
bash ./.github/scripts/modcheck.sh diff
bash ./.github/scripts/modcheck.sh cached-diff
bash ./.github/scripts/modcheck.sh update
```

Action checks:
```sh
bash ./.github/scripts/actioncheck.sh verify
bash ./.github/scripts/actioncheck.sh currency
bash ./.github/scripts/actioncheck.sh cached-currency
```

Licence headers:
```sh
bash ./.github/scripts/licencecheck.sh verify
bash ./.github/scripts/licencecheck.sh diff
bash ./.github/scripts/licencecheck.sh update
```

Repository policy:
```sh
bash ./.github/scripts/policycheck.sh
```

The module and licence-header `update` commands change the working tree. The
other documented commands do not. Force uncached currency checks with:
```sh
MODCHECK_CACHE_MAX_AGE_MINUTES=0 bash ./.github/scripts/devcheck.sh
ACTIONCHECK_CACHE_MAX_AGE_MINUTES=0 bash ./.github/scripts/devcheck.sh
```

The gate tests its coverage and repository-policy scripts. It then checks
repository policy, merge markers, private-key markers and maintained shell
scripts with pinned ShellCheck. It discovers workflows, action and container
image references, Go packages, fuzz targets and an optional Cargo workspace.
Local action references fail closed until a reviewed resolver is implemented.
`.github/.coverage` sets the default and optional package-specific
statement-coverage floors. The default is 90 per cent.

Rust completion checks detect omitted or failed execution under reviewed test
code; they do not authenticate a deliberately hostile test executable.

Package overrides use:
```text
package windows amd64 celestia.research/celestia/example 95
```

Each override applies only to its exact supported Go OS and architecture. It
is rejected if the named package is absent on that target.

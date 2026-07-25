# Governed Deterministic Operation

Celestia implementation repository. No operation has been implemented.

Repository history and push requirements are defined in
[`COMMIT_POLICY.md`](COMMIT_POLICY.md).

Source structure, naming and comment requirements are defined in
[`PROGRAMMING_POLICY.md`](PROGRAMMING_POLICY.md).

Static-analysis admission and suppression requirements are defined in
[`LINTER_POLICY.md`](LINTER_POLICY.md).

## Verification

Run the local gate:
```sh
bash ./.github/scripts/devcheck.sh
```

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
scripts with pinned ShellCheck. It discovers workflows, action references, Go
packages, fuzz targets and an optional Cargo workspace. `.github/.coverage`
sets the default and optional package-specific statement-coverage floors. The
default is 90 per cent.

Package overrides use:
```text
package celestia.research/governed-operation/example 95
```

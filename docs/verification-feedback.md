# Verification Feedback

This document maps the current verification controls before latency changes.
It does not define a new verification contract or make quick verification
equivalent to sign-off.

## Profiles

Profile | Owner | Scope | Escalation
--- | --- | --- | ---
`config` | `devcheck.sh` | Configuration and action policy only | Stops after Config
`quick` | `devcheck.sh` | Cached conservative feedback | Ambiguous or load-bearing changes require full
`full` | `devcheck.sh` | Complete Product gate | Independent of quick results
`shell` | `devcheck.sh` | Product policy for bounded documentation and policy changes | Other changes escalate before selection
Assurance | `sec/devcheck.sh` | Complete Assurance repository gate | Separate Product and Assurance custody

## Product Controls

Control | Command owner | Principal inputs | Writable state | Cache | Platform | Consumer
--- | --- | --- | --- | --- | --- | ---
Environment | `devcheck.sh` | `go.mod`, Rust toolchain and tool modules | Go tool cache | Go | Host | Every Product profile
Config | `check_config` | Linter, workflow, Rust and shell configuration | Tool caches and temporary inventories | Go and tool caches | Host | Config, quick and full profiles
Verification Scripts | `verification_test.sh` | Tracked verification families and their bound source snapshot | Isolated temporary snapshot and family directories | Tool caches | Host | Full profile
Policy | `policycheck.sh` | Tracked and untracked maintained source, manifests and architecture policy | Temporary inventory and Go cache | Go | Host | Full, quick and shell profiles
Modules | `modcheck.sh verify` | Go and Cargo manifests and lockfiles | Isolated temporary directory | None | Host | Full and quick profiles
Currency Exceptions | `currencycheck.sh verify` | `.github/.currency` and governed manifests | Temporary inventories | None | Host | Full and quick profiles
Licence Headers | `licencecheck.sh verify` | Eligible tracked and untracked source | Temporary inventories | Optional digest cache | Host | Full and quick profiles
Currency | Module, action and version currency commands | Manifests, actions, tools and remote release state | `.cache` entries and temporary inventories | Bounded repository caches | Networked host | Selected full jobs and nightly
Go Build and Static | Go build, fix, format, vet and lint | Go source, build tags and linter policy | Go and linter caches | Go and linter caches | Host | Quick or full according to stage
Go Platform Lint | `platformlint.sh` | Go source and `.golangci.yml` | Go and linter caches | Shared sequential caches | Linux, AIX and Plan 9 targets | Full; Linux AMD64 CI owner
Go Test | `testcheck.sh go` | Compiled test inventory and Go source | Isolated completion inventory and Go cache | Go | Host | Quick or full
Go Race | `testcheck.sh go race` | Go tests and race-enabled binaries | Isolated completion inventory and Go cache | Go | Supported CGO host | Full
Go Coverage | `coveragecheck.sh verify` | Policy and package tests | Isolated temporary profiles | None | Host | Full
Go Fuzz | `fuzz_smoke` | Discovered fuzz targets and seed corpora | Go fuzz and build caches | Go | Host | Full
Go Vulnerabilities | `govulncheck` | Go dependency graph and vulnerability database | Go vulnerability cache | Go | Networked host | Full
Rust Static | Cargo check, format and clippy | Workspace, worker source and lockfile | Cargo target and registry state | Cargo | Host | Quick and full
Rust Test | `rustcheck.sh tests` | Workspace tests and executable inventory | Cargo target plus isolated completion inventory | Cargo | Host | Quick and full
Qualification Fixtures | Cargo fixture checks and tests | Separate hostile-fixture package and lockfile | Fixture target and registry state | Cargo | Host | Quick and full
Rust Docs and Coverage | Cargo doc and llvm-cov | Workspace and fixture source | Cargo target and coverage state | Cargo | Host | Full
Rust Artefacts | `rustcheck.sh artefacts` | Release workspace and explicit allowlist | Isolated release target | Cargo registry | Host | Full
Rust Supply Chain | Cargo audit and deny | Both lockfiles and deny policy | Registry and advisory state | Cargo | Networked host | Selected full jobs

## Inner Timing Owners
- `devcheck.sh` measures Config subchecks and fuzz discovery and execution.
- `policycheck.sh` measures each policy subcheck without changing its result.
- `verification_test.sh` measures immutable family setup and each family.
- `source_policy_test.sh` measures each ordered hostile source-policy script.
- `platformlint.sh` measures each target sequentially.
- `testcheck.sh` separates Go discovery from execution and Rust construction
  from execution.
- Outer `devcheck.sh` stages remain the authoritative profile result.

Product and Assurance output use the same section, aligned label, status,
duration and final-summary conventions. Their implementations and evidence
remain separately owned.

## Corrected Duplication

Before optimisation, `actioncheck.sh verify` ran in both Config and a separate
Actions stage. Config now owns the check for every profile authorised to cover
action changes and the later duplicate invocation is removed. The bounded
`shell` profile runs only Policy; the conservative change classifier escalates
action, workflow, source, module and unknown paths to full verification.

Action and verification family execution previously had separate process,
deadline, snapshot and cleanup drivers. One driver now executes either declared
family set. The action-specific wrapper owns only its four-family declaration.
One focused run of those four families took 69.5 seconds after consolidation.
That observation is not a benchmark but proves the deleted second driver would
have repeated material immutable setup and family execution.

Policy verification previously inventoried the repository in the shell then
started four separate source-policy processes. The source-policy owner now
inventories once and reports Architecture, Manifests, Test Skips, Suppressions
and Source Files from one source-bound process. Source-file naming, generated
file and size rules moved from per-file shell subprocesses into that owner.

Rust completion verification previously executed every discovered test once
with exact terminal-summary validation then ran the same ordinary tests again
through Cargo. Library targets and therefore doctests are prohibited by the
architecture policy. The redundant second execution is removed; every
discovered test still runs exactly once and missing terminal outcomes still
fail the stage. Successful harness transcripts are retained only for checking
and printed only when their result is invalid.

Action and Rust currency checks previously continued remote lookups after a
decisive malformed, resolution or stale-version failure. They now stop at the
first failed component while retaining the bounded retry policy for the active
action lookup.

Action cache-key construction previously started one `git hash-object` process
for every governed action and policy file. It now sends the same ordered,
NUL-delimited path inventory through bounded `xargs -0` batches. The cache
self-test uses a deterministic toolchain while mutating non-toolchain inputs
then changes that toolchain for the dedicated relevance case. Its focused warm
observation fell from 20 seconds to 4.5 seconds without removing an input case.

Action verification previously parsed and validated every workflow once to
inventory remote actions then again to enforce permissions. One source-bound
mode now emits the action inventory and enforces permissions from the same
validated documents. The focused repository check passed in 3.5 seconds;
separate inventory and permission fixtures remain independently executable.

The source-policy architecture fixture now compiles its immutable checker once
after proving the production wrapper and environment boundary. Seven expected
repository-drift failures reuse that binary because none changes checker source
and depguard was unreachable after their required source-policy rejection. Five
forbidden artefact extensions are presented together but each distinct
diagnostic remains mandatory. One focused exact-candidate observation fell from
29 seconds to 22 seconds.

The manifest fixture builds one source-bound checker for later hostile source
cases. The ordered family now retains one production-wrapper execution for each
of `source-files`, `test-skips` and `suppressions` then reuses that binary for
later repository-only mutations. An affected-subset run recorded 7 seconds for
Go execution, 1 second for Rust and Cargo and 2 seconds for suppressions; the
setup and manifest prerequisites remained 3 and 12 seconds respectively.

The manifest boundary previously started the immutable checker once for every
changed contract then once again for every missing contract. It now reports
the bounded set with path-qualified diagnostics, allowing the filesystem
fixture to prove all 17 changed and all 17 missing contracts in two executions.
The focused stage remained 12 seconds at whole-second resolution, showing that
checker construction rather than these short executions dominates that stage.
The ordered architecture and manifest stages now share that source-bound
executable instead of linking it twice. With an equivalent prebuilt checker,
the focused manifest stage took 6 seconds instead of 12.

Assurance fuzz discovery previously started `go test -list` separately for all
26 packages in both its local gate and long campaign. One bounded JSON test
inventory now owns both consumers. Equivalent warm discovery fell from 33.0
seconds to 7.5 seconds; the two fuzz targets remain independently bounded and
the first failed target still stops execution.
Its ordinary and race suites previously repeated the real repository discovery
inside the discovery regression. That regression now injects the exact command
result and checks invocation, decoding, ordering and command failure; the
dedicated fuzz gate retains the real integration. The focused regression fell
from 7.4 seconds to 0.6 seconds.

Assurance checkout validation previously started `git check-attr` separately
for each of 358 tracked files. One ordered NUL-delimited attribute stream now
checks cardinality, paths, attribute names and values; a focused observation
fell from 20.1 seconds to 0.5 seconds. Its licence check now reads the first two
lines of 235 eligible files directly instead of starting `head` and `grep` for
each file; a focused observation fell from 17.3 seconds to 0.3 seconds. Both
known-bad fixtures retained their rejection and diagnostic.
Assurance formatting now consumes the governed tracked-and-untracked Go
inventory rather than recursively scanning ignored run caches and propagates
formatter execution failure before interpreting its output. Its focused check
took 0.4 seconds and rejected an unformatted tracked fixture.

The main CI matrix previously repeated the explicit Linux, AIX and Plan 9
cross-lint targets on five hosts. Linux AMD64 now owns that target matrix once;
local full verification still runs it by default and an invalid ownership value
fails before verification starts. Host-specific tests, race, coverage and fuzz
remain on every existing matrix leg. Exact-head CI timing remains pending.

## Provisional Windows Baseline

These measurements were taken from Product base `d4c4481` plus the uncommitted
timing-only changes described above. They are not immutable sign-off evidence
and no budget is derived from them.

Environment | Observed value
--- | ---
Operating system | Windows 11 Pro 10.0.26200, AMD64
Processor | Intel Core i5-13400F, 10 cores and 16 logical processors
Memory | 31.8 GiB
Go | 1.26.5, CGO enabled
Rust | rustc 1.97.1 and cargo 1.97.1
Power and virtualisation | Unmeasured

Control | Cache state | Seconds | Median | Range
--- | --- | --- | ---: | ---:
Config | Existing warm Go and tool caches | 37, 38, 42 | 38 | 5
Config | Empty isolated Go build cache per run | 157, 118, 137 | 137 | 39
Policy | Existing warm Go and tool caches | 48, 48, 46 | 48 | 2
Policy | Empty isolated Go build cache per run | 172, 167, 140 | 167 | 32

The Config command was
`DEVCHECK_PROFILE=config DEVCHECK_OUTPUT=all bash
./.github/scripts/devcheck.sh`. The Policy command was
`bash ./.github/scripts/policycheck.sh`. Cold runs used a distinct empty
`GOCACHE` beneath `.cache` while retaining the module download cache. Warm runs
used the host's existing Go and tool caches. No control was skipped in either
focused command.

Warm Config is dominated by ShellCheck at 32 seconds in all three runs. Cold
Config adds 63 to 103 seconds for Go linter configuration. Warm Policy is
dominated by `test-skips` at 22 to 23 seconds and source-file policy at 16 to
17 seconds. Cold Policy adds 42 to 74 seconds to `test-skips` and 78 to 80
seconds to architecture policy.

After source-policy consolidation, one equivalent warm Policy observation was
33 seconds. The consolidated source-policy process reported 23.6 seconds for
Test Skips and less than one second for its other four checks. This single
observation demonstrates removed orchestration but is not a stable benchmark.

ShellCheck now analyses two dependency-complete groups concurrently. The root
and action-policy group includes the shared verification fixture; the
verification group retains its complete fixture closure. On the same Windows
host, one sequential warm observation took 62 seconds and the two-group form
took 22 seconds. Three complete warm Config observations after the change took
33.3, 34.9 and 36.3 seconds. Both groups have controlled failure evidence.

Licence verification now classifies files and compares the ten required header
lines with Bash built-ins. Three equivalent warm Windows observations fell
from 30.0, 30.1 and 31.2 seconds to 0.83, 0.87 and 0.90 seconds. Diff, repair,
cache and malformed-header behaviour remains owned by the hostile licence
family.

Fuzz discovery previously ran `go test -list` once per package. The governed
test inventory now emits its fuzz-only view from one bounded `go list` pass.
One equivalent warm comparison fell from 20.3 seconds to 3.5 seconds. Active
fuzz targets remain separately bounded. A failed target now stops the stage
before any later target consumes another timeout window.

Typed test policy now reuses build contexts only when the OS, architecture,
selected packages and complete selected repository source set are identical.
Explicit race and CGO source remains distinct. One warm Test Skips observation
fell from 22 to 23 seconds to 19.6 seconds.

Go coverage previously started one Go command per package and allowed full
sign-off to reuse a writable ignored report cache. It now runs one sequential
atomic workspace coverage command while retaining package isolation,
per-package floors and bounded failure output. Persistent report caching is
removed because quick verification does not run coverage and sign-off must be
independent of earlier results. One equivalent Windows observation of the
combined execution fell from 76 seconds to 51.6 seconds.

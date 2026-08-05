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

## Measured Commands

Concept | Command | Required environment | Meaning
--- | --- | --- | ---
Quick | `bash ./.github/scripts/devcheck.sh` | `DEVCHECK_PROFILE=quick` | Conservative cached Product feedback
Sign-off | `bash ./.github/scripts/devcheck.sh` | `DEVCHECK_PROFILE=full` | Complete local Product gate independent of quick results
Product campaign | `verification_test.sh`, `testcheck.sh go race`, `testcheck.sh go fuzz` | Clean source-bound checkout | Checker self-tests plus race and active fuzz evidence
Assurance quick | `assure check` | `--profile quick` | Non-signable independent feedback
Assurance sign-off | `assure check` | `--profile signoff` | Complete signable exact-pair evidence
Assurance campaign | `assure check` | `--profile campaign` | Sign-off controls plus extended campaign controls

`full` is the Product driver's implementation name for sign-off. Campaign
commands remain separate because CI runs them concurrently and local sign-off
may delegate them only through explicit environment selections. A Product
result with `DEVCHECK_SELF_TEST=false` or `DEVCHECK_GO_CAMPAIGN=false` is one
part of the CI sign-off composition and is not complete sign-off by itself.

### Quick Go Selection

Quick testing selects a modified package-local test without its importers. A
transformation-source change selects that package and every transitive reverse
dependant. Documentation-only changes select no Go test package.

Deleted files, build constraints, tools, protocols, persistence, supervision,
operation orchestration, module state, policy and unknown paths select all Go
packages. An unavailable Git base, package graph or changed package also falls
back to all packages. Sign-off remains complete and does not consume a quick
result.

## Control Dependencies

Consumer | Required predecessors | Reused output | Independent writable state
--- | --- | --- | ---
Every Product profile | Environment | Validated toolchain identity | Language tool caches
Config | Environment | None | Tool caches and temporary workflow inventories
Policy | Config for quick and full | One source-policy inventory and process | Temporary source inventory
Modules and currency exceptions | Policy | None | Isolated manifest inventories
Licence headers | Policy | Maintained source classification only | Optional content-addressed cache
Go build, fix, format and lint | Product policy controls | Go package graph and language caches | Go and linter caches
Go platform lint | Go static controls | No semantic result | Target-specific analyser caches
Go standard test | Go static controls | Atomic coverage profile | Isolated test inventory and profile
Go coverage | Go standard test | Exact atomic profile | No second test execution
Go race | Go static controls | No test result | Isolated completion inventory
Go fuzz | Go static controls | One governed target inventory | Per-target fuzz and build caches
Rust static | Product policy controls | Cargo dependency and build state | Cargo target
Rust test | Rust static | Discovered executable inventory | Isolated completion inventory
Rust coverage and artefacts | Rust test | Cargo dependency state only | Isolated coverage and release targets
Verification-script campaign | Environment | One immutable source snapshot and family checker builds | Per-family directories
Assurance sign-off | Clean exact Product and Assurance commits | Immutable source material and control digests | Run output directory
Assurance campaign | Assurance sign-off controls | Sign-off control results within the same run | Campaign-owned temporary directories

No row authorises reuse of a behavioural pass from an earlier run. Reuse is
limited to immutable discovery, build or profile output within the named
source-bound execution.

## Product Controls

Control | Command owner | Principal inputs | Writable state | Cache | Platform | Consumer
--- | --- | --- | --- | --- | --- | ---
Environment | `devcheck.sh` | `go.mod`, Rust toolchain and tool modules | Go tool cache | Go | Host | Every Product profile
Config | `check_config` | Linter, workflow, Rust and shell configuration | Tool caches and temporary inventories | Go and tool caches | Host | Config, quick and full profiles
Verification Scripts | `verification_test.sh` | Tracked verification families and their bound source snapshot | Isolated temporary snapshot and family directories | Tool caches | Host | Full profile
Policy | `policycheck.sh` | Tracked and untracked maintained source, manifests and architecture policy | Temporary inventory and Go cache | Go | Host | Full, quick and shell profiles
Module integrity | `modcheck.sh verify` | Go and Cargo manifests, lockfiles and downloaded Go modules | Isolated temporary directory | None | Host | Full profile
Module tidiness | `modcheck.sh tidy` | Go source and module manifests | Go build cache | Go | Host | Quick profile
Currency Exceptions | `currencycheck.sh verify` | `.github/.currency` and governed manifests | Temporary inventories | None | Host | Full and quick profiles
Licence Headers | `licencecheck.sh verify` | Eligible tracked and untracked source | Temporary inventories | Optional digest cache | Host | Full and quick profiles
Currency | Module, action and version currency commands | Manifests, actions, tools and remote release state | `.cache` entries and temporary inventories | Bounded repository caches | Networked host | Selected full jobs and nightly
Go Build and Static | Go build, fix, format and lint | Go source, build tags and linter policy | Go and linter caches | Go and linter caches | Host | Quick or full according to stage
Go Platform Lint | `platformlint.sh` | Go source and `.golangci.yml` | Go and linter caches | Shared sequential caches | Linux, AIX and Plan 9 targets | Full; Linux AMD64 CI owner
Go Test | `testcheck.sh go` | Compiled test inventory and Go source | Isolated completion inventory and Go cache | Go | Host | Quick or full
Go Race | `testcheck.sh go race` | Go tests and race-enabled binaries | Isolated completion inventory and Go cache | Go | Supported CGO host | Local full and blocking CI campaign
Go Coverage | `testcheck.sh go standard` then `coveragecheck.sh enforce` | Standard tests and package floors | Isolated atomic profile | None | Host | Full
Go Fuzz | `testcheck.sh go fuzz` | Discovered fuzz targets and seed corpora | Go fuzz and build caches | Go | Host | Local full and blocking CI campaign
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
NUL-delimited path inventory through bounded `xargs -0` batches and hashes the
ordered paths as well as their content. The cache self-test uses a deterministic
toolchain while mutating non-toolchain inputs, renaming an action then changing
that toolchain for the dedicated relevance case. Its focused warm observation
fell from 20 seconds to 4.5 seconds without removing an input case.

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

ShellCheck initially analysed two dependency-complete groups concurrently. The root
and action-policy group includes the shared verification fixture; the
verification group retains its complete fixture closure. On the same Windows
host, one sequential warm observation took 62 seconds and the two-group form
took 22 seconds. Three complete warm Config observations after the change took
33.3, 34.9 and 36.3 seconds. Both groups have controlled failure evidence.

The maintained shell corpus has four independently analysable families: root,
action policy, verification and source policy. Against Product `3df05da`,
three alternating warm comparisons recorded 46, 45 and 46 seconds for the
two-group ShellCheck stage and 42, 39 and 38 seconds for the byte-identical
four-group candidate. The median fell from 46 to 39 seconds on the measured
host. Each group has a controlled failure fixture; groups receive the source
files needed for indirect function and sourced-file analysis and write
diagnostics to separate temporary files.

Module verification is not safely source-cacheable because corruption of the
module download cache would not change a repository-derived key. Three
consecutive sign-off module observations took 272.1, 2.9 and 3.0 seconds as the
filesystem and module cache warmed. Quick feedback now runs only the
source-sensitive `go mod tidy -diff`; one equivalent warm comparison took 0.3
seconds for tidiness and 3.1 seconds for complete verification. Sign-off still
runs both `go mod verify` and tidiness. A controlled direct-import fixture
proved that quick tidiness rejects source-to-manifest drift.

The cached module update-diff check binds its marker to ordered Go source paths
and content, module files, its checker, the Go platform and module-resolution
environment. Its focused fixture rejects stale markers and proves that source
content, source paths and proxy policy each change the key. Sign-off module
verification remains uncached.

Licence verification now classifies files and compares the ten required header
lines with Bash built-ins. Three equivalent warm Windows observations fell
from 30.0, 30.1 and 31.2 seconds to 0.83, 0.87 and 0.90 seconds. Diff, repair,
cache and malformed-header behaviour remains owned by the hostile licence
family.

Standard Go tests now emit the atomic coverage profile consumed by the package
floor check. On the same Windows host, separate warm standard and coverage
executions took 51.1 and 64.2 seconds. The combined execution and enforcement
took 60.4 and 1.8 seconds, removing one complete package-test pass while
retaining shuffled terminal-outcome and package-floor checks.

CI runs the complete verification-script campaign in a separate Linux job.
The green `b34f75d` run spent 317 seconds on that campaign before beginning the
remaining Product controls; the independent job removes that serial dependency
without changing local full verification or the campaign's family inventory.

Go linting owns `govet` and its deliberately defective fixture. The separate
`go vet` invocation repeated the same analyser immediately before that gate and
was removed; `govet` remains blocking through the pinned linter configuration.

The retained persistent result caches are action currency, module update diff
and licence headers. Each key binds ordered path and content identity plus its
checker and applicable tool or environment inputs; focused fixtures reject
stale markers and changed relevance inputs. Go and Cargo build caches remain
tool-owned acceleration rather than trusted verification results.

Concurrent shell analysis writes only to separate diagnostic files. Windows
shell runs receive separate result-cache, Cargo-target and temporary roots.
Remaining sleeps and polls own explicit retry, deadline, process-tree cleanup
or hostile-fixture behaviour; no delay is used to make an ordinary assertion
eventually pass. Standard, race and fuzz discovery remains separate where the
campaign or target inventory is independently owned.

Windows AMD64 quick-profile measurements at Product `c2d87e7` used an Intel
Core i5-13400F with 16 logical processors, 34,185,990,144 bytes of memory, Go
1.26.5 and Rust 1.97.1. Three warm runs took 158.0, 116.7 and 115.2 seconds
(median 116.7; range 42.8). Three runs with a new empty Go build cache and the
existing module download cache took 263.9, 199.5 and 196.8 seconds (median
199.5; range 67.1). Currency, verification-script and Go campaign controls
were disabled according to the quick profile; ambiguous branch-wide changes
conservatively selected all Go packages.

CI runs race and active fuzz controls in a separate blocking matrix for every
qualified Product runner. Local full verification retains both controls. The
green `b34f75d` run spent 93 seconds on race and 15 seconds on fuzz for Linux
AMD64 plus 138 seconds on race and 51 seconds on fuzz for Windows AMD64; the
campaign matrix removes those serial dependencies from Product verification.

The linter self-test uses one run-local content-addressed analyser cache across
its sequential defective and correct fixture states. Every state is still
executed and asserted; changing a fixture from rejected to accepted also proves
that the shared cache does not retain the earlier source result.

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

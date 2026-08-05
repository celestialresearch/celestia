# Production Simplification Inventory

Bound Production commit: `d032bb0691f0f6f35aa12b234a9440efa2a8aabe`

This inventory covers maintained Production Go packages before the first
simplification change. Counts include all platform-selected production files;
tests are counted separately. Export consumers exclude tests and packages
outside Production. No compatibility is retained for unused pre-release
protocols or persistence formats.

## Package Measures

Package | Files | Lines | Statements | Functions | Exports | Unconsumed exports | Interfaces | Tests | Fuzz | Benchmarks | Statement coverage
--- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---:
`internal/execution/supervision` | 18 | 2,537 | 864 | 117 | 31 | `ErrInvalid`, `ErrUnavailable` | 0 | 119 | 0 | 0 | 99.6%
`internal/operation/urlreference` | 8 | 561 | 115 | 17 | 21 | All; no current Production caller | 0 | 26 | 0 | 1 | 100.0%
`internal/operation/urlreference/admission` | 2 | 122 | 28 | 4 | 5 | None | 0 | 6 | 0 | 0 | 100.0%
`internal/operation/urlreference/attempt` | 29 | 4,218 | 1,505 | 203 | 38 | `Admitted`, `ErrActive`, `ErrCorrupt`, `ErrDuplicate`, `ErrInvalid`, `ErrUncommitted`, `ErrUnsupported`, `Publication`, `Receipt`, `Records`, `Recovery` | 2 | 262 | 2 | 0 | 99.9%
`internal/operation/urlreference/protocol` | 5 | 689 | 294 | 31 | 45 | `Correlation`, `DecodeResponse`, `ErrProtocol`, `MaxDiagnostics`, `MaxDurationNS`, `MaxJSONDepth`, `MaxMessageBytes`, `ValidateRequest`, `WorkerID`, `WorkerVersion` | 0 | 19 | 2 | 1 | 99.6%
`internal/operation/urlreference/transform` | 5 | 461 | 199 | 24 | 8 | `ErrInvalid`, `MaxInputBytes`, `MaxReferenceBytes` | 0 | 9 | 1 | 1 | 100.0%
`tools/actionpolicy` | 6 | 777 | 384 | 29 | 0 | None | 0 | 33 | 1 | 0 | 98.5%
`tools/sourcepolicy` | 45 | 6,904 | 2,760 | 283 | 0 | None | 1 | 195 | 0 | 0 | 91.8%

The root operation exports are retained because they are the declared internal
capability boundary even though no CLI currently consumes them. Other
unconsumed exports require separate contract and test-consumer review before
unexporting or deletion. Attempt persistence declares two narrow file-operation
interfaces and source policy declares one command-lifecycle interface. Each has
one real implementation and a fault-test implementation.

## Source Inventory

Package | Production files and line counts
--- | ---
`internal/execution/supervision` | `cleanup_windows.go` 105; `doc.go` 13; `image_windows.go` 338; `launch_windows.go` 173; `native_pointer_windows.go` 20; `native_windows.go` 301; `observation_windows.go` 89; `outcome_windows.go` 147; `pipes_windows.go` 65; `process_start_windows.go` 281; `resources_windows.go` 67; `runtime_windows.go` 240; `stream_windows.go` 200; `supervisor.go` 71; `supervisor_unsupported.go` 33; `supervisor_windows.go` 166; `timing_windows.go` 68; `wait_windows.go` 160
`internal/operation/urlreference` | `doc.go` 13; `evidence_windows.go` 104; `operation.go` 68; `operation_unsupported.go` 41; `operation_windows.go` 149; `platform_windows.go` 60; `projection_windows.go` 59; `verification_windows.go` 67
`internal/operation/urlreference/admission` | `admission.go` 109; `doc.go` 13
`internal/operation/urlreference/attempt` | `acl_windows.go` 282; `contract.go` 17; `doc.go` 14; `inspect.go` 186; `lock.go` 307; `lock_root.go` 72; `lock_windows.go` 215; `observation_validation.go` 131; `ownership.go` 161; `paths.go` 200; `platform.go` 18; `publish.go` 176; `publish_windows.go` 128; `record.go` 106; `record_io.go` 238; `record_name.go` 56; `record_validation.go` 217; `record_windows.go` 93; `recover.go` 308; `repair_windows.go` 107; `request_v1.go` 300; `root.go` 191; `root_parent_windows.go` 18; `root_path_windows.go` 88; `stage.go` 187; `store.go` 75; `store_unsupported.go` 24; `terminal.go` 129; `transition.go` 174
`internal/operation/urlreference/protocol` | `doc.go` 13; `frame.go` 289; `protocol.go` 105; `request.go` 149; `response.go` 133
`internal/operation/urlreference/transform` | `doc.go` 13; `host.go` 202; `parse.go` 107; `text.go` 64; `transform.go` 75
`tools/actionpolicy` | `actions.go` 202; `doc.go` 13; `document.go` 193; `main.go` 60; `permissions.go` 206; `stream.go` 103
`tools/sourcepolicy` | `architecture.go` 95; `architecture_action_policy.go` 92; `architecture_attempt_split.go` 312; `architecture_documentation.go` 99; `architecture_evaluation.go` 179; `architecture_imports.go` 178; `architecture_inventory.go` 28; `architecture_limits.go` 45; `architecture_operation_split.go` 91; `architecture_ownership.go` 252; `architecture_paths.go` 66; `architecture_policy.go` 176; `architecture_rust.go` 183; `architecture_scripts.go` 37; `architecture_source_policy.go` 251; `architecture_split.go` 195; `architecture_supervision_split.go` 295; `architecture_values.go` 106; `cargo.go` 267; `cargoconfig.go` 117; `doc.go` 13; `executable_inventory.go` 152; `gobuildtags.go` 146; `gocgo.go` 82; `goexit.go` 180; `gofallback.go` 234; `goinspect.go` 158; `golangci.go` 40; `goload.go` 252; `goskip.go` 205; `gotarget.go` 337; `gotestmain.go` 158; `inventory.go` 116; `main.go` 225; `manifest.go` 116; `module_replacement.go` 53; `rustpolicy.go` 172; `rustsyntax.go` 398; `scan.go` 130; `source.go` 99; `source_files.go` 104; `source_open_other.go` 20; `source_open_unix.go` 23; `suppression.go` 147; `testinventory.go` 280

## Ownership Map

Package | Dependencies | Reverse dependencies | State and authority
--- | --- | --- | ---
`internal/execution/supervision` | Standard library and Win32 | Root URL operation | Owns process statuses, limits, worker identity, containment and cleanup
`internal/operation/urlreference` | Supervision, admission, attempt, protocol, transform | None | Owns terminal operation status and orchestration only
`internal/operation/urlreference/admission` | Protocol, transform | Root operation, attempt | Owns admission and request construction
`internal/operation/urlreference/attempt` | Admission, protocol, transform | Root operation | Owns staged, published and recovered evidence transitions
`internal/operation/urlreference/protocol` | Transform | Root operation, admission, attempt | Owns request and response frame validity and correlation
`internal/operation/urlreference/transform` | Standard library | Root operation, admission, attempt, protocol | Owns URL grammar and deterministic fang/defang semantics
`tools/actionpolicy` | YAML library | Verification scripts | Owns workflow action, image and permission policy
`tools/sourcepolicy` | Go packages and standard library | Verification scripts | Owns source, manifest, architecture, suppression and test inventory policy

Legal lifecycle states are:
- Supervision: `completed`, `start_failed`, `timed_out`, `cancelled`,
  `output_overflow`, `error_overflow`, `exit_failed` and `cleanup_failed`.
- Operation: `failed`, `rejected`, `cancelled`, `timed_out`,
  `executed_unverified`, `verified` and `indeterminate`.
- Protocol response: `completed`, `rejected` and `failed`.
- Transformation: `active` and `defanged`; modes are `fang` and `defang`.
- Evidence: admitted staging reaches one observation or recovery terminal record,
  receipt then publication marker. `transition.go` owns legal cross-field states.

## Retained Fields

The protocol request owns `protocol_version`, `operation_id`,
`operation_version`, `attempt_id`, `request_nonce`, `input_media_type`,
`input_length`, `input_sha256`, `mode`, `deadline`, `timeout_ms`, `limits` and
`input`. Limits own `input_bytes`, `output_bytes`, `stderr_bytes`,
`memory_bytes` and `processes`.

The response owns the correlation fields plus `worker_id`, `worker_version`,
`status`, optional output media, length, hash and value, `diagnostics` and
`duration_ns`.

Evidence owns:
- admitted: version, identity, admission time, original input and request frame;
- observation: worker hash, process result, streams, cleanup, protocol,
  verification, terminal status and duration;
- recovery: identity, terminal status and reason;
- receipt: identity, terminal kind, record names, hashes and terminal status;
- publication: identity and receipt hash.

There is no older-version compatibility obligation. A future removal must
change every maintained reader, writer, fixture and contract together.

## Validation And Proof Ownership

Admission validates authorisation inputs then delegates grammar and frame
constants to transform and protocol. Protocol alone validates JSON shape,
correlation, status, output and diagnostics. Transform alone validates URL
grammar and computes the independent result. Attempt validates retained record
shape, hashes, evidence bindings and legal transitions. Supervision validates
the configured image, limits, deadlines and native resource lifecycle. The two
policy tools own only repository policy and must not become runtime authorities.

Statement coverage above is from one Windows AMD64 atomic run. The command
reported the package results but failed after treating the output profile path
as an extra package, so no combined profile is retained. Per-package decision,
invariant and mutation coverage are not currently measured; tests and
Assurance controls provide evidence but no truthful package percentage. This is
an explicit inventory gap rather than an inferred zero.

Production suppressions are limited to two reviewed Win32 `G103` conversions.
There are no architecture file exceptions. Test, fuzz and benchmark ownership
is recorded in the package table.

## First Boundary

`closeFiles` in `image_windows.go` has no Production caller and only forwards
to `closeFilesWith`. Its sole test can invoke the owning function directly with
`(*os.File).Close`, retaining the real closed-file error path. This is the first
bounded deletion. `awaitProcess` and `failedJob` have the same test-only-wrapper
shape but remain separate candidate slices.

## Candidate Reconciliation

Production source was audited through `6f9b4d0`. Against the baseline, the
candidate removes 39 net non-test Go lines across 25 files. No Production Go
file reaches the 500-line structural-review threshold.

The candidate removes the identified dead wrappers, dormant exports,
single-value factories, forwarding aliases and duplicated native security
attribute construction. Every remaining export has a current Production
consumer or owns a declared operation, protocol or evidence contract.

The remaining operation tables and `With` functions inject native failures at
their owning boundary. Removing them would either remove fault evidence or
duplicate the real platform bindings in tests. Admission, protocol,
transformation, evidence and supervision validation remain separate because
they govern different trust transitions. Independent transformation
verification remains intentionally separate.

No obsolete protocol reader, persistence reader, migration path, accidental
interface or architecture exception remains. Both native pointer suppressions
remain at the smallest Win32 boundary that requires them. The configured
unused-code and parameter analysers report no Production finding.

The source audit satisfies the static simplification criteria. Complete
Production and Assurance sign-off remains the phase exit requirement.

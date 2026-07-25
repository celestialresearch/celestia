# Linter Policy

This policy governs adding, configuring, suppressing and removing static
analysers. Linters are executable risk controls, not a score or collection.

## Core Rule

Enable a linter only when it protects an identified defect class in code that
exists or is being implemented.

Every enabled linter must have:
- a named defect class;
- a defined scope;
- reviewed configuration;
- a failing positive fixture;
- a passing negative fixture where false positives are plausible;
- acceptable runtime;
- an owner in the repository's engineering policy;
- a suppression policy;
- a removal condition.

Do not use `enable-all`. Do not enable overlapping linters for the same
property unless each detects a demonstrated distinct failure class.

## Baseline

The baseline applies whenever Go packages exist:
- compiler, `go vet`, `staticcheck`, `unused`, `errcheck`, `ineffassign`;
- resource and error checks already listed in `.golangci.yml`;
- enum, tag, Unicode and security checks already listed there;
- `cyclop` with a maximum function complexity of 12;
- `funlen` with maxima of 80 lines and 50 statements;
- neutral-English `misspell` restricted to Go comments;
- test-helper and standard-testing checks;
- `modernize` as secondary evidence after `go fix`.

`.golangci.yml` is the executable allowlist. `GO_STANDARD.md` is the normative
contract. This policy decides when the allowlist may change.

## Admission

Before enabling a linter:
1. Identify a concrete bug, recurring review finding or newly introduced
   subsystem that creates its defect class.
2. Confirm the compiler, `go vet`, an enabled linter and repository tests do
   not already enforce the property.
3. Review the linter's maintenance, Go-version support, licence, provenance,
   known false positives and runtime.
4. Configure the narrowest useful rule set.
5. Prove the analyser rejects a deliberately defective fixture.
6. Prove representative correct code passes.
7. Run the complete repository gate and inspect every new finding.
8. Correct valid findings before enabling the gate.
9. Document any unavoidable suppression under the suppression contract.
10. Update `.golangci.yml`, `GO_STANDARD.md`, both applicable `AGENTS.md`
    files and this policy in one coherent change.

Do not enable a linter and globally exclude its initial findings. Existing
findings must be corrected or individually justified.

## Conditional Linters

Linter | Enable When | Required Configuration or Proof
--- | --- | ---
`contextcheck` | Context propagation crosses multiple application layers | Cancellation and derived-context fixtures
`containedctx` | Application structs begin carrying contexts | Prove contexts remain operation-scoped; do not suppress stored contexts casually
`fatcontext` | Context creation occurs in loops or closures | Fixture proving repeated derivation is detected
`sloglint` | A stable `log/slog` contract exists | Configure approved keys, context use and static-message rules
`loggercheck` | Another structured logger is adopted | Configure only the selected logger APIs
`spancheck` | Tracing spans exist | Cover every span owner, error recording and end path
`promlinter` | Prometheus metrics exist | Establish naming, unit and cardinality policy first
`protogetter` | Generated protobuf APIs exist | Confirm generated API and nil semantics
`testifylint` | Testify is materially adopted | Enable only rules matching the adopted assertion style
`depguard` | Package dependency directions exist | Encode documented package boundaries and prove allowed imports remain possible
`unqueryvet` | SQL queries or query builders exist | Prove explicit-column policy and generated-query exclusions
`canonicalheader` | Go code constructs HTTP headers | Prove protocol-defined non-canonical exceptions
`sloglint` and `spancheck` | Both logging and tracing exist | Keep their contracts separate; do not infer tracing from logging

## Evidence-Triggered Linters

These require a recurring defect or review failure rather than mere code
presence:

Linter | Enable When | Constraint
--- | --- | ---
`gocognit` | Functions remain hard to understand despite the complexity and size gates | Set a measured threshold from representative code
`nestif` | Deep conditional nesting repeatedly passes other controls | Do not use it to force guard clauses that obscure a state machine
`dupl` | Semantic copy-and-modify defects recur | Review every finding for shared meaning, not textual similarity
`goconst` | Repeated literals cause real consistency defects | Exclude protocol fixtures and unrelated equal strings
`mnd` | Unnamed numeric policy values cause defects | Define units and accepted domain constants before enabling
`revive` | One named rule closes an uncovered defect class | Enable that rule only; never enable broad defaults
`wrapcheck` | External errors repeatedly lose required operation context | Define which boundaries own wrapping
`gocritic` | One stable diagnostic catches a demonstrated repository defect | Enable selected checks rather than an unreviewed bundle

## Rejected or Redundant Controls

Do not add:
- `golint`, because it is deprecated;
- `gocyclo`, because `cyclop` already owns cyclomatic complexity;
- `goheader`, because `licencecheck.sh` enforces the cross-language notice;
- a US `misspell` locale;
- broad `revive` defaults;
- a second formatter that conflicts with `gofmt`;
- a linter used only to increase the enabled-linter count.

Reconsider a rejected control only when its ownership or implementation changes
materially and the replacement protects a distinct demonstrated defect class.

## Suppressions

A suppression is an exception to an enforced invariant.

Every `//nolint` must:
- name the exact linter;
- explain why the code is correct;
- identify the invariant preserved;
- remain on the narrowest line or declaration;
- avoid `all`;
- include a removal condition when temporary.

Do not suppress:
- a finding that can be corrected locally without reducing clarity;
- an entire file for one finding;
- a security finding without a reviewed compensating control;
- complexity caused by mixed responsibilities;
- generated code unless its generator and drift check are authoritative.

`nolintlint` must remain enabled with specific-linter and explanation
requirements.

## Review and Removal

Review the allowlist when:
- Go or golangci-lint changes major behaviour;
- an analyser is deprecated, archived or incompatible;
- a linter creates recurring false positives;
- runtime materially slows normal feedback;
- its triggering subsystem is removed;
- another enabled control fully replaces it.

Remove or replace a linter when it no longer protects a distinct defect class.
Before removal, preserve any valuable invariant through another analyser, test
or repository-policy check.

## Completion

A linter change is complete only when:
1. configuration validation passes;
2. the intended defective fixture fails for the intended diagnostic;
3. representative correct code passes;
4. the complete local gate passes;
5. no broad exclusion or unexplained suppression was introduced;
6. documentation names the protected defect class;
7. runtime impact is recorded when material.

# Programming Policy

This policy governs source structure, naming and comments. Correctness takes
priority over every size or naming target.

## Core Rule

Code must be correct, minimal, cohesive and obvious at its ownership boundary.
Do not add explanation, indirection or abstraction to make simple code appear
more substantial.

Prefer:
- fewer concepts;
- precise domain names;
- short functions with one purpose;
- files grouped by intent;
- explicit invariants;
- tests that prove behaviour;
- comments that explain a non-obvious reason.

Reject:
- duplicated semantic rules;
- speculative extension points;
- broad utility packages;
- names that narrate implementations;
- files that accumulate unrelated cases;
- tests written only to increase coverage;
- comments that translate code into prose.

## Names

Names must be the shortest precise expression of the domain concept.

New Celestia-owned package paths, filenames, identifiers, commands and
configuration keys use British English. Use names such as `analysers`,
`normalise`, `serialise`, `authorise`, `behaviour` and `licence`.

Preserve exact external names including standard-library identifiers, protocol
fields, third-party APIs, generated symbols, official product terms and
conventional repository files such as `LICENSE`.

Use:
- nouns for values and types;
- verbs for operations;
- questions for predicates;
- plural nouns for collections;
- units where a number would otherwise be ambiguous;
- established acronyms with consistent casing.

Avoid:
- `data`, `info`, `item`, `object`, `thing`, `value` or `result` when a precise
  domain noun exists;
- `helper`, `util`, `common`, `base`, `core`, `manager`, `processor` or
  `service` without a specific owned responsibility;
- repeating the package or receiver name;
- names that encode call order, implementation detail or historical context;
- abbreviations that save little space but require interpretation.

A function, method or test name should ordinarily contain no more than five
semantic words. An acronym counts as one word. Exceeding five words requires a
clear reason and usually indicates that the function or test owns too much.

Do not compress a bad design into a shorter cryptic name. Reduce the owned
concept first.

## Files and Packages

Use lowercase descriptive filenames. Go and Rust multiword filenames use
`snake_case`.

A filename should ordinarily contain one to four semantic words and describe
the behaviour or invariant it owns.

Do not use vague accumulation names:
- `misc`;
- `extra`;
- `additional`;
- `extended`;
- `helpers`;
- `utils`;
- `common`;
- `more`;
- numbered continuation files.

Names such as `additional_test.go`, `more_test.go` and
`extended_test.go` are prohibited. Move each test to the file that owns the
behaviour or create a narrowly named behavioural test file.

A generic `coverage_test.go` is prohibited. A narrowly named
`<intent>_coverage_test.go` is permitted only under the residual coverage rule
defined below.

Split files by intent and invariant, not by arbitrary line count. A file should
have one reviewable reason to change.

Production and test files should ordinarily remain between 100 and 400 lines.
Files above 500 lines require immediate cohesion review. Generated code,
declarative tables and genuinely cohesive protocol definitions may justify an
exception.

Do not create a new package merely to reduce file size. A package must own a
real domain boundary, invariant or replaceable external boundary.

## Functions

A function must:
- perform one operation at one level of abstraction;
- make side effects and blocking visible;
- return or preserve useful error context;
- keep ownership and cleanup explicit;
- use guard clauses where they clarify the successful path;
- avoid hidden global state.

Functions should ordinarily remain between 5 and 30 lines. A function over 50
lines requires immediate decomposition review. Keep it intact only when
splitting would obscure one cohesive state machine, transaction or declarative
algorithm.

Do not split a long function into fragments that merely pass the same large
parameter list between them. First identify the actual responsibilities and
state ownership.

Prefer no more than four positional parameters. Use a validated domain request
type when several values form one concept. Do not introduce an options type
merely to conceal unrelated parameters.

Avoid:
- boolean mode parameters;
- deeply nested branches;
- mixed validation, persistence and presentation;
- functions whose names contain an entire workflow;
- callbacks used only to avoid naming an owned operation;
- getters and setters without a domain invariant.

Three levels of nesting require review. Prefer early refusal and small named
operations.

## Duplication

Do not duplicate:
- validation rules;
- status transitions;
- protocol constants;
- path or URL policy;
- serialisation contracts;
- security decisions;
- error classification;
- test fixture construction with identical semantics.

Extract shared code only when it centralises the same invariant. Similar syntax
with different domain meaning may remain separate.

Do not create a generic helper before its stable shared responsibility is
demonstrated.

## Comments

Code should explain what it does through names, types and control flow.
Comments explain what the code cannot show.

Write a comment for:
- a non-obvious invariant;
- a security or authority boundary;
- an atomicity or durability constraint;
- a portability or protocol requirement;
- a counter-intuitive standard-library or platform behaviour;
- a measured performance trade-off;
- why a simpler-looking implementation is incorrect.

Do not write comments that:
- repeat the identifier;
- narrate the next statement;
- restate a type definition;
- announce ordinary control flow;
- describe obvious input or output;
- compensate for a vague name;
- preserve deleted code;
- document historical implementation steps;
- praise the implementation.

Prohibited examples include:
```go
// CreateRecord creates a record.
// LoadOptions controls loading.
// StatusOpen means the status is open.
// Set the value.
value = next
```

Rewrite the name or remove the comment.

Exported documentation must describe contract information such as errors,
side effects, ownership, idempotency, concurrency or compatibility. Do not add
an exported comment solely to repeat the declaration.

Comments inside a function must be rare. If several blocks need explanatory
headings, the function probably owns several operations.

Every suppression must name the exact rule and explain why the code is correct.
Do not use comments to silence a valid finding.

## Tests

Name tests after the unit and observable behaviour:
```go
func TestDecoder_RejectsTrailingBytes(t *testing.T)
func TestStore_PreservesCommittedRecord(t *testing.T)
```

Keep the main test name short. Use table cases or subtests for input variants
rather than encoding every condition in the function name.

Test files must follow the production intent they verify. Do not collect
unrelated failures into broad coverage or regression files.

An ordinary test file approaching or exceeding 1,000 lines requires a
structural review. First split independently reviewable behaviours into
intent-named files. If the remaining cases are cohesive residual branches or
error paths that would otherwise fragment the primary behavioural tests, place
them in a narrowly named file such as `decoder_coverage_test.go`.

A residual coverage file must:
- name the production intent it covers;
- contain related cases only;
- assert observable behaviour;
- include failure and boundary assertions where applicable;
- remain independently reviewable;
- be split again if it accumulates another responsibility.

Coverage files are not permitted to:
- call code merely to execute lines;
- collect unrelated package-wide leftovers;
- duplicate stronger behavioural tests;
- conceal missing design boundaries;
- justify a weak assertion or percentage-only test.

Tests must:
- assert behaviour rather than implementation sequence;
- cover success, refusal and important failure paths;
- remain deterministic;
- avoid arbitrary sleeps;
- preserve useful failing inputs as fixtures or fuzz seeds;
- fail against a relevant defective implementation;
- clean up every process, file and resource they own.

Test helpers follow the same naming and size rules as production functions.
Do not pass long lists of unrelated fixture values. Use a narrowly typed fixture
only when those values form one test concept.

Do not:
- call code without asserting the result;
- duplicate production logic in the expected value;
- weaken an assertion to obtain coverage;
- add a test whose only purpose is executing uncovered lines;
- hide a scenario behind a helper more complex than the behaviour under test.

## Types and APIs

Represent domain states explicitly. Distinguish absent, empty, unknown, invalid
and unavailable values.

Constructors must validate invariants or be omitted. Return concrete types
unless a consumer requires substitution.

Do not export an identifier for possible future use. Exported names are
contracts and require an actual consumer.

Do not add:
- one-implementation interfaces without a consumer-owned reason;
- generic event buses;
- dependency-injection frameworks;
- untyped maps for structured domain data;
- magic strings or numbers;
- nullable values with ambiguous meaning.

## Errors and Logging

Errors must identify the failed operation and preserve their useful cause.
Avoid duplicate context at every stack level.

Do not:
- discard an error;
- panic for an expected failure;
- parse unstable error text;
- log and return the same error at multiple layers;
- include secrets or sensitive content;
- use `failed` without naming the operation.

Log only at the boundary that owns reporting. Keep fields stable, structured
and redacted.

## Review Triggers

Stop and review the design when:
- a name exceeds five semantic words;
- a function exceeds 50 lines;
- a file exceeds 500 lines;
- a function has more than four positional parameters;
- nesting reaches three levels;
- a test file begins accumulating unrelated scenarios;
- a test file approaches or exceeds 1,000 lines without a documented
  intent-based split;
- a residual coverage file gains a second responsibility;
- a comment explains ordinary syntax;
- a new abstraction has one implementation;
- another exception is needed for the same design.

These thresholds are review triggers, not permission to damage clarity to meet
a number. An exception must preserve one cohesive invariant and be obvious to a
hostile reviewer.

## Completion

Before accepting code:
1. remove unnecessary comments;
2. shorten names without losing precision;
3. split mixed responsibilities;
4. remove duplicated semantic rules;
5. delete unused code and speculative abstractions;
6. inspect tests for behavioural assertions;
7. run the applicable repository gate;
8. inspect the complete diff for accidental complexity.

Code that needs extensive prose to explain ordinary behaviour is not complete.

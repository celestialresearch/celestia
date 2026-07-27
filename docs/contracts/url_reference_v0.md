# URL-Reference Operation v0

## Scope

Celestia v0 transforms one inert URL reference. It never resolves, fetches,
opens, follows or executes the reference. Output remains untrusted text and
must never be used automatically as a network target.

The operation identifier is `url-reference`, operation version is `0` and
protocol version is `0`. The only modes are `fang` and `defang`.

This contract is internal and versioned. Any incompatible change requires a
new operation or protocol version and fixtures for both versions.

## Change Brief

Current behaviour is one internal Go use case that admits, stages, supervises,
validates, independently verifies and durably records the operation on
Windows. No public command exists.

The current internal flow is:
```text
typed request -> admission -> attempt and nonce -> evidence staging
    -> contained one-shot worker -> protocol validation -> Go verification
    -> terminal publication -> receipt
```

Any future CLI owns parsing and presentation. Admission owns permission to
execute. The Rust worker owns only transformation. Go owns process
supervision, protocol validation, verification, evidence publication and
terminal outcome. No worker field grants authority or trust.

One application-owned evidence root contains immutable attempt directories.
Only accepted attempts reach it. One supervisor call owns one worker process
and joins its complete process tree before returning. Protocol and evidence
formats are compatible only within their declared versions.

The selected options are a future standard-library CLI, strict byte-preserving
grammar, one-shot JSON protocol and per-attempt filesystem bundles. Cobra,
permissive normalisation, SQLite and a persistent worker add no demonstrated
correctness benefit in this slice.

Windows containment and attempt evidence are defined in
`windows_containment_v0.md` and `attempt_evidence_v0.md`. Other platforms fail
closed. Proof requires table and property tests for grammar and transformation,
hostile worker fixtures, protocol fuzzing, interruption and recovery tests,
race-tested process cleanup and native platform evidence.

## Input

An original operation input is exact UTF-8 with no byte-order mark. It must be
between 1 and 4,096 bytes. A transformed reference may be revalidated up to the
8,192-byte output limit so idempotency and round trips remain defined after
host markers expand the original input. Literal NUL, ASCII controls and DEL
are rejected. The rejected
whitespace scalars are U+0020, U+0085, U+00A0, U+1680, U+2000 through U+200A,
U+2028, U+2029, U+202F, U+205F, U+3000 and U+FEFF. No trimming, Unicode
normalisation, case folding or IDNA conversion occurs.

The complete grammar is:
```text
reference = scheme "://" authority [path] ["?" query] ["#" fragment]
scheme    = "http" | "https" | "hxxp" | "hxxps"
authority = host [":" port]
host      = dns-host | ipv4-host | "[" ipv6-address "]"
path      = "/" *path-byte
query     = *query-byte
fragment  = *fragment-byte
port      = 1*5DIGIT
```

`path-byte` excludes literal `?` and `#`. `query-byte` excludes literal `#`.
`fragment-byte` has no additional delimiter. Each is otherwise admitted UTF-8.
Every `%` must begin a percent triplet containing two ASCII hexadecimal digits.
Percent triplets are preserved and are not decoded. A missing scheme, missing
`://`, empty host, empty port or extra unescaped authority delimiter is
rejected.

Grammar literals are byte-for-byte case-sensitive. Only the four lowercase
ASCII scheme tokens shown above are admitted.

User information is not supported. Any `@` in the authority is rejected. An
`@` after the authority is ordinary preserved content.

### DNS Hosts

An active DNS host is an ASCII DNS name with labels separated by `.`. A
defanged DNS host has the same labels separated by the exact three-byte marker
`[.]`.

Each label is 1 to 63 ASCII letters, digits or hyphens. A label must start and
end with a letter or digit. The logical defanged host before an optional final
root separator is at most 253 bytes including separators. The root separator
may add one byte. Physical `[.]` marker bytes do not count towards that logical
limit. A final root separator is permitted and transformed. Single-label hosts
are permitted.

ASCII letters retain their input case. Punycode A-labels such as `xn--...` are
ordinary labels. Unicode domain labels, percent encoding in a host and Unicode
dot lookalikes are rejected. Four all-decimal labels, with or without a final
root separator, are always interpreted as an IPv4 candidate and cannot fall
back to DNS-name validation.

### IPv4 Hosts

An active IPv4 host contains four decimal octets separated by `.`. A defanged
IPv4 host contains the same octets separated by `[.]`. Each octet is from 0 to
255 and has no leading zero unless it is exactly `0`.

### IPv6 Hosts

IPv6 must be bracketed and match the
[RFC 3986 section 3.2.2](https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2)
`IPv6address` grammar after excluding every alternative containing
`IPv4address`. It may therefore contain only ASCII hexadecimal digits and
colons. Zone identifiers are rejected. Platform parsers may assist but cannot
admit text outside this grammar and the shared conformance fixtures.

An embedded dotted-quad or IPv4-mapped dotted form is rejected. Its hexadecimal
equivalent may be used. No bytes inside brackets are transformed.

### Ports and Suffixes

A port is decimal from 1 to 65,535. Its exact digits are preserved including
leading zeroes. Paths, queries and fragments are preserved byte for byte.
Dots and `[.]` outside the host are never transformed.

## Transformation State

For DNS and IPv4 hosts with separators:
- active means `http` or `https` with only `.` host separators;
- defanged means `hxxp` or `hxxps` with only `[.]` host separators;
- every mixed scheme/host state is rejected;
- a host containing both separator forms is rejected.

For single-label and IPv6 hosts the host is neutral, so the scheme alone
determines state.

`defang` accepts active or defanged input. Active input changes `http` to
`hxxp`, `https` to `hxxps` and each host separator `.` to `[.]`. Defanged input is
returned unchanged.

`fang` accepts active or defanged input. Defanged input changes `hxxp` to
`http`, `hxxps` to `https` and each host marker `[.]` to `.`. Active input is
returned unchanged.

No other byte changes. Therefore:
- `defang(defang(x)) = defang(x)`;
- `fang(fang(x)) = fang(x)`;
- `fang(defang(x)) = x` for admitted active input;
- `defang(fang(x)) = x` for admitted defanged input.

Partially transformed, ambiguous and unsupported input is rejected before
worker execution.

## Resource Contract

The Go supervisor enforces:
```text
original input bytes    4,096
reference/output bytes  8,192
request bytes          65,536
response bytes         65,536
standard-error bytes    8,192
wall time            2 seconds
memory                 64 MiB
worker processes             1
```

Timing has five distinct phases:
- admission validates bounded in-memory input and creates an absolute start
  deadline two seconds after admission;
- evidence staging must finish before that start deadline;
- containment startup is checked against the earlier of the remaining start
  allowance and a separate two-second startup budget;
- successful process resume starts the worker's full two-second execution
  timer;
- termination and process-tree observation use a separate one-second cleanup
  deadline.

Staging and startup use synchronous filesystem and Windows calls. Their
deadlines are checked between calls and immediately before process resume; they
do not claim to pre-empt a blocking operating-system call. A start deadline
that expires before resume records `start_failed` execution and a `timed_out`
terminal result. After resume, only the execution state machine may classify
the worker outcome.

The worker receives one request on standard input and emits one response on
standard output. Both are compact UTF-8 JSON objects with no byte-order mark,
prefix, suffix or terminal newline. End of file terminates each frame. Unknown
fields and duplicate JSON object keys are rejected.

Standard error is diagnostic text only. It is bounded, retained as bytes and
never parsed as protocol or authority.

Pipe cancellation and joins may use one bounded grace after that deadline.
Synchronous handle closure and AppContainer deletion are not pre-emptible. An
overrun or incomplete join records `cleanup_failed`.

The worker receives a private per-attempt directory containing only its staged
image and `Temp` at launch, a documented environment allowlist and no
unnecessary inherited handles. It may not open
credentials, use a shell, spawn a process, load a user-selected library or
access a network. Worker launch remains disabled on each platform until the Go
supervisor's containment and complete process-tree cleanup are qualified
there.

Each platform has a named and versioned containment profile. Availability is
checked before admission and fails closed. Qualification requires hostile
fixtures that attempt an outbound socket, credential-store access, absolute
filesystem access, a child and grandchild process, memory exhaustion and
survival after cancellation. The profile must deny every attempt and prove
complete owned-process cleanup before that platform can enable the operation.

The selected Windows profile is defined in
[`windows_containment_v0.md`](windows_containment_v0.md).

## Request Envelope

All fields are required:
```json
{
  "protocol_version": 0,
  "operation_id": "url-reference",
  "operation_version": 0,
  "attempt_id": "base64url-32-random-bytes",
  "request_nonce": "base64url-32-random-bytes",
  "input_media_type": "text/plain; charset=utf-8",
  "input_length": 21,
  "input_sha256": "64-lowercase-hex-digits",
  "mode": "defang",
  "deadline": "RFC3339Nano UTC",
  "timeout_ms": 2000,
  "limits": {
    "input_bytes": 4096,
    "output_bytes": 8192,
    "stderr_bytes": 8192,
    "memory_bytes": 67108864,
    "processes": 1
  },
  "input": "https://example.test/"
}
```

Identifiers and nonces use unpadded base64url. Hashes cover exact UTF-8 bytes.
The deadline uses a `Z` offset and is the latest permitted process-resume time.
Admission derives it from `timeout_ms`. After resume, `timeout_ms` supplies a
fresh execution allowance measured by the supervisor's monotonic timer.
Lengths and hashes must match the decoded exact input. The exact serialised
request bytes are retained.

Every JSON number is an unsigned base-ten integer with no sign, fraction,
exponent or leading zero except the value `0`. Length fields range from zero
through their declared limit. `timeout_ms` is exactly `2000`. Memory and
process limits cover the complete worker process tree and the worker counts as
the single allowed process. Unknown fields are rejected recursively in every
object.

Request string fields have these exact rules:
- `operation_id`, `input_media_type` and `mode` are the literals or enum shown;
- `attempt_id` and `request_nonce` decode to exactly 32 bytes;
- `input_sha256` is exactly 64 lowercase hexadecimal digits;
- `deadline` is an RFC3339Nano string in UTC;
- `input` is the admitted string and its byte length is from 1 through 4,096.

Protocol and operation versions are integer `0`. Every limit is the exact
integer shown. The `limits` object contains no additional field.

## Response Envelope

All fields are required when status is `completed`. Output fields are absent
for every other status:
```json
{
  "protocol_version": 0,
  "operation_id": "url-reference",
  "operation_version": 0,
  "attempt_id": "echoed-attempt-id",
  "request_nonce": "echoed-request-nonce",
  "worker_id": "celestia-url-reference",
  "worker_version": "0",
  "status": "completed",
  "output_media_type": "text/plain; charset=utf-8",
  "output_length": 23,
  "output_sha256": "64-lowercase-hex-digits",
  "output": "hxxps://example[.]test/",
  "diagnostics": [],
  "duration_ns": 1000
}
```

Worker statuses are `completed`, `rejected` and `failed`. `worker_id` is
`celestia-url-reference`, `worker_version` is `0` and the output media type is
the request media type. Output length ranges from 1 through 8,192 and its hash
is exactly 64 lowercase hexadecimal digits. `duration_ns` is an integer from
zero through 2,000,000,000. A diagnostic is an object
containing required string fields `code` and `message`. A response has at most
16 diagnostics. Codes contain 1 to 64 lowercase ASCII letters, digits and
underscores. Messages contain at most 512 UTF-8 bytes. Messages are
worker-controlled, potentially sensitive evidence and are not stable API text.
They are retained in the protected attempt bundle but are never copied to
ordinary logs, standard error or CLI output. Operator-facing diagnostics are
selected by Go from validated status-code pairs and use only host-owned
messages. `completed` exposes none. `invalid_reference` is recognised only for
`rejected`; every other pair becomes `worker_failure`.

For `completed`, every shown field is required and diagnostics may be empty.
For `rejected` and `failed`, output media type, length, hash and output are
absent while at least one diagnostic is required. All identity, version,
nonce, diagnostics and duration fields remain required.

Process exit `0` is valid only with `completed`, exit `2` only with `rejected`
and exit `3` only with `failed`. Any other exit, missing response or
status/exit mismatch is an execution failure. A valid `rejected` response after
Go admission records execution `completed`, protocol `valid`, verification
`not_run` and terminal `failed`; it cannot retroactively reject admission. A
valid `failed` response records execution `exit_failed`, protocol `valid` and
terminal `failed`. Only `completed` proceeds to independent verification.

Worker status is a claim. It cannot determine admission, protocol validity,
verification, durability or the final Celestia outcome.

## Outcome Model

Every admitted attempt records independent dimensions:
```text
admission:    accepted | rejected
execution:    completed | start_failed | timed_out | cancelled | output_overflow |
              error_overflow | exit_failed | cleanup_failed
protocol:     not_run | valid | rejected
verification: not_run | verified | rejected
durability:   pending | durable | indeterminate
recovery:     none | pending | corrupt
```

The terminal summary is derived in this order:
1. Non-durable or contradictory required evidence is `indeterminate`.
2. Admission denial before execution is `rejected`.
3. Cancellation is `cancelled`.
4. Deadline expiry is `timed_out`.
5. Execution failure or protocol rejection is `failed`.
6. Valid protocol plus verified postcondition is `verified`.
7. Valid protocol without a verified postcondition is `executed_unverified`.

`indeterminate` never means allowed or verified. Protocol completion is not
verification. `verified` means only that the named Go verifier established
this contract's deterministic postcondition.

## Evidence and Recovery

Rejected input is not retained because it may contain unsupported credentials
or other sensitive material. Its rejection class may be shown without echoing
the input.

An accepted attempt receives a new random identity. Before worker start the
store exclusively creates:
```text
attempts/.pending/<attempt-id>/bundle/
```

Every accepted bundle is potentially sensitive because paths, queries and
fragments may contain credentials. The application-owned evidence root uses
owner-only permissions, rejects links and reparse points at every component
and is retained until explicit operator deletion. v0 performs no automatic
garbage collection.

The bundle contains exact input, request, response and diagnostic bytes plus
versioned JSON records for admission, process outcome, protocol validation,
verification and pre-publication outcome. `attempt_evidence_v0.md` is the
authoritative persistent schema. Its receipt hashes the admitted and terminal
records; worker and verifier identity remain inside the hashed terminal
observation. Record files do not contain their own hashes. The manifest set
excludes the receipt and publication marker.

Records are written through same-directory temporary files, flushed and
published to unused final names through the platform procedure defined in
`attempt_evidence_v0.md`. The receipt is written last and hashed separately.
The complete pending attempt is verified, flushed and atomically renamed to:
```text
attempts/<attempt-id>/
```

The renamed directory is visible but remains uncommitted. After file data and
parent-directory metadata meet the qualified platform durability procedure, a
complete read-back verifies every receipt link. The store then atomically
writes and flushes `publication.json` containing only the attempt identity,
receipt hash and publication schema version. Its validated presence is the
publication boundary. Durability is derived during inspection rather than
self-declared inside a pre-publication record.

Existing attempt identities are rejected before worker start. Bundle records
are never modified after rename and the publication marker is created at most
once. A pending attempt is never resumed or re-executed. A permanent
per-attempt lock file provides the cross-process ownership identity. Execution
holds its operating-system lock from staging through publication. Recovery
fails while that lock is held and may proceed after process death releases it.
Lock files are not deleted because replacing a locked inode would split
ownership. A permanent ownership-era marker distinguishes current attempts
with a missing lock from pre-lock v0 bundles. Recovery may only:
- validate and publish a complete pending attempt;
- retain and report an incomplete pending attempt;
- report a corrupt pending or published attempt.

If staging fails before `admitted.json` is durable, the permanent ownership
marker burns the generated identity but the result does not expose that identity
as inspectable or recoverable.

If execution succeeds but publication fails, the result is `indeterminate`.
The CLI may display a clearly labelled non-durable output but must not describe
it as verified or retained. Inspection verifies stored hashes and state
transitions without rerunning the worker.

A receipt is an internal consistency manifest under the assumption that the
evidence root has not been rewritten by a hostile writer. It provides no
cryptographic provenance or external tamper resistance. It does not prove that
a URL is safe, reachable, authentic or externally true.

## Planned CLI Contract

A future standard-library CLI will accept one mode and exactly one
URL-reference argument. It will reject missing or extra arguments before
application execution. Standard output will contain only the transformed
reference after a `verified` outcome. Diagnostics and non-verified summaries
will use standard error.

Planned exit statuses are:
```text
0 verified
2 rejected
3 failed
4 executed_unverified
5 cancelled
6 timed_out
7 indeterminate
```

No machine-readable CLI format is defined in v0.

## Non-Goals

This strict contract does not define URL safety, reputation, reachability, DNS,
HTTP, general URL parsing, prose extraction, permissive indicator
normalisation, canonicalisation, credential handling, network use, a reusable
worker framework, a database or any learned component. Wrapped words, HTML
entities, escaped separators, Unicode punctuation and zero-width evasion
characters belong to a separate future ingestion-normalisation contract.

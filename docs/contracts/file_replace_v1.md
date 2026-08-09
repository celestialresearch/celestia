# File Replacement v1

## Scope

File replacement v1 replaces one existing regular file beneath one configured
root on Windows AMD64. Trusted Go code owns admission, the filesystem effect,
postcondition observation, evidence and recovery.

This slice is separately authorised after the completed restructuring plan.
It supersedes that plan's second-operation non-goal only for this operation.

## Typed Request

The request contains:
- one direct-child filename encoded as valid UTF-8;
- the lowercase SHA-256 of the expected current bytes;
- replacement bytes no larger than 1 MiB.

The filename is one ordinary Windows filename. It cannot be empty, absolute,
`.` or `..`; contain a separator, colon, control character, trailing space or
trailing full stop; or name a reserved Windows device including the documented
`COM` and `LPT` forms using superscript digits. Nested paths, alternate data
streams, wildcard expansion and path normalisation are not supported.

The target must already exist as one regular non-reparse file with one hard
link. Creation, directory replacement and replacement across volumes are not
supported.

## Authority

Application configuration supplies separate target and evidence roots. User
input cannot select either root. Both roots must be absolute paths on fixed
local Windows volumes. The operation opens each root as a rooted filesystem
capability and refuses unsafe ownership, permissions, links or volume types.
It compares the opened roots by volume serial and 128-bit file identifier. The
same identity is retained in each intent and must match before recovery touches
the target root.

Admission validates request shape but grants no filesystem authority. The
final effect boundary reopens the target beneath the retained root capability,
revalidates its identity and safety properties then hashes its current bytes.
The replacement proceeds only when that digest equals the admitted
precondition.

An administrator and code running as the Celestia account remain trusted.
This operation does not claim protection from either actor rewriting files or
evidence directly.

## Effect

The operation:
1. Retains admitted intent before preparing the effect.
2. Creates one exclusive private temporary file in the target root.
3. Writes the complete replacement, synchronises it then closes it.
4. Revalidates target authority and the exact precondition.
5. Atomically renames the temporary file over the target through the rooted
   directory handle.
6. Observes the target through a new handle and verifies its length and
   SHA-256 independently from the write path.
7. Retains the effect observation, verification and terminal receipt.

The implementation must not delete the target before renaming and must not
fall back to a path-based non-atomic sequence.

## State

States are:
- `requested`: request received but not admitted;
- `admitted`: validated request and durable intent;
- `prepared`: synchronised replacement exists but commitment has not started;
- `rejected`: admission or authority refusal before effect preparation;
- `failed`: no replacement occurred and the failure is established;
- `cancelled`: cancellation was observed before commitment and no replacement
  occurred;
- `verified`: the independently observed target matches the replacement;
- `indeterminate`: commitment may have occurred but the postcondition or
  required durable evidence cannot be established.

The successful rooted rename is the commitment boundary. Cancellation before
that boundary removes the temporary file and returns `cancelled`. Cancellation
at or after that boundary cannot become `cancelled`; the operation completes
postcondition observation and reports `verified` or `indeterminate`.

Cleanup status is retained separately and cannot overwrite the primary
terminal state. It covers temporary-file and effect cleanup completed before
terminal publication. A later attempt-lock release error remains a returned
resource error but cannot rewrite the append-only receipt.

## Evidence

Evidence is operation-specific and versioned. It retains:
- admitted request, attempt identity and timestamp;
- the opened target-root volume serial and 128-bit file identifier;
- expected and replacement digests plus replacement length;
- the private temporary filename;
- whether commitment was attempted and the native result;
- postcondition target length and digest;
- primary terminal state and cleanup outcome;
- hashes of every retained record in one terminal receipt.

Records never retain replacement bytes. Evidence publication is bounded to
1 MiB per attempt. A record is canonical JSON with one trailing line feed. A
record is written to an exclusive staging name, synchronised, closed, atomically
published to its final name then followed by directory synchronisation. A retry
accepts the same canonical record and rejects different bytes.

## Recovery

Recovery requires exclusive operation ownership. It never repeats a rename.
No new attempt may begin while any non-terminal intent exists. A corrupt
non-terminal record also requires operator recovery rather than allowing a new
effect.
It removes a retained temporary file only when evidence proves commitment was
not attempted. Once commitment may have started, recovery observes the target:
- a target matching the replacement digest can become `verified`;
- a retained native failure can become `failed` because the rename did not
  occur;
- every other or unavailable observation becomes `indeterminate`.

Recovery records its own observation and publishes one terminal receipt only
after every referenced record is present and hash-matching. Retried recovery
reuses an identical durable verification record and rejects a changed record.
Inspection derives the match result from the retained intent, observed digest
and observed length; it rejects a contradictory stored `matched` value.

## Platforms

Windows AMD64 is the only supported execution and evidence platform. Every
other operating system or architecture returns an unsupported error without
admission, filesystem access or evidence creation. Cross-compilation proves
only that the refusal path builds.

## Non-Goals

This slice does not add:
- a worker or worker protocol;
- dynamic discovery, plug-ins or runtime registration;
- a generic operation interface or catalogue;
- shared abstractions extracted from URL reference;
- nested targets, file creation or directory mutation;
- compatibility readers or migrations for unused pre-release formats;
- network access or learned-model authority.

## Falsifiers

The design is false if any test can demonstrate that:
- an invalid request reaches filesystem mutation;
- a changed, linked, reparse or out-of-root target is replaced;
- cancellation after commitment is reported as no effect;
- recovery repeats an uncertain rename;
- verification trusts bytes retained from the write path;
- cleanup failure overwrites the primary outcome;
- another operation is imported or grants this operation authority;
- unsupported platforms touch a configured root.

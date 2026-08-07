# Attempt Evidence v1

Status: implemented for the internal URL-reference operation on Windows AMD64.
The same store semantics and bounded native persistence qualification are
implemented on Linux AMD64 but operation execution remains unavailable there.

## Layout

Each admitted attempt starts in a private pending bundle:
```text
<root>/attempts/.pending/<attempt-id>/bundle/
  admitted.json
  observation.json | recovery.json
  receipt.json

<root>/.locks/<attempt-id>.lock
<root>/.locks/<attempt-id>.owned
```

The complete bundle is moved to `<root>/attempts/<attempt-id>/` before its
publication marker is written.

`admitted.json` retains the original input and exact request frame.
Inspection uses the versioned `protocol` frame semantics. It requires
the request attempt identity and input to match the duplicated admitted fields
then enforces the deadline, input length, input hash, mode and fixed operation
limits. It does not rerun admission, the URL grammar, the transformation or
the worker.
`observation.json` retains the worker identity, exact bounded streams, process
outcome, protocol result, verification result and terminal status.
`recovery.json` records an interrupted attempt as `indeterminate`.

The receipt contains SHA-256 hashes of the admitted and terminal records.
`publication.json` contains the receipt hash and is the atomic terminal
publication marker. A bundle without a valid publication marker is not a
durable terminal outcome.

## Atomicity and Recovery
- The evidence root may be created only beneath an existing secure directory.
  Windows requires the protected single-user ACL used by evidence directories.
  Linux AMD64 requires current-user ownership, no group or world write access
  and a local ext4 or XFS filesystem. `New` does not create missing ancestor
  directories.
- Windows evidence roots require a fixed local drive whose DOS device target is
  a hard-disk volume. UNC, device, mapped, substituted, removable and RAM-disk
  roots are rejected before evidence access.
- Attempt persistence is implemented on Windows and Linux AMD64. Other
  operating systems fail before evidence access with `ErrUnsupported`. Linux
  operation execution remains unavailable until native qualification passes.
- Each attempt has a permanent lock file. Its operating-system exclusive lock
  is held from staging through terminal publication.
- Writers publish `admitted.json` before creating the permanent ownership
  marker. The marker is the staging commit point.
- An error after marker object creation retains the pending admitted bundle for
  recovery; it does not roll back across the possible commit point.
- Recovery holds the attempt lock while removing a pending directory that has
  no ownership marker and returns `ErrUncommitted`. The identity may then be
  staged again. A missing marker on a committed attempt is corruption.
- Recovery uses a non-blocking acquisition and refuses an active attempt.
  Process death releases the lock without a timestamp or stale-age guess.
- Lock files are never replaced or removed, preventing ownership from splitting
  across different filesystem objects.
- Pending and published directory creation refuses duplicate identities.
- Every record is flushed then published to its final name without replacement.
  Windows uses a write-through move. Linux uses
  `renameat2(RENAME_NOREPLACE)` through a no-follow directory descriptor then
  flushes that directory.
- Under exclusive recovery ownership the store removes only recognised writer
  temporary names left by interrupted record publication.
- A receipt is published only after both referenced records are readable and
  hashed.
- The complete bundle is moved without replacement into the published namespace
  before `publication.json` is created. Linux flushes both the pending and
  published parent directories after the move.
- Inspection accepts only fixed record names, regular files, matching attempt
  identities, matching schema versions, matching terminal states and matching
  hashes. It validates the retained protocol relationship without replaying
  URL grammar or transformation semantics.
- Recovery never reruns the worker. It publishes an `indeterminate` recovery
  record for an incomplete attempt or resumes publication of an existing valid
  terminal record.
- New recovery reasons are valid UTF-8, contain no control characters or
  surrounding whitespace and are limited to 512 bytes.
- A persistence failure cannot produce `verified`.

v1 is the only maintained evidence format. The `protocol` package defines its
frame semantics. The `transform` package defines the admission and publication
semantics but inspection does not replay them. Before operational use, an
incompatible change replaces all maintained readers, writers, fixtures and
contracts in place. No superseded format or migration path is retained.

The filesystem and same user remain trusted. This format does not defend
against an authorised user replacing the complete evidence root or modifying
records and recomputing every hash.

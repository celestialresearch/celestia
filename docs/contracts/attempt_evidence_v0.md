# Attempt Evidence v0

Status: implemented for the internal URL-reference operation.

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
Inspection uses the current v0 frame decoder and requires its attempt identity
and input to match the duplicated admitted fields. The decoder enforces the
v0 URL grammar, deadline, input length, input hash, mode and fixed operation
limits. It does not rerun admission or generate new identities.
`observation.json` retains the worker identity, exact bounded streams, process
outcome, protocol result, verification result and terminal status.
`recovery.json` records an interrupted attempt as `indeterminate`.

The receipt contains SHA-256 hashes of the admitted and terminal records.
`publication.json` contains the receipt hash and is the atomic terminal
publication marker. A bundle without a valid publication marker is not a
durable terminal outcome.

## Atomicity and Recovery
- The evidence root may be created only beneath an existing secure directory.
  On Unix the parent must be owned by the current user and not group or world
  writable. On Windows the parent must have the protected single-user ACL used
  by evidence directories. `New` does not create missing ancestor directories.
- Windows evidence roots require a fixed local drive whose DOS device target is
  a hard-disk volume. UNC, device, mapped, substituted, removable and RAM-disk
  roots are rejected before evidence access. Network-mounted Unix filesystems
  are not qualified by v0.
- Each attempt has a permanent lock file. Its operating-system exclusive lock
  is held from staging through terminal publication.
- Writers create a permanent ownership marker before staging. A missing lock or
  marker is corruption.
- A staging failure before `admitted.json` is durable burns the identity but
  does not expose it as an inspectable or recoverable attempt.
- Recovery uses a non-blocking acquisition and refuses an active attempt.
  Process death releases the lock without a timestamp or stale-age guess.
- Lock files are never replaced or removed, preventing ownership from splitting
  across different filesystem objects.
- Pending and published directory creation refuses duplicate identities.
- Every record is flushed then published to its final name without replacement.
  Windows uses a write-through move. Unix-like systems link, sync, unlink the
  temporary name then sync again.
- Under exclusive recovery ownership, Windows and Unix-like systems remove only
  recognised writer temporary names left by an interrupted record publication.
  Unix linked targets must identify the same owner-only regular file before
  repair.
- A receipt is published only after both referenced records are readable and
  hashed.
- The complete bundle is moved into the published namespace before
  `publication.json` is created. Unix-like systems sync the target parent before
  the source parent after this cross-directory move.
- Inspection accepts only fixed record names, regular files, matching attempt
  identities, matching schema versions, matching terminal states and matching
  hashes. It replays protocol validation and deterministic URL verification
  against the retained request and response.
- Recovery never reruns the worker. It publishes an `indeterminate` recovery
  record for an incomplete attempt or resumes publication of an existing valid
  terminal record.
- New recovery reasons are valid UTF-8, contain no control characters or
  surrounding whitespace and are limited to 512 bytes.
- A persistence failure cannot produce `verified`.

Celestia has no pre-release persistence compatibility guarantee. Evidence
created before the first supported release may be rejected after an internal
schema or semantic change. Persistent compatibility must be defined before
operational evidence is retained across upgrades.

The filesystem and same user remain trusted. This format does not defend
against an authorised user replacing the complete evidence root or modifying
records and recomputing every hash.

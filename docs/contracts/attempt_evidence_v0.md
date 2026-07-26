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
```

The complete bundle is moved to `<root>/attempts/<attempt-id>/` before its
publication marker is written.

`admitted.json` retains the original input and exact request frame.
Inspection uses the frozen v0 frame decoder and requires its attempt identity
and input to match the duplicated admitted fields. The decoder enforces the
v0 deadline, input length, input hash, mode and fixed operation limits. It does
not replay the current admission policy.
`observation.json` retains the worker identity, exact bounded streams, process
outcome, protocol result, verification result and terminal status.
`recovery.json` records an interrupted attempt as `indeterminate`.

The receipt contains SHA-256 hashes of the admitted and terminal records.
`publication.json` contains the receipt hash and is the atomic terminal
publication marker. A bundle without a valid publication marker is not a
durable terminal outcome.

## Atomicity and Recovery
- Each attempt has a permanent lock file. Its operating-system exclusive lock
  is held from staging through terminal publication.
- Recovery uses a non-blocking acquisition and refuses an active attempt.
  Process death releases the lock without a timestamp or stale-age guess.
- Lock files are never replaced or removed, preventing ownership from splitting
  across different filesystem objects.
- Pending and published directory creation refuses duplicate identities.
- Every record is flushed then published to its final name without replacement.
  Windows uses a write-through move; Unix-like systems link then sync the
  containing directory.
- A receipt is published only after both referenced records are readable and
  hashed.
- The complete bundle is moved into the published namespace before
  `publication.json` is created.
- Inspection accepts only fixed record names, regular files, matching attempt
  identities, matching schema versions, matching terminal states and matching
  hashes.
- Recovery never reruns the worker. It publishes an `indeterminate` recovery
  record for an incomplete attempt or resumes publication of an existing valid
  terminal record.
- A persistence failure cannot produce `verified`.

The filesystem and same user remain trusted. This format does not defend
against an authorised user replacing the complete evidence root or modifying
records and recomputing every hash.

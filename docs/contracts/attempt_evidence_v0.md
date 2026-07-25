# Attempt Evidence v0

Status: implemented for the internal URL-reference operation.

## Layout

Each admitted attempt starts in a private pending bundle:
```text
<root>/attempts/.pending/<attempt-id>/bundle/
  admitted.json
  observation.json | recovery.json
  receipt.json
```

The complete bundle is moved to `<root>/attempts/<attempt-id>/` before its
publication marker is written.

`admitted.json` retains the original input and exact request frame.
`observation.json` retains the worker identity, exact bounded streams, process
outcome, protocol result, verification result and terminal status.
`recovery.json` records an interrupted attempt as `indeterminate`.

The receipt contains SHA-256 hashes of the admitted and terminal records.
`publication.json` contains the receipt hash and is the atomic terminal
publication marker. A bundle without a valid publication marker is not a
durable terminal outcome.

## Atomicity and Recovery
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

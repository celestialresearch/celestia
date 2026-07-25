# Attempt Evidence v0

Status: implemented for the internal URL-reference operation.

## Layout

Each admitted attempt owns one directory named by its generated attempt
identity:
```text
<root>/<attempt-id>/
  admitted.json
  observation.json | recovery.json
  receipt.json
```

`admitted.json` retains the original input and exact request frame.
`observation.json` retains the worker identity, exact bounded streams, process
outcome, protocol result, verification result and terminal status.
`recovery.json` records an interrupted attempt as `indeterminate`.

The receipt contains SHA-256 hashes of the admitted and terminal records. It is
the atomic terminal publication marker. A terminal record without a receipt is
not a durable terminal outcome.

## Atomicity and Recovery
- Attempt directory creation refuses duplicate identities.
- Every record is flushed then published to its final name without replacement.
  Windows uses a write-through move; Unix-like systems link then sync the
  containing directory.
- A receipt is published only after both referenced records are readable and
  hashed.
- Inspection accepts only fixed record names, regular files, matching attempt
  identities, matching terminal states and matching hashes.
- Recovery never reruns the worker. It publishes an `indeterminate` recovery
  record for an admitted attempt without a receipt.
- A persistence failure cannot produce `verified`.

The filesystem and same user remain trusted. This format does not defend
against an authorised user replacing the complete evidence root or modifying
records and recomputing every hash.

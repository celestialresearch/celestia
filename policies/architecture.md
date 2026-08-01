# Architecture Policy

This policy owns Production directory, package, module and import structure.
`policies/architecture.json` is its machine-readable form. Source policy owns
paths, package declarations, documentation and migration exceptions. Depguard
owns Go import direction. Assurance independently compiles the forbidden
boundary and rejects a weaker Production policy.

## Root Ownership
Tracked directories are limited to repository configuration, `.cargo`,
`.github`, `cmd`, `docs`, `internal`, `policies`, `testdata`, `tools` and
`worker`.
Root files are individually declared in the machine policy. A recognised root
does not admit an arbitrary package or command beneath it.

`cmd` is reserved but no command is currently declared. A command requires an
operation root, binary artefact, platform scope and output contract before its
directory is admitted.

Generic accumulation segments are prohibited. The policy evaluates complete
path segments so a specific domain term containing the same letters is not
rejected as a substring.

## Package Ownership
The current Production packages are the six governed URL-reference packages
and the two repository-policy tools declared in the machine policy. An
unregistered flat package, forwarding package or duplicate implementation is
rejected.

Every package requires one concise package comment describing its present
owner and authority. A package at its final path must use `doc.go`. A package
beneath one of the four migration roots may place the comment in an existing
file until its assigned move because its frozen inventory cannot gain a file.

## Dependency Direction
The governed URL-reference operation may depend on attempt evidence, admission,
protocol, transformation and process supervision. Attempt evidence may depend
on admission, protocol and transformation. Admission may depend on protocol
and transformation. Protocol may depend on transformation. Transformation and
process supervision do not depend on another Production package.

The following directions are always rejected:
- one operation importing another operation;
- an operation subpackage importing its orchestration root;
- execution importing an operation;
- Production importing Assurance;
- a runtime package importing `tools` or worker source;
- a command importing an operation subpackage;
- the independent Assurance oracle importing Production.

Tests and platform files receive no broad exception. Imports are checked by
exact module and package prefixes.

## Migration Registry
The temporary registry contains exactly:
- `internal/attemptstore` to `internal/operation/urlreference/attempt` in
  `CEL-STRUCT-004D`;
- `internal/urladmission` to `internal/operation/urlreference/admission` in
  `CEL-STRUCT-004C`;
- `internal/urloperation` to `internal/operation/urlreference` in
  `CEL-STRUCT-004E`.

Each entry binds the exact base commit, file count and canonical inventory
digest. Existing files may be corrected, moved or deleted. A new tracked file
beneath a migration root is rejected. Wildcards, parent roots, expired entries and
recreated migrated paths are rejected. `internal/processsupervision`,
`internal/urlreferencev1` and `internal/workerprotocolv1` are retired and cannot
be recreated. Each migration slice removes its entry when it moves the package;
`CEL-STRUCT-005` reconciles the registry to empty.

## Exceptions
Architecture exceptions are exact path records with an owner, reason, removal
condition and expiry. Wildcards and parent exceptions are invalid. The initial
policy contains no file exception.

## Non-Claims
Static architecture policy does not prove runtime correctness, containment,
durability or external truth. It does not qualify another platform and does not
authorise a package move, command, worker or learned subsystem. This slice
deliberately resets the unused internal module identity to
`celestia.research/celestia` without a forwarding path.

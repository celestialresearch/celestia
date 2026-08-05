# Architecture Policy

This policy owns Production directory, package, module and import structure.
`policies/architecture.json` is its machine-readable form. Source policy owns
paths, package declarations and documentation. Depguard
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
The current governed repository packages are the six Production URL-reference
packages, the Windows test Cargo owner and the two repository-policy tools
declared in the machine policy. `internal/testcargo` is test support only and
cannot become runtime authority. An unregistered flat package, forwarding
package or duplicate implementation is rejected.

Every package requires one concise package comment describing its present
owner and authority in `doc.go`.

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
exact module and package prefixes. The Windows test Cargo owner is restricted
to the supervision qualification test and the two URL-operation test files
that build fixed worker inputs.

## Prohibited Paths
The six obsolete package roots cannot be recreated. They have no forwarding,
compatibility or migration surface. The machine policy declares each exact
path and source policy rejects every file at or beneath it.

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

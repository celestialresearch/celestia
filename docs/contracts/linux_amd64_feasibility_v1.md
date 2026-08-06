# Linux AMD64 Feasibility v1

## Status

Proposed feasibility work only. Linux operation execution and attempt
persistence remain unsupported. Windows AMD64 remains the sole qualified
operation boundary. The
[machine-readable manifest](cel_plat_linux_amd64_feas_001.json) is authoritative;
this file is its review summary.

## Outcome

One named native Linux AMD64 host either demonstrates every listed primitive
or records the first refusal before a Production worker can execute. A feasible
observation is not Linux support or a persistence qualification.

The maintainer-only `tools/linuxamd64feasibility` preflight performs bounded
read-only checks and emits only `unavailable` or `indeterminate`. It is not a
release artefact and cannot qualify the platform.

The internal cgroup checkpoint validates a caller-supplied delegated cgroup v2
root under exclusive same-authority custody then creates and removes one owned
empty leaf. A native qualification harness may provide one bootstrap command to
the placement primitive. The primitive sets `pids.max` to one then starts the
bootstrap through Go's clone3-backed cgroup file descriptor path. The bootstrap
blocks on an inherited gate before its payload; the checkpoint verifies leaf
membership, freezes the leaf, releases the gate, proves that no ready byte is
produced before thaw then kills and reaps the bootstrap. Same-authority
processes outside that custody boundary can defeat filesystem ownership and are
not an isolation target. The result retains the first primitive outcome
separately from cleanup completion. This is payload-gate evidence only: it does
not validate bootstrap identity, claim instruction-level suspension before
`exec`, retain an observation or enable Linux operation execution or attempt
persistence.

The `celestia.linux-amd64-feasibility-observation.v1` schema is reserved for a
future native probe. Its synthetic fixtures prove only strict decoding and
state validation. They do not qualify Linux, enable operation execution or
enable attempt persistence.

## Required evidence
- A writable delegated cgroup v2 subtree exposes `cgroup.kill`, `pids.max`,
  `memory.max` and `cpu.max`.
- The launch primitive is `clone3` with `CLONE_INTO_CGROUP`; it places the
  bootstrap in the owned cgroup atomically. Missing kernel support, an invalid
  cgroup file descriptor or any other placement method is unavailable.
- `pids.max` permits four accounted probe roles: bootstrap or fixture, one
  deliberate descendant, one challenge helper and one remaining owned slot.
  The observation records every member PID and role before cleanup.
- A user namespace has explicit host-to-namespace UID and GID mappings and
  the required cgroup delegation. Mount propagation is private. The mount
  allowlist is the owned fixture root plus required read-only runtime mounts.
  `/proc` is a newly mounted private instance with no host process view.
- PID, IPC and UTS namespaces are private. The network namespace has no
  network configuration and loopback remains down.
- Only file descriptors `0`, `1` and `2` are inherited by the bootstrap and
  fixture. The observation proves the allowlist.
- The fixture is an exact static AMD64 ELF image. The observation records its
  SHA-256, ELF machine and type, absence of `PT_INTERP`, executable inode and
  device plus the probe executable SHA-256. No ambient loader identity is
  accepted.
- Root-relative resolution beneath an owned temporary root refuses symbolic
  links, magic links, parent escapes and absolute-path escapes.
- One named local ext4 or XFS evidence root demonstrates a same-directory
  temporary file, `fsync` of that file, `renameat2(RENAME_NOREPLACE)` into the
  final name and `fsync` of the parent directory. Any unsupported or failed
  primitive is unavailable.
- The canonical observation identifies the exact Product commit, probe commit
  and SHA-256; fixture identity; host architecture; kernel release; boot ID;
  cgroup v2 mount and subtree identity, filesystem type and device, namespace
  configuration and every primitive result.

## Refusal boundaries

Refuse before worker execution when:
- the host cannot provide the delegated cgroup v2 controllers, `cgroup.kill`
  or atomic `clone3(CLONE_INTO_CGROUP)` placement;
- user mapping, delegation, any required namespace, mount rule, descriptor
  allowlist, static fixture identity or root-relative resolution guarantee is
  unavailable;
- the evidence root is not a named local ext4 or XFS filesystem or any
  required `fsync` or `renameat2(RENAME_NOREPLACE)` primitive fails;
- any hostile fixture can enable loopback, connect, read outside its root,
  inherit an undeclared descriptor or leave a descendant alive;
- cleanup, process accounting, synchronisation or canonical observation
  identity is incomplete.

No fallback to process groups, post-start cgroup placement, `setrlimit`,
environment scrubbing, Docker, a privileged daemon, QEMU or a hosted runner
without the same delegated authority is permitted.

## Non-claims

This feasibility packet does not qualify seccomp, Landlock, SELinux, AppArmor
or another LSM. It makes no claim that a namespace alone denies every kernel,
filesystem, device, credential or network mechanism. A later execution slice
must state and test any such control it relies on.

## Falsifiers
- A process executes before atomic placement in the owned cgroup.
- User mappings, mount propagation, `/proc` or network-loopback state differ
  from the recorded configuration.
- A network, host-file or descriptor escape succeeds.
- A descendant survives owned-tree cleanup or process accounting exceeds four.
- Filesystem durability is inferred without the required file and directory
  synchronisation plus no-replace rename evidence.
- Linux operation or persistence becomes constructible during feasibility.

## Non-goals
- Implement Linux execution, persistence or a portable supervision layer.
- Qualify Linux ARM64, macOS or any BSD.
- Add a dependency, container, daemon, worker pool or persistent worker.
- Change Windows behaviour, URL grammar, protocol, evidence records or
  terminal outcomes.

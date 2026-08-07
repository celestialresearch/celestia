# Linux AMD64 Feasibility v1

## Status

Proposed feasibility work only. Linux operation execution remains unsupported.
Linux AMD64 attempt storage is implemented but has no native qualification.
Windows AMD64 remains the sole qualified operation boundary. The
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
the placement primitive. The primitive sets `pids.max` to four then starts the
bootstrap through Go's clone3-backed cgroup file descriptor path. The Go
bootstrap receives only `GOMAXPROCS=1` so its runtime remains within that task
ceiling. It blocks on an inherited gate before its payload; the checkpoint
verifies leaf
membership, freezes the leaf, releases the gate, proves that no ready byte is
produced before thaw then kills and reaps the bootstrap. Same-authority
processes outside that custody boundary can defeat filesystem ownership and are
not an isolation target. The result retains the first primitive outcome
separately from cleanup completion. This is payload-gate evidence only: it does
not validate bootstrap identity, claim instruction-level suspension before
`exec`, retain an observation, enable Linux operation execution or qualify
attempt persistence.

The maintainer feasibility executable has a private bootstrap mode used only
after atomic cgroup placement. The bootstrap requires PID 1 in the new PID
namespace, sets a fixed UTS hostname and makes mount propagation private. It
mounts bounded `tmpfs` staging and root filesystems with `nosuid`, `nodev` and
`noexec`, mounts a private `/proc` inside the new root, pivots into that root,
detaches the old root then refuses an enabled loopback interface before
reporting ready. The new filesystem exposes only the bounded root and private
`/proc`; the validated fixture descriptor is the sole deliberate reference to
the prior filesystem. After the second gate the bootstrap closes every
descriptor above `5`, marks `5` close-on-exec, closes both control descriptors
then executes `/proc/self/fd/5` with an empty environment. The fixture therefore
inherits only descriptors `0`, `1` and `2`. Hostile escape probes remain native
qualification work.

The fixture-image checkpoint opens one canonical relative path beneath an
absolute non-linked root through `openat2`. Resolution refuses symlinks, magic
links, mount crossings and path escapes. The opened descriptor must identify a
single-linked, same-user, size-bounded AMD64 ELF executable that is not
group-writable or world-writable. Its bytes are copied into a sealed in-memory
descriptor before ELF validation. The SHA-256, device and inode identify that
non-writable static AMD64 ELF snapshot with no `PT_INTERP`; the bootstrap
executes the same descriptor inside the bounded namespace filesystem view.
Native observation of that boundary remains unavailable.

The internal durability checkpoint accepts one caller-supplied absolute root
of at most 64 components and 255 bytes per component only on Linux AMD64. It
opens every component without following links, requires root or current-user
custody of the path, binds the opened root to one ext4 or XFS mount and creates
one owned fixture directory. The checkpoint writes and syncs one exact
temporary record, publishes it with
`renameat2(RENAME_NOREPLACE)`, syncs the containing directory, reopens and
verifies the exact record then removes only identity-matched files and syncs
their parent directories. The first primitive outcome remains separate from
cleanup completion. This checkpoint retains no record and has no native runtime
observation. The Production attempt store uses the same declared ext4/XFS
durability boundary but remains unqualified until native recovery and
inspection evidence exists.

## Required evidence
- A writable delegated cgroup v2 subtree exposes `cgroup.kill`, `pids.max`,
  `memory.max`, `memory.swap.max` and `cpu.max`. The memory probe sets
  `memory.swap.max` to zero so swap cannot enlarge the declared memory bound.
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
- The qualification bootstrap inherits descriptors `0`, `1` and `2` plus two
  fixed control pipes used only for pre-payload gating. It closes both control
  descriptors before fixture `exec`. The hostile fixture inherits only
  descriptors `0`, `1` and `2`; the observation proves both allowlists.
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
- Linux operation execution becomes constructible or attempt persistence is
  reported qualified without the required native evidence.

## Non-goals
- Implement Linux execution or a portable supervision layer.
- Qualify Linux ARM64, macOS or any BSD.
- Add a dependency, container, daemon, worker pool or persistent worker.
- Change Windows behaviour, URL grammar, protocol, evidence records or
  terminal outcomes.

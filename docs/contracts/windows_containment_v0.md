# Windows Containment v0

Status: implemented and locally qualified for the probes below on Windows.

## Profile
- A unique AppContainer profile is created for each attempt with no capabilities.
- The worker image is copied into that profile then rehashed under a read lock.
- The configured worker must use a local drive-letter path. UNC and device
  paths are rejected before filesystem access.
- The process starts suspended and enters a Job Object before execution.
- The Job Object forbids breakaway and enforces process count, job-tree memory,
  CPU time and kill-on-close.
- Only standard input, standard output and standard error handles are inherited.
- The environment contains only `SystemRoot`, `WINDIR`, `LOCALAPPDATA`, `TEMP`
  and `TMP`.
- Standard input, standard output, standard error, wall time and cleanup time
  are bounded.
- Profile creation, image staging and process setup are checked against the
  earlier of the admitted start deadline and the startup budget between
  synchronous Windows operations and immediately before resume. These checks
  do not pre-empt a blocking Windows call.
- Successful resume is the execution boundary. The full execution timer starts
  after resume, so setup latency cannot reduce its allowance.
- The complete Job Object process tree must reach zero active processes before
  cleanup succeeds.

## Evidence
- The real Rust worker completes through the profile.
- An outbound loopback connection is denied.
- An undeclared user file is denied.
- Child creation is denied when the process limit is one.
- A permitted descendant is terminated before the supervisor returns.
- A permitted grandchild is terminated before the supervisor returns.
- Windows Credential Manager enumeration is denied in the tested profile.
- An attempted allocation above the Job Object memory limit cannot complete.
- Output overflow, diagnostic overflow, timeout, crash and cancellation remain
  distinct process outcomes.

## Non-Guarantees
- This profile does not protect against the same user, an administrator, the
  Windows kernel or a compromised supervisor.
- A regular AppContainer can access Windows resources granted to all
  AppContainers. It is not a virtual machine.
- The configured image identity is checked before each run. The unique staging
  profile and locked rehash narrow but do not eliminate interference by the
  same user.
- Profile deletion is cleanup rather than durable erasure. A deletion failure
  makes cleanup fail.
- CPU time and wall time are separate limits.
- No other Windows release, architecture or worker is qualified by this local
  evidence.

Worker launch remains unavailable on every non-Windows platform.

This evidence does not establish denial of every Windows credential mechanism,
filesystem object, network mechanism or shared AppContainer resource.

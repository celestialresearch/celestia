# Commit and Push Policy

This policy governs repository history and pushes. It is not a contribution
guide.

## Commit Quality

Each commit must:
- represent one coherent change;
- leave the repository buildable and its applicable checks passing;
- include required tests, fixtures and documentation;
- exclude unrelated formatting, generated output, caches and local files;
- contain no secrets, credentials, private keys or sensitive test data;
- be small enough to review completely;
- be safe to revert without removing unrelated work.

Do not commit partial fixes, debugging residue, commented-out code, unexplained
suppressions or speculative scaffolding. Do not use `WIP`, `fixup!` or
`squash!` commits in protected history.

## Commit Names

Use Conventional Commits:
```text
type(scope): summary
```

Allowed types:
- `feat`: user-visible capability;
- `fix`: defect correction;
- `refactor`: structural change without intended behavioural change;
- `perf`: measured performance improvement;
- `test`: test-only change;
- `docs`: documentation-only change;
- `build`: build system or dependency change;
- `ci`: continuous-integration change;
- `chore`: bounded maintenance not covered above;
- `revert`: reversion of an earlier commit.

Use `fix(security)` for security corrections rather than a separate type.

The scope is optional. When present it must name the smallest stable ownership
area such as `cli`, `protocol`, `worker`, `evidence`, `ci` or `repo`. Do not use
a filename as a scope unless the file is itself the maintained system boundary.

The summary must:
- begin with a lowercase imperative verb;
- describe the observable change;
- contain no trailing full stop;
- remain at or below 72 characters;
- use `implement` rather than `add` for a new capability;
- avoid vague terms such as `update`, `changes`, `cleanup`, `misc` or `fixes`.

Examples:
```text
chore(repo): establish verification scaffold
feat(cli): implement governed URL-reference operation
fix(protocol): reject mismatched response nonce
test(worker): cover truncated response
ci: qualify macOS Bash 3.2 verification
```

## Commit Body

A body is required when the summary cannot explain the reason, contract or
risk. Explain:
- why the change is necessary;
- the invariant or externally visible behaviour;
- important compatibility, security or migration consequences;
- evidence that verifies the result.

Describe the decision and evidence. Do not narrate file edits.

Use `BREAKING CHANGE:` in the footer only for an intentional incompatible
public contract change. Reference an issue or decision record when one exists;
do not create artificial issue references merely to satisfy a format.

## Signing

Every locally created commit and annotated tag must use the configured Celestia
GPG key and show a valid signature:
```sh
git commit -S
git tag -s
```

Do not use DCO sign-off trailers unless a separate policy requires them.
Platform-created merge commits must show GitHub's verified signature. An
unsigned or unverifiable commit must not enter `main`.

## Branches and Pull Requests

`main` is the protected integration branch.

The initial repository bootstrap may be pushed directly to establish branch
protection and CI. After bootstrap, substantive changes require a pull request.
Substantive changes include:
- production or test code;
- dependencies or tool versions;
- CI, security or repository policy;
- public interfaces and command behaviour;
- protocols, persistence formats or evidence contracts;
- generated artefacts maintained by the repository.

Use short-lived branches named:
```text
type/short-description
```

Examples:
```text
feat/governed-url-operation
fix/response-nonce-validation
ci/bsd-toolchain
```

Keep branches focused and delete them after merge. Do not maintain long-lived
development branches or use branch names containing personal information.

## Pre-Push Gate

Before pushing:
1. inspect `git status`;
2. inspect the complete staged diff;
3. run `bash ./.github/scripts/devcheck.sh`;
4. confirm every intended commit is signed;
5. confirm the branch contains no merge conflict markers, temporary artefacts
   or secrets;
6. confirm documentation and the checklist match changed behaviour.

Do not push when a required check fails. If a required platform or tool is
unavailable, record the gap and use the pull-request CI result before merge.

## Push Safety

Push only the intended branch to the configured `origin`.

Do not:
- force-push `main`;
- delete or rewrite protected history;
- use `--no-verify` to bypass a repository check;
- push tags, releases or generated binaries without separate authority;
- combine unrelated local branches in one push;
- treat a successful push as evidence that CI passed.

`--force-with-lease` may be used only on an unprotected short-lived branch when
rewriting that branch is deliberate and no other person's work can be lost.
Plain `--force` is prohibited.

After pushing, verify the remote commit, signature and required CI status before
describing the change as accepted.

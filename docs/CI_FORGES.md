# CI forge boundary

GitHub's light pull-request job keeps the required name `Go and policy` and a
ten-minute budget: all Go packages build, then the admin authentication,
credential, receipt and catalog unit suites, three fast workflow policy tests,
and vet run. It uses the `installer-diagnostics` job ID so the existing GitHub
`Kind lifecycle` job can remain verbatim, including its prerequisite, 45-minute
budget, source pins, lifecycle commands and artifact receipts. Both jobs run only
on pull requests, with read-only contents access, pinned actions and concurrency
that cancels superseded PR runs. The owner has not authorized moving or removing
that required lifecycle check. This is an explicit exception to #157's original
one-job boundary, as directed in the PR #160 revision.

The light job does not certify installation, race freedom, or native lifecycle
behavior. The Gitea graph retains its lifecycle proof too, so its aggregate still
covers the complete graph. No new paid Actions or native runner activation is
authorized by this change.

Gitea owns the complete heavy CI graph in `.gitea/workflows/ci.yml`, and the
separate installer performance lab in `installer-performance.yml`. The existing
make targets, profile/mode sets, race shards, envtest partitions, pinned actions,
artifact receipts, and fail-closed `Go and policy` aggregate remain required.
Each signed binary lifecycle leg has its own job and a 170-minute budget:
135/fresh, 137/fresh, and 137/transition. The transition job acquires and verifies
the same immutable historical installer commit and tree before execution.
Timeout, cancellation, failure, and skipped or absent prerequisites never count
as a successful aggregate. No lifecycle coverage is replaced by the light check.

The heavy workflows use only `ci-kind`, `ci-build`, and `ci-light` runners. They
accept literal named-branch pushes, manual dispatch, and nightly schedules.
The main graph runs nightly at 09:00 UTC; the performance lab runs at 09:30 UTC,
after the 03:00 America/New_York quiet-hours boundary in either season. Concurrency
groups include workflow, ref, source SHA, and run ID so distinct main/manual runs
cannot replace each other. Each workflow still sets cancel-in-progress.

Infra Lead must provision the runner environment, repository mirror, Docker,
Go tooling and the shared `/config/.local/bin/heavy-run` lock wrapper before
enabling these workflows. Shell steps use that wrapper with `HEAVY_WAIT=1800` and normalize umask to `022`,
matching the existing safe/unsafe fixture assumptions;
exit 75 is a capacity/quiet-hours refusal and exit 78 is an accounting/config
refusal, neither is passing test evidence. Retry capacity refusals later; route
configuration failures to Infra Lead. Runner environments must honor the two
worker limits and existing namespace/cluster ownership boundaries. No cluster
administration is performed by this workflow migration.

The migration requires Argus's PASS before merge, and this PR remains held.
Required-check settings stay unchanged: `Go and policy` and `Kind lifecycle`
are bound to the GitHub Actions app. F1/C1 is an owner decision: the light job
retains the former name but no longer aggregates the pre-merge heavy proofs.
Gitea runs on main pushes, nightly schedules and manual dispatch, so the owner
must decide whether that post-merge heavy evidence meets the merge policy.
There is no reporter option and agents must not post commit statuses or use an
admin bypass. A successful GitHub light check alone is not the heavy proof.
The pre-existing same-tick ctime limitation (F2/C2) is tracked in issue #174;
waiting for a changed timestamp in the fixture does not fix that limitation. After the first nightly, record the three binary legs' real
execution times and run links on issue #158. A leg approaching 170 minutes needs
review; do not raise the timeout or weaken the proof to obtain a pass.

Validate workflow syntax with:

```sh
actionlint -config-file .github/actionlint.yaml .github/workflows/ci.yml .gitea/workflows/ci.yml .gitea/workflows/installer-performance.yml
```

The Go workflow tests enforce the forge boundary, every required proof, exact
historical acquisition, and aggregate refusal for unsuccessful leg outcomes.

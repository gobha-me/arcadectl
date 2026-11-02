# CI forge boundary

GitHub runs one exact-head pull-request check, with a ten-minute job budget:
all Go packages build, then the admin authentication, credential, receipt and
catalog unit suites run with vet. It does not run on branch pushes. This light
check does not certify installation, race freedom, or native lifecycle behavior.

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
enabling these workflows. Shell steps use that wrapper with `HEAVY_WAIT=30` and normalize umask to `022`,
matching the existing safe/unsafe fixture assumptions;
exit 75 is a capacity/quiet-hours refusal and exit 78 is an accounting/config
refusal, neither is passing test evidence. Retry capacity refusals later; route
configuration failures to Infra Lead. Runner environments must honor the two
worker limits and existing namespace/cluster ownership boundaries. No cluster
administration is performed by this workflow migration.

The migration requires Argus's PASS before merge. Required-check settings stay
unchanged. Infra Lead and Argus must verify how the Gitea aggregate is reported
for the exact candidate and main SHA; a successful GitHub light check alone is
not the heavy proof. After the first nightly, record the three binary legs' real
execution times and run links on issue #158. A leg approaching 170 minutes needs
review; do not raise the timeout or weaken the proof to obtain a pass.

Validate workflow syntax with:

```sh
actionlint -config-file .github/actionlint.yaml .github/workflows/ci.yml .gitea/workflows/ci.yml .gitea/workflows/installer-performance.yml
```

The Go workflow tests enforce the forge boundary, every required proof, exact
historical acquisition, and aggregate refusal for unsuccessful leg outcomes.

# CI operation and budgets

Ordinary pull requests run every existing proof: both Kubernetes profiles,
all cold/warm admission legs, all three signed-installer legs, recovery,
32 race shards and 33 envtest parts. Race uses max-parallel 4, envtest 3,
and every matrix retains fail-fast false. Race and envtest start only after
all their foundations succeed; a failed or cancelled foundation skips those
matrices and makes the `Go and policy` aggregate fail. Envtest also waits for
Go and policy checks to finish, but their result does not gate its execution.

A normal push to main runs Installer CLI and diagnostic controls, Go and policy
checks, and the Go and policy gate (plus the tiny classifier). The gate expects
all heavy jobs to be skipped, and requires both cheap jobs to succeed. This
relies on main's strict up-to-date PR checks, enforced for admins, and squash
merges with linear history: the merged tree is the tested PR head tree.
Changing that merge policy requires revisiting this optimization.

The complete proof set runs on main nightly at **9:00 PM EDT / 8:00 PM EST
(01:00 UTC)**. Per Atlas's ruling at **9:19 PM EDT (01:19 UTC)**, a nightly
may skip only after proving a successful **first-attempt, full-scope** run of
the **same workflow file and workflow-file blob SHA on that exact main commit**.
Both prior `schedule` and `workflow_dispatch` runs remain eligible under
identical conditions; push and PR runs cannot justify a skip. The default
`GITHUB_TOKEN` is sufficient; only the classifier job adds `actions: read`
to `contents: read`.

The guard checks main still matches the scheduled SHA, identifies the current
run, and queries successful runs of its workflow on main for that SHA. Both
`workflow_id` and `path` must match exactly. The only accepted path is the bare
`.github/workflows/ci.yml`: any `@ref` suffix is rejected, even if both paths
have the same suffix, rather than guessing which workflow content it denotes.
For the current run and each eligible candidate, the guard reads the file at
that run's `head_sha` using the contents API and requires `type: file`, the
exact path, and equal 40-hex blob `sha` values. This uses the documented
[repository contents endpoint](https://docs.github.com/en/rest/repos/contents#get-repository-content)
with a commit `ref`; the run's `head_sha` identifies the commit, not the file
blob. See also the documented
[workflow run endpoints](https://docs.github.com/en/rest/actions/workflow-runs).

Up to five newest eligible previous runs are considered. Each must have
`head_sha` equal to the scheduled SHA, `head_branch: main`, run
`status: completed`, `conclusion: success`, and `run_attempt: 1`; reruns cannot prove
coverage because they can contain only a subset of jobs. Its complete
attempt-1 jobs response must match the embedded expected name-to-count table
**exactly: 89 jobs**, no extra, missing, duplicate or skipped job. Every job
must belong to that run and commit and have `status: completed` and
`conclusion: success`. The table covers classification, diagnostics, every
Kind profile/mode leg, all three binary legs, 32 race shards, 33 envtest parts,
Go and policy checks, Kind lifecycle, and the Go and policy aggregate. A
separately authored policy test will keep this table in sync with the jobs/matrices. Full
scope is proven by this complete successful job set, including the lifecycle
sentinel and the aggregate that validates the scope: idle/docs/cheap scopes
cannot satisfy it. Main is checked again immediately before accepting proof.

Any API error, timeout, missing/odd field, unexpected type, inconsistent
response, moved/unexpected HEAD, missing proof or pagination uncertainty
runs the full set (`skip=false`). Run/job responses must contain fewer than
100 entries with matching `total_count` and unique positive integer IDs;
larger histories/pages fall back to full rather than assuming coverage.
Every API call is `gh api --method GET`, with a 20-second call timeout and a
240-second total lookup budget inside the classifier's five-minute budget.
The five-candidate bound also limits requests. No proof within these bounds
means full CI. Commit age has no bearing on coverage, so cron delays cannot
strand an untested SHA outside a rolling time window. A proven skip logs a
notice, skips checkout and every proof, and leaves a green aggregate that
verifies those skips. `workflow_dispatch` bypasses this guard and always runs
the complete set on the selected ref on demand.

Only a superseded head of the same PR cancels an in-progress run. Atlas's
**9:19 PM EDT (01:19 UTC)** decision appends `github.run_id` for every non-PR
event, preserving each queued main, nightly and manual run:

```yaml
concurrency:
  group: ${{ github.event_name == 'pull_request' && format('ci-{0}-{1}', github.workflow, github.event.pull_request.number) || format('ci-{0}-{1}-{2}', github.workflow, github.ref, github.run_id) }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

For this workflow (`github.workflow == 'CI'`), the evaluated groups are:

| Event | Evaluated concurrency group |
|---|---|
| `pull_request` | `ci-CI-<PR number>` (e.g. `ci-CI-140`, unchanged) |
| `push` to main | `ci-CI-refs/heads/main-<run_id>` |
| `schedule` | `ci-CI-refs/heads/main-<run_id>` |
| `workflow_dispatch` | `ci-CI-<selected github.ref>-<run_id>` (e.g. `ci-CI-refs/heads/main-12345`) |

GitHub replaces an older pending run when a new run enters the same group,
even with `cancel-in-progress: false`. Unique run IDs prevent replacement
between separate non-PR runs and allow those runs to overlap, increasing
aggregate runner demand. PR grouping and cancellation remain unchanged. See
[GitHub's concurrency behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

## Runner fairness: at most ten hosted jobs per CI run

Every matrix now has an explicit `max-parallel`: baseline **2**,
precontroller **2**, signed binary **3**, full admission **3**, v3 admission
**3**, race **4**, envtest **3**. **Capping parallelism is not reducing shards:
every profile, mode, all 32 race shards and all 33 envtest parts still run,
unreduced**, subject to the existing scope exception and race/envtest's
failed-foundation early exit.

All three binary legs remain eligible immediately after diagnostics succeed,
keeping the 290/350-minute-budget long pole as early as possible. Baseline, GC,
precontroller and native authentication run alongside them. Both admission
matrices wait for that entire early Kind group. Atlas's fourth ruling at
**9:54 PM EDT (01:54 UTC)** reverses the previous delay of Go/policy feedback:
Go and policy checks now need only classification and diagnostics, with no
direct or transitive dependency on Kind, race or envtest. They run alongside
the early Kind group on full runs and immediately after diagnostics on cheap
main pushes. Reducing v3 admission from
four slots to three leaves room for policy alongside binary and both admission
matrices; all four v3 legs still run.

Race retains its exact foundation dependencies and `success()` condition.
Envtest adds a capacity-only dependency on policy, preventing binary (3),
race (4), envtest (3) and policy (1) from overlapping at eleven jobs. Its
condition now uses `!cancelled()` and explicit success checks on all eight
existing foundations: classify, installer-diagnostics, kind-install-gc,
kind-install-admission, kind-install-admission-v3, kind-install-auth,
kind-install-baseline and kind-install-precontroller. Its existing scope
conditions remain. Thus a failed foundation still skips envtest, while a
Go/policy failure does not. Recovery and lifecycle still wait for envtest;
API replaces its former policy dependency with envtest and shares those three
released slots with them.

Every capacity-only barrier uses `!cancelled()` with the existing scope
conditions, so failure or skip of a capacity-only predecessor does not suppress
the proof; envtest additionally checks its original foundations as described
above. Binary has no new capacity-only needs edges and retains its original
diagnostic-success requirement with `success()` plus the scope conditions.
Diagnostic failure skips binary, which only lowers concurrency; the caps table
is unchanged. Failed foundations still skip race/envtest under item 2;
recovery and the other 135/137 matrices remain eligible.
The unchanged aggregate rejects any failed or unexpectedly skipped proof.
The exact required check names remain `Go and policy` and `Kind lifecycle`.

Caps are worst-case upper bounds, including arbitrary failure/skip outcomes;
non-matrix jobs count as one. Each row is a possible overlap phase, not a
promise about runner scheduling. Each row enumerates a maximal antichain of
the transitive `needs` graph, with weight `min(max-parallel, matrix legs)`
for each matrix and one for each other job. Binary may span every heavy phase;
race can overlap policy before envtest, envtest itself, or the post-envtest jobs.

| Concurrency phase | Jobs (in cap order) | Caps | Sum | Phase maximum |
|---|---|---|---|---:|
| Classifier | classify | 1 | 1 | 1 |
| Diagnostics | installer-diagnostics | 1 | 1 | 1 |
| Early Kind and policy | binary, baseline, GC, precontroller, auth, policy | 3, 2, 1, 2, 1, 1 | 3 + 2 + 1 + 2 + 1 + 1 | 10 |
| Admission and policy | binary, admission, admission-v3, policy | 3, 3, 3, 1 | 3 + 3 + 3 + 1 | 10 |
| Race while policy finishes | binary, race, policy | 3, 4, 1 | 3 + 4 + 1 | 8 |
| Bulk proofs | binary, race, envtest | 3, 4, 3 | 3 + 4 + 3 | 10 |
| After envtest, possibly with race | binary, race, recovery, lifecycle, API | 3, 4, 1, 1, 1 | 3 + 4 + 1 + 1 + 1 | 10 |
| Aggregate | go-and-policy | 1 | 1 | 1 |

The maximum over every unordered set of jobs in the `needs` graph is **10**;
this does not assume a successful or typical-duration run. Cheap, docs-only
and idle scopes are subsets and cannot increase the bound.

From `october-durations.tsv`, a conservative wave model uses
`ceil(legs / cap) * slowest_leg_duration` within each matrix. After diagnostics,
the early Kind group takes at most **19.2 / 22.8 minutes** using p50 / p99 leg
inputs; admission now adds **24.6 / 35.2** (previously **21.6 / 31.4**).
Policy finishes **21.2 / 22.2** minutes after diagnostics, before admission
finishes in this model, so its new envtest edge adds no modeled delay.
Race takes **64.0 / 181.6**; envtest **28.6 / 68.2**, followed by at most
**62.8 / 67.1** for recovery (longer than
lifecycle or API). Thus all non-binary work finishes within
**135.2 / 239.6 minutes** after diagnostics (previously **132.2 / 235.8**).
The binary transition's **241.7 / 328.9 minutes** still dominates, before and
after this change:
**estimated added full-PR wall clock: 0 minutes** at both modeled inputs.
Including diagnostics gives **247.3 / 341.8 minutes**, plus unmodeled common
classification/gate overhead. Go/policy feedback previously arrived at
**90.6 / 144.6 minutes** after diagnostics and now arrives at **21.2 / 22.2**,
about **69.4 / 122.4 minutes earlier**. V3 admission adds one wave; the admission
phase grows **3.0 / 3.8 minutes**, hidden under binary, and affected heavy proofs
report later. This model combines per-job percentiles, not observed whole-run
percentiles or a guarantee. Queueing,
cache behavior, outliers and changed binary performance can change wall time.
Successful runner-minutes remain about **1,116.2 per full run**; caps alone
claim no compute-minute saving.

The bound is **per run, not repo-wide**. Two PR runs can request **20 jobs**,
using the account's approximately 20-slot pool and leaving none for other
repos. One full PR plus a cheap main run and the unchanged performance lab
can request **10 + 1 + 7 = 18** (the lab has six membership shards plus one
independent phase-barrier job). A PR plus a full nightly can request **20**;
two PRs plus that nightly and the lab can request **37**, with excess jobs
queued by the account. Main pushes, nightlies and dispatches now have distinct
run-ID groups and may overlap; each additional cheap main run can request one
more job, and each additional full run can request ten more jobs.
Long binary-only tails often use fewer slots, but do not provide a hard limit.
A hard repo-wide ten-job cap needs a shared ten-slot admission controller with
a durable queue across all runs/workflows, or a dedicated runner pool limited
to ten workers. A single global workflow concurrency group would replace
pending runs by default and is not implemented. The performance workflow and
repository settings are unchanged.

## Documentation and lint configuration exception

A classifier compares the exact PR head with the merge base of the event's
base/head SHAs, or a main push's `before`/`after` SHAs. It uses a NUL-delimited
`git diff --no-renames` so deletions and both sides of a rename count. Only
Markdown files (including root Markdown), `docs/**`, root `LICENSE`,
`LICENSE.txt`, `NOTICE`, `NOTICE.txt`, `.golangci.yml`, `.golangci.yaml`,
`.editorconfig`, and root `.markdownlint*` qualify. `.github/**`, `hack/**`,
`config/**` and `docs/generated/**` always require proofs, even if the changed
file is Markdown. Generated CLI reference/completions in `docs/generated/cli/`
are checked by `hack/verify-generated.sh`. Other generator outputs already
require proofs: `api/v1alpha1/zz_generated.deepcopy.go`, `api/admin/v1/openapi.json`,
`config/crd/bases/**`, `config/rbac/**`, `config/install/anchors.yaml` and
`config/install/controller.yaml`. The runtime-assets verifier's Dockerfiles,
shell helpers, `.dockerignore` and `licenses/restic-LICENSE` also fall outside
the allowlist. Root LICENSE/NOTICE text remains the explicit docs exception.

For a qualifying PR or push, only the classifier and aggregate run. `Kind
lifecycle` is skipped, which satisfies its required check; `Go and policy`
explicitly succeeds after requiring every proof to be intentionally skipped.
No workflow-level path filters or duplicate required-check names are used.

An unknown event, missing/zero/invalid SHA, force push, new/deleted branch,
unavailable history, checkout identity mismatch, diff error, invalid filename
encoding, empty diff, or more than **300 files** defaults to the full set.
This conservative fallback can run the full set even on a main push; ordinary
verified main pushes use the cheap set. A failed classifier job cannot produce
a passing aggregate. Dispatches always select the full set; schedules use the
separate same-SHA coverage guard described above. The aggregate independently
checks the event/ref: `cheap` is accepted only for a push to `refs/heads/main`,
`idle` only for a schedule on that ref, and `docs` only for a pull request or a
push to main. Any mismatch fails, even when every proof result matches its scope.

## Retry only failed jobs

Retry a failed or flaky run with `gh run rerun <run-id> --failed`, or the UI's
**Re-run failed jobs**; never choose **Re-run all jobs**. October's full reruns
consumed **5,017 minutes**, repeating already successful proofs.

## Timeout budgets and watchdog

The table uses successful jobs from October 1–27, 2026, measured from runner
start to completion. All values are minutes. Budgets are
`max(ceil_to_5(success_max + 5), min(old_timeout, ceil_to_5(max(p99 * 1.3, p99 + 10))))`.
Matrix-specific budgets preserve the complete matrix. The new classifier has
no historical sample and a five-minute budget. The rule caps the p99 formula
at the old timeout while preserving the success-max-plus-five floor, rounded
up to five minutes. Every existing measured leg stays at or below its old
budget; diagnostics remains 20, race 30 and transition 350 minutes.
The aggregate's historical sample includes older behavior, so its 40-minute
budget is intentionally conservative for today's assertion-only step.

| Job / leg | Success p99 | Success max | Old timeout | New timeout | Rule applied |
|---|---:|---:|---:|---:|---|
| API-server lifecycle transitions PART | 6.2 | 7.3 | 45 | 20 | min(45, 20) = 20; floor 15 |
| Go and policy | 27.8 | 27.8 | 45 | 40 | min(45, 40) = 40; floor 35 |
| Go and policy checks | 22.2 | 22.2 | 45 | 35 | min(45, 35) = 35; floor 30 |
| Installer CLI and diagnostic controls | 12.9 | 12.9 | 20 | 20 | min(20, 25) = 20; floor 20 |
| Installer engine race shard N | 22.7 | 24.5 | 30 | 30 | min(30, 35) = 30; floor 30 |
| Kind authenticated admin API | 14.0 | 14.0 | 40 | 25 | min(40, 25) = 25; floor 20 |
| Kind baseline native foreground GC 137 | 6.8 | 13.5 | 30 | 20 | min(30, 20) = 20; floor 20 |
| Kind baseline-active v3 admission 135 cold | 14.0 | 17.2 | 50 | 25 | min(50, 25) = 25; floor 25 |
| Kind baseline-active v3 admission 135 warm | 17.3 | 17.4 | 50 | 30 | min(50, 30) = 30; floor 25 |
| Kind baseline-active v3 admission 137 cold | 14.1 | 14.5 | 50 | 25 | min(50, 25) = 25; floor 20 |
| Kind baseline-active v3 admission 137 warm | 17.6 | 18.2 | 50 | 30 | min(50, 30) = 30; floor 25 |
| Kind installation security baseline 135 | 6.7 | 7.0 | 30 | 20 | min(30, 20) = 20; floor 15 |
| Kind installation security baseline 137 | 6.3 | 6.7 | 30 | 20 | min(30, 20) = 20; floor 15 |
| Kind installer full admission 135 cold | 12.8 | 14.5 | 50 | 25 | min(50, 25) = 25; floor 20 |
| Kind installer full admission 135 warm | 15.2 | 15.8 | 50 | 30 | min(50, 30) = 30; floor 25 |
| Kind installer full admission 137 cold | 12.7 | 14.4 | 50 | 25 | min(50, 25) = 25; floor 20 |
| Kind installer full admission 137 warm | 15.7 | 15.8 | 50 | 30 | min(50, 30) = 30; floor 25 |
| Kind installer native authentication | 22.8 | 23.2 | 50 | 35 | min(50, 35) = 35; floor 30 |
| Kind lifecycle | 20.4 | 21.1 | 45 | 35 | min(45, 35) = 35; floor 30 |
| Kind pre-controller runtime 135 | 19.4 | 20.6 | 40 | 30 | min(40, 30) = 30; floor 30 |
| Kind pre-controller runtime 137 | 21.1 | 21.4 | 40 | 35 | min(40, 35) = 35; floor 30 |
| Kind recovery failure safety | 67.1 | 67.7 | 100 | 90 | min(100, 90) = 90; floor 75 |
| Kind signed installer binary 135 fresh | 221.4 | 221.4 | 350 | 290 | min(350, 290) = 290; floor 230 |
| Kind signed installer binary 137 fresh | 221.1 | 221.1 | 350 | 290 | min(350, 290) = 290; floor 230 |
| Kind signed installer binary 137 transition | 328.9 | 328.9 | 350 | 350 | min(350, 430) = 350; floor 335 |

Only the **137 transition** signed-installer step uses
`hack/ci-no-progress-watchdog.sh`, with a **30-minute silence** threshold.
It forwards combined stdout/stderr as bytes arrive (including partial lines),
resets the deadline only on child output, and terminates the command's process
group with TERM then KILL after five seconds of cleanup grace. It preserves
normal exit status, fails on silence with exit 124 and an Actions error, and
cleans up on cancellation. Fresh legs use the original make target directly.
No test selection or assertion changes. Existing inner make/Go deadlines
(including the transition's 340-minute Go timeout) remain in force.

This watchdog is a **stopgap for future silent stalls**, tracked in
[issue #139](https://github.com/gobha-me/arcadectl/issues/139). It **would not
have caught the ten October 331–334-minute failures**: that cohort kept logging
until the inner **340-minute Go deadline**. No retrospective saving is claimed
for that cohort. The real transition fix remains separate.

## Cache ownership

`setup-go` caching is disabled. All jobs restore the shared Go module/build
cache; only **Go and policy checks** publishes it after success on a main push
or a main nightly. Keys include OS, architecture, exact Go version, go.mod/sum
hash, and commit; a prefix restores the latest compatible main entry. Paths
are the GitHub Ubuntu defaults `~/go/pkg/mod` and `~/.cache/go-build`. PRs and
manual dispatches never save. One writer avoids publishing many partial
600 MB entries. Cold misses still download/build normally.

Kind jobs statically resolve the existing digest-pinned nodes in
`internal/installengine/target_auth_kind_test.go` (`targetKind135`,
`targetKind137`), confirming the 137 pin agrees with
`internal/install/api_kind_test.go` and `hack/test-kind-lifecycle.sh`:

- 135: `kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0`
- 137: `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5`

Tarball keys hash the exact selected references, OS and architecture, with no
fallback to another image version. Matrix legs restore their one node;
authentication restores both. Baseline legs and authentication publish those
three tarballs only on main push/nightly cache misses, before their proofs.
Other Kind jobs and PRs only restore. The performance lab also only restores,
using the pins in its exact checked-out revision.

`docker load` restores layers; Docker backends that lose `RepoDigests` during
save/load may still need a pinned `docker pull` to reattach registry metadata,
reusing those layers. A missing/corrupt tarball falls back to the exact pinned
pull. If pins cannot be determined statically, or independent harness pins
differ, the cache is bypassed and the unmodified harness pulls normally. The
new restore/save actions are SHA-pinned `actions/cache` v4.3.0.

## October cost estimate

The report measured **14,404 minutes across 31 main pushes**. Using cheap-job
medians plus roughly one minute each for the classifier and gate gives
**893 minutes** for those pushes, or **13.5k gross minutes avoided**.
Read-only `gh api` enumeration of main commits from October 1–27, 2026
(ET date boundaries; committer dates under squash-only merges) found exactly
**31 commits on 14 distinct ET merge-days**: October 1, 2, 5, 7, 8, 14, 20,
21, 22, 23, 24, 25, 26 and 27.

Summing successful job/leg p50s with all 32 race shards and 33 envtest parts
gives **1,116.2 runner-minutes per full run**. Assuming one full nightly per
merge-day, 14 nightlies cost **15,626.8 minutes**; compared with daily runs on
all 27 days (**30,137.4 minutes**), the guard avoids about **14.5k minutes**.
Item 4 therefore models about **2.1k additional minutes net**, rather than a
net saving (15,626.8 + 892.8 - 14,404). This sum-of-medians estimate is not an
observed whole-run cost. Merge-days are only a cost scenario, not the guard's
criterion: the guard requires successful full coverage of the exact SHA.
Failed/incomplete runs, bounded history or API uncertainty can add full runs;
a successful manual main run for the same SHA can avoid a nightly. Schedule
jitter changes which main SHA is selected, without a commit-age coverage gap.
No guaranteed total saving is claimed. The watchdog saves nothing on the historical logging cohort above;
timeout, early-exit, retry and cache savings overlap and need observation.

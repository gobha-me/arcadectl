# CI operation and budgets

Ordinary pull requests run every existing proof: both Kubernetes profiles,
all cold/warm admission legs, all three signed-installer legs, recovery,
32 race shards and 33 envtest parts. Both bulk matrices retain max-parallel 4
and fail-fast false. Race and envtest start only after all their foundations
succeed; a failed or cancelled foundation skips those matrices and makes the
`Go and policy` aggregate fail.

A normal push to main runs Installer CLI and diagnostic controls, Go and policy
checks, and the Go and policy gate (plus the tiny classifier). The gate expects
all heavy jobs to be skipped, and requires both cheap jobs to succeed. This
relies on main's strict up-to-date PR checks, enforced for admins, and squash
merges with linear history: the merged tree is the tested PR head tree.
Changing that merge policy requires revisiting this optimization.

The complete proof set runs on main nightly at **9:00 PM EDT / 8:00 PM EST
(01:00 UTC)** when main has a commit in the last 24 hours. A cheap guard uses
only the default `GITHUB_TOKEN` with `contents: read`: it verifies the API's
main HEAD matches the scheduled SHA, checks its committer timestamp, and
confirms the recent-commits API returns an empty list before skipping. Main's
squash-only policy makes these committer dates the merge/landing dates. An API
error, timeout, malformed response, missing timestamp or moved/unexpected HEAD
runs the full set. An unchanged-main skip logs a clear notice, skips checkout
and every proof, and leaves a green aggregate that verifies those skips.
`workflow_dispatch` bypasses the freshness guard and always runs the complete
set on the selected ref on demand. Event-specific concurrency groups prevent a
main push or manual run from cancelling a nightly; only superseded PR runs are
automatically cancelled. Schedule and main-push runs are not cancelled in
progress.

## Documentation and lint configuration exception

A classifier compares the exact PR head with the merge base of the event's
base/head SHAs, or a main push's `before`/`after` SHAs. It uses a NUL-delimited
`git diff --no-renames` so deletions and both sides of a rename count. Only
Markdown files (including root Markdown), `docs/**`, root `LICENSE`,
`LICENSE.txt`, `NOTICE`, `NOTICE.txt`, `.golangci.yml`, `.golangci.yaml`,
`.editorconfig`, and root `.markdownlint*` qualify. `.github/**`, `hack/**` and
`config/**` always require proofs, even if the changed file is Markdown.

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
separate unchanged-main guard described above.

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
observed whole-run cost. ET calendar days approximate the actual 9 PM EDT
(01:00 UTC) rolling 24-hour windows; schedule delays, API fail-safe full runs
and manual dispatches can change the total. No guaranteed total saving is
claimed. The watchdog saves nothing on the historical logging cohort above;
timeout, early-exit, retry and cache savings overlap and need observation.

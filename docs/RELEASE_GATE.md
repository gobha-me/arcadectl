# Exact-source release evidence

Tracking: [#41](https://github.com/gobha-me/arcadectl/issues/41).

Arcadectl has no supported v1 release until the complete release decision is
approved. A green check, successful focused test, unmerged repair, or this
evidence collector alone cannot authorize a tag, publication, or deployment.

## Full CI evidence collector

`hack/ci-evidence` reads the requested source commit from local Git and reads
GitHub Actions through the existing `gh` login. It makes no forge writes: it
does not set statuses, rerun jobs, merge, tag, sign, publish, or contact a cluster.

The collector loads `.github/workflows/ci.yml` from the **requested Git object**,
not the current working-tree file. It derives every expected job display name
from that workflow's finite matrices and exclusions. It binds the run and every
job to the requested repository, run ID, exact SHA, and valid attempt. It fetches
all pages of latest job results and rereads run metadata to reject a changing
run/attempt snapshot. The report records the workflow blob identity, run and
per-job attempts, results, and public evidence URLs.

For candidate evidence, after the requested source object is locally available:

```sh
candidate_sha=$(git rev-parse HEAD)
go run ./hack/ci-evidence --sha "$candidate_sha" \
  --run-id "$CANDIDATE_RUN_ID" > candidate-ci.json
```

`CANDIDATE_RUN_ID` must identify the complete CI workflow for that exact source.
It is not a job ID or a diagnostic/performance-only run. The source commit must
be fetched before collection; the collector never fetches or changes Git refs.

For the exact integrated main commit, after the normal approved merge process:

```sh
git fetch origin main
main_sha=$(git rev-parse origin/main)
go run ./hack/ci-evidence --sha "$main_sha" --run-id "$MAIN_RUN_ID" \
  --main --first-attempt > main-ci.json
```

`--main` requires a main push, scheduled run, or manual main run. The stricter
`--first-attempt` option refuses a rerun as first-attempt evidence. Without that
option, reused successful jobs from earlier attempts of the same run/SHA remain
visible with their original attempt numbers; they are not relabeled as fresh.
Archive earlier failures separately rather than erasing their history.

| JSON verdict | Binary exit | Meaning |
| --- | ---: | --- |
| `pass` | 0 | Every expected CI job is present exactly once and successful; identity and policy checks passed. |
| `fail` | 1 | A failed, cancelled, skipped, missing, duplicate, unexpected, inconsistent or incorrectly bound proof prevents a complete pass. |
| `unavailable` | 2 | Arguments, Git history, supported workflow shape, API retrieval or a stable snapshot could not establish evidence. Never interpret this as a pass. |
| `pending` | 3 | No completed failure was observed, but the run or its complete job set is unfinished. |

`go run` itself exits nonzero for nonzero program exits and may print the
program's exit status. Build the binary if automation needs the exact numeric
exit values above. Always retain and inspect the versioned JSON verdict.

The collector is deliberately strict. Dynamic matrices, matrix `include`,
unresolved name expressions, implicit matrix display names, ambiguous duplicate
names, excessive expansion, and incomplete pagination are unsupported evidence,
not a reason to accept a partial proof. Update its independent regression tests
when the workflow requires a new supported form.

An intentionally cheap/docs-only CI run with native jobs skipped cannot satisfy
the full-proof collector. If the CI policy uses cheap main pushes, require a
successful full scheduled/manual run on that same main SHA. A first-attempt
result for a different commit, branch, workflow file or workflow name is not a
substitute.

This collector evaluates the complete job set of **the CI workflow only**.
Security, mutation, signing, compatibility and other independent workflows or
approvals must be checked separately on the exact SHA. Provider JSON is read
over GitHub's API and is not a signed offline attestation; the JSON report alone
must not become an artifact trust root.

## Remaining release decision

| Gate | Required evidence / tracking |
| --- | --- |
| Operator and recovery journey | Clean disposable-cluster CLI journey, backup/isolated restore, deliberate-destroy refusals, install/upgrade/rollback/uninstall and retained-world recovery; #27, #28, #29. |
| Reliability | Repeatable restart/fault/upgrade soak thresholds, convergence or stable actionable refusal, retained identity and singleton safety; #36. |
| Security | No unresolved critical/high security or data-loss findings, all redaction paths and authority boundaries reviewed on the integrated candidate; #37. |
| Observability | Compatible finite metrics/events/logs, dependency-aware health and operator guidance; #38. |
| Artifact identity | Images, CLI, manifests, SBOMs, signatures, provenance and compatibility/certification metadata resolve to the exact source SHA; #39. |
| Documentation | Supported versions/limitations and tested operator/recovery/upgrade commands, generated examples and internal links; #40. |
| Exact CI | Complete candidate proof, every other required workflow, and complete exact-main evidence before a tag or publication; #41. |

The release maintainer records a go/no-go decision with those artifacts and
review approvals. Missing or red evidence means no release. Future adapters,
hosted accounts, UI, billing and tenant-isolation claims are outside this first
Factorio release decision.

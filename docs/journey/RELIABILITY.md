# Lifecycle reliability and soak components

Issue #36 needs exact-candidate evidence across retained-world transitions and
platform failures. The bounded runner below composes existing disposable kind
proofs and refuses dirty/changing source, child failure, missing/mismatched
Factorio evidence or observed runtime overlap. It is a component harness, not
completion of the full fault matrix.

Inspect all modes offline, without Go, Docker or cluster execution:

```sh
bash hack/test-kind-soak.sh short --plan
bash hack/test-kind-soak.sh long --plan
bash hack/test-kind-soak.sh upgrade --plan
```

Execution requires `CI=true` on an isolated disposable runner with the
[documented prerequisites](../TESTING.md). No mode accepts a kubeconfig,
context, cluster name, arbitrary command or arbitrary repetition count. Every
child owns its cluster and private registry; the runner unsets ambient
`KUBECONFIG`. Children run serially with two processors and a 1 GiB Go heap
limit. Keep the inherited Go/build parallelism limits. Do not run these on a
real cluster or locally while the heavy-run hold is in effect.

| Mode | Exact CI command | Work and bounds |
| --- | --- | --- |
| Short | `CI=true bash hack/test-kind-soak.sh short` | One certified Factorio fixture, 25-minute child bound plus 30-second termination grace. |
| Long | `CI=true bash hack/test-kind-soak.sh long` | Twelve serial Factorio fixtures, each with the same bound. Budget at least 306 minutes plus runner bookkeeping. Not run locally. |
| Upgrade component | `CI=true bash hack/test-kind-soak.sh upgrade` | The exact profile-137 signed-binary predecessor/install/enrollment/upgrade/rollback/retaining-uninstall test; Go bound 340 minutes, outer child bound 345 minutes plus 30-second termination grace. Not run locally. |

The upgrade mode additionally needs the exact historical installer commits
and provenance checks described in [INSTALLATION_PACKAGE.md](../INSTALLATION_PACKAGE.md).
It retains only the numeric wrapper summary and the existing sanitized Go
job output; it does not manufacture Factorio world evidence for that mode.

A nonzero child stops the sequence immediately, preserving its exit status.
There is no success-through-retry. No later round runs after failed evidence
verification. Inspect the failed original operation/receipt before deciding
recovery. A timeout is a failed experiment, not convergence or cleanup proof.
The fixture must check exact owned cluster/container identities during teardown;
this runner adds no broad cleanup, force deletion or orphan adoption route.

## Evidence and thresholds

Each invocation reserves a new directory under `artifacts/lifecycle-soak/`,
mode 0700 with mode-0600 files. `summary.tsv` records exact source SHA, mode,
round, exit status and elapsed whole seconds. Each Factorio round uses its own
artifact directory and must produce exactly one `evidence.txt` with the same
candidate SHA, `source_dirty=false`, and exactly one maximum observed running
game container. Duplicate required keys, absent evidence, an alternate source,
dirty source or overlap fail the wrapper even if the child exited zero.

Retain the child's sanitized `transitions.tsv`, `evidence.txt`, current-generation
GameServer conditions and tool/cluster versions with the summary. The underlying
Factorio proof checks a real save, marker, exact PVC/PV/data identity, distinct
restart/update Pod UIDs, and exact-UID reattachment. Its per-transition waits
remain the bounds implemented by that fixture; record those bounds and actual
elapsed times in the [evidence template](SOAK_EVIDENCE_TEMPLATE.md). Missing
latency is `unknown`, never zero. Sampling a maximum of one is evidence at the
fixture's sampling interval, not a mathematical proof that no sub-sample overlap
occurred. There is no new reconcile-latency instrumentation in this runner.

Archive only the sanitized allowlisted artifact directories and exact-head CI
links. Never archive kubeconfig, credential/client JSON, Secret data, private
workspace contents, raw node/CRI logs or process dumps. No artifact upload or
workflow setting is changed here. The existing required `Kind lifecycle` job
runs the underlying short Factorio proof; this wrapper's refusal paths run in
the ordinary Go race suite. Hosted execution/archive wiring for the long and
upgrade modes needs a separate authorized workflow change. Do not infer that
these wrappers ran from an underlying job's green result.

## Fault matrix and remaining proof

| Scenario | Existing component | Remaining #36 evidence |
| --- | --- | --- |
| Start/stop/restart/digest update, controller redeploy | Short Factorio fixture; each long round independently repeats it | Repeated cycles and sustained availability on one continuously retained world |
| Worker crash, bad credentials, corruption, capacity/storage failure | Separate CSI/Restic `make test-kind-recovery` proof | A combined reliability journey and bounded recovery metrics on the exact source |
| Signed platform upgrade/rollback | Upgrade component retains two inert nonbinding claims | Existing bound physical Factorio world and verified save across the same signed transition |
| API restart, node drain, transient API errors | No new executable injection here | Exact owned-resource injection, fresh identity/conditions and bounded actionable recovery |
| Image-pull failure, Service delay, storage reattachment delay | No new executable injection here | Stable refusal or recovery, no writers/overlap, unchanged claim identities and marker |

The long mode creates a fresh cluster and world each round. It is a repeated
lifecycle stress run, not a 24-hour continuous-world availability soak. A future
continuous-world fixture must own one cluster for a fixed 24-hour window,
rotate its test credentials, sample readiness at a documented interval, preserve
world identity through each bounded fault, and archive gaps/recovery latencies.
It must retain the production refusal/deadline behavior; extending a test's
observation window cannot silently relax operation deadlines.

The authenticated API fixture currently has a 28-minute context and a parent
assertion that its API Pod never restarts. Altering that fixture also overlaps
active PRs #127/#145. Its restructuring, new fault injections, physical-world
upgrade composition and long-run CI/archive wiring remain separate work. Keep
#36 open until the full matrix and exact-head evidence are reviewed. Neither
static tests nor component orchestration establish production readiness.

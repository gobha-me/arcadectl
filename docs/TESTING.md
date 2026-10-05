# Isolated lifecycle testing

The synthetic lifecycle harness proves server lifecycle and cold backup in a
disposable local Kubernetes cluster. A separate production-catalog recovery
suite exercises the complete Factorio backup/restore/destroy journey and
failure injection. Run the synthetic harness from the repository root on
Linux with:

```sh
make test-kind-lifecycle
```

The host must provide a working Docker daemon plus the ordinary Go toolchain
and POSIX command-line tools checked by the harness. The Make target enforces a
15-minute outer deadline. Remote container inputs are digest-pinned. The MinIO
fixture is built from checksum-pinned official source rather than unavailable
upstream container images; its separate source, license, and build recipe are
included in the fixture image. See [fixture provenance](../images/minio-fixture/README.md).
A cold Go
cache or Docker build cache may also retrieve modules whose content is locked
by `go.sum`; no unversioned module or ambient Kubernetes tool is accepted.

A pull-request run starts from a clean checkout and is exact-SHA evidence. A
local run from a dirty worktree records that state in failure diagnostics and
is useful while developing, but it is not release evidence.

## What the proof covers

The harness builds a controller that contains only a compile-time test adapter
and a small non-production conformance server. The production controller still
contains only certified production adapters. It then installs the generated
CRD, RBAC, and controller manifests and proves:

- stopped creation, start, stop, restart, settings update, and controller
  redeploy;
- workload reconstruction after the Deployment is removed;
- current-generation Ready and endpoint status, using a narrowly scoped test
  LoadBalancer status provider;
- service reachability from a separate restricted probe pod;
- exact controller and game image digests at runtime;
- unchanged PVC UID, PV binding, data identity, and on-volume marker through
  stop and redeploy; blocked implicit same-name adoption after GameServer
  deletion; and successful explicit exact-UID reattachment;
- real cold backup to isolated MinIO for an initially running server that
  returns to `Ready` and an initially stopped server that remains `Stopped`;
  each result binds the exact server/PVC identities and is repository-verified;
- a real Restic verification process killed with `SIGKILL`, followed by
  same-operation stale-lock recovery and exactly one usable verified artifact;
- atomic refusal of a second live worker Pod plus controller-serialized retry
  only after every prior worker Pod is absent;
- suspended Job admission and exact gated-Pod readback, proving injected
  containers or credential/source mounts remain unscheduled and unauthorized;
- server-side admission refusal of an ungated managed worker, executable-field
  mutation, and non-controller gate removal;
- safe-uninstall refusal while a real backup worker and operation Lease are
  active, followed by a quiesced post-terminal uninstall that retains the
  backup-worker admission gate and proves it still denies use of retained
  operation authority;
- refusal to uninstall if the live admission policy permits arbitrary gate
  removal, even when all backup workers have already been cleaned up;
- exact Secret/PVC authorization inside the worker Pod, read-only source
  mounts, terminal worker cleanup, and credential canaries absent from CR
  status, Events, controller logs, and captured real authorized/refused worker
  logs and termination status before cleanup; an independent repository-only
  inspector also scans every stored file and manifest for credential canaries;
- fail-closed behavior when a foreign Service occupies a deterministic name,
  with no partial sibling resources; and
- explicit verified-backup destruction of a separate stopped world after
  its GameServer has been removed: a durable cold marker, read-only preview
  and restore guidance, challenge confirmation, fresh repository verification,
  exact-UID deletion journal, and exact-name PVC absence; the primary world
  stays unchanged and the `Retain` PV and physical sentinel remain;
- separate ordinary and destroy controller PVC permissions and warning-free
  CEL typechecking of the destroy admission policies; and
- safe uninstall of both controllers that leaves the namespace, all Arcadectl CRDs, GameServer,
  operation records, and retained PVC.

The MinIO service uses an ephemeral volume and exists only inside the owned Kind
cluster. It runs the locally built fixture by digest and waits for S3 write
quorum. Restic initializes and verifies the actual S3-compatible repository;
no fake S3 client or fake worker participates in this path. This is controller
lifecycle evidence, not Factorio client automation or proof of a cloud
LoadBalancer implementation.

Worker unit tests capture independent upload-time repository bytes instead of
dumping the live source. Manifest corruption, same-size corruption, truncation,
extra bytes, missing files, and repository read errors must all refuse a usable
result, preserve source contents, and refuse duplicate snapshots on retry.

## Restore validation

Issue #20 adds hermetic tests for v2 manifest directory topology, Restic
inventory drift, candidate file verification and unsafe-entry rejection,
restore authorizer identity checks, CSI backing-volume isolation, API
admission/status rules, and controller retry and rollback paths. The existing
`make test-kind-lifecycle` and
`make test-kind-factorio` scenarios still exercise backup and lifecycle, not
the full `GameRestore` journey.

On 2026-10-01 an isolated external Kubernetes test using CSI-backed Ceph RBD
storage completed the positive restore journey with a dirty, test-only image.
A real Factorio server reached Ready and wrote a save; Restic uploaded and
verified a v2 artifact; repository-only preflight completed before target
stop; a fresh, distinct CSI-backed claim was populated and verified; and the
server returned to Ready using that new claim. A marker written before backup
survived, while one written after backup was absent. The prior claim remained
separate. Unauthorized worker Pod and candidate-PVC admission probes were
denied. The test namespace, both PVs, and exact test-owned cluster-scoped
resources were removed afterward. Network-plugin annotations discovered in
this run are covered by focused tests without weakening controller-owned Pod
identity fields.

This external test proves the positive path on one CSI environment, not a
release image. The separate recovery suite below adds reproducible disposable
Kind evidence for selected failures. Cluster-level cancellation, activation
rollback and CSI alias rejection remain separate unproven experiments; unit
and envtest coverage is not a substitute. Do not treat an older v1 backup as
restorable.

## Factorio recovery and failure safety

Run this independently and serially with the other cluster/build suites:

```sh
GOMAXPROCS=2 GOMEMLIMIT=1GiB make test-kind-recovery
```

The 90-minute outer deadline accommodates the pinned Restic backend's real
15-minute retry window for some repository errors. This suite uses the
production controller catalog, the certified Factorio image, real Restic and
CSI-backed persistent MinIO. Its digest-pinned CSI hostpath driver is a
privileged, **disposable-Kind-only test fixture**, not a production storage
recommendation. See its [provenance](../hack/csi-hostpath/PROVENANCE.md).
Finite world, repository and unrelated-sentinel capacity pools are independent.
The fixture's logical world-capacity allocation does not fill the host disk.

The journey includes:

- a real Ready Factorio server and nonempty save, with an 8 MiB durable marker
  before backup and a second marker after backup;
- backup-independent decommission and explicit creation-time exact-UID
  reattachment; implicit same-name adoption remains refused;
- bad object-store credentials, actual pack-object metadata corruption in a
  separate repository prefix, and actual Secret UID/resourceVersion races,
  each refused during repository-only preflight without candidates or a fence;
- finite CSI capacity exhaustion and the actual five-minute cold-fence
  provisioning deadline, with a retained Pending candidate whose later binding
  cannot revive the recorded failure;
- three real authorized populate-worker process crashes, exact process/Pod/Job
  identities and exit 137, and unchanged candidates across bounded retries;
- real populate-time filesystem exhaustion using a **2 MiB tmpfs over only one
  fresh candidate CSI UUID directory**. Mount propagation into the CSI driver
  is checked before authorization; three retries, zero available bytes and
  exact ordinary unmount are observed. This is not physical host-disk filling;
- original-world identity and A+B readback after each preactivation failure;
- a real controller Pod restart during an active repository-only worker, then
  successful verified restore into distinct claims and CSI handles. Marker A
  is read from the restored running Factorio Pod; B is absent, and the original
  world still contains both;
- a fresh LeaveStopped backup of the restored candidate, retained-world
  decommission, missing/stale backup and confirmation refusals, unauthorized
  unsafe-request denial, and confirmed repository-reverified exact destruction;
- UID-preconditioned fixture cleanup while unrelated PVC/ConfigMap sentinels
  remain unchanged. Test cleanup is separate from the product destroy proof;
  removing a Retain PV API object does not claim physical erasure.

Controller image labels, source SHA and dirty flag, runtime image IDs,
operation records, transition times, exact storage identities, marker hashes
and cleanup evidence are retained under `artifacts/kind-recovery/`. Secrets,
kubeconfig, credential values and raw CRI inspection are excluded. CI uploads
sanitized evidence on success or failure for three days. Only a clean exact-SHA
CI run is delivery evidence; partial smoke runs and dirty local runs are not.

For bounded diagnosis, `ARCADECTL_RECOVERY_POSTFAULTS_ONLY=true` runs setup,
Secret-identity races, controller-restart restore, confirmed destroy and scoped
cleanup without the preceding fault injections. It reports a partial diagnostic
result explicitly; it cannot satisfy this issue's full failure-matrix gate.
`ARCADECTL_RECOVERY_SMOKE_ONLY=true` proves only CSI setup and sentinel I/O.
`ARCADECTL_RECOVERY_DIAGNOSTIC_FAULT=filesystem-full` selects one bounded fault
followed by the same identity, positive recovery, destroy, and cleanup journey.
The other accepted selections are `bad-credentials`, `capacity`, `worker-crash`,
and `corruption`; unknown selections or combining this selection with another
partial mode are refused.
Single-fault results are also explicitly partial, never full-matrix evidence.
None of these switches is enabled in CI.

## Destroy validation boundary

The synthetic Kind proof exercises the normal `VerifiedBackup` positive path
against real Restic/MinIO and Kubernetes controllers. It intentionally uses a
separate disposable world, not a production cluster or the primary retention
fixture. PVC deletion is not physical erasure when the PV reclaim policy is
`Retain`; the proof checks that distinction explicitly.

Unit tests cover exact-UID replacement, lease conflicts, confirmation expiry,
cancel/finalizer cleanup, repository rejection, retry after a durable journal,
and partial multi-claim deletion. Real API-server envtest cases cover CRD
immutability/status rules and admission denial of ordinary PVC deletion,
cold-marker forgery, unsafe requests by the wrong identity, and worker
gate/executable mutation. These do not prove every interruption or CSI path in
a real cluster. The unsafe no-backup exception is never exercised against a
real world in the Kind proof.

## Certified Factorio lifecycle

Run the production-catalog proof serially after the synthetic proof:

```sh
make test-kind-factorio
```

This mode builds the repository's pinned Factorio image twice with distinct
test-only OCI labels, pushes both variants to its private local registry, and
addresses them only by their resolved immutable digests. Both variants contain
the same certified Factorio binary; the second digest proves the update path
without expanding this test into certification of another Factorio release.

The proof creates a stopped server, binds retained storage owned by UID/GID
845, starts a real Factorio server, publishes only UDP/34197, and observes
Ready without container intervention. It then proves stop/start, digest update,
controller redeploy, rejected implicit adoption after `GameServer` deletion,
and explicit exact-UID recreation while preserving the same PVC, PV, durable
data identity, world marker, and non-empty Factorio save. A separate read-only
verifier Pod checks the save only while game compute is stopped. The synthetic
LoadBalancer status used by kind is endpoint-status evidence, not a cloud load
balancer test or Factorio client session.

Every wait is bounded. Sanitized success evidence is written below
`artifacts/factorio-lifecycle/` with the exact candidate SHA, dirty-state flag,
pinned cluster inputs, immutable image references, object identities,
transition timings, and maximum observed running game-container count during
the image update. It excludes Secrets, kubeconfig, configuration contents,
RCON credentials, and unredacted logs. CI uploads this evidence for three days.

## Isolation and cleanup

Every run and suite creates unique names for its kind cluster, local registry,
kubeconfig, images, and Kubernetes ownership marker. The harness refuses to
adopt existing objects. Teardown validates the recorded container IDs, Docker
labels, kind node names, and in-cluster marker before deleting the exact cluster
or registry; it never deletes an ambient cluster or shared Docker network.

The harness extracts kubectl from a digest-pinned image into its private
workspace, so it does not use an ambient kubectl binary or kubeconfig. The
synthetic image and kind, node, registry, kubectl, materializer, and builder
inputs are pinned in source.

On failure, allowlisted object summaries and redacted fixed-fixture logs are
written below the suite's `artifacts/kind-lifecycle/`,
`artifacts/factorio-lifecycle/` or `artifacts/kind-recovery/` directory before cleanup. ConfigMap data,
Secrets, raw node logs, and the kubeconfig are never copied into diagnostics.
CI uploads only those directories for three days.
## Authenticated API proof

`make test-kind-api` creates a checksum-pinned disposable Kind cluster and private
registry. It builds a separate non-root API image, initializes a fake generated
administrator credential using the trusted-admin utility, and provisions a
test-only TLS certificate. It proves HTTPS authentication, projected-secret
rotation without restart, old-token rejection, expired-credential recovery
from an unready API, private output modes, and token/verifier-free audit logs.
The same owned cluster installs all five CRDs and native admission policies,
then exercises real HTTP create/configure/start/stop/restart/update/decommission
against the normal controller and checksum-pinned Factorio runtime. In-flight
retry storms and equivalent integer settings converge on one receipt; conflicting
original input is refused. Real runtime Pod identities change on restart/update,
while retained PVC/PV UIDs and a world marker SHA remain unchanged. The retained
world read preserves original server identity after decommission. This fixture
uses a prebound Retain hostPath PV inside its disposable node, not a CSI claim
or a public server endpoint; its test administrator supplies the isolated
Service endpoint because Kind has no cloud load balancer. Native recovery's
separate real CSI/Restic journey remains the data-operation proof; this HTTP
lifecycle test does not claim a full HTTP backup/restore/destroy journey.
The same fixture builds the ordinary `arcadectl` binary, logs in using only a
private credential path and explicit CA, and proves status, start admission,
exact receipt waiting, and stopped completion against those actual controllers.
Its private stdout/stderr join the token/verifier-canary scan. No second cluster
or direct Kubernetes mutation authority is given to the CLI.
It then removes only the exact task-owned cluster, registry, image tags, and
private temporary files. No real-world cluster, server, or credential is used.

The ordinary race suite covers malformed/duplicate headers, authorization-before-
body/handler, expiry/revocation, strict verifier parsing/serial high watermarks,
concurrent credential CAS and ambiguous writes, bounded failed/stalled auditing,
live capability lifetime, TLS trust and certificate readiness, and deterministic
API manifest/RBAC shape. The real API-server envtest additionally proves ordinary
API read-only native permissions and immutable receipt creation, denied
status/core/cluster/foreign-namespace authority, and the distinct-identity unsafe
destroy admission boundary. Receipt admission tests prove whole-spec immutability,
once-set plans/children/snapshots, append-only journals, and immutable terminal
status including whole-status removal. Controller tests inject transient reads,
ambiguous writes, exact identity/spec conflicts, and stale native observations;
none may manufacture completion or adopt a replacement. Uninstall tests cover
pending receipts, lingering finalizers, API Pods/Deployment, and a second safety
snapshot after controller quiescence.

The CLI race suite separately covers every ordinary lifecycle route against the
real TLS API handler with a receipt-only fake store. It publishes controller
outcomes explicitly; it does not claim workload execution. It tests terminal
failure and fresh intents, definitive rejection and explicit resolve, active and
stale-terminal timeout, stable-principal credential rotation, receipt/child UID
replacement, cancellation that loses to completed deletion, private metadata,
and redaction. Linux pseudo-terminal tests require exact challenge input and
visible inventory, refuse pipes, and prove prompt expiry. Saved-attempt tests
cover crash/replay boundaries, frozen bytes/ETags, missing admitted receipts,
fresh destructive replay, and changed contexts. A dependency guard proves the
ordinary CLI cannot import Kubernetes mutation clients/controllers. Generated
offline help/completions have a drift gate.

# Isolated lifecycle testing

The existing lifecycle harness proves server lifecycle and cold backup in a
disposable local Kubernetes cluster. It does **not yet** prove the new restore
controller end to end. Run the established harness from the repository root on
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

## Restore validation status

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

This proves the positive path on one CSI environment, not all failure paths or
a release image. Cluster-level interrupted populate, cancellation, rollback,
and CSI alias rejection remain unproven; unit and envtest coverage is not a
substitute for those experiments. Do not treat an older v1 backup as
restorable.

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
written below the suite's `artifacts/kind-lifecycle/` or
`artifacts/factorio-lifecycle/` directory before cleanup. ConfigMap data,
Secrets, raw node logs, and the kubeconfig are never copied into diagnostics.
CI uploads only those directories for three days.

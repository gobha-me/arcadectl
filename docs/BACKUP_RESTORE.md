# Backup and restore operation contract

Arcadectl represents data movement as durable namespaced resources. A
`GameBackup` or `GameRestore` records one immutable request, survives client and
controller restarts, and exposes bounded progress through status. Cold backup
and restore execution are implemented in the controller and bounded workers.
The restore path has been proved end-to-end on an isolated Factorio server with
CSI-backed candidate and previous PVCs; this does not certify production use.

Creating a `GameBackup` may stop and later restart its exact source server,
create one bounded worker Job, and read every adapter-declared path. It never
writes source world data or deletes a source claim. A successful `LeaveStopped`
backup records its UID in a protected PVC annotation before becoming terminal;
the game controller clears that marker before any later runtime activation.
This permits [deliberate destroy](DESTROY.md) to reject intervening Arcadectl
starts even after the original GameServer was removed. A `GameRestore` verifies a repository
snapshot before stopping its target, then writes only to separately retained
candidate claims; it never mounts the previous world's claims in its worker.

## Exact authority

Every GameServer, backup, repository Secret, and claim reference contains a
`name` and Kubernetes `uid`. A GameServer reference also records `generation`
and the desired state at that generation. This durable pre-operation state is
what makes `RestorePreviousState` replayable after a controller crash.
All references are local: the containing operation's namespace is implicit.
The schema recognizes `namespace` only as a rejection sentinel, so ordinary
admission rejects any attempt to supply a namespace selector instead of
silently pruning it. Admission also rejects missing identities and changes to
an accepted reference. This prevents deletion and
recreation under the same name from silently redirecting an operation.

Repository connection configuration and credentials live together in the
exact referenced Secret. The reference pins its resource version, and a worker
must reject a Secret unless Kubernetes reports `immutable: true` and the exact
UID and resource version still match. Rotation therefore requires a new
operation; one retry cannot be redirected to another repository. The operation
schema intentionally has no endpoint,
access-key, password, token, arbitrary environment, or signed-URL field. Strict
API validation rejects attempts to add inline credentials.

The immutable Secret contract is:

| Key | Required | Meaning |
| --- | --- | --- |
| `repository` | yes | `s3:http://host/bucket[/prefix]` or `s3:https://host/bucket[/prefix]`, without user info, query, or fragment |
| `password` | yes | Restic repository password |
| `awsAccessKeyID` | yes | S3 access key ID |
| `awsSecretAccessKey` | yes | S3 secret access key |
| `awsSessionToken` | no | temporary S3 session token |
| `ca.crt` | no | additional PEM CA bundle for a private HTTPS endpoint |

No other key is accepted. Public HTTPS roots are included in the worker image.
The controller never reads credential bytes. It creates a per-operation
ServiceAccount, Role, and RoleBinding restricted by `resourceNames` to the one
Secret, exact source claim names, and operation Lease. A short-lived init
container can start only after a two-stage admission gate. The Job is created
suspended and its stored owner, metadata, authority objects, and full Pod
template are read back and matched exactly. After activation, the admitted Pod
remains unscheduled behind `arcade.gobha.me/backup-authorized`; the controller
compares its owner, labels, annotations, containers, mounts, volumes,
environment, security context, and all other Pod spec fields with the stored
Job template before annotating that exact Pod UID and removing the gate. An
admission-injected sidecar or mount therefore remains unscheduled and never
receives credentials or source volumes on a node. A fail-closed Kubernetes
`ValidatingAdmissionPolicy` independently requires the gate on create, rejects
executable-field changes while it is removed, and permits gate removal plus
the exact Pod-UID marker only from the controller ServiceAccount. The
short-lived init
container then atomically claims the operation Lease for its Pod UID before it GETs the
Secret, verifies UID, resource version, `immutable: true`, and the PVC UIDs,
then materializes credentials into a private EmptyDir. A second Pod cannot
receive credentials while the first Pod's execution claim remains. The API
token is mounted only into that init container; the Restic container receives
only the authorized credential files and read-only source volumes. The
controller Role contains Secret `get` only as the Kubernetes RBAC delegation
ceiling required to create that narrower Role; controller code does not
retrieve the Secret.

The retained-data Lease is deliberately not owned by the `GameBackup` object.
It carries the exact operation UID, operation name, server name, and data
identity instead, and terminal/finalizer reconciliation deletes it explicitly.
This lets the Lease survive foreground garbage collection long enough to
authorize and observe required runtime settlement. Forcibly removing the
operation finalizer can therefore leave an orphaned Lease; that is an
intentional fail-closed state which blocks world reuse until an administrator
inspects the operation identity. While the Lease exists, the GameServer
controller freezes retained-storage reconciliation as well as runtime. Only an
exact Lease annotation for the controller-owned restart generation permits the
server to resume.

Controller uninstall is fail-closed around this boundary. It requires every
backup, restore, and destroy to be terminal at its current generation and refuses while
any data-operation Job, Pod, or retained-data Lease remains. Both worker
admission policies and the controller-only restore-candidate PVC CREATE policy,
with their bindings, remain installed after controller removal. Without these
gates, a principal could reuse operation authority or preempt a candidate name.

Before work begins, status records one source snapshot:

- exact GameServer identity and generation;
- game ID and immutable image digest;
- a SHA-256 fingerprint of canonical validated settings; and
- every adapter-declared path, mount point, and exact PVC identity.

The snapshot is the artifact manifest boundary. An implementation must recheck
it before each external mutation and fail with `IdentityMismatch` if live
identity changed.

## Cold backup

The controller and worker enforce all of these gates across the cold-backup
path:

1. the exact source still exists and the repository reference is structurally
   valid;
2. the adapter declares cold-backup support;
3. no other data operation owns the server;
4. the requested UID, generation, and pre-operation desired state still match;
5. the GameServer is changed to `Stopped` when needed and status records an
   immutable cold-data fence at that exact stopped generation;
6. the game workload is absent; and
7. uncached API reads show no Pod using a source claim and no attached CSI
   `VolumeAttachment` for its bound PV; and
8. Kubernetes admits the suspended Job and gated Pod without changing their
   exact executable shape; and
9. the controller authorizes only that exact Pod UID, after which the worker
   init container rechecks the exact Secret and PVC identities while the
   referenced claims are protected.

`LeaveStopped` is the default restart policy.
`RestorePreviousState` returns a previously running server to that state only
after data work is safely terminal. A fenced operation cannot itself become
terminal until status records the exact final GameServer generation and
observed `Ready` or `Stopped` phase required by the restart policy. Thus a
retry after a crash knows whether recovery is still due. Uncertain data or
activation always remains stopped.

Success means repository-side verification covered every declared path. Status
then records a deterministic artifact ID derived from the `GameBackup` UID,
format version, manifest digest, byte size, path count, timestamps, `Verified`
result, and immutable provenance binding the exact backup and repository Secret
revision. An uploaded but unverified or differently sourced object is not a
usable backup. The worker tags the one UID-derived snapshot with its manifest
digest, removes only stale Restic locks, reuses an already committed matching
snapshot after interruption, runs a full repository data check, then
independently dumps and hashes the stored manifest and every recorded file. It
rehashes the cold source afterward. Completed Jobs and Pods are removed before
runtime settlement, so their historical Pod specs cannot block the next
backup. Every retry of one operation uses the same operation-unique Pod
hostname. Restic can therefore recognize a lock abandoned by that operation's
dead prior Pod as local and stale without removing another host's live lock.
The Job itself has no automatic backoff. Kubernetes may still transiently
overlap Job Pods, so the per-operation Lease admits credentials to exactly one
Pod UID. An overlap or interrupted worker makes the controller delete the Job,
observe every labeled worker Pod absent, clear the execution claim, increment
the bounded attempt counter, and only then create the next Job. Consequently a
new process cannot run `unlock` while a prior same-hostname process is live.
An existing Job is accepted only when its exact owner, metadata, and complete
Job/Pod spec match after normalizing the documented Kubernetes API defaults and
generated selector labels. The separately admitted Pod is checked before its
scheduling gate is removed. Added containers, mounts, volumes, environment, or
other admitted mutations fail closed while execution is still gated. The
policy is cluster-scoped, bound only to the `arcadectl-system` namespace, and
installed before the controller Deployment. A principal able to delete or
replace admission policies remains part of the trusted cluster control plane.

CRD admission binds backup provenance to the operation name and exact
repository revision. Kubernetes CRD CEL does not expose `metadata.uid`, so the
mandatory status validator additionally binds the provenance UID and
deterministic artifact ID to the live `GameBackup` UID before every status
write. The reconciler uses that validator before every status write; it is not
optional worker policy.

New backups use manifest format `arcadectl.backup/v2`. It records every regular
file's size and SHA-256 plus the complete child-directory topology, including
empty directories, for each adapter-declared path. Both backup and restore
verification reject symlinks, special entries, unlisted repository nodes, and
incomplete or noncanonical manifests. A successful v1 artifact remains a
historical backup record, but this restore worker does not accept it; create a
new verified v2 backup before requesting restore. There is no automatic v1-to-v2
conversion.

## Restore and atomic activation

A restore references one exact `GameBackup` UID, immutable repository Secret
revision, and target GameServer generation. The source must be a successful,
verified v2 artifact matching the target game, image digest, settings digest,
and complete persistent-path contract. If the target already has a
controller-selected data set, `spec.targetData` must pin that complete exact
claim set; similarly, a later backup of a restored world must pin
`spec.sourceData`.

The first worker is a repository-only preflight with no target PVC mount or
GameServer/PVC read authority. It checks the exact snapshot and manifest,
complete Restic inventory, repository data, and each stored file before the
controller acquires the previous-world lease or requests a cold stop. The
controller then waits for the exact stopped generation and full Pod/CSI
VolumeAttachment detachment before provisioning candidate PVCs.

The populate worker mounts only those candidates. A separate, namespace-bound
fail-closed admission policy requires its Pod to remain scheduling-gated until
the controller verifies the exact admitted Job and Pod shape and marks its
UID. Its short-lived authorizer checks both operation-held data leases, the
stopped GameServer's selected and observed previous claim set, exact bound
PVC identities, and the immutable Secret revision before releasing credentials
into a Pod-private memory volume. The Restic container receives no Kubernetes
API token. Preflight and populate use distinct stage authority and workers;
their RBAC and inputs are removed after worker cleanup.

Before candidate writes and again before activation, uncached PVC/PV checks
require distinct bound volumes and CSI driver/volume handles across the
previous and candidate sets. Candidates must also be distinct from any
still-existing exact backup-source PVCs; the source and previous world may
legitimately be the same volume.
The candidate PVC must have been created no earlier than its GameRestore, and
its backing CSI PV no earlier than the candidate PVC. This rejects rebinding an
older retained source PV even if the backup-source PVC was removed. Candidate
PVC creation is admitted only for the controller service account; the
storage control plane may still bind and update the claim afterward. These
proofs assume the admission policies remain protected and CSI drivers assign
unique handles to independent volumes.
Only CSI PV sources with non-empty driver and volume handle are certified for
this isolation check. HostPath, Local, NFS, and unknown sources fail closed;
using them for a target or candidate does not silently weaken restore safety.

Restore never writes over active world data. A worker populates candidate
claims whose deterministic identities derive from the `GameRestore` UID and
path name. It rejects unlisted candidate entries and symlinks, verifies each
written file's exact size and hash, syncs files and directories, and rebuilds
the complete canonical manifest from the candidates. A failed populate Job
may be retried at most twice after its old Job, Pod, and execution claim have
been cleared; all three attempts use the same exact candidate PVC identities.
Before `Activating`, status must bind the exact backup/repository
provenance, record a candidate verification whose manifest digest and path count
match the verified artifact, and record a complete, distinct previous-claim
set for rollback. Status distinguishes candidate, active, and previous claim
identities. Activation must be one controller-owned reference change, and
success requires the active set to equal the verified candidates. If
confirmation fails, the operation enters `RollingBack`; previous claims remain
retained and are the rollback authority. `activationStartedAt` makes that
obligation durable across controller restarts and later terminal phases. A
restore that reached activation cannot become `Failed` or `Cancelled` until
immutable `activeData` proves every active claim is again the corresponding
previous claim and the requested previous runtime has settled. A failed or
cancelled restore retains both previous and candidate PVCs; it never deletes
either set. An unresolved identity or rollback mismatch holds the leases and
requires operator inspection rather than guessing which world is active.

## Retry, cancellation, and retention

`metadata.uid` is the idempotency key. A backup artifact ID and each restore
candidate identity are pure functions of that UID. Reconciliation may repeat
work, but it must converge on those same identities. It may never allocate a
second successful artifact or a second candidate set for the same object.

Transient backup work can increment `status.attempts`; restore population has
its own `populateAttempts`, `populateRetryPending`, and exact Job-UID journal.
All retries retain the same data identities. Resolved source, fence, artifact,
runtime disposition, and restore claim identities are set-once and immutable
through API admission. Terminal
`Succeeded`, `Failed`, and `Cancelled` phases cannot regress. Retrying a
terminal request requires a new operation object and therefore an explicit new
UID.

`spec.cancelRequested` may change only from false to true. Backup admission
rejects a new cancellation request after terminal completion. Every status write
must observe the current operation generation; once cancellation increments
that generation, validation permits only cancellation, mandatory restore
rollback, or failure progress.
`Cancelled` is reported only after the active worker is
stopped and no partial artifact or candidate can be treated as usable.
If cancellation arrives after the operation requests a stop but before the
cold fence is recorded, it still settles the exact requested restart policy
and waits for the runtime generation to be observed before releasing its Lease.
Cancellation during uncertain activation rolls back or remains stopped; it
does not guess which data is active.

`Retain` is the only backup retention policy in `v1alpha1`. Deleting either
operation record never deletes an artifact, active world, candidate, or
previous claim. Scheduled expiration and remote deletion are future explicitly
authorized operations. Deleting an active backup first stops its worker and,
when `RestorePreviousState` applies, observes the exact prior runtime state
before releasing its data lease and finalizer. Deleting an already-terminal
historical record is runtime-neutral: its recorded disposition was observed
before terminal status, and later administrator-owned server generations are
never reasserted.

## Observable state

The bounded phases are `Pending`, `Blocked`, `Preparing`, `Running`,
`Verifying`, `Activating`, `RollingBack`, `Cancelling`, `Cancelled`,
`Succeeded`, and `Failed`. Backup does not use activation or rollback phases.

Conditions use stable types (`Accepted`, `SourceReady`, `TargetReady`,
`ArtifactReady`, `Verified`, and `Complete`) and finite reasons such as
`InvalidReference`, `IdentityMismatch`, `SecretUnavailable`,
`ColdStopPending`, `OperationConflict`, `WorkerRetrying`, `WorkerFailed`, and
`VerificationFailed`. A false or unknown condition message must name the safe
operator action using a controller-authored template. Raw Kubernetes errors,
worker output, repository responses, settings, and Secret data are forbidden.

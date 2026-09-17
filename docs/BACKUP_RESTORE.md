# Backup and restore operation contract

Arcadectl represents data movement as durable namespaced resources. A
`GameBackup` or `GameRestore` records one immutable request, survives client and
controller restarts, and exposes bounded progress through status. This contract
is implemented; the workers that execute it arrive in separately reviewed
backup and restore slices.

Creating one of these resources does not currently stop a server, read a
Secret, copy data, or alter a claim. The controller role can only observe the
operation resources and update their status. It cannot read Secrets, create
worker Pods or Jobs, or delete PVCs.

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
API validation rejects attempts to add inline credentials. A future worker may
mount only the documented Secret keys; it must never copy their values into
status, logs, conditions, or artifacts.

Before work begins, status records one source snapshot:

- exact GameServer identity and generation;
- game ID and immutable image digest;
- a SHA-256 fingerprint of canonical validated settings; and
- every adapter-declared path, mount point, and exact PVC identity.

The snapshot is the artifact manifest boundary. An implementation must recheck
it before each external mutation and fail with `IdentityMismatch` if live
identity changed.

## Cold backup

A backup can leave `Pending` only when all of these are true:

1. the exact source and repository Secret still exist;
2. the adapter declares cold-backup support;
3. no other data operation owns the server;
4. the requested UID, generation, and pre-operation desired state still match;
5. the GameServer is changed to `Stopped` when needed and status records an
   immutable cold-data fence at that exact stopped generation;
6. the game workload is absent; and
7. every declared volume is detached or mounted only through a reviewed,
   read-safe worker path.

Stopping is part of the future backup implementation, not permission to bypass
these checks. `LeaveStopped` is the default restart policy.
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
usable backup.

CRD admission binds backup provenance to the operation name and exact
repository revision. Kubernetes CRD CEL does not expose `metadata.uid`, so the
mandatory status validator additionally binds the provenance UID and
deterministic artifact ID to the live `GameBackup` UID before every status
write. A future reconciler must use that validator; it is not optional worker
policy.

## Restore and atomic activation

A restore references one exact `GameBackup` UID and one exact target GameServer
generation. The source artifact must have a successful verification result and
must match the target adapter contract before any target mutation.

Restore never writes over active world data. A worker populates fresh candidate
claims whose deterministic identities derive from the `GameRestore` UID and
path name. Before `Activating`, status must bind the exact backup/repository
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
previous claim.

## Retry, cancellation, and retention

`metadata.uid` is the idempotency key. A backup artifact ID and each restore
candidate identity are pure functions of that UID. Reconciliation may repeat
work, but it must converge on those same identities. It may never allocate a
second successful artifact or a second candidate set for the same object.

Transient work can increment `status.attempts` while retaining the same
identities. Resolved source, fence, artifact, runtime disposition, and restore
claim identities are set-once and immutable through API admission. Terminal
`Succeeded`, `Failed`, and `Cancelled` phases cannot regress. Retrying a
terminal request requires a new operation object and therefore an explicit new
UID.

`spec.cancelRequested` may change only from false to true. Every status write
must observe the current operation generation; once cancellation increments
that generation, validation permits only cancellation, mandatory restore
rollback, or failure progress.
`Cancelled` is reported only after the active worker is
stopped and no partial artifact or candidate can be treated as usable.
Cancellation during uncertain activation rolls back or remains stopped; it
does not guess which data is active.

`Retain` is the only backup retention policy in `v1alpha1`. Deleting either
operation record never deletes an artifact, active world, candidate, or
previous claim. Scheduled expiration and remote deletion are future explicitly
authorized operations.

## Observable state

The bounded phases are `Pending`, `Blocked`, `Preparing`, `Running`,
`Verifying`, `Activating`, `RollingBack`, `Cancelling`, `Cancelled`,
`Succeeded`, and `Failed`. Backup does not use activation or rollback phases.

Conditions use stable types (`Accepted`, `SourceReady`, `TargetReady`,
`ArtifactReady`, `Verified`, and `Complete`) and finite reasons such as
`InvalidReference`, `IdentityMismatch`, `SecretUnavailable`,
`ColdStopPending`, `OperationConflict`, `WorkerFailed`, and
`VerificationFailed`. A false or unknown condition message must name the safe
operator action using a controller-authored template. Raw Kubernetes errors,
worker output, repository responses, settings, and Secret data are forbidden.

# Deliberate world destruction

`GameDestroy` is the only supported Arcadectl operation that deletes retained
world PVCs. Stopping a server, deleting its `GameServer`, uninstalling the
controller, and a failed restore do not invoke this operation. Namespace
deletion is outside this protection boundary and can delete every PVC in that
namespace.

Destroy is an administrative Kubernetes operation, not a tenant API. A
request pins its namespace (the object's namespace), original GameServer name
and UID, game ID, data identity, and the complete adapter-declared set of PVC
names and UIDs. A decommissioned world can be destroyed only when durable
backup provenance proves that original server identity. For a world whose
`GameServer` has already been removed, the successful `LeaveStopped` backup
must have recorded its UID as a cold-backup marker on every exact retained
PVC before removal. Historical backups made before that marker existed do
not establish this continuity and fail closed; make a new backup while the
original server still exists before decommissioning. Replacing a server,
claim, backup, or repository Secret under the same name never redirects a
request.

## Verified-backup path

Before creating a request, stop the GameServer and wait for its current
generation to report `Stopped`; leave it stopped. Use a successful,
`LeaveStopped` `GameBackup` of this exact world and an immutable repository
Secret reference (name, UID, and resource version). Discover and record the
exact retained PVC UIDs; do not infer them from names. The controller refuses
claims still used by a Pod or attached through a CSI VolumeAttachment.

Create a `GameDestroy` with `mode: VerifiedBackup`, exact `target`, `backupRef`,
and `repositorySecretRef`, but **without** `confirmationChallenge`. The
controller performs a read-only preflight and publishes `status.preview` with
a short-lived random challenge, expiration, and restore guidance. Review the
whole target, backup, and guidance. Only then echo the challenge into
`spec.confirmationChallenge`. A stale, mismatched, or expired challenge is not
authority to delete anything; create a new request after correcting the
problem.

After confirmation the controller holds a data-operation lease that excludes
normal game, backup, and restore activity. It rechecks the cold, detached world
and runs a credential-gated, repository-only verification worker. That worker
checks the exact v2 snapshot, manifest, inventory, and stored bytes; it never
mounts a world PVC. Only after successful verification and worker cleanup can
the controller enter `Deleting`. Before each claim deletion it rechecks the
exact identity, lease, backup, cold state, Pod mounts, and CSI attachments,
writes the exact PVC UID to a durable deletion journal, then uses a
UID-preconditioned DELETE. It confirms the exact name is absent before
marking an entry complete. A conflict or ambiguous partial failure keeps the
operation in `Deleting` for inspection and retry; it does not silently switch
targets or report success.
The first journal entry is the durable commitment to destruction. The preview
must still be valid when that entry is written; after commitment, retries may
continue even if the short-lived preview has expired, because a delete may
already have been sent and stopping halfway would leave an ambiguous world.

The cold marker detects Arcadectl-managed runtime activation after a backup:
the normal controller clears it before creating any subsequent game workload,
including a reattached server. Admission prevents other ordinary principals
from creating or changing that marker. This is a trusted-namespace boundary,
not a proof against a cluster administrator or another principal permitted to
create arbitrary Pods/Jobs that mount these claims. Such principals must be
excluded by namespace RBAC and cluster policy; Kubernetes audit and storage
provider access logs may be needed for independent forensic evidence. A
data-operation Lease alone does not fence arbitrary Kubernetes Pods.

The backup remains the recovery path. Keep its repository and credentials
available until recovery is no longer needed. Deleting a PVC object is not a
certified physical erasure: a PV with reclaim policy `Retain` may preserve the
backing volume. Conversely, `Delete` may remove it permanently. Check the
bound PV reclaim policy and storage provider behavior before confirmation.

## Unsafe exception

`UnsafeNoBackup` is a separately authorized exception, never a default or a
fallback from failed repository verification. It requires an explicit
`unsafeReason`, the same two-phase preview and exact identity checks, and a
distinct Kubernetes destroy-admin identity for creation or spec mutation.
On an unsafe request, include the immutable annotation
`arcade.gobha.me/unsafe-requested-by` with value
`system:serviceaccount:arcadectl-system:arcadectl-destroy-admin`.
The admission policy emits an audit annotation with the target UID;
API-server auditing must be enabled and retained for an actual audit trail.
The destroy controller's service account is distinct from both the ordinary controller
and the destroy admin. Unsafe mode cannot supply a backup reference; it
cannot be selected by editing a verified request. An unproven original UID
for a decommissioned world is not sufficient authority for an unsafe destroy.

Cancellation is allowed before the first PVC journal entry. Once deletion
starts, the controller retains its finalizer and retry record until all exact
claim names are observed absent or an administrator resolves a fail-closed
conflict. Do not remove finalizers, leases, or admission policies to make a
stuck operation disappear; investigate the recorded identity and storage
state first.

No credential values belong in the request, its status, events, logs, or
diagnostic artifacts. Only the isolated verifier receives the exact immutable
repository Secret revision.

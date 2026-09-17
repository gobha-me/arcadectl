# Kubernetes lifecycle contract

Arcadectl separates a server's durable data identity from its active compute.
This distinction is the foundation of stop, update, decommission, restore, and
deliberate destruction.

## Desired state

`GameServer` is a namespaced `arcade.gobha.me/v1alpha1` resource. Its spec
selects a curated game adapter, a registry-resolved image digest, `Running` or
`Stopped` intent, bounded CPU and memory, persistent storage, and settings that
must satisfy the adapter's JSON Schema.

The authenticated API will be responsible for resolving human-facing versions
to image digests and authorizing writes. Direct custom-resource access is an
administrator-level cluster permission, not an alternate tenant API.

## Resource ownership

For a running server, the deterministic planner produces:

- one independently retained persistent volume claim per adapter-declared data
  path;
- one owned ConfigMap containing only rendered non-secret configuration;
- a single-replica, recreate-strategy Deployment; and
- one LoadBalancer Service containing only player-scoped endpoints.

The ConfigMap, Deployment, and Service have a controlling `GameServer` owner
reference. The persistent volume claims deliberately have none. Consequently,
Kubernetes garbage collection can remove disposable runtime state when a
`GameServer` is deleted, but it cannot cascade that deletion into world data.

Claim names include the server name, adapter identity, and persistent-path
identity. Every claim also carries a durable `arcade.gobha.me/data-identity`
derived from the creating `GameServer` UID. Names and labels support discovery;
they are not attachment authority. A replacement server must explicitly name
the complete adapter path set and pin every local claim by name and Kubernetes
UID. A same-name replacement without that declaration fails with
`RetainedDataReferenceRequired` instead of adopting the old world.

For `Stopped` intent, the controller first preflights ownership of all
disposable runtime resources and removes them before storage validation. A
missing or conflicting claim can therefore never keep game compute running.
For `Running` intent, the controller preflights
the complete selected claim set and every ConfigMap, Deployment, and Service
before mutation. It refuses missing, extra, duplicate, terminating,
foreign-owned, or mismatched claims. New-world claims may expand
but are never shrunk; explicitly reattached claims are neither repaired nor
expanded. Runtime resources
use deterministic reconciliation. Deployments and Services use server-side
apply so API-server defaults do not cause update loops; the disposable
ConfigMap uses exact replacement so stale rendered keys cannot survive.

## Observed lifecycle

Every status write is one snapshot for `metadata.generation`. The top-level
`observedGeneration` and all six conditions carry that generation. The
controller replaces the complete condition set in this canonical order, so a
condition from an older generation cannot remain accidentally true:

| Condition | True reason | Progress or stopped reasons | Failure reasons |
| --- | --- | --- | --- |
| `SpecValid` | `Valid` | — | `InvalidSpec`, `ControllerMisconfigured` |
| `StorageReady` | `ClaimsReady` | `ClaimsProvisioning`, `ClaimExpansionPending` | `RetainedDataReferenceRequired`, `RetainedDataMissing`, `RetainedDataConflict`, `ResourceCollision`, `StorageOperationFailed` |
| `ConfigurationReady` | `ConfigurationReady` | `RuntimeStopping`, `RuntimeStopped` | `ResourceCollision`, `ConfigurationOperationFailed` |
| `WorkloadReady` | `WorkloadAvailable` | `WorkloadProgressing`, `RuntimeStopping`, `RuntimeStopped` | `ResourceCollision`, `WorkloadUnavailable`, `WorkloadOperationFailed` |
| `NetworkReady` | `PlayerEndpointReady` | `PlayerEndpointPending`, `RuntimeStopping`, `RuntimeStopped` | `ResourceCollision`, `NetworkOperationFailed` |
| `Ready` | `Ready` | `StoragePending`, `WorkloadPending`, `PlayerEndpointPending`, `RuntimeStopping`, `RuntimeStopped` | `InvalidSpec`, `ControllerMisconfigured`, `RetainedDataReferenceRequired`, `RetainedDataMissing`, `RetainedDataConflict`, `ResourceCollision`, `ReconcileFailed` |

A downstream stage that could not be observed is `Unknown` with reason
`Blocked`; previously observed truth is never retained. `Pending` means storage
is still binding or expanding. `Starting` means prerequisites are reconciled
but the exact current singleton workload or player endpoint is not yet ready.
`Ready` requires bound storage, exactly one current updated/ready/available
replica, and a current LoadBalancer address. `Stopping` is based on disposable
resources still observed during removal; `Stopped` means they are absent.
`Failed` identifies a validation, collision, or bounded operation failure.

Status endpoints exist only while the aggregate `Ready` condition is true for
the current generation. Their names, protocols, and ports come from the
certified player-only adapter plan, intersected with the observed Service by an
exact tuple. The controller ignores NodePorts, target ports, extra live Service
ports, administrator and internal endpoints, malformed ingress values, and
terminating Services. An ingress with per-port status is eligible only when
every certified player port has a matching protocol and no provider error;
addresses must be globally unicast IPs or valid DNS names. The controller
selects a canonical IP (then hostname) and sorts endpoints by name. Losing
workload availability or ingress immediately clears the endpoint list.

Condition messages are finite controller-authored templates. They may name a
Kubernetes kind and `namespace/name` plus a safe operator action, but never copy
settings, admission responses, child Event text, or raw reconciliation errors.
Arcadectl currently emits no Kubernetes Events; any future GameServer Events
must reuse the same bounded reasons and safe messages. Readiness uses either a
named player-scoped TCP endpoint or the fixed `/arcadectl/readiness` helper in a
certified image. Adapters cannot provide commands. Factorio's silent helper
checks RCON only inside the container; its administrator port and probe details
do not appear in the Pod spec or kubelet probe Events.

## Operations

- **Start:** reconcile retained claims, render configuration, atomically
  materialize it with a non-root init container, then start compute and player
  networking.
- **Stop:** remove configuration, compute, and player networking; retain every
  claim.
- **Update:** change the digest or validated settings and replace the singleton
  workload without overlapping game processes.
- **Decommission:** delete the `GameServer`; owned runtime resources are
  collected and unowned claims remain.
- **Reattach:** inspect the retained claim while the server name is absent,
  then create a replacement whose `spec.storage.reattach` carries the claim's
  data identity and exact name and UID. The declaration must cover every
  adapter path. It is immutable for that `GameServer` identity. To correct a
  bad reference, keep desired state `Stopped`, delete the object, and recreate
  it with the corrected exact references; retained claims remain untouched.
  Restore activation will use its separately reviewed typed operation contract
  rather than weakening this reattachment fence.
- **Backup:** represented by an immutable `GameBackup`; execution is not yet
  implemented. The request pins the GameServer generation and repository
  Secret identity, and success will require verification of every adapter path.
- **Restore:** represented by an immutable `GameRestore`; execution is not yet
  implemented. Candidate and previous data identities support verified atomic
  activation and rollback without overwriting the active world.
- **Destroy:** not implemented. It will be a separate authorized operation with
  exact identity confirmation and a successful backup by default.

The disposable-cluster test suite proves this contract first with a synthetic
conformance adapter and then with the certified Factorio runtime. The Factorio
proof starts a real server, verifies a real save from a separate read-only Pod
while compute is stopped, updates between distinct immutable image digests,
checks that the recreate strategy never exposes overlapping running game
containers, redeploys the controller without replacing the game Pod, and
recreates the `GameServer` around the same retained world identity. This is
isolated lifecycle evidence, not production readiness: backup and restore have
durable API contracts but no workers; explicit destruction and production
deployment remain unimplemented. See
[the backup and restore contract](BACKUP_RESTORE.md) for the exact boundary.

## Retained-world discovery and reattachment

For the single-path Factorio adapter, discover the retained identity without
modifying the claim:

```sh
kubectl get pvc factory-factorio-world --namespace arcadectl-system \
  --output='custom-columns=NAME:.metadata.name,UID:.metadata.uid,DATA_ID:.metadata.labels.arcade\.gobha\.me/data-identity,GAME:.metadata.labels.arcade\.gobha\.me/game,PATH:.metadata.labels.arcade\.gobha\.me/data-path,CLASS:.spec.storageClassName'
```

Copy those exact observed values into the replacement:

```yaml
spec:
  game: factorio
  storage:
    size: 10Gi
    storageClassName: observed-class
    reattach:
      identity: data-observed-identity
      claims:
        - path: world
          claimRef:
            name: factory-factorio-world
            uid: observed-pvc-uid
```

Do not infer identity from a name or repair labels to make a claim match. An
omitted/defaulted storage class is not accepted for exact reattachment to a
claim whose API-observed class is non-empty; copy the observed class. A missing
claim reports `RetainedDataMissing`. Any UID, identity, game, path, ownership,
class, access-mode, size, or set mismatch reports `RetainedDataConflict` and
creates no runtime resources.

Kubernetes Pod volumes select PVCs by name, not UID. Arcadectl therefore
rechecks the exact UID immediately before runtime reconciliation, but the final
check-to-mount race is secure only when ordinary Arcadectl users cannot create,
update, or delete managed PVCs. Cluster administrators and the storage control
plane remain trusted. Deployments that include hostile PVC writers need an
admission policy in addition to this controller contract.

Development snapshots from before durable data identities are intentionally
not eligible for in-place controller upgrade: their PVCs have no
`arcade.gobha.me/data-identity`, and Arcadectl refuses to invent or add one.
Keep the older controller stopped, preserve the claim and its exact UID, and
use a separately reviewed backup/restore or migration procedure. This is a
fail-closed development compatibility gate, not an automatic adoption path.

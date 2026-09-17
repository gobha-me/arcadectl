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
identity. Recreating the same server under a different game therefore cannot
silently attach the old game's data. The reconciler also fails closed if an
existing claim's labels or storage class conflict with the plan.

The controller preflights every existing claim, ConfigMap, Deployment, and
Service before mutation. It refuses foreign ownership or mismatched data
identity. Existing claims may expand but are never shrunk. Runtime resources
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
| `StorageReady` | `ClaimsReady` | `ClaimsProvisioning`, `ClaimExpansionPending` | `ResourceCollision`, `StorageOperationFailed` |
| `ConfigurationReady` | `ConfigurationReady` | `RuntimeStopping`, `RuntimeStopped` | `ResourceCollision`, `ConfigurationOperationFailed` |
| `WorkloadReady` | `WorkloadAvailable` | `WorkloadProgressing`, `RuntimeStopping`, `RuntimeStopped` | `ResourceCollision`, `WorkloadUnavailable`, `WorkloadOperationFailed` |
| `NetworkReady` | `PlayerEndpointReady` | `PlayerEndpointPending`, `RuntimeStopping`, `RuntimeStopped` | `ResourceCollision`, `NetworkOperationFailed` |
| `Ready` | `Ready` | `StoragePending`, `WorkloadPending`, `PlayerEndpointPending`, `RuntimeStopping`, `RuntimeStopped` | `InvalidSpec`, `ControllerMisconfigured`, `ResourceCollision`, `ReconcileFailed` |

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
- **Destroy:** not implemented. It will be a separate authorized operation with
  exact identity confirmation and a successful backup by default.

The current repository contains the API, generated CRD, validation, typed
adapter settings rendering, pure resource planner, controller image build, and
generated least-privilege namespaced installation. Complete isolated-cluster
game lifecycle validation is not implemented yet, so it is not deployable for
production use.

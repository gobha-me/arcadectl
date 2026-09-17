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

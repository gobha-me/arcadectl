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
- a single-replica, recreate-strategy Deployment; and
- one LoadBalancer Service containing only player-scoped endpoints.

The Deployment and Service have a controlling `GameServer` owner reference.
The persistent volume claims deliberately have none. Consequently, Kubernetes
garbage collection can remove compute and networking when a `GameServer` is
deleted, but it cannot cascade that deletion into world data.

Claim names include the server name, adapter identity, and persistent-path
identity. Recreating the same server under a different game therefore cannot
silently attach the old game's data. A future reconciler must also fail closed
if an existing claim's labels or requested capacity conflict with the plan.

## Operations

- **Start:** reconcile retained claims, then create compute and player
  networking.
- **Stop:** remove compute and player networking; retain every claim.
- **Update (planned):** change the digest or validated settings and replace the
  singleton workload without overlapping game processes.
- **Decommission:** delete the `GameServer`; owned runtime resources are
  collected and unowned claims remain.
- **Destroy:** not implemented. It will be a separate authorized operation with
  exact identity confirmation and a successful backup by default.

The current repository contains the API, generated CRD, validation, and pure
resource planner. Adapter-specific settings rendering, the controller, and its
cluster-side adoption checks are not implemented yet, so it is not deployable.

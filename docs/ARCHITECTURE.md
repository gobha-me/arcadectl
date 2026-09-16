# Arcadectl v2 architecture

## Product boundary

Arcadectl is a game-server platform. Factorio is the first certified adapter,
not a special case in the platform core.

The initial deployment profile is one administrator, one Kubernetes cluster,
and one installed game adapter. That is a delivery boundary, not a permanent
single-game or single-tenant domain assumption.

## Components

The planned runtime contains three binaries in one Go module:

1. `arcadectl`, a CLI that calls the authenticated API.
2. `arcadectl-api`, the validation, authorization, and operation boundary.
3. `arcadectl-controller`, the Kubernetes reconciler and sole normal mutator
   of workloads, networking, and persistent storage.

Kubernetes custom resources hold desired and observed state. The API service
account may mutate Arcadectl resources but cannot directly mutate workloads.
The controller may reconcile approved resources but does not manage users or
accept public requests.

The first implemented Kubernetes boundary is the `GameServer` API and a pure
resource planner. It creates independent claims for adapter-declared persistent
paths and never gives those claims a `GameServer` owner reference. Controller,
API, and CLI processes remain planned rather than implemented.

## Game adapter contract

A game definition supplies only constrained data:

- stable identity and display metadata;
- an image repository whose selected version is resolved to a digest;
- named TCP or UDP endpoints with player, administrator, or internal scope;
- persistent paths included in cold backup and restore;
- an optional named TCP readiness endpoint;
- a bounded JSON settings schema; and
- declared lifecycle capabilities.

Definitions cannot contain arbitrary containers, shell commands, host paths,
privileged security contexts, raw Kubernetes objects, or inline secrets.
Future game-specific hooks require a separately reviewed typed contract; they
will not be smuggled in as shell fragments.

The core operates only on these generic concepts. Production core packages
live below `internal/platform` and must not contain Factorio paths, ports, RCON
assumptions, image names, or save semantics.

## Slice-one decisions

- Factorio is the first certified adapter.
- A TCP-only synthetic adapter with a different data path is the conformance
  counterexample.
- LoadBalancer Services are the first supported player-network provider.
- Traefik port allocation and NodePort are deferred providers.
- Backups are cold backups: stop cleanly, copy every declared persistent path
  with a Restic-compatible worker, verify, and then optionally restart.
- The first automated backup target is S3-compatible object storage; isolated
  tests use MinIO.
- Images are launched by digest. Mutable tags may be user-facing version
  selectors but are resolved before mutation.
- The initial API uses a generated administrator bearer token stored in a
  Kubernetes Secret. Authentication is behind an interface so OIDC and hosted
  control planes can replace it without changing adapters or reconciliation.

## Lifecycle and data semantics

`stop`, `restart`, `update`, controller redeployment, and API unavailability do
not delete persistent data. Decommissioning removes compute and networking but
retains the server record and its data.

`destroy` is a different operation. It requires the exact server identity,
explicit confirmation, and a successful backup by default. An override must be
equally explicit and is recorded as an unsafe administrative decision.

Restore targets a newly provisioned volume before it changes the active server
reference. A failed restore cannot partially replace the active world.

## Extension test

Every adapter runs the shared conformance suite. A second real game is accepted
only when it can be implemented without changing the core lifecycle controller.
If the core must change, the missing platform capability is designed and tested
generically before the adapter is added.

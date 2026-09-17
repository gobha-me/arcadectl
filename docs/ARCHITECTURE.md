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

The implemented Kubernetes boundary is the `GameServer` API, a pure resource
planner, and the controller process. It creates independent claims for
adapter-declared persistent paths and never gives those claims a `GameServer`
owner reference. The generated controller role deliberately omits PVC deletion.
The authenticated API and CLI remain planned rather than implemented.

## Game adapter contract

A game definition supplies only constrained data:

- stable identity and display metadata;
- an image repository whose selected version is resolved to a digest;
- named TCP or UDP endpoints with player, administrator, or internal scope;
- persistent paths included in cold backup and restore;
- an optional named TCP readiness endpoint using one of two fixed platform
  modes: a player-scoped TCP probe or a certified image-local private helper;
- a bounded JSON settings schema and a renderer that can supply bytes only for
  statically declared configuration targets;
- a certified non-root UID, GID, and filesystem group for the selected image;
- configuration target paths nested below declared persistent roots; and
- declared lifecycle capabilities.

Definitions cannot contain arbitrary containers, shell commands, host paths,
privileged security contexts, raw Kubernetes objects, or inline secrets.
They also cannot choose an exec probe command: private readiness always invokes
the fixed `/arcadectl/readiness` image helper, whose implementation is reviewed
with the certified image and emits no endpoint details.
The settings hook is deliberately narrower than a template or pod hook: it
cannot select paths, expose secrets, or influence containers. Future
game-specific hooks require a separately reviewed typed contract; they will not
be smuggled in as shell fragments.

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

Validated non-secret settings are rendered into an owned ConfigMap. A pinned,
non-root init container mounts that ConfigMap read-only and atomically
materializes its individual files at adapter-declared paths on retained
storage. This avoids the root-owned parent directory that Kubernetes creates
for a nested ConfigMap `subPath`, while keeping the game container and init
container at the adapter's certified runtime identity. A deterministic content
hash on the pod template triggers recreate-strategy replacement when settings
change. The ConfigMap is disposable runtime state and is removed on stop; the
materialized non-secret file remains with retained storage and is atomically
overwritten from the desired GameServer settings on the next start.

The certified Factorio runtime is a thin derivative of a digest-pinned
`factoriotools/factorio` image. Its wrapper suppresses only the upstream Bash
trace stream, which would otherwise expand the generated RCON password into
container logs; Factorio's normal stdout and stderr remain available. Its
silent, fixed readiness helper checks RCON only inside the container, so the
administrator port and probe diagnostics never enter the Pod spec or Events.

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

# Isolated lifecycle testing

The lifecycle harness proves the controller contract in a disposable local
Kubernetes cluster. Run it from the repository root on Linux with:

```sh
make test-kind-lifecycle
```

The host must provide a working Docker daemon plus the ordinary Go toolchain
and POSIX command-line tools checked by the harness. The Make target enforces a
15-minute outer deadline. Remote container inputs are digest-pinned. A cold Go
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
- fail-closed behavior when a foreign Service occupies a deterministic name,
  with no partial sibling resources; and
- safe uninstall that leaves the namespace, all Arcadectl CRDs, GameServer,
  operation records, and retained PVC.

This is controller lifecycle evidence, not Factorio client automation or proof
of a cloud LoadBalancer implementation.

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

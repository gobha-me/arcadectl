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
- unchanged PVC UID, PV binding, and on-volume marker through stop, redeploy,
  GameServer deletion, and same-name recreation;
- fail-closed behavior when a foreign Service occupies a deterministic name,
  with no partial sibling resources; and
- safe uninstall that leaves the namespace, CRD, GameServer, and retained PVC.

This is controller lifecycle evidence, not Factorio client automation or proof
of a cloud LoadBalancer implementation.

## Isolation and cleanup

Every run creates unique names for its kind cluster, local registry, kubeconfig,
images, and Kubernetes ownership marker. The harness refuses to adopt existing
objects. Teardown validates the recorded container IDs, Docker labels, kind
node names, and in-cluster marker before deleting the exact cluster or registry;
it never deletes an ambient cluster or shared Docker network.

The harness extracts kubectl from a digest-pinned image into its private
workspace, so it does not use an ambient kubectl binary or kubeconfig. The
synthetic image and kind, node, registry, kubectl, materializer, and builder
inputs are pinned in source.

On failure, allowlisted object summaries and redacted fixed-fixture logs are
written below `artifacts/kind-lifecycle/` before cleanup. ConfigMap data,
Secrets, raw node logs, and the kubeconfig are never copied into diagnostics.
CI uploads only that directory for three days.

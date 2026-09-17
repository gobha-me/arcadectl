# Install and uninstall

This installation is for an isolated cluster evaluation. It installs one
controller that watches only `arcadectl-system`. Creating the namespace and the
cluster-scoped Arcadectl CRDs require cluster-administrator authority; the
running controller receives only a namespaced Role.

## Build and identify the candidate image

Build from a clean exact commit. The builder image, Go toolchain, module graph,
and final scratch runtime are pinned or locked by the repository.

```sh
candidate_sha="$(git rev-parse HEAD)"
source_date_epoch="$(git show -s --format=%ct HEAD)"
docker build \
  --build-arg VCS_REF="$candidate_sha" \
  --build-arg SOURCE_DATE_EPOCH="$source_date_epoch" \
  --tag registry.example/arcadectl/controller:"$candidate_sha" \
  .
docker push registry.example/arcadectl/controller:"$candidate_sha"
```

Use the immutable `repository@sha256:digest` reported by the registry. A
task-owned local registry is sufficient for a disposable kind cluster; this
milestone does not publish a public image.

## Install

Confirm the active Kubernetes context, then install without editing manifests:

```sh
kubectl config current-context
./hack/install.sh 'registry.example/arcadectl/controller@sha256:<64 hex characters>'
```

The installer applies `config/install/anchors.yaml` first, waits for all three
CRDs to be Established, renders the digest-pinned controller resources, applies them,
and waits for the Deployment to become available. The committed
`config/install/controller.yaml` uses an all-zero digest only as a deterministic
generation fixture; it is not an image to deploy.

Verify the boundary:

```sh
kubectl get deployment,pods --namespace arcadectl-system
kubectl auth can-i delete persistentvolumeclaims \
  --as=system:serviceaccount:arcadectl-system:arcadectl-controller \
  --namespace arcadectl-system
```

The authorization check must print `no`. `GameServer` resources and every
resource they control must be created in `arcadectl-system`.

## Safe controller uninstall

First set every `GameServer` to desired state `Stopped` and wait until every
status phase is `Stopped`. Then run:

```sh
./hack/uninstall.sh
```

The script refuses to proceed while any server is not both desired and observed
Stopped at its current generation. It removes only the controller Deployment,
RoleBinding, Role, and ServiceAccount. It deliberately retains:

- the `arcadectl-system` Namespace;
- the `GameServer`, `GameBackup`, and `GameRestore` CRDs and all their objects;
- retained backup artifacts, which are not owned by operation objects; and
- every independently retained world PVC.

Do not delete `config/install/anchors.yaml`, the `arcadectl-system` Namespace,
or the install resources as one aggregate bundle. Namespace deletion erases
retained PVCs regardless of owner references. CRD deletion erases durable
server and data-operation intent. A destructive full purge is not implemented by this
milestone.

Reinstall by running `hack/install.sh` with a certified digest. The retained
namespace, API objects, and claims remain available to the new controller.

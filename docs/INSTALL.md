# Install and uninstall

This installation is for an isolated cluster evaluation. It installs one
controller that watches only `arcadectl-system`. Creating the namespace and the
cluster-scoped Arcadectl CRDs and admission policy require
cluster-administrator authority. The running controller receives a namespaced
Role and a read-only cluster Role for VolumeAttachment detachment checks.

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

Ordinary Arcadectl users must also be denied create, update, patch, delete, and
deletecollection on managed PVCs. Exact UID checks cannot close Kubernetes'
PVC-name mount race against a principal that can replace a claim. Cluster
administrators and the storage control plane are trusted; use admission
enforcement if that assumption does not hold.

## Safe controller uninstall

First set every `GameServer` to desired state `Stopped`, wait until every
status phase is `Stopped`, and let every `GameBackup` reach `Succeeded`,
`Failed`, or `Cancelled`. Then run:

```sh
./hack/uninstall.sh
```

The script refuses to proceed while any server is deleting or is not both
desired and observed Stopped at its current generation; while any backup is
deleting, non-terminal, or stale; or while any backup Job, Pod, or retained-data
operation Lease remains. It checks once while the controller is running, scales
the controller to zero, and checks again before removing authority. If the
second check fails, it restores the prior replica count. The script requires
`jq`. Each check compares the complete installed policy and binding
specifications with the shipped manifests and uses a server-side dry-run
to prove that an ungated backup worker is denied. It also waits for controller
Pods to disappear even if the Deployment already reports zero replicas. It removes the
controller Deployment, namespaced controller RBAC, controller ServiceAccount,
and VolumeAttachment-reader cluster RBAC. It deliberately retains:

- the `arcadectl-system` Namespace;
- the `GameServer`, `GameBackup`, and `GameRestore` CRDs and all their objects;
- the backup-worker ValidatingAdmissionPolicy and binding, which continue to
  fence the narrowly scoped authority retained by historical backup objects;
- retained backup artifacts, which are not owned by operation objects; and
- every independently retained world PVC.

Do not manually remove that admission policy or binding while any backup-owned
ServiceAccount, Role, or RoleBinding exists. Reinstall reapplies the same
fail-closed policy before starting the controller.

Do not delete `config/install/anchors.yaml`, the `arcadectl-system` Namespace,
or the install resources as one aggregate bundle. Namespace deletion erases
retained PVCs regardless of owner references. CRD deletion erases durable
server and data-operation intent. A destructive full purge is not implemented by this
milestone.

Deleting a namespace deletes its PVC objects regardless of owner references.
That invokes each PV's reclaim policy: `Delete` can destroy the backing volume;
`Retain` preserves the PV but requires manual recovery. Deleting a StorageClass
does not itself delete a bound PVC or PV, but can prevent later expansion or
replacement provisioning. Follow the discovery and exact reattachment process
in [the lifecycle contract](LIFECYCLE.md); never recreate labels as a substitute
for the original PVC UID.

Reinstall by running `hack/install.sh` with a certified digest. The retained
namespace, API objects, and claims remain available to the new controller.
This statement applies to releases that already write durable data identities.
Pre-release claims without `arcade.gobha.me/data-identity` must not be upgraded
in place; Arcadectl deliberately refuses to infer or repair their authority.

# Disposable CSI recovery fixture

This is a test-only adaptation of Kubernetes SIG Storage's Apache-2.0
`csi-driver-host-path` deployment, not an Arcadectl production storage installer.
Install it only in the harness-owned, disposable, single-node Kind cluster. The
privileged driver mounts that node's kubelet directories and `/dev`; this fixture
must never be applied to an existing cluster. The upstream license is preserved
verbatim in [LICENSE](LICENSE).

## Immutable sources

All hashes below are SHA-256 of the original upstream file bytes, before changes.
The driver release is v1.18.0, commit
`cc78ee78ae23908c9e0607df2fe09c7ecfa52597`.

| Source | SHA-256 |
| --- | --- |
| [Driver plugin deployment](https://github.com/kubernetes-csi/csi-driver-host-path/blob/cc78ee78ae23908c9e0607df2fe09c7ecfa52597/deploy/kubernetes-1.34/hostpath/csi-hostpath-plugin.yaml) | `886f526c4ec17289e300efd933f295c42ac82e6cac28b839a057b7c5539e9221` |
| [Driver registration](https://github.com/kubernetes-csi/csi-driver-host-path/blob/cc78ee78ae23908c9e0607df2fe09c7ecfa52597/deploy/kubernetes-1.34/hostpath/csi-hostpath-driverinfo.yaml) | `464307265464b77189bd4b339774cd2de69589458a62a740028b248f248c7e9a` |
| [Driver license](https://github.com/kubernetes-csi/csi-driver-host-path/blob/cc78ee78ae23908c9e0607df2fe09c7ecfa52597/LICENSE) | `b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1` |
| [Attacher v4.12.0 RBAC](https://github.com/kubernetes-csi/external-attacher/blob/f395fb4ff4d3fb41d2e2dfde0f8373d9e7162aeb/deploy/kubernetes/rbac.yaml) | `3a38b5198b0496927c0ce26c63e71d43e2263e2dbbb93a83acdec71d7c90a766` |
| [Provisioner v6.3.0 RBAC](https://github.com/kubernetes-csi/external-provisioner/blob/34c6fc2149a354cea116724d1836262516f83225/deploy/kubernetes/rbac.yaml) | `0ee8427b746a1d3b695705b74c2d7fb165121110b1a10c0b6e204918d93e814f` |

The sidecar release tags above resolved to the displayed immutable commits.
Upstream's deploy script fetches sidecar RBAC separately; the roles are not
contained in the plugin YAML itself. No upstream root-level NOTICE file is
present for these manifest sources.

## Pinned images

Images are pinned by registry digest, not floating tag. Tags here explain the
selected release; the manifest uses only the digest references.

| Container | Registry image | Release | Digest |
| --- | --- | --- | --- |
| hostpath | `registry.k8s.io/sig-storage/hostpathplugin` | v1.18.0 | `sha256:44e2cb773c42f31ea2b6c1d736b53e96805ab03aec743d2ceea445b17b75b85c` |
| node-driver-registrar | `registry.k8s.io/sig-storage/csi-node-driver-registrar` | v2.17.0 | `sha256:f9de845b170155199f2a2a3f9531cf13d78e31235e9db6b6582a8b0db0a50dad` |
| liveness-probe | `registry.k8s.io/sig-storage/livenessprobe` | v2.19.0 | `sha256:06da0d5b8908072f2e4522692aee8dc119fba7247a9658497e1153992cd777e9` |
| csi-attacher | `registry.k8s.io/sig-storage/csi-attacher` | v4.12.0 | `sha256:b9dc9a714a484ccdeeb6f86d88d4db9b7a5ecfc5a55da6db3a60bb3fa33c278a` |
| csi-provisioner | `registry.k8s.io/sig-storage/csi-provisioner` | v6.3.0 | `sha256:a4b0b1a37605b7b04a293e136edf7006ec1786a8eb3f4e5a945f81d667dcc371` |

The v1.18.0 source deployment still specifies **hostpathplugin v1.17.1**. This
adaptation deliberately selects the actual v1.18.0 release digest instead of
silently retaining that stale YAML image tag.

## Changes from upstream

- Renamed resources and fixed all namespaced resources and RBAC subjects to the
  dedicated namespace `arcadectl-recovery-csi`; every managed resource and Pod
  template has the `arcade.gobha.me/test-run: __RUN_ID__` ownership label.
  The harness substitutes only a validated alphanumeric/hyphen run identifier.
- Reduced the deployment to five containers: driver, node registrar, liveness
  probe, attacher, provisioner. No snapshot CRDs or snapshotter, resizer,
  external-health-monitor, socat, NodePort, or other upstream helper deployment
  is included. Only the driver is privileged; the Kind fixture assumes no
  SELinux policy requiring privileged sidecars.
- Set `CSIDriver.attachRequired: true` and driver `--enable-attach=true`
  explicitly. The driver's default is false; merely shipping the attacher does
  not otherwise prove an attachment lifecycle. Only persistent volumes are
  advertised, with upstream `podInfoOnMount` and `fsGroupPolicy: File` retained.
- Disabled volume expansion, snapshot listing, VolumeAttributesClass, sidecar
  leader election, and storage-capacity publication. Provisioner and attacher
  each have one worker. Combined RBAC retains only the resources needed for
  provisioning, attachment, topology, and events; no Secret permissions,
  snapshot/expansion resources, namespaced leader-election roles, or bindings.
  The provisioner detects missing snapshot APIs; snapshots are not a fixture
  capability. No privileged third-party CSI controller is installed outside the
  owned Kind cluster.
- Added one internal headless Service for the StatefulSet and a driver readiness
  probe. It does not expose a host port or externally accessible service.
- Retained upstream bidirectional kubelet publish/plugin mount propagation.
  Added `HostToContainer` propagation to `/csi-data-dir`, allowing a test-owned
  child tmpfs mount on the Kind node to become visible inside the driver for
  bounded ENOSPC injection. The directory is backed by
  `/var/lib/csi-hostpath-data` on the Kind node, not on the shared execution pod.
- Added simulated, independent capacity pools via the driver's documented
  `--capacity=<kind>=<quantity>` flags: `world=4Gi`, `repository=2Gi`,
  `sentinel=64Mi`. These track requested PVC capacity; they do **not** allocate
  that much RAM or enforce a byte-write quota. Disk-full tests require the
  separate small tmpfs fault, not node-disk exhaustion.
- Added the four explicit, immediate-binding storage classes below. None is the
  default StorageClass. World retention is explicit; transient filler,
  repository, and sentinel storage uses Delete for owned-cluster cleanup.
- Bounded CPU, memory, Go concurrency, and logging. Total container memory
  requests are **224Mi**, total limits **512Mi**; total CPU requests **100m**,
  limits **1600m**. Per-container Go soft heap limits leave headroom beneath
  hard cgroup limits. Run only one storage-heavy harness at a time.

## Inventory and harness integration

`fixture.yaml` contains exactly eleven API objects:

1. Namespace `arcadectl-recovery-csi`.
2. ServiceAccount `arcadectl-csi-hostpath` in that namespace.
3. ClusterRole `arcadectl-recovery-csi`.
4. ClusterRoleBinding `arcadectl-recovery-csi` to that exact ServiceAccount.
5. CSIDriver `hostpath.csi.k8s.io`.
6. Headless Service `arcadectl-csi-hostpath` in that namespace.
7. Single-replica StatefulSet `arcadectl-csi-hostpath` in that namespace.
8. StorageClass `arcadectl-world-retain`: `kind=world`, reclaim policy Retain.
9. StorageClass `arcadectl-world-filler`: `kind=world`, reclaim policy Delete.
10. StorageClass `arcadectl-repository`: `kind=repository`, reclaim policy Delete.
11. StorageClass `arcadectl-sentinel`: `kind=sentinel`, reclaim policy Delete.

The Pod is `arcadectl-csi-hostpath-0`. Select the driver with
`app.kubernetes.io/name=arcadectl-csi-hostpath` plus the exact run label. The
CSI socket is `/var/lib/kubelet/plugins/csi-hostpath/csi.sock` on the Kind node
and `/csi/csi.sock` inside containers. Node registration uses
`/var/lib/kubelet/plugins_registry`. Volume directories are below the node's
`/var/lib/csi-hostpath-data` and container's `/csi-data-dir`; derive an exact
owned volume directory from its CSI volume handle rather than a broad glob.

The upstream deployment directory targets Kubernetes 1.34. The harness must
prove registration, dynamic provisioning, attachment/detachment, and the
negative/recovery scenarios on its pinned Kind Kubernetes version; source
compatibility alone is not runtime certification. This single-node host-path
driver does not prove Ceph/cloud storage, multi-node failover, or persistence
after the Kind node is destroyed. All API objects, volumes, node mounts, and
directories belong to that disposable Kind cluster and must be cleaned with it.

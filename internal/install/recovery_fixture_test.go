// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func recoveryFixtureObjects(t *testing.T) []*unstructured.Unstructured {
	t.Helper()
	return decodeObjects(t, recoveryFixtureFile(t, "hack", "csi-hostpath", "fixture.yaml"))
}

func recoveryFixtureFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(append([]string{repositoryRoot(t)}, parts...)...))
	if err != nil {
		t.Fatalf("read recovery fixture: %v", err)
	}
	return contents
}

func TestRecoveryCSIInventoryAndIsolation(t *testing.T) {
	t.Parallel()
	objects := recoveryFixtureObjects(t)
	want := []string{
		"/v1, Kind=Namespace /arcadectl-recovery-csi",
		"/v1, Kind=ServiceAccount arcadectl-recovery-csi/arcadectl-csi-hostpath",
		"rbac.authorization.k8s.io/v1, Kind=ClusterRole /arcadectl-recovery-csi",
		"rbac.authorization.k8s.io/v1, Kind=ClusterRoleBinding /arcadectl-recovery-csi",
		"storage.k8s.io/v1, Kind=CSIDriver /hostpath.csi.k8s.io",
		"/v1, Kind=Service arcadectl-recovery-csi/arcadectl-csi-hostpath",
		"apps/v1, Kind=StatefulSet arcadectl-recovery-csi/arcadectl-csi-hostpath",
		"storage.k8s.io/v1, Kind=StorageClass /arcadectl-world-retain",
		"storage.k8s.io/v1, Kind=StorageClass /arcadectl-world-filler",
		"storage.k8s.io/v1, Kind=StorageClass /arcadectl-repository",
		"storage.k8s.io/v1, Kind=StorageClass /arcadectl-sentinel",
	}
	if got := objectIdentities(objects); !slices.Equal(got, want) {
		t.Fatalf("fixture inventory = %v, want %v", got, want)
	}
	for _, object := range objects {
		if object.GetLabels()["arcade.gobha.me/test-run"] != "__RUN_ID__" {
			t.Errorf("%s/%s lacks exact run ownership placeholder", object.GetKind(), object.GetName())
		}
		if ns := object.GetNamespace(); ns != "" && ns != "arcadectl-recovery-csi" {
			t.Errorf("fixture escaped dedicated namespace: %s/%s", ns, object.GetName())
		}
	}
	for _, name := range []string{"anchors.yaml", "controller.yaml", "uninstall.yaml"} {
		production := decodeObjects(t, recoveryFixtureFile(t, "config", "install", name))
		for _, identity := range objectIdentities(production) {
			if slices.Contains(want, identity) {
				t.Errorf("privileged disposable fixture leaked into production %s: %s", name, identity)
			}
		}
	}
	namespace := &corev1.Namespace{}
	convertObject(t, objects[0], namespace)
	for _, mode := range []string{"enforce", "audit", "warn"} {
		if namespace.Labels["pod-security.kubernetes.io/"+mode] != "privileged" {
			t.Errorf("test-only CSI namespace %s security policy changed", mode)
		}
	}
	role := &rbacv1.ClusterRole{}
	convertObject(t, objects[2], role)
	allowed := []string{"persistentvolumes", "persistentvolumeclaims", "events", "nodes", "storageclasses", "csinodes", "volumeattachments", "volumeattachments/status"}
	var granted []string
	for _, rule := range role.Rules {
		granted = append(granted, rule.Resources...)
		if slices.Contains(rule.Verbs, "*") || slices.Contains(rule.APIGroups, "*") || len(rule.NonResourceURLs) != 0 {
			t.Errorf("CSI fixture unexpectedly grants wildcard or nonresource authority: %#v", rule)
		}
	}
	slices.Sort(granted)
	slices.Sort(allowed)
	if !slices.Equal(granted, allowed) {
		t.Errorf("CSI authority resources = %v, want no Secret/snapshot/expansion/lease authority %v", granted, allowed)
	}
	binding := &rbacv1.ClusterRoleBinding{}
	convertObject(t, objects[3], binding)
	if binding.RoleRef.APIGroup != rbacv1.GroupName || binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != role.Name || len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "ServiceAccount" ||
		binding.Subjects[0].Name != objects[1].GetName() || binding.Subjects[0].Namespace != "arcadectl-recovery-csi" {
		t.Errorf("CSI binding is not limited to its exact test-owned ServiceAccount: %#v", binding)
	}
}

func TestRecoveryCSIStorageAndRuntime(t *testing.T) {
	t.Parallel()
	objects := recoveryFixtureObjects(t)
	if len(objects) != 11 {
		t.Fatalf("CSI fixture has %d objects, want eleven", len(objects))
	}
	driver := &storagev1.CSIDriver{}
	convertObject(t, objects[4], driver)
	if driver.Spec.AttachRequired == nil || !*driver.Spec.AttachRequired || driver.Spec.PodInfoOnMount == nil || !*driver.Spec.PodInfoOnMount ||
		driver.Spec.FSGroupPolicy == nil || *driver.Spec.FSGroupPolicy != storagev1.FileFSGroupPolicy ||
		!slices.Equal(driver.Spec.VolumeLifecycleModes, []storagev1.VolumeLifecycleMode{storagev1.VolumeLifecyclePersistent}) {
		t.Fatalf("CSI fixture must prove actual attach and persistent filesystem mounts: %#v", driver.Spec)
	}
	service := &corev1.Service{}
	convertObject(t, objects[5], service)
	if service.Spec.ClusterIP != corev1.ClusterIPNone || service.Spec.Type == corev1.ServiceTypeNodePort || service.Spec.Type == corev1.ServiceTypeLoadBalancer {
		t.Errorf("test CSI service must remain internal/headless: %#v", service.Spec)
	}
	sts := &appsv1.StatefulSet{}
	convertObject(t, objects[6], sts)
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != 1 || len(sts.Spec.VolumeClaimTemplates) != 0 ||
		sts.Spec.ServiceName != service.Name || sts.Spec.Template.Labels["arcade.gobha.me/test-run"] != "__RUN_ID__" {
		t.Fatalf("CSI StatefulSet must have exactly one owned replica and no implicit storage: %#v", sts.Spec)
	}
	pod := sts.Spec.Template.Spec
	if len(pod.Containers) != 5 || len(pod.InitContainers) != 0 || pod.ServiceAccountName != objects[1].GetName() || pod.HostNetwork || pod.HostPID || pod.HostIPC {
		t.Fatalf("CSI Pod shape or isolation changed: %#v", pod)
	}
	wantImages := map[string]string{
		"hostpath":              "registry.k8s.io/sig-storage/hostpathplugin@sha256:44e2cb773c42f31ea2b6c1d736b53e96805ab03aec743d2ceea445b17b75b85c",
		"node-driver-registrar": "registry.k8s.io/sig-storage/csi-node-driver-registrar@sha256:f9de845b170155199f2a2a3f9531cf13d78e31235e9db6b6582a8b0db0a50dad",
		"liveness-probe":        "registry.k8s.io/sig-storage/livenessprobe@sha256:06da0d5b8908072f2e4522692aee8dc119fba7247a9658497e1153992cd777e9",
		"csi-attacher":          "registry.k8s.io/sig-storage/csi-attacher@sha256:b9dc9a714a484ccdeeb6f86d88d4db9b7a5ecfc5a55da6db3a60bb3fa33c278a",
		"csi-provisioner":       "registry.k8s.io/sig-storage/csi-provisioner@sha256:a4b0b1a37605b7b04a293e136edf7006ec1786a8eb3f4e5a945f81d667dcc371",
	}
	var requestMemory, limitMemory, requestCPU, limitCPU int64
	var hostpath corev1.Container
	for _, container := range pod.Containers {
		want, found := wantImages[container.Name]
		if !found || container.Image != want {
			t.Errorf("CSI container %s digest = %q, want %q", container.Name, container.Image, want)
		}
		delete(wantImages, container.Name)
		for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
			request, limit := container.Resources.Requests[name], container.Resources.Limits[name]
			if request.Sign() <= 0 || limit.Sign() <= 0 || request.Cmp(limit) > 0 {
				t.Errorf("CSI container %s has unbounded or invalid %s resources", container.Name, name)
			}
		}
		requestMemory += container.Resources.Requests.Memory().Value()
		limitMemory += container.Resources.Limits.Memory().Value()
		requestCPU += container.Resources.Requests.Cpu().MilliValue()
		limitCPU += container.Resources.Limits.Cpu().MilliValue()
		if !slices.ContainsFunc(container.Env, func(env corev1.EnvVar) bool { return env.Name == "GOMAXPROCS" && env.Value == "1" }) ||
			!slices.ContainsFunc(container.Env, func(env corev1.EnvVar) bool { return env.Name == "GOMEMLIMIT" && env.Value != "" }) {
			t.Errorf("CSI container %s lacks explicit Go concurrency/heap limits", container.Name)
		}
		if container.Name == "hostpath" {
			hostpath = container
			if container.SecurityContext == nil || container.SecurityContext.Privileged == nil || !*container.SecurityContext.Privileged {
				t.Error("test CSI driver requires its explicit test-only privilege")
			}
		} else if container.SecurityContext == nil || (container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
			container.SecurityContext.AllowPrivilegeEscalation == nil || *container.SecurityContext.AllowPrivilegeEscalation {
			t.Errorf("CSI sidecar %s must remain unprivileged", container.Name)
		}
		if container.Name == "csi-attacher" || container.Name == "csi-provisioner" {
			for _, arg := range []string{"--leader-election=false", "--worker-threads=1", "--timeout=10s"} {
				if !slices.Contains(container.Args, arg) {
					t.Errorf("CSI sidecar %s lost bounded singleton setting %s", container.Name, arg)
				}
			}
		}
		if container.Name != "hostpath" {
			for _, mount := range container.VolumeMounts {
				if mount.Name == "csi-data-dir" || (mount.MountPropagation != nil && *mount.MountPropagation != corev1.MountPropagationNone) {
					t.Errorf("sidecar %s must not receive CSI data or mount propagation", container.Name)
				}
			}
		}
	}
	if len(wantImages) != 0 {
		t.Errorf("missing CSI containers: %v", wantImages)
	}
	wantRequestMemory, wantLimitMemory := resource.MustParse("224Mi"), resource.MustParse("512Mi")
	if requestMemory != wantRequestMemory.Value() || limitMemory != wantLimitMemory.Value() || requestCPU != 100 || limitCPU != 1600 {
		t.Errorf("CSI fixture resource totals changed: memory request/limit=%d/%d CPU millicores=%d/%d", requestMemory, limitMemory, requestCPU, limitCPU)
	}
	var capacities []string
	for _, arg := range hostpath.Args {
		if strings.HasPrefix(arg, "--capacity=") {
			capacities = append(capacities, arg)
		}
	}
	if !slices.Equal(capacities, []string{"--capacity=world=4Gi", "--capacity=repository=2Gi", "--capacity=sentinel=64Mi"}) {
		t.Errorf("fixture must have three finite independent capacity pools: %v", capacities)
	}
	for _, arg := range []string{"--enable-attach=true", "--enable-volume-expansion=false", "--enable-list-snapshots=false", "--statedir=/csi-data-dir"} {
		if !slices.Contains(hostpath.Args, arg) {
			t.Errorf("CSI driver lost explicit fixture contract %s", arg)
		}
	}
	wantMounts := map[string]corev1.MountPropagationMode{
		"mountpoint-dir": corev1.MountPropagationBidirectional,
		"plugins-dir":    corev1.MountPropagationBidirectional,
		"csi-data-dir":   corev1.MountPropagationHostToContainer,
	}
	for _, mount := range hostpath.VolumeMounts {
		if want, ok := wantMounts[mount.Name]; ok {
			if mount.MountPropagation == nil || *mount.MountPropagation != want {
				t.Errorf("mount %s propagation must be %s", mount.Name, want)
			}
			delete(wantMounts, mount.Name)
		} else if mount.MountPropagation != nil && *mount.MountPropagation != corev1.MountPropagationNone {
			t.Errorf("unexpected propagation on fixture mount %s", mount.Name)
		}
	}
	if len(wantMounts) != 0 {
		t.Errorf("missing required CSI propagation mounts: %v", wantMounts)
	}
	wantVolumes := map[string]string{"socket-dir": "/var/lib/kubelet/plugins/csi-hostpath", "mountpoint-dir": "/var/lib/kubelet/pods",
		"registration-dir": "/var/lib/kubelet/plugins_registry", "plugins-dir": "/var/lib/kubelet/plugins",
		"csi-data-dir": "/var/lib/csi-hostpath-data", "dev-dir": "/dev"}
	for _, volume := range pod.Volumes {
		want, ok := wantVolumes[volume.Name]
		if !ok || volume.HostPath == nil || volume.HostPath.Path != want {
			t.Errorf("CSI backing volume must stay in exact disposable-node directories: %#v", volume)
		}
		delete(wantVolumes, volume.Name)
	}
	if len(wantVolumes) != 0 {
		t.Errorf("CSI fixture lost required node volumes: %v", wantVolumes)
	}
	classes := []struct {
		pool   string
		policy corev1.PersistentVolumeReclaimPolicy
	}{{"world", corev1.PersistentVolumeReclaimRetain}, {"world", corev1.PersistentVolumeReclaimDelete}, {"repository", corev1.PersistentVolumeReclaimDelete}, {"sentinel", corev1.PersistentVolumeReclaimDelete}}
	for index, want := range classes {
		class := &storagev1.StorageClass{}
		convertObject(t, objects[7+index], class)
		if class.Provisioner != driver.Name || !reflect.DeepEqual(class.Parameters, map[string]string{"kind": want.pool}) ||
			class.ReclaimPolicy == nil || *class.ReclaimPolicy != want.policy || class.VolumeBindingMode == nil ||
			*class.VolumeBindingMode != storagev1.VolumeBindingImmediate || class.AllowVolumeExpansion == nil || *class.AllowVolumeExpansion ||
			class.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" || class.Annotations["storageclass.beta.kubernetes.io/is-default-class"] == "true" {
			t.Errorf("StorageClass %s escaped explicit isolated pool/retention/binding contract: %#v", class.Name, class)
		}
	}
}

func TestRecoveryRepositoryTemplate(t *testing.T) {
	t.Parallel()
	contents := recoveryFixtureFile(t, "hack", "recovery-repository.yaml.tmpl")
	for _, placeholder := range []string{"@@MINIO_IMAGE@@", "@@REPOSITORY_PASSWORD@@", "@@ACCESS_KEY@@", "@@OBJECT_KEY@@"} {
		if strings.Count(string(contents), placeholder) != 1 {
			t.Errorf("repository template must use exactly one inert %s placeholder", placeholder)
		}
	}
	// Only inert fixture values are substituted; no credentials or cluster calls.
	rendered := strings.NewReplacer("@@RUN_ID@@", "hermetic-recovery-test", "@@MINIO_IMAGE@@", testControllerImage,
		"@@REPOSITORY_PASSWORD@@", "fake-template-password", "@@ACCESS_KEY@@", "fake-template-access", "@@OBJECT_KEY@@", "fake-template-object").Replace(string(contents))
	objects := decodeObjects(t, []byte(rendered))
	want := []string{"/v1, Kind=Secret arcadectl-system/recovery-repository", "/v1, Kind=PersistentVolumeClaim arcadectl-system/recovery-repository-data",
		"/v1, Kind=Service arcadectl-system/minio", "apps/v1, Kind=Deployment arcadectl-system/minio"}
	if got := objectIdentities(objects); !slices.Equal(got, want) {
		t.Fatalf("repository fixture inventory = %v, want %v", got, want)
	}
	for _, object := range objects {
		if object.GetLabels()["arcade.gobha.me/e2e-run"] != "hermetic-recovery-test" {
			t.Errorf("repository fixture %s lacks exact run ownership", object.GetName())
		}
	}
	secret := &corev1.Secret{}
	convertObject(t, objects[0], secret)
	expected := map[string]string{"repository": "s3:http://minio:9000/arcadectl", "password": "fake-template-password",
		"awsAccessKeyID": "fake-template-access", "awsSecretAccessKey": "fake-template-object"}
	if secret.Immutable == nil || !*secret.Immutable || secret.Type != corev1.SecretTypeOpaque || len(secret.Data) != 0 || !reflect.DeepEqual(secret.StringData, expected) {
		t.Error("repository Secret must contain immutable fake-placeholder authority only")
	}
	claim := &corev1.PersistentVolumeClaim{}
	convertObject(t, objects[1], claim)
	if claim.Spec.StorageClassName == nil || *claim.Spec.StorageClassName != "arcadectl-repository" ||
		claim.Spec.Resources.Requests.Storage().Cmp(resource.MustParse("2Gi")) != 0 || !slices.Equal(claim.Spec.AccessModes, []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}) {
		t.Errorf("repository must use independent persistent CSI capacity: %#v", claim.Spec)
	}
	deployment := &appsv1.Deployment{}
	convertObject(t, objects[3], deployment)
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType ||
		len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Labels["arcade.gobha.me/e2e-run"] != "hermetic-recovery-test" {
		t.Fatalf("repository must keep one exact test-owned Recreate runtime: %#v", deployment.Spec)
	}
	pod := deployment.Spec.Template.Spec
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || len(pod.Volumes) != 2 ||
		pod.Volumes[0].PersistentVolumeClaim == nil || pod.Volumes[0].PersistentVolumeClaim.ClaimName != claim.Name || pod.Volumes[1].EmptyDir == nil {
		t.Errorf("repository must retain CSI data across credential rollouts without API authority: %#v", pod)
	}
	container := pod.Containers[0]
	if container.Image != testControllerImage {
		t.Error("repository image must be supplied through the fixture placeholder")
	}
	for _, name := range []string{"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"} {
		if !slices.ContainsFunc(container.Env, func(env corev1.EnvVar) bool {
			return env.Name == name && env.Value == "" && env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil && env.ValueFrom.SecretKeyRef.Name == secret.Name
		}) {
			t.Errorf("repository credential %s must reference its immutable Secret", name)
		}
	}
}

package destroyauth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

func TestPreflightReleasesOnlyExactSecret(t *testing.T) {
	f := newFixture(t)
	client, game := f.clients(t)
	input, readErr := readInput(f.inputPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err := verifyAuthority(context.Background(), Config{Client: client, GameClient: game, Now: f.now}, "games", input, "job-uid", "world-identity"); err != nil {
		t.Fatalf("fixture authority: %v", err)
	}
	output := filepath.Join(t.TempDir(), "credentials")
	err := Run(context.Background(), Config{InputPath: f.inputPath, OutputPath: output, Namespace: "games", PodName: "destroy-pod", PodUID: "pod-1", Now: f.now, Client: client, GameClient: game})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(filepath.Join(output, platformdata.RepositoryKeyPassword)); err != nil {
		t.Fatalf("authorized credential absent: %v", err)
	}
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "persistentvolumeclaims" || action.GetResource().Resource == "persistentvolumes" {
			t.Fatalf("preflight read world data: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
	lease, err := client.CoordinationV1().Leases("games").Get(context.Background(), f.workerLease.Name, metav1.GetOptions{})
	if err != nil || lease.Annotations[platformkube.AnnotationWorkerPodUID] != "pod-1" {
		t.Fatalf("worker lease was not claimed: %#v, %v", lease, err)
	}
	world, err := client.CoordinationV1().Leases("games").Get(context.Background(), f.worldLease.Name, metav1.GetOptions{})
	if err != nil || world.Annotations[platformkube.AnnotationWorkerPodUID] != "" {
		t.Fatalf("data lease was mutated: %#v, %v", world, err)
	}
}

func TestAuthorityFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*fixture)
	}{
		{"wrong destroy UID", func(f *fixture) { f.destroy.UID = "recreated-destroy" }},
		{"wrong backup UID", func(f *fixture) { f.backup.UID = "recreated-backup" }},
		{"wrong world identity", func(f *fixture) { f.destroy.Spec.Target.Data.Identity = "other-world" }},
		{"wrong claim UID", func(f *fixture) { f.destroy.Spec.Target.Data.Claims[0].ClaimRef.UID = "other-claim" }},
		{"changed artifact", func(f *fixture) { f.backup.Status.Artifact.ManifestDigest = "sha256:" + strings.Repeat("d", 64) }},
		{"stale confirmation", func(f *fixture) { f.destroy.Spec.ConfirmationChallenge = "stale-challenge-000" }},
		{"expired preview", func(f *fixture) { f.destroy.Status.Preview.ExpiresAt = metav1.NewTime(f.now().Add(-time.Second)) }},
		{"cancel requested", func(f *fixture) { f.destroy.Spec.CancelRequested = true }},
		{"wrong phase", func(f *fixture) { f.destroy.Status.Phase = arcadev1alpha1.DestroyPhasePreview }},
		{"stale generation", func(f *fixture) { f.destroy.Generation++ }},
		{"worker lease wrong owner", func(f *fixture) { f.workerLease.OwnerReferences[0].UID = "other-destroy" }},
		{"worker lease wrong identity", func(f *fixture) { f.workerLease.Labels[platformkube.LabelDataIdentity] = "other-world" }},
		{"world lease wrong holder", func(f *fixture) { f.worldLease.Spec.HolderIdentity = ptr.To("other-destroy") }},
		{"world lease missing", func(f *fixture) { f.worldLease = nil }},
		{"wrong Pod UID", func(f *fixture) { f.pod.UID = "recreated-pod" }},
		{"Pod marker absent", func(f *fixture) { delete(f.pod.Annotations, platformkube.AnnotationDestroyPodAuthorized) }},
		{"Pod marker stale", func(f *fixture) { f.pod.Annotations[platformkube.AnnotationDestroyPodAuthorized] = "old-pod" }},
		{"Pod still gated", func(f *fixture) {
			f.pod.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: platformkube.DestroySchedulingGate}}
		}},
		{"Pod wrong Job owner", func(f *fixture) { f.pod.OwnerReferences[0].UID = "other-job" }},
		{"Pod wrong destroy label", func(f *fixture) { f.pod.Labels[platformkube.LabelDestroyUID] = "other-destroy" }},
		{"Pod wrong data identity", func(f *fixture) { f.pod.Labels[platformkube.LabelDataIdentity] = "other-world" }},
		{"worker lease wrong Job marker", func(f *fixture) { f.workerLease.Annotations[annotationDestroyJobAuthorized] = "other-job" }},
		{"Pod source volume", func(f *fixture) {
			f.pod.Spec.Volumes = []corev1.Volume{{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "factory-world"}}}}
		}},
		{"Pod API token to worker", func(f *fixture) {
			f.pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "authority", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount"}}
		}},
		{"secret revision changed", func(f *fixture) { f.secret.ResourceVersion = "43" }},
		{"secret not immutable", func(f *fixture) { f.secret.Immutable = ptr.To(false) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			test.mutate(&f)
			client, game := f.clients(t)
			output := filepath.Join(t.TempDir(), "credentials")
			err := Run(context.Background(), Config{InputPath: f.inputPath, OutputPath: output, Namespace: "games", PodName: "destroy-pod", PodUID: "pod-1", Now: f.now, Client: client, GameClient: game})
			if err == nil || strings.Contains(err.Error(), "password-canary") {
				t.Fatalf("authority released or leaked credential: %v", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("authority created credential directory: %v", err)
			}
		})
	}
}

func TestCompetingWorkerCannotReceiveCredentials(t *testing.T) {
	f := newFixture(t)
	client, game := f.clients(t)
	first := filepath.Join(t.TempDir(), "first")
	config := Config{InputPath: f.inputPath, OutputPath: first, Namespace: "games", PodName: "destroy-pod", PodUID: "pod-1", Now: f.now, Client: client, GameClient: game}
	if err := Run(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	config.OutputPath = filepath.Join(t.TempDir(), "second")
	secondPod := f.pod.DeepCopy()
	secondPod.Name = "destroy-pod-2"
	secondPod.UID = "pod-2"
	secondPod.Annotations[platformkube.AnnotationDestroyPodAuthorized] = "pod-2"
	if _, err := client.CoreV1().Pods("games").Create(context.Background(), secondPod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	config.PodName = secondPod.Name
	config.PodUID = "pod-2"
	err := Run(context.Background(), config)
	if err != ErrExecutionOwned || ExitCode(err) != executionExitCode {
		t.Fatalf("overlap = %v, code %d", err, ExitCode(err))
	}
	if _, err := os.Stat(config.OutputPath); !os.IsNotExist(err) {
		t.Fatalf("competing worker received credentials: %v", err)
	}
}

func TestPodApprovalRecheckedAfterLeaseCAS(t *testing.T) {
	f := newFixture(t)
	client, game := f.clients(t)
	client.PrependReactor("update", "leases", func(action clienttesting.Action) (bool, runtime.Object, error) {
		object, err := client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("pods"), "games", f.pod.Name)
		if err != nil {
			t.Fatal(err)
		}
		pod := object.(*corev1.Pod).DeepCopy()
		delete(pod.Annotations, platformkube.AnnotationDestroyPodAuthorized)
		if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, "games"); err != nil {
			t.Fatal(err)
		}
		return false, nil, nil
	})
	output := filepath.Join(t.TempDir(), "credentials")
	err := Run(context.Background(), Config{InputPath: f.inputPath, OutputPath: output, Namespace: "games", PodName: f.pod.Name, PodUID: string(f.pod.UID), Now: f.now, Client: client, GameClient: game})
	if err == nil {
		t.Fatal("authorization succeeded after Pod approval was revoked")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("credential directory created after revoked approval: %v", err)
	}
}

type fixture struct {
	inputPath   string
	destroy     *arcadev1alpha1.GameDestroy
	backup      *arcadev1alpha1.GameBackup
	secret      *corev1.Secret
	pod         *corev1.Pod
	workerLease *coordinationv1.Lease
	worldLease  *coordinationv1.Lease
	now         func() time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	operation := arcadev1alpha1.ExactLocalReference{Name: "destroy", UID: "destroy-uid"}
	backupRef := arcadev1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"}
	repository := arcadev1alpha1.ExactSecretReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42"}
	server := arcadev1alpha1.ExactGameServerReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "factory-uid"}, Generation: 1, DesiredState: arcadev1alpha1.DesiredStateStopped}
	claim := arcadev1alpha1.ExactLocalReference{Name: "factory-world", UID: "claim-uid"}
	source := arcadev1alpha1.DataSourceSnapshot{GameServer: server, Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("b", 64), SettingsDigest: "sha256:" + strings.Repeat("c", 64), Paths: []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: claim}}}
	artifactID, err := platformdata.ArtifactID(types.UID(backupRef.UID))
	if err != nil {
		t.Fatal(err)
	}
	artifact := arcadev1alpha1.BackupArtifact{ID: artifactID, FormatVersion: platformdata.BackupFormatVersion, ManifestDigest: "sha256:" + strings.Repeat("a", 64), PathCount: 1,
		Provenance: arcadev1alpha1.ArtifactProvenance{BackupRef: backupRef, RepositorySecretRef: repository}, Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified}}
	input := restoreworker.Input{Version: restoreworker.InputVersion, Stage: restoreworker.StagePreflight, OperationRef: operation, BackupRef: backupRef, Target: server,
		WorkerLeaseName: platformkube.DestroyWorkerLeaseName(types.UID(operation.UID)), RepositorySecretRef: repository, Artifact: artifact, Source: source,
		TargetGame: source.Game, TargetImageDigest: source.ImageDigest, TargetSettingsDigest: source.SettingsDigest,
		TargetPaths: []restoreworker.PathContract{{Name: "state", MountPath: "/factorio"}}}
	if err := restoreworker.ValidateInput(input); err != nil {
		t.Fatalf("fixture input invalid: %v", err)
	}
	contents, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(inputPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	target := arcadev1alpha1.GameDestroyTarget{GameServer: server.ExactLocalReference, Game: "factorio", Data: arcadev1alpha1.RetainedDataReference{Identity: "world-identity", Claims: []arcadev1alpha1.RetainedDataClaimReference{{Path: "state", ClaimRef: claim}}}}
	destroy := &arcadev1alpha1.GameDestroy{TypeMeta: metav1.TypeMeta{APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameDestroy"}, ObjectMeta: metav1.ObjectMeta{Name: operation.Name, Namespace: "games", UID: types.UID(operation.UID), Generation: 2},
		Spec:   arcadev1alpha1.GameDestroySpec{Target: target, Mode: arcadev1alpha1.DestroyModeVerifiedBackup, BackupRef: &backupRef, RepositorySecretRef: &repository, ConfirmationChallenge: "challenge-1234567890"},
		Status: arcadev1alpha1.GameDestroyStatus{Phase: arcadev1alpha1.DestroyPhaseVerifying, ObservedGeneration: 2, Preview: &arcadev1alpha1.GameDestroyPreview{Challenge: "challenge-1234567890", ExpiresAt: metav1.NewTime(now.Add(time.Minute)), RestoreGuidance: "Restore from the verified backup"}}}
	backup := &arcadev1alpha1.GameBackup{TypeMeta: metav1.TypeMeta{APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameBackup"}, ObjectMeta: metav1.ObjectMeta{Name: backupRef.Name, Namespace: "games", UID: types.UID(backupRef.UID)},
		Spec:   arcadev1alpha1.GameBackupSpec{DataOperationRequest: arcadev1alpha1.DataOperationRequest{RepositorySecretRef: repository}, Source: server},
		Status: arcadev1alpha1.GameBackupStatus{DataOperationStatus: arcadev1alpha1.DataOperationStatus{Phase: arcadev1alpha1.DataPhaseSucceeded, Source: &source, Artifact: &artifact}}}
	labels := map[string]string{platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelInstance: server.Name, platformkube.LabelDestroyUID: operation.UID, platformkube.LabelDataIdentity: target.Data.Identity}
	annotations := map[string]string{platformkube.AnnotationDestroyName: operation.Name, annotationDestroyJobAuthorized: "job-uid"}
	workerLease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: input.WorkerLeaseName, Namespace: "games", Labels: labels, Annotations: annotations,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameDestroy", Name: operation.Name, UID: types.UID(operation.UID)}}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(operation.UID)}}
	worldLease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: platformkube.DataOperationLeaseName(target.Data.Identity), Namespace: "games", Labels: labels, Annotations: annotations}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(operation.UID)}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "destroy-pod", Namespace: "games", UID: "pod-1", Labels: map[string]string{
		platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelName: "destroy-worker", platformkube.LabelDestroyUID: operation.UID,
		platformkube.LabelDestroyStage: string(restoreworker.StagePreflight), platformkube.LabelDataOperation: "destroy", platformkube.LabelDataIdentity: target.Data.Identity, platformkube.LabelInstance: server.Name,
	}, Annotations: map[string]string{
		platformkube.AnnotationDestroyName: operation.Name, platformkube.AnnotationArtifactID: artifact.ID, platformkube.AnnotationDestroyPodAuthorized: "pod-1",
	}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: platformkube.DestroyResourceName(types.UID(operation.UID)), UID: "job-uid", Controller: ptr.To(true)}}},
		Spec: corev1.PodSpec{ServiceAccountName: platformkube.DestroyResourceName(types.UID(operation.UID)) + "-authority", AutomountServiceAccountToken: ptr.To(false),
			InitContainers: []corev1.Container{{Name: "destroy-authorizer"}}, Containers: []corev1.Container{{Name: "destroy-worker"}}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: repository.Name, Namespace: "games", UID: types.UID(repository.UID), ResourceVersion: repository.ResourceVersion}, Immutable: ptr.To(true), Data: map[string][]byte{
		platformdata.RepositoryKeyRepository: []byte("s3:http://minio.example/arcadectl"), platformdata.RepositoryKeyPassword: []byte("password-canary"),
		platformdata.RepositoryKeyAccessKeyID: []byte("access-canary"), platformdata.RepositoryKeySecretAccessKey: []byte("secret-canary"),
	}}
	return fixture{inputPath: inputPath, destroy: destroy, backup: backup, secret: secret, pod: pod, workerLease: workerLease, worldLease: worldLease, now: func() time.Time { return now }}
}

func (f fixture) clients(t *testing.T) (*kubefake.Clientset, *fake.FakeDynamicClient) {
	t.Helper()
	objects := []runtime.Object{f.secret, f.workerLease, f.pod}
	if f.worldLease != nil {
		objects = append(objects, f.worldLease)
	}
	client := kubefake.NewSimpleClientset(objects...)
	toUnstructured := func(object runtime.Object) *unstructured.Unstructured {
		mapObject, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
		if err != nil {
			t.Fatal(err)
		}
		mapObject["apiVersion"] = arcadev1alpha1.GroupVersion.String()
		switch object.(type) {
		case *arcadev1alpha1.GameDestroy:
			mapObject["kind"] = "GameDestroy"
		case *arcadev1alpha1.GameBackup:
			mapObject["kind"] = "GameBackup"
		}
		return &unstructured.Unstructured{Object: mapObject}
	}
	game := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{destroyResource: "GameDestroyList", backupResource: "GameBackupList"})
	if _, err := game.Resource(destroyResource).Namespace("games").Create(context.Background(), toUnstructured(f.destroy), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := game.Resource(backupResource).Namespace("games").Create(context.Background(), toUnstructured(f.backup), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return client, game
}

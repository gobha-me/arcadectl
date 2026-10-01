// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package restoreauth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	"k8s.io/utils/ptr"
)

func TestPreflightReadsNoTargetAndReleasesExactSecret(t *testing.T) {
	f := newAuthFixture(t, restoreworker.StagePreflight)
	// No target GameServer, previous Lease, or PVC is present. Preflight must
	// still succeed using only the candidate Lease and repository Secret.
	client := kubefake.NewSimpleClientset(f.secret, f.candidateLease)
	output := filepath.Join(t.TempDir(), "credentials")
	if err := Run(context.Background(), Config{InputPath: f.inputPath, OutputPath: output, Namespace: "games", PodUID: "pod-uid", Client: client}); err != nil {
		t.Fatalf("preflight authorization: %v", err)
	}
	if _, err := os.ReadFile(filepath.Join(output, platformdata.RepositoryKeyPassword)); err != nil {
		t.Fatalf("authorized credentials absent: %v", err)
	}
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "persistentvolumeclaims" || action.GetResource().Resource == "persistentvolumes" {
			t.Fatalf("preflight read target data: %s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}
}

func TestPopulateRequiresStoppedExactPreviousSelection(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*authFixture)
	}{
		{"wrong GameServer UID", func(f *authFixture) { f.server.UID = types.UID("other-target") }},
		{"changed active data at same generation", func(f *authFixture) {
			f.server.Status.ActiveData = &arcadev1alpha1.RetainedDataReference{Identity: f.candidateIdentity, Claims: []arcadev1alpha1.RetainedDataClaimReference{{Path: "state", ClaimRef: f.input.CandidatePaths[0].ClaimRef}}}
		}},
		{"stale observed data", func(f *authFixture) { f.server.Status.ObservedData.Claims[0].ClaimRef.UID = "other-world" }},
		{"runtime still running", func(f *authFixture) { f.server.Spec.DesiredState = arcadev1alpha1.DesiredStateRunning }},
		{"stale stopped generation", func(f *authFixture) { f.server.Status.ObservedGeneration-- }},
		{"previous lease missing", func(f *authFixture) { f.previousLease = nil }},
		{"previous lease changed holder", func(f *authFixture) { f.previousLease.Spec.HolderIdentity = ptr.To("other-restore") }},
		{"candidate aliases previous PV", func(f *authFixture) { f.candidateClaim.Spec.VolumeName = f.previousClaim.Spec.VolumeName }},
		{"candidate UID changed", func(f *authFixture) { f.candidateClaim.UID = types.UID("other-candidate") }},
		{"previous UID changed", func(f *authFixture) { f.previousClaim.UID = types.UID("other-previous") }},
		{"secret revision changed", func(f *authFixture) { f.secret.ResourceVersion = "43" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newAuthFixture(t, restoreworker.StagePopulate)
			test.mutate(&f)
			objects := []runtime.Object{f.secret, f.candidateLease, f.previousClaim, f.candidateClaim}
			if f.previousLease != nil {
				objects = append(objects, f.previousLease)
			}
			client := kubefake.NewSimpleClientset(objects...)
			game := fakeGameClient(t, f.server)
			output := filepath.Join(t.TempDir(), "credentials")
			err := Run(context.Background(), Config{InputPath: f.inputPath, OutputPath: output, Namespace: "games", PodUID: "pod-uid", Client: client, GameClient: game})
			if err == nil || strings.Contains(err.Error(), "password-canary") || strings.Contains(err.Error(), "secret-canary") {
				t.Fatalf("unsafe populate authority: %v", err)
			}
			if entries, readErr := os.ReadDir(output); !os.IsNotExist(readErr) && (readErr != nil || len(entries) != 0) {
				t.Fatalf("failed authority released credentials: %#v, %v", entries, readErr)
			}
		})
	}
}

func TestPopulateClaimsOnePodAndRejectsOverlap(t *testing.T) {
	f := newAuthFixture(t, restoreworker.StagePopulate)
	client := kubefake.NewSimpleClientset(f.secret, f.candidateLease, f.previousLease, f.previousClaim, f.candidateClaim)
	game := fakeGameClient(t, f.server)
	output := filepath.Join(t.TempDir(), "first")
	if err := Run(context.Background(), Config{InputPath: f.inputPath, OutputPath: output, Namespace: "games", PodUID: "first-pod", Client: client, GameClient: game}); err != nil {
		t.Fatalf("populate authorization: %v", err)
	}
	lease, err := client.CoordinationV1().Leases("games").Get(context.Background(), f.candidateLease.Name, metav1.GetOptions{})
	if err != nil || lease.Annotations[platformkube.AnnotationWorkerPodUID] != "first-pod" {
		t.Fatalf("candidate execution lease not claimed: %#v, %v", lease, err)
	}
	second := filepath.Join(t.TempDir(), "second")
	err = Run(context.Background(), Config{InputPath: f.inputPath, OutputPath: second, Namespace: "games", PodUID: "second-pod", Client: client, GameClient: game})
	if err != ErrExecutionOwned || ExitCode(err) != executionExitCode {
		t.Fatalf("second worker = %v, code %d; want overlap refusal", err, ExitCode(err))
	}
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatalf("second worker received credentials: %v", err)
	}
}

type authFixture struct {
	input             restoreworker.Input
	inputPath         string
	candidateIdentity string
	secret            *corev1.Secret
	candidateLease    *coordinationv1.Lease
	previousLease     *coordinationv1.Lease
	previousClaim     *corev1.PersistentVolumeClaim
	candidateClaim    *corev1.PersistentVolumeClaim
	server            *arcadev1alpha1.GameServer
}

func newAuthFixture(t *testing.T, stage restoreworker.Stage) authFixture {
	t.Helper()
	operation := arcadev1alpha1.ExactLocalReference{Name: "restore", UID: "restore-uid"}
	backup := arcadev1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"}
	repository := arcadev1alpha1.ExactSecretReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "42"}
	candidateIdentity, err := platformdata.RestoreDataIdentity(types.UID(operation.UID))
	if err != nil {
		t.Fatal(err)
	}
	previousIdentity := "data-original"
	candidateName, err := platformdata.RestoreCandidateID(types.UID(operation.UID), "state")
	if err != nil {
		t.Fatal(err)
	}
	previousPath := arcadev1alpha1.DataPathIdentity{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous", UID: "previous-uid"}}
	candidatePath := arcadev1alpha1.DataPathIdentity{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: candidateName, UID: "candidate-uid"}}
	artifactID, err := platformdata.ArtifactID(types.UID(backup.UID))
	if err != nil {
		t.Fatal(err)
	}
	input := restoreworker.Input{
		Version: restoreworker.InputVersion, Stage: stage, OperationRef: operation, BackupRef: backup,
		Target:          arcadev1alpha1.ExactGameServerReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "target-uid"}, Generation: 1, DesiredState: arcadev1alpha1.DesiredStateRunning},
		WorkerLeaseName: platformkube.DataOperationLeaseName(candidateIdentity), RepositorySecretRef: repository,
		Artifact: arcadev1alpha1.BackupArtifact{
			Provenance: arcadev1alpha1.ArtifactProvenance{BackupRef: backup, RepositorySecretRef: repository},
			ID:         artifactID, FormatVersion: platformdata.BackupFormatVersion,
			ManifestDigest: "sha256:" + strings.Repeat("a", 64), PathCount: 1,
			Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified},
		},
		Source: arcadev1alpha1.DataSourceSnapshot{
			GameServer: arcadev1alpha1.ExactGameServerReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "source", UID: "source-uid"}, Generation: 1, DesiredState: arcadev1alpha1.DesiredStateStopped},
			Game:       "factorio", ImageDigest: "sha256:" + strings.Repeat("b", 64), SettingsDigest: "sha256:" + strings.Repeat("c", 64),
			Paths: []arcadev1alpha1.DataPathIdentity{{Name: "state", MountPath: "/factorio", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "source-world", UID: "source-claim-uid"}}},
		},
		TargetGame: "factorio", TargetImageDigest: "sha256:" + strings.Repeat("b", 64), TargetSettingsDigest: "sha256:" + strings.Repeat("c", 64),
		TargetPaths: []restoreworker.PathContract{{Name: "state", MountPath: "/factorio"}},
	}
	if stage == restoreworker.StagePopulate {
		input.PreviousDataIdentity = previousIdentity
		input.PreviousData = []arcadev1alpha1.DataPathIdentity{previousPath}
		input.CandidatePaths = []arcadev1alpha1.DataPathIdentity{candidatePath}
	}
	if err := restoreworker.ValidateInput(input); err != nil {
		t.Fatalf("invalid authorizer fixture: %v", err)
	}
	contents, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(inputPath, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: repository.Name, Namespace: "games", UID: types.UID(repository.UID), ResourceVersion: repository.ResourceVersion}, Immutable: ptr.To(true), Data: map[string][]byte{
		platformdata.RepositoryKeyRepository:      []byte("s3:http://minio.example/arcadectl"),
		platformdata.RepositoryKeyPassword:        []byte("password-canary"),
		platformdata.RepositoryKeyAccessKeyID:     []byte("access-canary"),
		platformdata.RepositoryKeySecretAccessKey: []byte("secret-canary"),
	}}
	previous := &arcadev1alpha1.RetainedDataReference{Identity: previousIdentity, Claims: []arcadev1alpha1.RetainedDataClaimReference{{Path: "state", ClaimRef: previousPath.ClaimRef}}}
	server := &arcadev1alpha1.GameServer{ObjectMeta: metav1.ObjectMeta{Name: "factory", Namespace: "games", UID: types.UID(input.Target.UID), Generation: 2},
		Spec:   arcadev1alpha1.GameServerSpec{DesiredState: arcadev1alpha1.DesiredStateStopped},
		Status: arcadev1alpha1.GameServerStatus{Phase: arcadev1alpha1.PhaseStopped, ObservedGeneration: 2, ActiveData: previous.DeepCopy(), ObservedData: previous.DeepCopy()},
	}
	return authFixture{
		input: input, inputPath: inputPath, candidateIdentity: candidateIdentity, secret: secret,
		candidateLease: fixtureLease(operation, candidateIdentity), previousLease: fixtureLease(operation, previousIdentity),
		previousClaim:  fixtureClaim("previous", previousPath.ClaimRef.UID, "pv-previous", previousIdentity, "state", ""),
		candidateClaim: fixtureClaim(candidateName, candidatePath.ClaimRef.UID, "pv-candidate", candidateIdentity, "state", operation.UID), server: server,
	}
}

func fixtureLease(operation arcadev1alpha1.ExactLocalReference, identity string) *coordinationv1.Lease {
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: platformkube.DataOperationLeaseName(identity), Namespace: "games", Labels: map[string]string{
			platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelRestoreUID: operation.UID,
			platformkube.LabelInstance: "factory", platformkube.LabelDataIdentity: identity,
		}, Annotations: map[string]string{platformkube.AnnotationRestoreName: operation.Name}},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(operation.UID)},
	}
}

func fixtureClaim(name, uid, volume, identity, path, restoreUID string) *corev1.PersistentVolumeClaim {
	labels := map[string]string{
		platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelName: "game-data",
		platformkube.LabelDataPolicy: "retain", platformkube.LabelDataIdentity: identity, platformkube.LabelDataPath: path,
	}
	if restoreUID != "" {
		labels[platformkube.LabelRestoreUID] = restoreUID
	}
	return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games", UID: types.UID(uid), Labels: labels},
		Spec: corev1.PersistentVolumeClaimSpec{VolumeName: volume}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
}

func fakeGameClient(t *testing.T, server *arcadev1alpha1.GameServer) *fake.FakeDynamicClient {
	t.Helper()
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(server)
	if err != nil {
		t.Fatal(err)
	}
	object["apiVersion"] = arcadev1alpha1.GroupVersion.String()
	object["kind"] = "GameServer"
	return fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gameServerResource: "GameServerList"}, &unstructured.Unstructured{Object: object})
}

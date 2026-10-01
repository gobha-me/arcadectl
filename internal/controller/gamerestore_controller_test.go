// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	"github.com/gobha-me/arcadectl/internal/restoreworker"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func restoreTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := arcadev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func restoreTestSelection(identity, claimName, claimUID string) *arcadev1alpha1.RetainedDataReference {
	return &arcadev1alpha1.RetainedDataReference{Identity: identity, Claims: []arcadev1alpha1.RetainedDataClaimReference{{
		Path: "saves", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: claimName, UID: claimUID},
	}}}
}

func TestRestoreActiveDataSwitchIsStatusOnly(t *testing.T) {
	ctx := context.Background()
	scheme := restoreTestScheme(t)
	previous := restoreTestSelection("previous-data", "previous", "previous-uid")
	candidate := restoreTestSelection("candidate-data", "candidate", "candidate-uid")
	server := &arcadev1alpha1.GameServer{
		ObjectMeta: metav1.ObjectMeta{Name: "world", Namespace: "games", UID: types.UID("server-uid"), Generation: 4},
		Spec:       arcadev1alpha1.GameServerSpec{DesiredState: arcadev1alpha1.DesiredStateStopped},
	}
	server.Status.ActiveData = previous
	server.Status.ObservedData = previous.DeepCopy()
	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(server).WithObjects(server).Build()
	r := &GameRestoreReconciler{Client: client, APIReader: client}
	if err := r.updateRestoreActiveData(ctx, server, candidate); err != nil {
		t.Fatal(err)
	}
	got := &arcadev1alpha1.GameServer{}
	if err := client.Get(ctx, types.NamespacedName{Namespace: "games", Name: "world"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.DesiredState != arcadev1alpha1.DesiredStateStopped || got.Generation != 4 ||
		!sameDataSelection(got.Status.ActiveData, candidate) || !sameDataSelection(got.Status.ObservedData, previous) {
		t.Fatal("status-only candidate switch changed runtime intent or falsely advanced observed data")
	}
}

func TestRestorePreviousSettlementBeforeFenceDoesNotMutateOriginalRuntime(t *testing.T) {
	ctx := context.Background()
	scheme := restoreTestScheme(t)
	server := &arcadev1alpha1.GameServer{
		ObjectMeta: metav1.ObjectMeta{Name: "world", Namespace: "games", UID: types.UID("server-uid"), Generation: 8},
		Spec:       arcadev1alpha1.GameServerSpec{DesiredState: arcadev1alpha1.DesiredStateRunning},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(server).Build()
	r := &GameRestoreReconciler{Client: client, APIReader: client}
	restore := &arcadev1alpha1.GameRestore{
		ObjectMeta: metav1.ObjectMeta{Name: "restore", Namespace: "games", UID: types.UID("restore-uid")},
		Spec: arcadev1alpha1.GameRestoreSpec{Target: arcadev1alpha1.ExactGameServerReference{
			ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "world", UID: "server-uid"},
			Generation:          8, DesiredState: arcadev1alpha1.DesiredStateRunning,
		}},
	}
	runtime, pending, err := r.settlePreviousBeforeActivation(ctx, restore)
	if err != nil || pending || runtime != nil {
		t.Fatalf("unfenced unchanged runtime must not be restarted: runtime=%v pending=%v err=%v", runtime, pending, err)
	}
	got := &arcadev1alpha1.GameServer{}
	if err := client.Get(ctx, clientKey(server), got); err != nil {
		t.Fatal(err)
	}
	if got.Generation != 8 || got.Spec.DesiredState != arcadev1alpha1.DesiredStateRunning {
		t.Fatal("preflight cancellation changed the original runtime")
	}
}

func TestRestoreDataClaimVerificationPinsUIDAndIdentity(t *testing.T) {
	ctx := context.Background()
	scheme := restoreTestScheme(t)
	path := arcadev1alpha1.DataPathIdentity{
		Name: "saves", MountPath: "/factorio/saves",
		ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous", UID: "previous-uid"},
	}
	makeClaim := func(uid types.UID, identity string) *corev1.PersistentVolumeClaim {
		return &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "previous", Namespace: "games", UID: uid, Labels: map[string]string{
				platformkube.LabelDataIdentity: identity, platformkube.LabelDataPath: "saves",
			}},
			Spec:   corev1.PersistentVolumeClaimSpec{VolumeName: "previous-pv"},
			Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound},
		}
	}
	for _, test := range []struct {
		name     string
		claim    *corev1.PersistentVolumeClaim
		wantFail bool
	}{
		{name: "exact", claim: makeClaim("previous-uid", "previous-data")},
		{name: "replaced claim", claim: makeClaim("replacement-uid", "previous-data"), wantFail: true},
		{name: "different identity", claim: makeClaim("previous-uid", "other-data"), wantFail: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(test.claim).Build()
			r := &GameRestoreReconciler{Client: fakeClient, APIReader: fakeClient}
			restore := &arcadev1alpha1.GameRestore{ObjectMeta: metav1.ObjectMeta{Namespace: "games"}}
			err := r.verifyRestoreDataClaims(ctx, restore, []arcadev1alpha1.DataPathIdentity{path}, "previous-data")
			if (err != nil) != test.wantFail {
				t.Fatalf("unexpected exact-claim result: %v", err)
			}
		})
	}
}

func TestRestorePopulateRetryIsBounded(t *testing.T) {
	for _, test := range []struct {
		attempts int32
		want     bool
	}{
		{attempts: 0, want: false},
		{attempts: 1, want: true},
		{attempts: 2, want: true},
		{attempts: 3, want: false},
		{attempts: 4, want: false},
	} {
		if got := canRetryRestorePopulate(test.attempts); got != test.want {
			t.Fatalf("attempt %d retry=%v, want %v", test.attempts, got, test.want)
		}
	}
}

func TestRestoreRetryPendingClearsOnEveryRunningExit(t *testing.T) {
	for _, test := range []struct {
		name  string
		phase arcadev1alpha1.DataOperationPhase
		want  bool
	}{
		{name: "still running", phase: arcadev1alpha1.DataPhaseRunning, want: true},
		{name: "cancel request", phase: arcadev1alpha1.DataPhaseCancelling},
		{name: "failed worker", phase: arcadev1alpha1.DataPhaseVerifying},
		{name: "deletion finalizer", phase: arcadev1alpha1.DataPhaseCancelled},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := restoreRetryPendingForPhase(test.phase, true); got != test.want {
				t.Fatalf("retry pending in %s = %v, want %v", test.phase, got, test.want)
			}
		})
	}
}

func TestRestoreWorkerCleanupWaitsForOldPodBeforeRetry(t *testing.T) {
	ctx := context.Background()
	scheme := restoreTestScheme(t)
	if err := batchv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	restore := &arcadev1alpha1.GameRestore{ObjectMeta: metav1.ObjectMeta{Name: "restore", Namespace: "games", UID: types.UID("restore-uid")}}
	name := platformkube.RestoreResourceName(restore.UID, restoreworker.StagePopulate)
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: name, Namespace: "games", UID: types.UID("job-uid"),
		OwnerReferences: []metav1.OwnerReference{{APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameRestore", Name: restore.Name, UID: restore.UID, Controller: boolPointer(true)}},
	}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old-worker", Namespace: "games", UID: types.UID("pod-uid"), Labels: map[string]string{
		platformkube.LabelRestoreUID: string(restore.UID), platformkube.LabelRestoreStage: string(restoreworker.StagePopulate),
	}}}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(job, pod).Build()
	r := &GameRestoreReconciler{Client: fakeClient, APIReader: fakeClient}
	if pending, err := r.deleteRestoreWorkerAndWait(ctx, restore, restoreworker.StagePopulate); err != nil || !pending {
		t.Fatalf("initial Job deletion must remain pending: pending=%v err=%v", pending, err)
	}
	if pending, err := r.deleteRestoreWorkerAndWait(ctx, restore, restoreworker.StagePopulate); err != nil || !pending {
		t.Fatalf("old Pod must block retry after Job deletion: pending=%v err=%v", pending, err)
	}
	if err := fakeClient.Delete(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if pending, err := r.deleteRestoreWorkerAndWait(ctx, restore, restoreworker.StagePopulate); err != nil || pending {
		t.Fatalf("cleanup should finish only after Pod absence: pending=%v err=%v", pending, err)
	}
}

func TestRestoreCompletedJobMissingResultHasBoundedGrace(t *testing.T) {
	now := time.Now().UTC()
	completed := metav1.NewTime(now.Add(-2 * restoreResultGrace))
	job := &batchv1.Job{Status: batchv1.JobStatus{
		CompletionTime: &completed,
		Conditions:     []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: completed}},
	}}
	if !restoreWorkerResultGraceExpired(job, now) {
		t.Fatal("completed Job without a result remained pending after the bounded grace")
	}
	completed = metav1.NewTime(now.Add(-restoreResultGrace / 2))
	job.Status.CompletionTime = &completed
	if restoreWorkerResultGraceExpired(job, now) {
		t.Fatal("newly completed Job lost its result grace period")
	}
	job.Status.Conditions = nil
	if restoreWorkerResultGraceExpired(job, now.Add(2*restoreResultGrace)) {
		t.Fatal("non-complete Job must not be classified as a missing completed result")
	}
}

func TestRestorePopulateJournalRejectsMissingOrReplacedJob(t *testing.T) {
	ctx := context.Background()
	scheme := restoreTestScheme(t)
	if err := batchv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	restore := &arcadev1alpha1.GameRestore{ObjectMeta: metav1.ObjectMeta{Name: "restore", Namespace: "games", UID: types.UID("restore-uid")}}
	restore.Status.PopulateAttempts = 1
	restore.Status.PopulateJobUID = "original-job-uid"
	name := platformkube.RestoreResourceName(restore.UID, restoreworker.StagePopulate)
	for _, test := range []struct {
		name string
		job  *batchv1.Job
	}{
		{name: "missing"},
		{name: "replaced", job: &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games", UID: types.UID("replacement-job-uid")}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if test.job != nil {
				builder = builder.WithObjects(test.job)
			}
			fakeClient := builder.Build()
			r := &GameRestoreReconciler{Client: fakeClient, APIReader: fakeClient}
			outcome, _, err := r.runRestoreWorker(ctx, restore, restoreworker.Input{Stage: restoreworker.StagePopulate}, game.RuntimeIdentity{})
			if err != nil || outcome != restoreWorkerFailed {
				t.Fatalf("journaled Job loss must consume the attempt before recreation: outcome=%v err=%v", outcome, err)
			}
			got := &batchv1.Job{}
			getErr := fakeClient.Get(ctx, types.NamespacedName{Namespace: "games", Name: name}, got)
			if test.job == nil && getErr == nil || test.job != nil && (getErr != nil || got.UID != test.job.UID) {
				t.Fatalf("worker check unexpectedly created or replaced a Job: %v", getErr)
			}
		})
	}
}

func TestRestoreRollbackBeforeCandidateStartJournalsPreviousRestart(t *testing.T) {
	ctx := context.Background()
	scheme := restoreTestScheme(t)
	for _, add := range []func(*runtime.Scheme) error{batchv1.AddToScheme, coordinationv1.AddToScheme, storagev1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	now := metav1.Now()
	const restoreUID = "restore-uid"
	const previousID = "previous-data"
	candidateID, err := platformdata.RestoreDataIdentity(types.UID(restoreUID))
	if err != nil {
		t.Fatal(err)
	}
	candidateName, err := platformdata.RestoreCandidateID(types.UID(restoreUID), "saves")
	if err != nil {
		t.Fatal(err)
	}
	previous := []arcadev1alpha1.DataPathIdentity{{Name: "saves", MountPath: "/factorio/saves", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "previous", UID: "previous-uid"}}}
	candidate := []arcadev1alpha1.DataPathIdentity{{Name: "saves", MountPath: "/factorio/saves", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: candidateName, UID: "candidate-uid"}}}
	backupRef := arcadev1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"}
	repository := arcadev1alpha1.ExactSecretReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"}, ResourceVersion: "123"}
	artifactID, err := platformdata.ArtifactID(types.UID(backupRef.UID))
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	target := arcadev1alpha1.ExactGameServerReference{ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "world", UID: "server-uid"}, Generation: 1, DesiredState: arcadev1alpha1.DesiredStateRunning}
	restore := &arcadev1alpha1.GameRestore{
		ObjectMeta: metav1.ObjectMeta{Name: "restore", Namespace: "games", UID: types.UID(restoreUID), Generation: 1},
		Spec:       arcadev1alpha1.GameRestoreSpec{DataOperationRequest: arcadev1alpha1.DataOperationRequest{RepositorySecretRef: repository, RestartPolicy: arcadev1alpha1.RestartRestorePreviousState}, BackupRef: backupRef, Target: target},
	}
	restore.Status.ObservedGeneration = 1
	restore.Status.Phase = arcadev1alpha1.DataPhaseRollingBack
	restore.Status.Fence = &arcadev1alpha1.ColdDataFence{GameServer: arcadev1alpha1.ExactGameServerReference{ExactLocalReference: target.ExactLocalReference, Generation: 2, DesiredState: arcadev1alpha1.DesiredStateStopped}, EstablishedAt: now}
	restore.Status.Source = &arcadev1alpha1.DataSourceSnapshot{GameServer: target, Game: "factorio", ImageDigest: digest, SettingsDigest: digest, Paths: []arcadev1alpha1.DataPathIdentity{{Name: "saves", MountPath: "/factorio/saves", ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "source", UID: "source-uid"}}}}
	restore.Status.Artifact = &arcadev1alpha1.BackupArtifact{ID: artifactID, FormatVersion: platformdata.BackupFormatVersion, ManifestDigest: digest, PathCount: 1, Provenance: arcadev1alpha1.ArtifactProvenance{BackupRef: backupRef, RepositorySecretRef: repository}, Verification: arcadev1alpha1.ArtifactVerification{Result: arcadev1alpha1.VerificationVerified, VerifiedAt: &now}}
	restore.Status.PreviousDataIdentity = previousID
	restore.Status.PreviousData = previous
	restore.Status.CandidateData = candidate
	restore.Status.CandidateVerification = &arcadev1alpha1.CandidateDataVerification{Result: arcadev1alpha1.VerificationVerified, ManifestDigest: digest, PathCount: 1, VerifiedAt: now}
	restore.Status.ActivationStartedAt = &now
	selected := restoreTestSelection(previousID, "previous", "previous-uid")
	server := &arcadev1alpha1.GameServer{ObjectMeta: metav1.ObjectMeta{Name: "world", Namespace: "games", UID: types.UID("server-uid"), Generation: 2}, Spec: arcadev1alpha1.GameServerSpec{DesiredState: arcadev1alpha1.DesiredStateStopped}}
	server.Status.ActiveData = selected
	server.Status.ObservedData = selected.DeepCopy()
	server.Status.ObservedGeneration = 2
	server.Status.Phase = arcadev1alpha1.PhaseStopped
	claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "previous", Namespace: "games", UID: types.UID("previous-uid"), Labels: map[string]string{platformkube.LabelDataIdentity: previousID, platformkube.LabelDataPath: "saves"}}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "previous-pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
	lease := func(identity string) *coordinationv1.Lease {
		return &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: platformkube.DataOperationLeaseName(identity), Namespace: "games", Labels: map[string]string{platformkube.LabelManagedBy: platformkube.ManagerName, platformkube.LabelRestoreUID: restoreUID, platformkube.LabelInstance: "world", platformkube.LabelDataIdentity: identity}, Annotations: map[string]string{platformkube.AnnotationRestoreName: "restore"}}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To(restoreUID)}}
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(restore, server).WithObjects(restore, server, claim, lease(previousID), lease(candidateID)).Build()
	r := &GameRestoreReconciler{Client: fakeClient, APIReader: fakeClient}
	if _, err := r.reconcileRestoreRollback(ctx, restore); err != nil {
		t.Fatalf("pre-start rollback must journal previous restart without a nil dereference: %v", err)
	}
	got := &arcadev1alpha1.GameRestore{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "games", Name: "restore"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.RuntimeJournal == nil || got.Status.RuntimeJournal.RollbackRestartGeneration != 3 || got.Status.RuntimeJournal.CandidateStartGeneration != 0 {
		t.Fatalf("previous restart intent was not journaled at F+1: %#v", got.Status.RuntimeJournal)
	}
}

func clientKey(object client.Object) types.NamespacedName {
	return types.NamespacedName{Namespace: object.GetNamespace(), Name: object.GetName()}
}

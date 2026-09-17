//go:build envtest

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformdata "github.com/gobha-me/arcadectl/internal/platform/data"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func testOperationAPI(t *testing.T, ctx context.Context, configuration *rest.Config, kubeClient client.Client) {
	t.Helper()

	backup := operationTestBackup("backup-valid")
	if err := kubeClient.Create(ctx, backup); err != nil {
		t.Fatalf("create valid GameBackup: %v", err)
	}

	missingUID := operationTestBackup("backup-missing-uid")
	missingUID.Spec.Source.UID = ""
	if err := kubeClient.Create(ctx, missingUID); err == nil || !apierrors.IsInvalid(err) {
		t.Fatalf("missing source UID error = %v, want invalid", err)
	}
	missingGeneration := operationTestBackup("backup-missing-generation")
	missingGeneration.Spec.Source.Generation = 0
	if err := kubeClient.Create(ctx, missingGeneration); err == nil || !apierrors.IsInvalid(err) {
		t.Fatalf("missing source generation error = %v, want invalid", err)
	}

	stored := &arcadev1alpha1.GameBackup{}
	key := client.ObjectKeyFromObject(backup)
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatalf("get GameBackup: %v", err)
	}
	stored.Spec.Source.Generation++
	if err := kubeClient.Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "source is immutable") {
		t.Fatalf("mutable source error = %v, want admission rejection", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatalf("refresh GameBackup for repository mutation: %v", err)
	}
	stored.Spec.RepositorySecretRef.ResourceVersion = "43"
	if err := kubeClient.Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "repositorySecretRef is immutable") {
		t.Fatalf("mutable repository Secret error = %v, want admission rejection", err)
	}

	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatalf("refresh GameBackup: %v", err)
	}
	stored.Spec.CancelRequested = true
	if err := kubeClient.Update(ctx, stored); err != nil {
		t.Fatalf("request GameBackup cancellation: %v", err)
	}
	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatalf("refresh cancelled GameBackup: %v", err)
	}
	stored.Spec.CancelRequested = false
	if err := kubeClient.Update(ctx, stored); err == nil || !strings.Contains(err.Error(), "cancelRequested cannot be cleared") {
		t.Fatalf("cleared cancellation error = %v, want admission rejection", err)
	}

	if err := kubeClient.Get(ctx, key, stored); err != nil {
		t.Fatalf("refresh GameBackup for status: %v", err)
	}
	stored.Status.Phase = arcadev1alpha1.DataPhasePending
	stored.Status.ObservedGeneration = stored.Generation
	stored.Status.Source = operationTestSourceSnapshot(stored.Spec.Source)
	if err := kubeClient.Status().Update(ctx, stored); err != nil {
		t.Fatalf("update GameBackup status subresource: %v", err)
	}
	observed := &arcadev1alpha1.GameBackup{}
	if err := kubeClient.Get(ctx, key, observed); err != nil {
		t.Fatalf("get status-updated GameBackup: %v", err)
	}
	if observed.Status.Phase != arcadev1alpha1.DataPhasePending || !observed.Spec.CancelRequested {
		t.Fatalf("status update result = spec %#v status %#v", observed.Spec, observed.Status)
	}
	mutatedSource := observed.DeepCopy()
	mutatedSource.Status.Source.Paths[0].ClaimRef.UID = "replacement-claim"
	if err := kubeClient.Status().Update(ctx, mutatedSource); err == nil || !strings.Contains(err.Error(), "source data paths are immutable") {
		t.Fatalf("mutable resolved source error = %v, want admission rejection", err)
	}
	removedSource := observed.DeepCopy()
	removedSource.Status.Source = nil
	if err := kubeClient.Status().Update(ctx, removedSource); err == nil || !strings.Contains(err.Error(), "resolved source status cannot be removed") {
		t.Fatalf("removed resolved source error = %v, want admission rejection", err)
	}
	observed.Status.Artifact = operationTestArtifact(
		1,
		arcadev1alpha1.ExactLocalReference{Name: observed.Name, UID: string(observed.UID)},
		observed.Spec.RepositorySecretRef,
	)
	wrongBackupProvenance := observed.Status.Artifact.Provenance.BackupRef
	observed.Status.Artifact.Provenance.BackupRef.Name = "other-backup"
	if err := kubeClient.Status().Update(ctx, observed); err == nil || !strings.Contains(err.Error(), "artifact provenance") {
		t.Fatalf("wrong backup provenance error = %v, want admission rejection", err)
	}
	observed.Status.Artifact.Provenance.BackupRef = wrongBackupProvenance
	if err := kubeClient.Status().Update(ctx, observed); err != nil {
		t.Fatalf("record immutable verified artifact: %v", err)
	}
	if err := kubeClient.Get(ctx, key, observed); err != nil {
		t.Fatalf("refresh artifact GameBackup: %v", err)
	}
	mutatedArtifact := observed.DeepCopy()
	mutatedArtifact.Status.Artifact.ID = "replacement-artifact"
	if err := kubeClient.Status().Update(ctx, mutatedArtifact); err == nil || !strings.Contains(err.Error(), "artifact ID is immutable") {
		t.Fatalf("mutable artifact error = %v, want admission rejection", err)
	}
	invalidFailure := observed.DeepCopy()
	invalidFailure.Status.Phase = arcadev1alpha1.DataPhaseFailed
	invalidFailure.Status.Conditions = nil
	if err := kubeClient.Status().Update(ctx, invalidFailure); err == nil || !strings.Contains(err.Error(), "actionable") {
		t.Fatalf("conditionless failed status error = %v, want admission rejection", err)
	}

	restore := operationTestRestore("restore-valid", string(observed.UID))
	if err := kubeClient.Create(ctx, restore); err != nil {
		t.Fatalf("create valid GameRestore: %v", err)
	}
	restored := &arcadev1alpha1.GameRestore{}
	restoreKey := client.ObjectKeyFromObject(restore)
	if err := kubeClient.Get(ctx, restoreKey, restored); err != nil {
		t.Fatalf("get GameRestore: %v", err)
	}
	restored.Spec.Target.Generation++
	if err := kubeClient.Update(ctx, restored); err == nil || !strings.Contains(err.Error(), "target is immutable") {
		t.Fatalf("mutable restore target error = %v, want admission rejection", err)
	}
	if err := kubeClient.Get(ctx, restoreKey, restored); err != nil {
		t.Fatalf("refresh GameRestore for backup mutation: %v", err)
	}
	restored.Spec.BackupRef.UID = "replacement-backup"
	if err := kubeClient.Update(ctx, restored); err == nil || !strings.Contains(err.Error(), "backupRef is immutable") {
		t.Fatalf("mutable backup reference error = %v, want admission rejection", err)
	}
	if err := kubeClient.Get(ctx, restoreKey, restored); err != nil {
		t.Fatalf("refresh GameRestore for status: %v", err)
	}
	restored.Status.ObservedGeneration = restored.Generation
	restored.Status.Phase = arcadev1alpha1.DataPhaseActivating
	now := metav1.Now()
	restored.Status.ActivationStartedAt = &now
	restored.Status.Source = operationTestTwoPathSource()
	restored.Status.Fence = operationTestFence(restored.Spec.Target, 2)
	restored.Status.Artifact = operationTestArtifact(2, restored.Spec.BackupRef, restored.Spec.RepositorySecretRef)
	restored.Status.CandidateVerification = &arcadev1alpha1.CandidateDataVerification{
		Result: arcadev1alpha1.VerificationVerified, ManifestDigest: restored.Status.Artifact.ManifestDigest, PathCount: 2, VerifiedAt: now,
	}
	worldCandidate, err := platformdata.RestoreCandidateID(restored.UID, "world")
	if err != nil {
		t.Fatalf("derive world candidate identity: %v", err)
	}
	modsCandidate, err := platformdata.RestoreCandidateID(restored.UID, "mods")
	if err != nil {
		t.Fatalf("derive mods candidate identity: %v", err)
	}
	restored.Status.CandidateData = []arcadev1alpha1.DataPathIdentity{operationTestPath("world", "/factorio", worldCandidate, "candidate-world-uid")}
	restored.Status.PreviousData = []arcadev1alpha1.DataPathIdentity{
		operationTestPath("world", "/factorio", "previous-world", "previous-world-uid"),
		operationTestPath("mods", "/factorio/mods", "previous-mods", "previous-mods-uid"),
	}
	if err := kubeClient.Status().Update(ctx, restored); err == nil || !strings.Contains(err.Error(), "complete candidate data") {
		t.Fatalf("partial candidate status error = %v, want admission rejection", err)
	}
	restored.Status.CandidateData = append(restored.Status.CandidateData, operationTestPath("mods", "/factorio/mods", modsCandidate, "candidate-mods-uid"))
	verification := restored.Status.CandidateVerification
	restored.Status.CandidateVerification = nil
	if err := kubeClient.Status().Update(ctx, restored); err == nil || !strings.Contains(err.Error(), "candidate contents") {
		t.Fatalf("unverified candidate status error = %v, want admission rejection", err)
	}
	restored.Status.CandidateVerification = verification
	previousData := restored.Status.PreviousData
	restored.Status.PreviousData = nil
	if err := kubeClient.Status().Update(ctx, restored); err == nil || !strings.Contains(err.Error(), "rollback data") {
		t.Fatalf("missing rollback status error = %v, want admission rejection", err)
	}
	restored.Status.PreviousData = previousData
	crossPathPrevious := restored.Status.PreviousData[1].ClaimRef
	restored.Status.PreviousData[1].ClaimRef = restored.Status.CandidateData[0].ClaimRef
	if err := kubeClient.Status().Update(ctx, restored); err == nil || !strings.Contains(err.Error(), "globally distinct rollback data") {
		t.Fatalf("cross-path rollback alias error = %v, want admission rejection", err)
	}
	restored.Status.PreviousData[1].ClaimRef = crossPathPrevious
	wrongProvenance := restored.Status.Artifact.Provenance
	restored.Status.Artifact.Provenance.BackupRef.UID = "other-backup"
	if err := kubeClient.Status().Update(ctx, restored); err == nil || !strings.Contains(err.Error(), "provenance") {
		t.Fatalf("wrong restore provenance error = %v, want admission rejection", err)
	}
	restored.Status.Artifact.Provenance = wrongProvenance
	if err := kubeClient.Status().Update(ctx, restored); err != nil {
		t.Fatalf("record complete restore candidates: %v", err)
	}
	if err := kubeClient.Get(ctx, restoreKey, restored); err != nil {
		t.Fatalf("refresh candidate GameRestore: %v", err)
	}
	mutatedCandidate := restored.DeepCopy()
	mutatedCandidate.Status.CandidateData[0].ClaimRef.UID = "replacement-candidate"
	if err := kubeClient.Status().Update(ctx, mutatedCandidate); err == nil || !strings.Contains(err.Error(), "candidate data is immutable") {
		t.Fatalf("mutable candidate data error = %v, want admission rejection", err)
	}
	unsafeActivation := restored.DeepCopy()
	unsafeActivation.Status.Phase = arcadev1alpha1.DataPhaseSucceeded
	completedAt := metav1.Now()
	unsafeActivation.Status.CompletedAt = &completedAt
	unsafeActivation.Status.Runtime = operationTestRuntime(unsafeActivation.Spec.Target, 2)
	unsafeActivation.Status.ActiveData = append([]arcadev1alpha1.DataPathIdentity(nil), unsafeActivation.Status.CandidateData...)
	unsafeActivation.Status.ActiveData[0].ClaimRef.UID = "unverified-active-claim"
	if err := kubeClient.Status().Update(ctx, unsafeActivation); err == nil || !strings.Contains(err.Error(), "active data to equal verified candidates") {
		t.Fatalf("unsafe active data error = %v, want admission rejection", err)
	}
	if err := kubeClient.Get(ctx, restoreKey, restored); err != nil {
		t.Fatalf("refresh GameRestore for rollback proof: %v", err)
	}
	restored.Spec.CancelRequested = true
	if err := kubeClient.Update(ctx, restored); err != nil {
		t.Fatalf("request GameRestore cancellation: %v", err)
	}
	if err := kubeClient.Get(ctx, restoreKey, restored); err != nil {
		t.Fatalf("refresh cancelled GameRestore: %v", err)
	}
	unsafeRollback := restored.DeepCopy()
	unsafeRollback.Status.ObservedGeneration = unsafeRollback.Generation
	unsafeRollback.Status.Phase = arcadev1alpha1.DataPhaseCancelled
	unsafeRollback.Status.Runtime = operationTestRuntime(unsafeRollback.Spec.Target, 2)
	unsafeRollback.Status.ActiveData = append([]arcadev1alpha1.DataPathIdentity(nil), unsafeRollback.Status.CandidateData...)
	if err := kubeClient.Status().Update(ctx, unsafeRollback); err == nil || !strings.Contains(err.Error(), "active data to equal rollback data") {
		t.Fatalf("unverified terminal rollback error = %v, want admission rejection", err)
	}
	verifiedRollback := restored.DeepCopy()
	verifiedRollback.Status.ObservedGeneration = verifiedRollback.Generation
	verifiedRollback.Status.Phase = arcadev1alpha1.DataPhaseCancelled
	verifiedRollback.Status.Runtime = operationTestRuntime(verifiedRollback.Spec.Target, 2)
	verifiedRollback.Status.ActiveData = append([]arcadev1alpha1.DataPathIdentity(nil), verifiedRollback.Status.PreviousData...)
	if err := kubeClient.Status().Update(ctx, verifiedRollback); err != nil {
		t.Fatalf("record verified terminal rollback: %v", err)
	}

	terminalBackup := operationTestBackup("backup-terminal")
	if err := kubeClient.Create(ctx, terminalBackup); err != nil {
		t.Fatalf("create terminal-phase GameBackup: %v", err)
	}
	terminalBackup.Status.ObservedGeneration = terminalBackup.Generation
	terminalBackup.Status.Phase = arcadev1alpha1.DataPhaseFailed
	terminalBackup.Status.Conditions = []metav1.Condition{{
		Type: arcadev1alpha1.ConditionOperationComplete, Status: metav1.ConditionFalse,
		ObservedGeneration: terminalBackup.Generation, Reason: arcadev1alpha1.ReasonInvalidReference,
		Message: "create a new operation with the current exact GameServer identity", LastTransitionTime: metav1.Now(),
	}}
	if err := kubeClient.Status().Update(ctx, terminalBackup); err != nil {
		t.Fatalf("record terminal failed GameBackup: %v", err)
	}
	if err := kubeClient.Get(ctx, client.ObjectKeyFromObject(terminalBackup), terminalBackup); err != nil {
		t.Fatalf("refresh terminal GameBackup: %v", err)
	}
	terminalBackup.Status.Phase = arcadev1alpha1.DataPhasePending
	if err := kubeClient.Status().Update(ctx, terminalBackup); err == nil || !strings.Contains(err.Error(), "terminal operation phase cannot change") {
		t.Fatalf("terminal phase regression error = %v, want admission rejection", err)
	}

	incompleteBackup := operationTestBackup("backup-incomplete-success")
	if err := kubeClient.Create(ctx, incompleteBackup); err != nil {
		t.Fatalf("create incomplete-success GameBackup: %v", err)
	}
	incompleteBackup.Status.ObservedGeneration = incompleteBackup.Generation
	incompleteBackup.Status.Phase = arcadev1alpha1.DataPhaseSucceeded
	incompleteBackup.Status.Source = operationTestSourceSnapshot(incompleteBackup.Spec.Source)
	incompleteBackup.Status.Fence = operationTestFence(incompleteBackup.Spec.Source, 2)
	incompleteBackup.Status.Artifact = operationTestArtifact(
		2,
		arcadev1alpha1.ExactLocalReference{Name: incompleteBackup.Name, UID: string(incompleteBackup.UID)},
		incompleteBackup.Spec.RepositorySecretRef,
	)
	incompleteBackup.Status.Runtime = operationTestRuntime(incompleteBackup.Spec.Source, 2)
	incompleteBackup.Status.CompletedAt = &completedAt
	if err := kubeClient.Status().Update(ctx, incompleteBackup); err == nil || !strings.Contains(err.Error(), "verified complete artifact") {
		t.Fatalf("incomplete backup success error = %v, want admission rejection", err)
	}

	skippedFence := operationTestBackup("backup-skipped-fence-generation")
	if err := kubeClient.Create(ctx, skippedFence); err != nil {
		t.Fatalf("create skipped-fence GameBackup: %v", err)
	}
	skippedFence.Status.ObservedGeneration = skippedFence.Generation
	skippedFence.Status.Phase = arcadev1alpha1.DataPhasePending
	skippedFence.Status.Fence = operationTestFence(skippedFence.Spec.Source, 3)
	if err := kubeClient.Status().Update(ctx, skippedFence); err == nil || !strings.Contains(err.Error(), "exact operation-owned stopped generation") {
		t.Fatalf("skipped fence generation error = %v, want admission rejection", err)
	}
	dynamicClient, err := dynamic.NewForConfig(configuration)
	if err != nil {
		t.Fatalf("create dynamic envtest client: %v", err)
	}
	unknownCredentials := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": arcadev1alpha1.GroupVersion.String(),
		"kind":       "GameBackup",
		"metadata": map[string]any{
			"name":      "backup-inline-credentials",
			"namespace": "games",
		},
		"spec": map[string]any{
			"source": map[string]any{
				"name": "factory", "uid": "server-uid", "generation": int64(1), "desiredState": "Running",
			},
			"repositorySecretRef": map[string]any{
				"name": "repository", "uid": "secret-uid", "resourceVersion": "42",
			},
			"restartPolicy":     "LeaveStopped",
			"retentionPolicy":   "Retain",
			"cancelRequested":   false,
			"inlineCredentials": map[string]any{"password": "must-not-enter-the-api"},
		},
	}}
	resource := dynamicClient.Resource(schema.GroupVersionResource{
		Group: arcadev1alpha1.GroupVersion.Group, Version: arcadev1alpha1.GroupVersion.Version, Resource: "gamebackups",
	}).Namespace("games")
	crossNamespace := unknownCredentials.DeepCopy()
	crossNamespace.SetName("backup-cross-namespace")
	delete(crossNamespace.Object["spec"].(map[string]any), "inlineCredentials")
	crossNamespace.Object["spec"].(map[string]any)["source"].(map[string]any)["namespace"] = "other"
	if _, err := resource.Create(ctx, crossNamespace, metav1.CreateOptions{}); err == nil || !strings.Contains(err.Error(), "references are local") {
		t.Fatalf("cross-namespace source error = %v, want ordinary admission rejection", err)
	}
	if _, err := resource.Create(ctx, unknownCredentials, metav1.CreateOptions{}); err == nil || !strings.Contains(err.Error(), "inline credentials are forbidden") {
		t.Fatalf("inline credentials error = %v, want ordinary admission rejection", err)
	}
}

func operationTestBackup(name string) *arcadev1alpha1.GameBackup {
	return &arcadev1alpha1.GameBackup{
		TypeMeta:   metav1.TypeMeta{APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameBackup"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games"},
		Spec: arcadev1alpha1.GameBackupSpec{
			DataOperationRequest: arcadev1alpha1.DataOperationRequest{
				RepositorySecretRef: arcadev1alpha1.ExactSecretReference{
					ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"},
					ResourceVersion:     "42",
				},
				RestartPolicy: arcadev1alpha1.RestartLeaveStopped,
			},
			Source: arcadev1alpha1.ExactGameServerReference{
				ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"},
				Generation:          1,
				DesiredState:        arcadev1alpha1.DesiredStateRunning,
			},
			RetentionPolicy: arcadev1alpha1.ArtifactRetentionRetain,
		},
	}
}

func operationTestRestore(name, backupUID string) *arcadev1alpha1.GameRestore {
	return &arcadev1alpha1.GameRestore{
		TypeMeta:   metav1.TypeMeta{APIVersion: arcadev1alpha1.GroupVersion.String(), Kind: "GameRestore"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "games"},
		Spec: arcadev1alpha1.GameRestoreSpec{
			DataOperationRequest: arcadev1alpha1.DataOperationRequest{
				RepositorySecretRef: arcadev1alpha1.ExactSecretReference{
					ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "secret-uid"},
					ResourceVersion:     "42",
				},
				RestartPolicy: arcadev1alpha1.RestartLeaveStopped,
			},
			BackupRef: arcadev1alpha1.ExactLocalReference{Name: "backup-valid", UID: backupUID},
			Target: arcadev1alpha1.ExactGameServerReference{
				ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"},
				Generation:          1,
				DesiredState:        arcadev1alpha1.DesiredStateRunning,
			},
		},
	}
}

func operationTestSourceSnapshot(reference arcadev1alpha1.ExactGameServerReference) *arcadev1alpha1.DataSourceSnapshot {
	return &arcadev1alpha1.DataSourceSnapshot{
		GameServer:     reference,
		Game:           "factorio",
		ImageDigest:    "sha256:" + strings.Repeat("1", 64),
		SettingsDigest: "sha256:" + strings.Repeat("2", 64),
		Paths: []arcadev1alpha1.DataPathIdentity{{
			Name: "world", MountPath: "/factorio",
			ClaimRef: arcadev1alpha1.ExactLocalReference{Name: "factory-factorio-world", UID: "claim-uid"},
		}},
	}
}

func operationTestTwoPathSource() *arcadev1alpha1.DataSourceSnapshot {
	reference := arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "source-factory", UID: "source-server-uid"},
		Generation:          7,
		DesiredState:        arcadev1alpha1.DesiredStateStopped,
	}
	source := operationTestSourceSnapshot(reference)
	source.Paths = append(source.Paths, operationTestPath("mods", "/factorio/mods", "source-mods", "source-mods-uid"))
	return source
}

func operationTestArtifact(pathCount int32, backup arcadev1alpha1.ExactLocalReference, repository arcadev1alpha1.ExactSecretReference) *arcadev1alpha1.BackupArtifact {
	now := metav1.Now()
	artifactID, err := platformdata.ArtifactID(types.UID(backup.UID))
	if err != nil {
		panic(err)
	}
	return &arcadev1alpha1.BackupArtifact{
		Provenance:     arcadev1alpha1.ArtifactProvenance{BackupRef: backup, RepositorySecretRef: repository},
		ID:             artifactID,
		FormatVersion:  "1",
		ManifestDigest: "sha256:" + strings.Repeat("3", 64),
		SizeBytes:      42,
		PathCount:      pathCount,
		CreatedAt:      now,
		Verification: arcadev1alpha1.ArtifactVerification{
			Result: arcadev1alpha1.VerificationVerified, VerifiedAt: &now,
		},
	}
}

func operationTestFence(reference arcadev1alpha1.ExactGameServerReference, generation int64) *arcadev1alpha1.ColdDataFence {
	reference.Generation = generation
	reference.DesiredState = arcadev1alpha1.DesiredStateStopped
	return &arcadev1alpha1.ColdDataFence{GameServer: reference, EstablishedAt: metav1.Now()}
}

func operationTestRuntime(reference arcadev1alpha1.ExactGameServerReference, generation int64) *arcadev1alpha1.RuntimeDisposition {
	reference.Generation = generation
	reference.DesiredState = arcadev1alpha1.DesiredStateStopped
	return &arcadev1alpha1.RuntimeDisposition{GameServer: reference, Phase: arcadev1alpha1.PhaseStopped, CompletedAt: metav1.Now()}
}

func operationTestPath(name, mount, claim, uid string) arcadev1alpha1.DataPathIdentity {
	return arcadev1alpha1.DataPathIdentity{
		Name: name, MountPath: mount,
		ClaimRef: arcadev1alpha1.ExactLocalReference{Name: claim, UID: uid},
	}
}

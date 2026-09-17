// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package data

import (
	"strings"
	"testing"
	"time"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestDeterministicOperationIdentities(t *testing.T) {
	t.Parallel()

	const uid types.UID = "a6f503fa-346b-4fce-8fd6-83848e75df94"
	first, err := ArtifactID(uid)
	if err != nil {
		t.Fatalf("ArtifactID() error = %v", err)
	}
	second, err := ArtifactID(uid)
	if err != nil {
		t.Fatalf("ArtifactID() repeat error = %v", err)
	}
	if first != second || first == "" {
		t.Fatalf("artifact IDs = %q and %q, want identical non-empty values", first, second)
	}

	world, err := RestoreCandidateID(uid, "world")
	if err != nil {
		t.Fatalf("RestoreCandidateID() error = %v", err)
	}
	worldAgain, _ := RestoreCandidateID(uid, "world")
	other, _ := RestoreCandidateID(uid, "mods")
	if world != worldAgain || world == other {
		t.Fatalf("candidate IDs world=%q repeat=%q other=%q", world, worldAgain, other)
	}
}

func TestDeterministicOperationIdentitiesRejectAmbiguity(t *testing.T) {
	t.Parallel()

	if _, err := ArtifactID(""); err == nil {
		t.Fatal("ArtifactID accepted an empty operation UID")
	}
	if _, err := RestoreCandidateID("uid", ""); err == nil {
		t.Fatal("RestoreCandidateID accepted an empty path name")
	}
}

func TestOperationPhaseSafety(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		kind     OperationKind
		from     arcadev1alpha1.DataOperationPhase
		to       arcadev1alpha1.DataOperationPhase
		verified bool
		wantErr  bool
	}{
		{name: "initialize", kind: BackupOperation, to: arcadev1alpha1.DataPhasePending},
		{name: "retry is idempotent", kind: BackupOperation, from: arcadev1alpha1.DataPhaseRunning, to: arcadev1alpha1.DataPhaseRunning},
		{name: "backup verified success", kind: BackupOperation, from: arcadev1alpha1.DataPhaseVerifying, to: arcadev1alpha1.DataPhaseSucceeded, verified: true},
		{name: "backup unverified success", kind: BackupOperation, from: arcadev1alpha1.DataPhaseVerifying, to: arcadev1alpha1.DataPhaseSucceeded, wantErr: true},
		{name: "restore verified activation", kind: RestoreOperation, from: arcadev1alpha1.DataPhaseVerifying, to: arcadev1alpha1.DataPhaseActivating, verified: true},
		{name: "restore unverified activation", kind: RestoreOperation, from: arcadev1alpha1.DataPhaseVerifying, to: arcadev1alpha1.DataPhaseActivating, wantErr: true},
		{name: "restore rolls back", kind: RestoreOperation, from: arcadev1alpha1.DataPhaseActivating, to: arcadev1alpha1.DataPhaseRollingBack, verified: true},
		{name: "restore activation cannot fail before rollback", kind: RestoreOperation, from: arcadev1alpha1.DataPhaseActivating, to: arcadev1alpha1.DataPhaseFailed, verified: true, wantErr: true},
		{name: "restore activation cannot cancel before rollback", kind: RestoreOperation, from: arcadev1alpha1.DataPhaseActivating, to: arcadev1alpha1.DataPhaseCancelling, verified: true, wantErr: true},
		{name: "restore rollback cannot finish cancellation unverified", kind: RestoreOperation, from: arcadev1alpha1.DataPhaseRollingBack, to: arcadev1alpha1.DataPhaseCancelled, wantErr: true},
		{name: "restore rollback can finish cancellation verified", kind: RestoreOperation, from: arcadev1alpha1.DataPhaseRollingBack, to: arcadev1alpha1.DataPhaseCancelled, verified: true},
		{name: "restore rollback can finish failure verified", kind: RestoreOperation, from: arcadev1alpha1.DataPhaseRollingBack, to: arcadev1alpha1.DataPhaseFailed, verified: true},
		{name: "terminal does not regress", kind: BackupOperation, from: arcadev1alpha1.DataPhaseSucceeded, to: arcadev1alpha1.DataPhaseRunning, verified: true, wantErr: true},
		{name: "cancel finishes", kind: BackupOperation, from: arcadev1alpha1.DataPhaseCancelling, to: arcadev1alpha1.DataPhaseCancelled},
		{name: "cannot skip work", kind: BackupOperation, from: arcadev1alpha1.DataPhasePreparing, to: arcadev1alpha1.DataPhaseVerifying, wantErr: true},
		{name: "unknown phase", kind: BackupOperation, from: "Surprised", to: arcadev1alpha1.DataPhaseFailed, wantErr: true},
		{name: "succeeded self transition still verified", kind: BackupOperation, from: arcadev1alpha1.DataPhaseSucceeded, to: arcadev1alpha1.DataPhaseSucceeded, wantErr: true},
		{name: "backup cannot activate", kind: BackupOperation, from: arcadev1alpha1.DataPhaseVerifying, to: arcadev1alpha1.DataPhaseActivating, verified: true, wantErr: true},
		{name: "backup cannot retain impossible restore phase", kind: BackupOperation, from: arcadev1alpha1.DataPhaseRollingBack, to: arcadev1alpha1.DataPhaseRollingBack, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTransition(test.kind, test.from, test.to, test.verified)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateTransition(%q, %q, verified=%t) error = %v, wantErr %t", test.from, test.to, test.verified, err, test.wantErr)
			}
		})
	}
}

func TestBackupStatusSafety(t *testing.T) {
	t.Parallel()

	backup := validBackupStatus()
	if err := ValidateBackupStatus(backup); err != nil {
		t.Fatalf("valid backup status rejected: %v", err)
	}

	wrongPathCount := backup.DeepCopy()
	wrongPathCount.Status.Artifact.PathCount = 1
	if err := ValidateBackupStatus(wrongPathCount); err == nil {
		t.Fatal("backup accepted artifact that omitted a source path")
	}

	wrongSource := backup.DeepCopy()
	wrongSource.Status.Source.GameServer.UID = "replacement-server"
	if err := ValidateBackupStatus(wrongSource); err == nil {
		t.Fatal("backup accepted a source snapshot for another GameServer")
	}

	wrongProvenance := backup.DeepCopy()
	wrongProvenance.Status.Artifact.Provenance.BackupRef.UID = "other-backup"
	if err := ValidateBackupStatus(wrongProvenance); err == nil {
		t.Fatal("backup accepted artifact provenance from another operation UID")
	}

	stale := backup.DeepCopy()
	stale.Generation++
	if err := ValidateBackupStatus(stale); err == nil {
		t.Fatal("backup accepted stale status after a new operation generation")
	}
	cancelled := backup.DeepCopy()
	cancelled.Spec.CancelRequested = true
	cancelled.Generation++
	cancelled.Status.ObservedGeneration = cancelled.Generation
	if err := ValidateBackupStatus(cancelled); err == nil {
		t.Fatal("backup advanced to success after cancellation was requested")
	}

	skippedFence := backup.DeepCopy()
	skippedFence.Status.Fence.GameServer.Generation++
	if err := ValidateBackupStatus(skippedFence); err == nil {
		t.Fatal("backup accepted a fence after an intervening GameServer generation")
	}
	skippedRuntime := backup.DeepCopy()
	skippedRuntime.Status.Runtime.GameServer.Generation++
	if err := ValidateBackupStatus(skippedRuntime); err == nil {
		t.Fatal("backup accepted a runtime disposition after an intervening GameServer generation")
	}
	missingStopGeneration := backup.DeepCopy()
	missingStopGeneration.Status.Fence.GameServer.Generation = 1
	if err := ValidateBackupStatus(missingStopGeneration); err == nil {
		t.Fatal("backup accepted the original running generation as a stopped fence")
	}

	blocked := validBackupStatus()
	blocked.Status = arcadev1alpha1.GameBackupStatus{DataOperationStatus: arcadev1alpha1.DataOperationStatus{
		ObservedGeneration: 1,
		Phase:              arcadev1alpha1.DataPhaseBlocked,
	}}
	if err := ValidateBackupStatus(blocked); err == nil {
		t.Fatal("blocked backup without an actionable condition was accepted")
	}
	blocked.Status.Conditions = []metav1.Condition{{
		Type:               arcadev1alpha1.ConditionSourceReady,
		Status:             metav1.ConditionFalse,
		ObservedGeneration: 1,
		Reason:             arcadev1alpha1.ReasonSecretUnavailable,
		Message:            "restore the immutable repository Secret and create a new operation",
	}}
	if err := ValidateBackupStatus(blocked); err != nil {
		t.Fatalf("actionable blocked backup rejected: %v", err)
	}

	restart := validBackupStatus()
	restart.Spec.RestartPolicy = arcadev1alpha1.RestartRestorePreviousState
	if err := ValidateBackupStatus(restart); err == nil {
		t.Fatal("backup accepted stopped disposition for previously running restart policy")
	}
	restart.Status.Runtime = &arcadev1alpha1.RuntimeDisposition{
		GameServer: arcadev1alpha1.ExactGameServerReference{
			ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"},
			Generation:          3,
			DesiredState:        arcadev1alpha1.DesiredStateRunning,
		},
		Phase:       arcadev1alpha1.PhaseReady,
		CompletedAt: testTime(),
	}
	if err := ValidateBackupStatus(restart); err != nil {
		t.Fatalf("crash-safe previous runtime disposition rejected: %v", err)
	}
	restartSkipped := restart.DeepCopy()
	restartSkipped.Status.Runtime.GameServer.Generation++
	if err := ValidateBackupStatus(restartSkipped); err == nil {
		t.Fatal("backup accepted a restarted disposition after an intervening GameServer generation")
	}
	alreadyStopped := validBackupStatus()
	alreadyStopped.Spec.Source.DesiredState = arcadev1alpha1.DesiredStateStopped
	alreadyStopped.Status.Source.GameServer.DesiredState = arcadev1alpha1.DesiredStateStopped
	alreadyStopped.Status.Fence.GameServer.Generation = 1
	alreadyStopped.Status.Runtime.GameServer.Generation = 1
	if err := ValidateBackupStatus(alreadyStopped); err != nil {
		t.Fatalf("already-stopped exact generation rejected: %v", err)
	}
	alreadyStoppedSkipped := alreadyStopped.DeepCopy()
	alreadyStoppedSkipped.Status.Fence.GameServer.Generation++
	if err := ValidateBackupStatus(alreadyStoppedSkipped); err == nil {
		t.Fatal("already-stopped backup accepted an operation-owned stop generation")
	}
}

func TestRestoreStatusRequiresCompleteAtomicData(t *testing.T) {
	t.Parallel()

	restore := validRestoreStatus()
	if err := ValidateRestoreStatus(restore); err != nil {
		t.Fatalf("valid restore status rejected: %v", err)
	}

	partial := restore.DeepCopy()
	partial.Status.CandidateData = partial.Status.CandidateData[:1]
	if err := ValidateRestoreStatus(partial); err == nil {
		t.Fatal("restore accepted a partial candidate path set")
	}

	unverifiedCandidate := restore.DeepCopy()
	unverifiedCandidate.Status.CandidateVerification = nil
	if err := ValidateRestoreStatus(unverifiedCandidate); err == nil {
		t.Fatal("restore accepted candidate claims without content verification")
	}

	duplicateCandidate := restore.DeepCopy()
	duplicateCandidate.Status.CandidateData[0].ClaimRef.Name = "another-candidate"
	duplicateCandidate.Status.ActiveData[0].ClaimRef.Name = "another-candidate"
	if err := ValidateRestoreStatus(duplicateCandidate); err == nil {
		t.Fatal("restore accepted a non-deterministic retry candidate identity")
	}

	wrongProvenance := restore.DeepCopy()
	wrongProvenance.Status.Artifact.Provenance.BackupRef.UID = "other-backup"
	if err := ValidateRestoreStatus(wrongProvenance); err == nil {
		t.Fatal("restore accepted artifact provenance from another backup")
	}

	redirected := restore.DeepCopy()
	redirected.Status.ActiveData[0].ClaimRef.UID = "unverified-claim"
	if err := ValidateRestoreStatus(redirected); err == nil {
		t.Fatal("restore accepted active data that was not the verified candidate")
	}

	noRollback := restore.DeepCopy()
	noRollback.Status.PreviousData[0].ClaimRef.UID = noRollback.Status.ActiveData[0].ClaimRef.UID
	if err := ValidateRestoreStatus(noRollback); err == nil {
		t.Fatal("restore accepted rollback data that aliases active data")
	}

	crossPathAlias := restore.DeepCopy()
	crossPathAlias.Status.PreviousData[1].ClaimRef = crossPathAlias.Status.CandidateData[0].ClaimRef
	if err := ValidateRestoreStatus(crossPathAlias); err == nil {
		t.Fatal("restore accepted a candidate claim aliased by another rollback path")
	}

	duplicateCandidateUID := restore.DeepCopy()
	duplicateCandidateUID.Status.CandidateData[1].ClaimRef.UID = duplicateCandidateUID.Status.CandidateData[0].ClaimRef.UID
	duplicateCandidateUID.Status.ActiveData[1].ClaimRef.UID = duplicateCandidateUID.Status.CandidateData[0].ClaimRef.UID
	if err := ValidateRestoreStatus(duplicateCandidateUID); err == nil {
		t.Fatal("restore accepted duplicate claim identities within candidate data")
	}

	duplicatePreviousName := restore.DeepCopy()
	duplicatePreviousName.Status.PreviousData[1].ClaimRef.Name = duplicatePreviousName.Status.PreviousData[0].ClaimRef.Name
	if err := ValidateRestoreStatus(duplicatePreviousName); err == nil {
		t.Fatal("restore accepted duplicate claim identities within rollback data")
	}

	cancellingActivation := restore.DeepCopy()
	cancellingActivation.Spec.CancelRequested = true
	cancellingActivation.Generation++
	cancellingActivation.Status.ObservedGeneration = cancellingActivation.Generation
	cancellingActivation.Status.Phase = arcadev1alpha1.DataPhaseRollingBack
	if err := ValidateRestoreStatus(cancellingActivation); err != nil {
		t.Fatalf("cancelled restore could not enter mandatory rollback: %v", err)
	}
	cancellingActivation.Status.Phase = arcadev1alpha1.DataPhaseActivating
	if err := ValidateRestoreStatus(cancellingActivation); err == nil {
		t.Fatal("cancelled restore was allowed to continue activation")
	}

	rollbackTerminal := restore.DeepCopy()
	rollbackTerminal.Spec.CancelRequested = true
	rollbackTerminal.Generation++
	rollbackTerminal.Status.ObservedGeneration = rollbackTerminal.Generation
	rollbackTerminal.Status.Phase = arcadev1alpha1.DataPhaseCancelled
	if err := ValidateRestoreStatus(rollbackTerminal); err == nil {
		t.Fatal("restore completed cancellation while candidate claims remained active")
	}
	rollbackTerminal.Status.ActiveData = append([]arcadev1alpha1.DataPathIdentity(nil), rollbackTerminal.Status.PreviousData...)
	if err := ValidateRestoreStatus(rollbackTerminal); err != nil {
		t.Fatalf("restore rejected a verified terminal rollback: %v", err)
	}
	rollbackTerminal.Status.ActiveData = nil
	if err := ValidateRestoreStatus(rollbackTerminal); err == nil {
		t.Fatal("restore completed cancellation without recording active rollback claims")
	}
}

func validBackupStatus() *arcadev1alpha1.GameBackup {
	repository := testRepository()
	sourceReference := arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "server-uid"},
		Generation:          1,
		DesiredState:        arcadev1alpha1.DesiredStateRunning,
	}
	return &arcadev1alpha1.GameBackup{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", UID: "backup-uid", Generation: 1},
		Spec: arcadev1alpha1.GameBackupSpec{
			DataOperationRequest: arcadev1alpha1.DataOperationRequest{RepositorySecretRef: repository, RestartPolicy: arcadev1alpha1.RestartLeaveStopped},
			Source:               sourceReference,
		},
		Status: arcadev1alpha1.GameBackupStatus{DataOperationStatus: arcadev1alpha1.DataOperationStatus{
			ObservedGeneration: 1,
			Phase:              arcadev1alpha1.DataPhaseSucceeded,
			CompletedAt:        timePointer(),
			Source:             testSourceSnapshot(sourceReference),
			Fence:              testFence("factory", "server-uid", 2),
			Artifact:           testArtifact(2, arcadev1alpha1.ExactLocalReference{Name: "backup", UID: "backup-uid"}, repository),
			Runtime:            testStoppedRuntime("factory", "server-uid", 2),
		}},
	}
}

func validRestoreStatus() *arcadev1alpha1.GameRestore {
	repository := testRepository()
	backupReference := arcadev1alpha1.ExactLocalReference{Name: "source-backup", UID: "source-backup-uid"}
	const restoreUID types.UID = "restore-uid"
	target := arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "factory", UID: "target-uid"},
		Generation:          1,
		DesiredState:        arcadev1alpha1.DesiredStateRunning,
	}
	source := testSourceSnapshot(arcadev1alpha1.ExactGameServerReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "old-factory", UID: "source-uid"},
		Generation:          7,
		DesiredState:        arcadev1alpha1.DesiredStateStopped,
	})
	worldCandidate, _ := RestoreCandidateID(restoreUID, "world")
	modsCandidate, _ := RestoreCandidateID(restoreUID, "mods")
	candidate := []arcadev1alpha1.DataPathIdentity{
		testPath("world", "/world", worldCandidate, "candidate-world-uid"),
		testPath("mods", "/mods", modsCandidate, "candidate-mods-uid"),
	}
	return &arcadev1alpha1.GameRestore{
		ObjectMeta: metav1.ObjectMeta{Name: "restore", UID: restoreUID, Generation: 1},
		Spec: arcadev1alpha1.GameRestoreSpec{
			DataOperationRequest: arcadev1alpha1.DataOperationRequest{RepositorySecretRef: repository, RestartPolicy: arcadev1alpha1.RestartLeaveStopped},
			BackupRef:            backupReference,
			Target:               target,
		},
		Status: arcadev1alpha1.GameRestoreStatus{
			DataOperationStatus: arcadev1alpha1.DataOperationStatus{
				ObservedGeneration: 1,
				Phase:              arcadev1alpha1.DataPhaseSucceeded,
				CompletedAt:        timePointer(),
				Source:             source,
				Fence:              testFence("factory", "target-uid", 2),
				Artifact:           testArtifact(2, backupReference, repository),
				Runtime:            testStoppedRuntime("factory", "target-uid", 2),
			},
			ActivationStartedAt: timePointer(),
			CandidateVerification: &arcadev1alpha1.CandidateDataVerification{
				Result: arcadev1alpha1.VerificationVerified, ManifestDigest: "sha256:" + strings.Repeat("3", 64), PathCount: 2, VerifiedAt: testTime(),
			},
			CandidateData: candidate,
			ActiveData:    append([]arcadev1alpha1.DataPathIdentity(nil), candidate...),
			PreviousData: []arcadev1alpha1.DataPathIdentity{
				testPath("world", "/world", "previous-world", "previous-world-uid"),
				testPath("mods", "/mods", "previous-mods", "previous-mods-uid"),
			},
		},
	}
}

func testSourceSnapshot(reference arcadev1alpha1.ExactGameServerReference) *arcadev1alpha1.DataSourceSnapshot {
	return &arcadev1alpha1.DataSourceSnapshot{
		GameServer:     reference,
		Game:           "factorio",
		ImageDigest:    "sha256:" + strings.Repeat("1", 64),
		SettingsDigest: "sha256:" + strings.Repeat("2", 64),
		Paths: []arcadev1alpha1.DataPathIdentity{
			testPath("world", "/world", "source-world", "source-world-uid"),
			testPath("mods", "/mods", "source-mods", "source-mods-uid"),
		},
	}
}

func testArtifact(pathCount int32, backup arcadev1alpha1.ExactLocalReference, repository arcadev1alpha1.ExactSecretReference) *arcadev1alpha1.BackupArtifact {
	artifactID, _ := ArtifactID(types.UID(backup.UID))
	return &arcadev1alpha1.BackupArtifact{
		Provenance:     arcadev1alpha1.ArtifactProvenance{BackupRef: backup, RepositorySecretRef: repository},
		ID:             artifactID,
		FormatVersion:  "1",
		ManifestDigest: "sha256:" + strings.Repeat("3", 64),
		SizeBytes:      42,
		PathCount:      pathCount,
		CreatedAt:      testTime(),
		Verification: arcadev1alpha1.ArtifactVerification{
			Result:     arcadev1alpha1.VerificationVerified,
			VerifiedAt: timePointer(),
		},
	}
}

func testRepository() arcadev1alpha1.ExactSecretReference {
	return arcadev1alpha1.ExactSecretReference{
		ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: "repository", UID: "repository-uid"},
		ResourceVersion:     "42",
	}
}

func testFence(name, uid string, generation int64) *arcadev1alpha1.ColdDataFence {
	return &arcadev1alpha1.ColdDataFence{
		GameServer: arcadev1alpha1.ExactGameServerReference{
			ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: name, UID: uid},
			Generation:          generation,
			DesiredState:        arcadev1alpha1.DesiredStateStopped,
		},
		EstablishedAt: testTime(),
	}
}

func testStoppedRuntime(name, uid string, generation int64) *arcadev1alpha1.RuntimeDisposition {
	return &arcadev1alpha1.RuntimeDisposition{
		GameServer: arcadev1alpha1.ExactGameServerReference{
			ExactLocalReference: arcadev1alpha1.ExactLocalReference{Name: name, UID: uid},
			Generation:          generation,
			DesiredState:        arcadev1alpha1.DesiredStateStopped,
		},
		Phase:       arcadev1alpha1.PhaseStopped,
		CompletedAt: testTime(),
	}
}

func testPath(name, mount, claim, uid string) arcadev1alpha1.DataPathIdentity {
	return arcadev1alpha1.DataPathIdentity{
		Name: name, MountPath: mount,
		ClaimRef: arcadev1alpha1.ExactLocalReference{Name: claim, UID: uid},
	}
}

func testTime() metav1.Time {
	return metav1.NewTime(time.Unix(1_700_000_000, 0).UTC())
}

func timePointer() *metav1.Time {
	value := testTime()
	return &value
}

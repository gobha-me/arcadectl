// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package data defines pure safety rules for durable backup and restore
// operations. It does not perform repository or Kubernetes mutations.
package data

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// OperationKind selects the state machine whose transition is validated.
type OperationKind string

const (
	BackupOperation  OperationKind = "backup"
	RestoreOperation OperationKind = "restore"
)

// ArtifactID returns the single repository artifact identity owned by a
// GameBackup. Reconciliation retries for the same Kubernetes UID converge on
// this value instead of allocating more artifacts.
func ArtifactID(operationUID types.UID) (string, error) {
	return deterministicID("backup", operationUID, "")
}

// RestoreCandidateID returns the stable candidate-data identity for one path
// of a GameRestore. A retry cannot allocate a second candidate for that path.
func RestoreCandidateID(operationUID types.UID, pathName string) (string, error) {
	if pathName == "" {
		return "", errors.New("persistent path name is required")
	}
	return deterministicID("restore", operationUID, pathName)
}

func deterministicID(kind string, operationUID types.UID, discriminator string) (string, error) {
	if operationUID == "" {
		return "", errors.New("operation UID is required")
	}
	digest := sha256.Sum256([]byte("arcadectl/" + kind + "/" + string(operationUID) + "/" + discriminator))
	return fmt.Sprintf("%s-%x", kind, digest[:]), nil
}

// ValidateTransition rejects state regression, unverified success, and restore
// activation before isolated candidate verification. Self-transitions are
// idempotent and terminal phases cannot change.
func ValidateTransition(kind OperationKind, current, next arcadev1alpha1.DataOperationPhase, verified bool) error {
	if kind != BackupOperation && kind != RestoreOperation {
		return fmt.Errorf("unsupported data operation kind %q", kind)
	}
	if !validPhase(current, true) || !validPhase(next, false) {
		return fmt.Errorf("unsupported data operation phase transition %q -> %q", current, next)
	}
	if kind == BackupOperation && (restoreOnlyPhase(current) || restoreOnlyPhase(next)) {
		return fmt.Errorf("backup operation cannot use restore-only phase %q -> %q", current, next)
	}
	if next == arcadev1alpha1.DataPhaseSucceeded && !verified {
		return errors.New("operation cannot succeed before verification")
	}
	if kind == RestoreOperation && next == arcadev1alpha1.DataPhaseActivating && !verified {
		return errors.New("restore cannot activate before candidate verification")
	}
	if current == next {
		return nil
	}
	if terminal(current) {
		return fmt.Errorf("terminal phase %s cannot transition to %s", current, next)
	}
	if kind == RestoreOperation && current == arcadev1alpha1.DataPhaseRollingBack &&
		(next == arcadev1alpha1.DataPhaseFailed || next == arcadev1alpha1.DataPhaseCancelled) {
		if !verified {
			return errors.New("restore rollback cannot become terminal before rollback verification")
		}
		return nil
	}
	if !allowed(kind, current, next) {
		return fmt.Errorf("invalid %s phase transition %s -> %s", kind, current, next)
	}
	return nil
}

// ValidateBackupStatus applies invariants that span the immutable request and
// observed status. Controllers must validate the complete candidate status
// before every write.
func ValidateBackupStatus(operation *arcadev1alpha1.GameBackup) error {
	if operation == nil {
		return errors.New("GameBackup is required")
	}
	status := &operation.Status.DataOperationStatus
	if err := validateCommonStatus(BackupOperation, &operation.Spec.DataOperationRequest, &operation.Spec.Source, status, operation.Generation); err != nil {
		return err
	}
	if status.Source != nil && !sameGameServer(status.Source.GameServer, operation.Spec.Source) {
		return errors.New("backup source snapshot does not match the requested GameServer identity")
	}
	if status.Artifact != nil {
		expectedID, err := ArtifactID(operation.UID)
		if err != nil || status.Artifact.ID != expectedID {
			return errors.New("backup artifact ID is not derived from the GameBackup UID")
		}
		if status.Artifact.Provenance.BackupRef.Name != operation.Name || status.Artifact.Provenance.BackupRef.UID != string(operation.UID) ||
			!sameSecret(status.Artifact.Provenance.RepositorySecretRef, operation.Spec.RepositorySecretRef) {
			return errors.New("backup artifact provenance does not match the operation and repository")
		}
	}
	return nil
}

// ValidateRestoreStatus prevents activation with incomplete path sets and
// proves that a completed activation retained an exact rollback set.
func ValidateRestoreStatus(operation *arcadev1alpha1.GameRestore) error {
	if operation == nil {
		return errors.New("GameRestore is required")
	}
	status := &operation.Status
	if err := validateCommonStatus(RestoreOperation, &operation.Spec.DataOperationRequest, &operation.Spec.Target, &status.DataOperationStatus, operation.Generation); err != nil {
		return err
	}
	if status.Artifact != nil {
		expectedID, err := ArtifactID(types.UID(operation.Spec.BackupRef.UID))
		if err != nil || status.Artifact.ID != expectedID ||
			!sameLocal(status.Artifact.Provenance.BackupRef, operation.Spec.BackupRef) ||
			!sameSecret(status.Artifact.Provenance.RepositorySecretRef, operation.Spec.RepositorySecretRef) {
			return errors.New("restore artifact provenance does not match the exact backup and repository")
		}
	}
	activationPhase := status.Phase == arcadev1alpha1.DataPhaseActivating ||
		status.Phase == arcadev1alpha1.DataPhaseRollingBack ||
		status.Phase == arcadev1alpha1.DataPhaseSucceeded
	if activationPhase && status.ActivationStartedAt == nil {
		return errors.New("restore activation requires durable activation history")
	}
	if !activationPhase && status.ActivationStartedAt == nil {
		return nil
	}
	if status.Source == nil {
		return errors.New("restore activation requires a resolved source manifest")
	}
	if err := completePathSet(status.Source.Paths, status.CandidateData, "candidate"); err != nil {
		return err
	}
	if status.CandidateVerification == nil || status.CandidateVerification.Result != arcadev1alpha1.VerificationVerified ||
		status.Artifact == nil || status.CandidateVerification.ManifestDigest != status.Artifact.ManifestDigest ||
		status.CandidateVerification.PathCount != int32(len(status.Source.Paths)) {
		return errors.New("restore activation requires verified candidate contents matching the artifact manifest")
	}
	if err := completePathSet(status.Source.Paths, status.PreviousData, "previous"); err != nil {
		return err
	}
	if err := distinctClaims(status.CandidateData, status.PreviousData); err != nil {
		return err
	}
	for _, candidate := range status.CandidateData {
		expectedName, err := RestoreCandidateID(operation.UID, candidate.Name)
		if err != nil || candidate.ClaimRef.Name != expectedName {
			return fmt.Errorf("candidate path %q does not use its deterministic restore identity", candidate.Name)
		}
	}
	if status.Phase == arcadev1alpha1.DataPhaseFailed || status.Phase == arcadev1alpha1.DataPhaseCancelled {
		if err := completePathSet(status.Source.Paths, status.ActiveData, "active"); err != nil {
			return errors.New("terminal restore after activation requires complete rollback data")
		}
		for _, previous := range status.PreviousData {
			active, ok := pathByName(status.ActiveData, previous.Name)
			if !ok || active.MountPath != previous.MountPath || active.ClaimRef.Name != previous.ClaimRef.Name || active.ClaimRef.UID != previous.ClaimRef.UID {
				return fmt.Errorf("active path %q does not identify its verified rollback claim", previous.Name)
			}
		}
		return nil
	}
	if status.Phase != arcadev1alpha1.DataPhaseSucceeded {
		return nil
	}
	if err := completePathSet(status.Source.Paths, status.ActiveData, "active"); err != nil {
		return err
	}
	for _, candidate := range status.CandidateData {
		active, ok := pathByName(status.ActiveData, candidate.Name)
		if !ok || active.ClaimRef.Name != candidate.ClaimRef.Name || active.ClaimRef.UID != candidate.ClaimRef.UID {
			return fmt.Errorf("active path %q does not identify its verified candidate claim", candidate.Name)
		}
	}
	return nil
}

func validateCommonStatus(kind OperationKind, request *arcadev1alpha1.DataOperationRequest, subject *arcadev1alpha1.ExactGameServerReference, status *arcadev1alpha1.DataOperationStatus, operationGeneration int64) error {
	if !validPhase(status.Phase, false) {
		return fmt.Errorf("status has unsupported or empty phase %q", status.Phase)
	}
	if kind == BackupOperation && restoreOnlyPhase(status.Phase) {
		return fmt.Errorf("backup status cannot use restore-only phase %q", status.Phase)
	}
	if status.ObservedGeneration != operationGeneration || operationGeneration < 1 {
		return errors.New("status observedGeneration must equal the current operation generation")
	}
	if request.CancelRequested && status.Phase != arcadev1alpha1.DataPhaseCancelling && status.Phase != arcadev1alpha1.DataPhaseCancelled && status.Phase != arcadev1alpha1.DataPhaseFailed &&
		!(kind == RestoreOperation && status.Phase == arcadev1alpha1.DataPhaseRollingBack) {
		return errors.New("cancelRequested blocks further operation progress")
	}
	if status.Phase == arcadev1alpha1.DataPhaseBlocked || status.Phase == arcadev1alpha1.DataPhaseFailed {
		if !hasActionableCondition(status.Conditions, status.ObservedGeneration) {
			return fmt.Errorf("%s status requires a current actionable condition", status.Phase)
		}
	}
	if status.Fence != nil {
		fenced := status.Fence.GameServer
		expectedGeneration := subject.Generation
		if subject.DesiredState == arcadev1alpha1.DesiredStateRunning {
			expectedGeneration++
		}
		if fenced.Name != subject.Name || fenced.UID != subject.UID || fenced.DesiredState != arcadev1alpha1.DesiredStateStopped || fenced.Generation != expectedGeneration {
			return errors.New("cold data fence does not identify a stopped generation of the requested GameServer")
		}
	}
	if (status.Phase == arcadev1alpha1.DataPhaseRunning ||
		status.Phase == arcadev1alpha1.DataPhaseVerifying ||
		status.Phase == arcadev1alpha1.DataPhaseActivating ||
		status.Phase == arcadev1alpha1.DataPhaseRollingBack ||
		status.Phase == arcadev1alpha1.DataPhaseSucceeded) && status.Fence == nil {
		return errors.New("data work requires an immutable cold data fence")
	}
	if status.Source != nil && status.Artifact != nil && status.Artifact.PathCount != int32(len(status.Source.Paths)) {
		return errors.New("artifact path count does not match the resolved source manifest")
	}
	if status.Phase == arcadev1alpha1.DataPhaseSucceeded {
		if status.Source == nil || !verifiedArtifact(status.Artifact) {
			return errors.New("succeeded operation requires a verified artifact and source manifest")
		}
		if status.CompletedAt == nil {
			return errors.New("succeeded operation requires completedAt")
		}
	}
	if terminal(status.Phase) && status.Fence != nil {
		if err := validateRuntimeDisposition(request.RestartPolicy, *subject, status.Fence, status.Runtime); err != nil {
			return err
		}
	}
	return nil
}

func hasActionableCondition(conditions []metav1.Condition, generation int64) bool {
	for _, condition := range conditions {
		if condition.ObservedGeneration != generation || condition.Status == metav1.ConditionTrue || strings.TrimSpace(condition.Message) == "" {
			continue
		}
		switch condition.Reason {
		case arcadev1alpha1.ReasonInvalidReference,
			arcadev1alpha1.ReasonIdentityMismatch,
			arcadev1alpha1.ReasonSecretUnavailable,
			arcadev1alpha1.ReasonColdStopPending,
			arcadev1alpha1.ReasonOperationConflict,
			arcadev1alpha1.ReasonWorkerFailed,
			arcadev1alpha1.ReasonVerificationFailed:
			return true
		}
	}
	return false
}

func verifiedArtifact(artifact *arcadev1alpha1.BackupArtifact) bool {
	return artifact != nil && artifact.Verification.Result == arcadev1alpha1.VerificationVerified && artifact.Verification.VerifiedAt != nil
}

func validateRuntimeDisposition(policy arcadev1alpha1.RestartPolicy, subject arcadev1alpha1.ExactGameServerReference, fence *arcadev1alpha1.ColdDataFence, disposition *arcadev1alpha1.RuntimeDisposition) error {
	if disposition == nil {
		return errors.New("terminal fenced operation requires a runtime disposition")
	}
	wantState := arcadev1alpha1.DesiredStateStopped
	wantPhase := arcadev1alpha1.PhaseStopped
	wantGeneration := fence.GameServer.Generation
	if policy == arcadev1alpha1.RestartRestorePreviousState {
		wantState = subject.DesiredState
		if wantState == arcadev1alpha1.DesiredStateRunning {
			wantPhase = arcadev1alpha1.PhaseReady
			wantGeneration++
		}
	}
	observed := disposition.GameServer
	if observed.Name != subject.Name || observed.UID != subject.UID || observed.DesiredState != wantState || observed.Generation != wantGeneration || disposition.Phase != wantPhase {
		return errors.New("runtime disposition does not satisfy the requested restart policy")
	}
	return nil
}

func completePathSet(source, observed []arcadev1alpha1.DataPathIdentity, label string) error {
	if len(source) == 0 || len(observed) != len(source) {
		return fmt.Errorf("%s data does not cover every source path", label)
	}
	for _, sourcePath := range source {
		path, ok := pathByName(observed, sourcePath.Name)
		if !ok || path.MountPath != sourcePath.MountPath || path.ClaimRef.Name == "" || path.ClaimRef.UID == "" {
			return fmt.Errorf("%s data path %q is missing or incompatible", label, sourcePath.Name)
		}
	}
	for index, path := range observed {
		for otherIndex := index + 1; otherIndex < len(observed); otherIndex++ {
			other := observed[otherIndex]
			if path.ClaimRef.Name == other.ClaimRef.Name || path.ClaimRef.UID == other.ClaimRef.UID {
				return fmt.Errorf("%s data paths %q and %q alias a claim identity", label, path.Name, other.Name)
			}
		}
	}
	return nil
}

func distinctClaims(candidate, previous []arcadev1alpha1.DataPathIdentity) error {
	for _, candidatePath := range candidate {
		for _, previousPath := range previous {
			if candidatePath.ClaimRef.Name == previousPath.ClaimRef.Name || candidatePath.ClaimRef.UID == previousPath.ClaimRef.UID {
				return fmt.Errorf("candidate path %q aliases previous path %q", candidatePath.Name, previousPath.Name)
			}
		}
	}
	return nil
}

func pathByName(paths []arcadev1alpha1.DataPathIdentity, name string) (arcadev1alpha1.DataPathIdentity, bool) {
	for _, path := range paths {
		if path.Name == name {
			return path, true
		}
	}
	return arcadev1alpha1.DataPathIdentity{}, false
}

func sameGameServer(left, right arcadev1alpha1.ExactGameServerReference) bool {
	return left.Name == right.Name && left.UID == right.UID && left.Generation == right.Generation && left.DesiredState == right.DesiredState
}

func sameLocal(left, right arcadev1alpha1.ExactLocalReference) bool {
	return left.Namespace == nil && right.Namespace == nil && left.Name == right.Name && left.UID == right.UID
}

func sameSecret(left, right arcadev1alpha1.ExactSecretReference) bool {
	return sameLocal(left.ExactLocalReference, right.ExactLocalReference) && left.ResourceVersion == right.ResourceVersion
}

func restoreOnlyPhase(phase arcadev1alpha1.DataOperationPhase) bool {
	return phase == arcadev1alpha1.DataPhaseActivating || phase == arcadev1alpha1.DataPhaseRollingBack
}

func validPhase(phase arcadev1alpha1.DataOperationPhase, allowEmpty bool) bool {
	if phase == "" {
		return allowEmpty
	}
	switch phase {
	case arcadev1alpha1.DataPhasePending,
		arcadev1alpha1.DataPhaseBlocked,
		arcadev1alpha1.DataPhasePreparing,
		arcadev1alpha1.DataPhaseRunning,
		arcadev1alpha1.DataPhaseVerifying,
		arcadev1alpha1.DataPhaseActivating,
		arcadev1alpha1.DataPhaseRollingBack,
		arcadev1alpha1.DataPhaseCancelling,
		arcadev1alpha1.DataPhaseCancelled,
		arcadev1alpha1.DataPhaseSucceeded,
		arcadev1alpha1.DataPhaseFailed:
		return true
	default:
		return false
	}
}

func terminal(phase arcadev1alpha1.DataOperationPhase) bool {
	return phase == arcadev1alpha1.DataPhaseCancelled ||
		phase == arcadev1alpha1.DataPhaseSucceeded ||
		phase == arcadev1alpha1.DataPhaseFailed
}

func allowed(kind OperationKind, current, next arcadev1alpha1.DataOperationPhase) bool {
	if next == arcadev1alpha1.DataPhaseFailed {
		return current != "" && !(kind == RestoreOperation && current == arcadev1alpha1.DataPhaseActivating)
	}
	if next == arcadev1alpha1.DataPhaseCancelling {
		return current != "" && current != arcadev1alpha1.DataPhaseRollingBack &&
			!(kind == RestoreOperation && current == arcadev1alpha1.DataPhaseActivating)
	}
	if current == arcadev1alpha1.DataPhaseCancelling {
		return next == arcadev1alpha1.DataPhaseCancelled
	}
	if current == arcadev1alpha1.DataPhaseBlocked {
		return next == arcadev1alpha1.DataPhasePreparing
	}
	switch current {
	case "":
		return next == arcadev1alpha1.DataPhasePending
	case arcadev1alpha1.DataPhasePending:
		return next == arcadev1alpha1.DataPhasePreparing || next == arcadev1alpha1.DataPhaseBlocked
	case arcadev1alpha1.DataPhasePreparing:
		return next == arcadev1alpha1.DataPhaseRunning || next == arcadev1alpha1.DataPhaseBlocked
	case arcadev1alpha1.DataPhaseRunning:
		return next == arcadev1alpha1.DataPhaseVerifying
	case arcadev1alpha1.DataPhaseVerifying:
		if kind == BackupOperation {
			return next == arcadev1alpha1.DataPhaseSucceeded
		}
		return next == arcadev1alpha1.DataPhaseActivating
	case arcadev1alpha1.DataPhaseActivating:
		return kind == RestoreOperation && (next == arcadev1alpha1.DataPhaseSucceeded || next == arcadev1alpha1.DataPhaseRollingBack)
	case arcadev1alpha1.DataPhaseRollingBack:
		return false
	default:
		return false
	}
}

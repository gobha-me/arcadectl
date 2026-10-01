// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// GameDestroyMode separates the backup-gated path from an explicitly unsafe
// administrative exception. Admission must require a distinct administrator
// identity and audit the latter; possession of a confirmation is not enough.
// +kubebuilder:validation:Enum=VerifiedBackup;UnsafeNoBackup
type GameDestroyMode string

const (
	DestroyModeVerifiedBackup GameDestroyMode = "VerifiedBackup"
	DestroyModeUnsafeNoBackup GameDestroyMode = "UnsafeNoBackup"
)

// GameDestroyPhase is the bounded, observable destroy lifecycle.
// +kubebuilder:validation:Enum=Pending;Preview;Verifying;Deleting;Succeeded;Failed;Cancelled
type GameDestroyPhase string

const (
	DestroyPhasePending   GameDestroyPhase = "Pending"
	DestroyPhasePreview   GameDestroyPhase = "Preview"
	DestroyPhaseVerifying GameDestroyPhase = "Verifying"
	DestroyPhaseDeleting  GameDestroyPhase = "Deleting"
	DestroyPhaseSucceeded GameDestroyPhase = "Succeeded"
	DestroyPhaseFailed    GameDestroyPhase = "Failed"
	DestroyPhaseCancelled GameDestroyPhase = "Cancelled"
)

// GameDestroyTarget pins the original server identity and the complete
// retained-world claim set. The GameServer may already have been removed.
// +kubebuilder:validation:XValidation:rule="self.data.claims.all(claim, self.data.claims.filter(other, other.claimRef.name == claim.claimRef.name).size() == 1 && self.data.claims.filter(other, other.claimRef.uid == claim.claimRef.uid).size() == 1)",message="retained claims must have unique names and UIDs"
type GameDestroyTarget struct {
	GameServer ExactLocalReference `json:"gameServer"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Game string                `json:"game"`
	Data RetainedDataReference `json:"data"`
}

// GameDestroySpec is an explicit, immutable destruction request. A client
// creates it without a confirmation, reads the controller-issued preview,
// then echoes the challenge once before its expiry. Cancellation is monotonic.
// +kubebuilder:validation:XValidation:rule="self.mode == 'VerifiedBackup' ? (has(self.backupRef) && has(self.repositorySecretRef) && !has(self.unsafeReason)) : (!has(self.backupRef) && !has(self.repositorySecretRef) && has(self.unsafeReason))",message="verified destroy requires exact backup and repository references; unsafe destroy requires only a reason"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.confirmationChallenge) || (has(self.confirmationChallenge) && self.confirmationChallenge == oldSelf.confirmationChallenge)",message="confirmation challenge cannot be changed or cleared"
type GameDestroySpec struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="destroy target is immutable"
	Target GameDestroyTarget `json:"target"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="destroy mode is immutable"
	Mode GameDestroyMode `json:"mode"`
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="backupRef is immutable"
	BackupRef *ExactLocalReference `json:"backupRef,omitempty"`
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="repositorySecretRef is immutable"
	RepositorySecretRef *ExactSecretReference `json:"repositorySecretRef,omitempty"`
	// UnsafeReason is recorded for the separately authorized, audited override;
	// it must not contain credentials or unbounded narrative.
	// +optional
	// +kubebuilder:validation:MinLength=8
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="unsafe reason is immutable"
	UnsafeReason string `json:"unsafeReason,omitempty"`
	// ConfirmationChallenge is the one-time echo of status.preview.challenge.
	// The controller must verify equality and expiry before deletion.
	// +optional
	// +kubebuilder:validation:MinLength=16
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_-]+$`
	ConfirmationChallenge string `json:"confirmationChallenge,omitempty"`
	// +kubebuilder:default=false
	// +kubebuilder:validation:XValidation:rule="!oldSelf || self",message="cancelRequested cannot be cleared"
	CancelRequested bool `json:"cancelRequested"`
}

// GameDestroyPreview provides a short-lived, controller-issued challenge and
// restore guidance before any irreversible step.
type GameDestroyPreview struct {
	// +kubebuilder:validation:MinLength=16
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_-]+$`
	Challenge string      `json:"challenge"`
	ExpiresAt metav1.Time `json:"expiresAt"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	RestoreGuidance string `json:"restoreGuidance"`
}

// GameDestroyVerification proves that the exact requested artifact was
// reverified in its repository while the target world remained cold.
type GameDestroyVerification struct {
	BackupRef           ExactLocalReference  `json:"backupRef"`
	RepositorySecretRef ExactSecretReference `json:"repositorySecretRef"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	ArtifactID string `json:"artifactID"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ManifestDigest string `json:"manifestDigest"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=16
	PathCount  int32       `json:"pathCount"`
	VerifiedAt metav1.Time `json:"verifiedAt"`
	// ColdAt records the last successful detached/cold observation. Controllers
	// must recheck this condition immediately before each destructive action.
	ColdAt metav1.Time `json:"coldAt"`
}

// GameDestroyClaimDeletion is a write-ahead journal entry for one exact PVC.
// RequestedAt precedes a delete call; ObservedDeletedAt is set only after
// absence of that exact UID is observed.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.observedDeletedAt) || (has(self.observedDeletedAt) && self.observedDeletedAt == oldSelf.observedDeletedAt)",message="observed PVC deletion cannot be cleared or changed"
type GameDestroyClaimDeletion struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`
	Path        string              `json:"path"`
	ClaimRef    ExactLocalReference `json:"claimRef"`
	RequestedAt metav1.Time         `json:"requestedAt"`
	// +optional
	ObservedDeletedAt *metav1.Time `json:"observedDeletedAt,omitempty"`
}

// GameDestroyStatus contains only bounded, controller-authored evidence.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.preview) || (has(self.preview) && self.preview == oldSelf.preview)",message="preview challenge and guidance are immutable"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.verification) || (has(self.verification) && self.verification == oldSelf.verification)",message="verification evidence is immutable"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.deletionJournal) || (has(self.deletionJournal) && oldSelf.deletionJournal.all(entry, self.deletionJournal.exists(current, current.path == entry.path && current.claimRef == entry.claimRef && current.requestedAt == entry.requestedAt)))",message="PVC deletion journal entries cannot be removed or retargeted"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.phase) || !(oldSelf.phase in ['Succeeded', 'Failed', 'Cancelled']) || (has(self.phase) && self.phase == oldSelf.phase)",message="terminal destroy phase cannot change"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || self.phase != 'Succeeded' || (has(self.deletionJournal) && self.deletionJournal.all(entry, has(entry.observedDeletedAt)))",message="successful destroy requires every journaled PVC to be observed deleted"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || self.phase != 'Cancelled' || !has(self.deletionJournal) || self.deletionJournal.size() == 0",message="destroy cannot be cancelled after PVC deletion begins"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || self.phase != 'Failed' || !has(self.deletionJournal) || self.deletionJournal.size() == 0",message="destroy cannot fail terminally after PVC deletion begins"
type GameDestroyStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	Phase GameDestroyPhase `json:"phase,omitempty"`
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	Preview *GameDestroyPreview `json:"preview,omitempty"`
	// +optional
	Verification *GameDestroyVerification `json:"verification,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=path
	DeletionJournal []GameDestroyClaimDeletion `json:"deletionJournal,omitempty"`
}

// GameDestroy requests irreversible deletion of one exact retained world.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gd
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.target.gameServer.name`
// +kubebuilder:validation:XValidation:rule="!has(self.spec.confirmationChallenge) || (has(self.status) && has(self.status.preview) && self.spec.confirmationChallenge == self.status.preview.challenge)",message="confirmation must echo the controller-issued preview challenge"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.phase) || !(self.status.phase in ['Deleting', 'Succeeded']) || (has(self.status.preview) && has(self.spec.confirmationChallenge) && self.spec.confirmationChallenge == self.status.preview.challenge)",message="deletion requires the immutable preview challenge echoed in spec"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.phase) || !(self.status.phase in ['Deleting', 'Succeeded']) || self.spec.mode != 'VerifiedBackup' || (has(self.status.verification) && self.status.verification.backupRef.name == self.spec.backupRef.name && self.status.verification.backupRef.uid == self.spec.backupRef.uid && self.status.verification.repositorySecretRef.name == self.spec.repositorySecretRef.name && self.status.verification.repositorySecretRef.uid == self.spec.repositorySecretRef.uid && self.status.verification.repositorySecretRef.resourceVersion == self.spec.repositorySecretRef.resourceVersion && self.status.verification.pathCount == self.spec.target.data.claims.size())",message="verified destroy requires matching complete repository proof"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.deletionJournal) || self.status.deletionJournal.all(entry, self.spec.target.data.claims.exists(claim, claim.path == entry.path && claim.claimRef.name == entry.claimRef.name && claim.claimRef.uid == entry.claimRef.uid))",message="PVC deletion journal must name only exact target claims"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.phase) || self.status.phase != 'Succeeded' || (has(self.status.deletionJournal) && self.status.deletionJournal.size() == self.spec.target.data.claims.size())",message="successful destroy requires every target PVC in the deletion journal"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.status) || !has(oldSelf.status.phase) || !(oldSelf.status.phase in ['Succeeded', 'Failed', 'Cancelled']) || self.spec.cancelRequested == oldSelf.spec.cancelRequested",message="cancellation cannot be newly requested after destroy completion"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.status) || !has(oldSelf.status.deletionJournal) || oldSelf.status.deletionJournal.size() == 0 || self.spec.cancelRequested == oldSelf.spec.cancelRequested",message="cancellation cannot be newly requested after deletion begins"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.phase) || self.status.phase != 'Verifying' || self.spec.mode == 'VerifiedBackup'",message="repository verification is only available in verified-backup mode"
type GameDestroy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GameDestroySpec   `json:"spec"`
	Status GameDestroyStatus `json:"status,omitempty"`
}

// GameDestroyList is a list of GameDestroy objects.
// +kubebuilder:object:root=true
type GameDestroyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GameDestroy `json:"items"`
}

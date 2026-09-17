// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DataOperationPhase is the bounded state shared by backup and restore
// operations. Detailed progress and safe operator actions belong in conditions.
// +kubebuilder:validation:Enum=Pending;Blocked;Preparing;Running;Verifying;Activating;RollingBack;Cancelling;Cancelled;Succeeded;Failed
type DataOperationPhase string

const (
	DataPhasePending     DataOperationPhase = "Pending"
	DataPhaseBlocked     DataOperationPhase = "Blocked"
	DataPhasePreparing   DataOperationPhase = "Preparing"
	DataPhaseRunning     DataOperationPhase = "Running"
	DataPhaseVerifying   DataOperationPhase = "Verifying"
	DataPhaseActivating  DataOperationPhase = "Activating"
	DataPhaseRollingBack DataOperationPhase = "RollingBack"
	DataPhaseCancelling  DataOperationPhase = "Cancelling"
	DataPhaseCancelled   DataOperationPhase = "Cancelled"
	DataPhaseSucceeded   DataOperationPhase = "Succeeded"
	DataPhaseFailed      DataOperationPhase = "Failed"
)

// Operation condition types are stable automation keys. Implementations must
// use bounded, controller-authored messages and never copy worker output.
const (
	ConditionOperationAccepted = "Accepted"
	ConditionSourceReady       = "SourceReady"
	ConditionTargetReady       = "TargetReady"
	ConditionArtifactReady     = "ArtifactReady"
	ConditionVerified          = "Verified"
	ConditionOperationComplete = "Complete"
)

// Operation condition reasons are intentionally finite and safe to expose.
const (
	ReasonOperationAccepted  = "Accepted"
	ReasonInvalidReference   = "InvalidReference"
	ReasonIdentityMismatch   = "IdentityMismatch"
	ReasonSecretUnavailable  = "SecretUnavailable"
	ReasonColdStopPending    = "ColdStopPending"
	ReasonOperationConflict  = "OperationConflict"
	ReasonWorkerFailed       = "WorkerFailed"
	ReasonVerificationFailed = "VerificationFailed"
	ReasonOperationCancelled = "Cancelled"
	ReasonOperationCompleted = "Completed"
)

// RestartPolicy controls what happens after an operation safely stops a
// running GameServer. LeaveStopped is the fail-closed default.
// +kubebuilder:validation:Enum=LeaveStopped;RestorePreviousState
type RestartPolicy string

const (
	RestartLeaveStopped         RestartPolicy = "LeaveStopped"
	RestartRestorePreviousState RestartPolicy = "RestorePreviousState"
)

// ArtifactRetentionPolicy describes ownership of a successful artifact.
// Retain is the only v1alpha1 policy: deleting the operation never deletes the
// artifact. Automated retention is deliberately deferred.
// +kubebuilder:validation:Enum=Retain
type ArtifactRetentionPolicy string

const ArtifactRetentionRetain ArtifactRetentionPolicy = "Retain"

// ExactLocalReference prevents name reuse from silently changing an
// operation's subject. The containing operation namespace is implicit, so a
// cross-namespace subject cannot be represented.
// +kubebuilder:validation:XValidation:rule="!has(self.namespace)",message="namespace must be omitted because references are local to the operation"
type ExactLocalReference struct {
	// Namespace is a rejection sentinel, not a selector. Its presence is
	// forbidden so ordinary API requests cannot silently prune cross-namespace
	// intent; the operation namespace is always authoritative.
	// +optional
	Namespace *string `json:"namespace,omitempty"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	UID string `json:"uid"`
}

// ExactGameServerReference pins both object identity and the spec generation
// from which a data operation was requested.
type ExactGameServerReference struct {
	ExactLocalReference `json:",inline"`
	// +kubebuilder:validation:Minimum=1
	Generation int64 `json:"generation"`
	// DesiredState is the durable pre-operation intent at Generation. It lets a
	// retry distinguish an originally running server from one already stopped.
	DesiredState DesiredState `json:"desiredState"`
}

// ExactSecretReference pins an immutable Secret revision. Implementations must
// also verify the live Secret has immutable=true before external work begins.
type ExactSecretReference struct {
	ExactLocalReference `json:",inline"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	ResourceVersion string `json:"resourceVersion"`
}

// InlineCredentials is a rejection sentinel. It deliberately has no fields
// and must never be present in an accepted operation.
type InlineCredentials struct{}

// ColdDataFence records the exact stopped generation under which volumes may
// be read or populated. It is set once after stop and detachment checks pass.
// +kubebuilder:validation:XValidation:rule="self.gameServer.desiredState == 'Stopped'",message="cold data fence must identify stopped intent"
type ColdDataFence struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="fenced GameServer identity is immutable"
	GameServer ExactGameServerReference `json:"gameServer"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="fence timestamp is immutable"
	EstablishedAt metav1.Time `json:"establishedAt"`
}

// RuntimeDisposition records the exact post-operation runtime state. A
// terminal operation that established a fence records this only after the
// requested restart policy has been durably observed.
// +kubebuilder:validation:XValidation:rule="(self.gameServer.desiredState == 'Running' && self.phase == 'Ready') || (self.gameServer.desiredState == 'Stopped' && self.phase == 'Stopped')",message="runtime disposition must match observed desired state"
type RuntimeDisposition struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="runtime GameServer identity is immutable"
	GameServer ExactGameServerReference `json:"gameServer"`
	// +kubebuilder:validation:Enum=Ready;Stopped
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="runtime phase is immutable"
	Phase GameServerPhase `json:"phase"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="runtime completion time is immutable"
	CompletedAt metav1.Time `json:"completedAt"`
}

// DataOperationRequest contains the common immutable repository and lifecycle
// authority boundary.
// +kubebuilder:validation:XValidation:rule="!has(self.inlineCredentials)",message="inline credentials are forbidden; use repositorySecretRef"
type DataOperationRequest struct {
	// InlineCredentials exists only so ordinary admission rejects this unsafe
	// shape instead of pruning it as an unknown field.
	// +optional
	InlineCredentials *InlineCredentials `json:"inlineCredentials,omitempty"`
	// RepositorySecretRef identifies the Secret holding both repository
	// connection configuration and credentials. Secret contents are never
	// copied into this API.
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="repositorySecretRef is immutable"
	RepositorySecretRef ExactSecretReference `json:"repositorySecretRef"`
	// +kubebuilder:default=LeaveStopped
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="restartPolicy is immutable"
	RestartPolicy RestartPolicy `json:"restartPolicy"`
	// CancelRequested is monotonic. An implementation reaches Cancelled only
	// after active work has stopped without exposing partial output.
	// +kubebuilder:default=false
	// +kubebuilder:validation:XValidation:rule="!oldSelf || self",message="cancelRequested cannot be cleared"
	CancelRequested bool `json:"cancelRequested"`
}

// GameBackupSpec is an immutable cold-backup request.
type GameBackupSpec struct {
	DataOperationRequest `json:",inline"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="source is immutable"
	Source ExactGameServerReference `json:"source"`
	// +kubebuilder:default=Retain
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="retentionPolicy is immutable"
	RetentionPolicy ArtifactRetentionPolicy `json:"retentionPolicy"`
}

// GameRestoreSpec restores one exact verified backup into fresh target data.
type GameRestoreSpec struct {
	DataOperationRequest `json:",inline"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="backupRef is immutable"
	BackupRef ExactLocalReference `json:"backupRef"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="target is immutable"
	Target ExactGameServerReference `json:"target"`
}

// DataPathIdentity records one adapter-declared persistent path and the exact
// claim that supplied or will receive its data.
type DataPathIdentity struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^/`
	MountPath string              `json:"mountPath"`
	ClaimRef  ExactLocalReference `json:"claimRef"`
}

// DataSourceSnapshot is the immutable source manifest resolved before work
// begins. SettingsDigest covers canonical validated settings, never settings
// bytes or credentials.
type DataSourceSnapshot struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="source GameServer identity is immutable"
	GameServer ExactGameServerReference `json:"gameServer"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="source game is immutable"
	Game string `json:"game"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="source image digest is immutable"
	ImageDigest string `json:"imageDigest"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="source settings digest is immutable"
	SettingsDigest string `json:"settingsDigest"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="source data paths are immutable"
	Paths []DataPathIdentity `json:"paths"`
}

// VerificationResult is repository-side verification state for an artifact.
// +kubebuilder:validation:Enum=Pending;Verified;Failed
type VerificationResult string

const (
	VerificationPending  VerificationResult = "Pending"
	VerificationVerified VerificationResult = "Verified"
	VerificationFailed   VerificationResult = "Failed"
)

// ArtifactVerification records a bounded result without raw worker output.
type ArtifactVerification struct {
	Result VerificationResult `json:"result"`
	// +optional
	VerifiedAt *metav1.Time `json:"verifiedAt,omitempty"`
}

// ArtifactProvenance binds repository metadata to the exact backup operation
// and immutable repository Secret revision that created it.
type ArtifactProvenance struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact backup provenance is immutable"
	BackupRef ExactLocalReference `json:"backupRef"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact repository provenance is immutable"
	RepositorySecretRef ExactSecretReference `json:"repositorySecretRef"`
}

// CandidateDataVerification proves freshly populated restore claims match the
// verified artifact manifest before any activation begins.
type CandidateDataVerification struct {
	// +kubebuilder:validation:Enum=Verified
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="candidate verification result is immutable"
	Result VerificationResult `json:"result"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="candidate manifest digest is immutable"
	ManifestDigest string `json:"manifestDigest"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="candidate path count is immutable"
	PathCount int32 `json:"pathCount"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="candidate verification time is immutable"
	VerifiedAt metav1.Time `json:"verifiedAt"`
}

// BackupArtifact identifies a complete repository object. ID is derived from
// the GameBackup UID, making same-object retries converge on one artifact.
type BackupArtifact struct {
	Provenance ArtifactProvenance `json:"provenance"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact ID is immutable"
	ID string `json:"id"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=32
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact format is immutable"
	FormatVersion string `json:"formatVersion"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact manifest digest is immutable"
	ManifestDigest string `json:"manifestDigest"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact size is immutable"
	SizeBytes int64 `json:"sizeBytes"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact path count is immutable"
	PathCount int32 `json:"pathCount"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact creation time is immutable"
	CreatedAt metav1.Time `json:"createdAt"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="artifact verification is immutable"
	Verification ArtifactVerification `json:"verification"`
}

// DataOperationStatus holds fields common to durable operation status.
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || !(self.phase in ['Blocked', 'Failed']) || (has(self.conditions) && self.conditions.exists(condition, condition.status != 'True' && condition.message.size() > 0))",message="blocked and failed phases require an actionable false or unknown condition"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || !(self.phase in ['Running', 'Verifying', 'Activating', 'RollingBack', 'Succeeded']) || has(self.fence)",message="data work requires an immutable cold data fence"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || self.phase != 'Succeeded' || (has(self.source) && has(self.artifact) && self.artifact.verification.result == 'Verified' && has(self.artifact.verification.verifiedAt) && self.artifact.pathCount == self.source.paths.size())",message="succeeded phase requires a verified complete artifact and source manifest"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.source) || has(self.source)",message="resolved source status cannot be removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.fence) || has(self.fence)",message="cold data fence cannot be removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.artifact) || has(self.artifact)",message="artifact status cannot be removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.runtime) || has(self.runtime)",message="runtime disposition cannot be removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.phase) || !(oldSelf.phase in ['Cancelled', 'Succeeded', 'Failed']) || (has(self.phase) && self.phase == oldSelf.phase)",message="terminal operation phase cannot change"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || !(self.phase in ['Cancelled', 'Succeeded', 'Failed']) || !has(self.fence) || has(self.runtime)",message="terminal operation with a data fence requires runtime disposition"
type DataOperationStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	Phase DataOperationPhase `json:"phase,omitempty"`
	// +optional
	// +kubebuilder:validation:Minimum=0
	Attempts int32 `json:"attempts,omitempty"`
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
	Source *DataSourceSnapshot `json:"source,omitempty"`
	// +optional
	Fence *ColdDataFence `json:"fence,omitempty"`
	// +optional
	Artifact *BackupArtifact `json:"artifact,omitempty"`
	// +optional
	Runtime *RuntimeDisposition `json:"runtime,omitempty"`
}

// GameBackupStatus is the observable cold-backup state.
type GameBackupStatus struct {
	DataOperationStatus `json:",inline"`
}

// GameRestoreStatus records isolated restore data identities. Candidate data
// cannot become active until artifact and candidate verification succeeds;
// PreviousData remains available for rollback.
// +kubebuilder:validation:XValidation:rule="!has(self.activationStartedAt) || (has(self.source) && has(self.artifact) && self.artifact.verification.result == 'Verified' && self.artifact.pathCount == self.source.paths.size() && has(self.candidateVerification) && self.candidateVerification.result == 'Verified' && self.candidateVerification.manifestDigest == self.artifact.manifestDigest && self.candidateVerification.pathCount == self.source.paths.size())",message="activation history requires verified artifact and candidate contents"
// +kubebuilder:validation:XValidation:rule="!has(self.activationStartedAt) || (has(self.source) && has(self.candidateData) && self.candidateData.size() == self.source.paths.size() && self.source.paths.all(sourcePath, self.candidateData.exists(candidatePath, candidatePath.name == sourcePath.name && candidatePath.mountPath == sourcePath.mountPath)))",message="activation history requires complete candidate data"
// +kubebuilder:validation:XValidation:rule="!has(self.candidateData) || self.candidateData.all(path, self.candidateData.filter(other, other.claimRef.name == path.claimRef.name).size() == 1 && self.candidateData.filter(other, other.claimRef.uid == path.claimRef.uid).size() == 1)",message="candidate paths must use unique claim identities"
// +kubebuilder:validation:XValidation:rule="!has(self.previousData) || self.previousData.all(path, self.previousData.filter(other, other.claimRef.name == path.claimRef.name).size() == 1 && self.previousData.filter(other, other.claimRef.uid == path.claimRef.uid).size() == 1)",message="previous paths must use unique claim identities"
// +kubebuilder:validation:XValidation:rule="!has(self.activeData) || self.activeData.all(path, self.activeData.filter(other, other.claimRef.name == path.claimRef.name).size() == 1 && self.activeData.filter(other, other.claimRef.uid == path.claimRef.uid).size() == 1)",message="active paths must use unique claim identities"
// +kubebuilder:validation:XValidation:rule="!has(self.activationStartedAt) || (has(self.source) && has(self.candidateData) && has(self.previousData) && self.previousData.size() == self.source.paths.size() && self.source.paths.all(sourcePath, self.previousData.exists(previousPath, previousPath.name == sourcePath.name && previousPath.mountPath == sourcePath.mountPath)) && self.previousData.all(previousPath, self.candidateData.all(candidatePath, candidatePath.claimRef.name != previousPath.claimRef.name && candidatePath.claimRef.uid != previousPath.claimRef.uid)))",message="activation history requires complete globally distinct rollback data"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || !(self.phase in ['Activating', 'RollingBack', 'Succeeded']) || has(self.activationStartedAt)",message="activation phases require durable activation history"
// +kubebuilder:validation:XValidation:rule="!has(self.activationStartedAt) || !(self.phase in ['Failed', 'Cancelled']) || (has(self.source) && has(self.previousData) && has(self.activeData) && self.activeData.size() == self.source.paths.size() && self.activeData.all(activePath, self.previousData.exists(previousPath, previousPath.name == activePath.name && previousPath.mountPath == activePath.mountPath && previousPath.claimRef.name == activePath.claimRef.name && previousPath.claimRef.uid == activePath.claimRef.uid)))",message="terminal restore after activation requires active data to equal rollback data"
// +kubebuilder:validation:XValidation:rule="!has(self.phase) || self.phase != 'Succeeded' || (has(self.source) && has(self.candidateData) && has(self.activeData) && self.activeData.size() == self.source.paths.size() && self.activeData.all(activePath, self.candidateData.exists(candidatePath, candidatePath.name == activePath.name && candidatePath.mountPath == activePath.mountPath && candidatePath.claimRef.name == activePath.claimRef.name && candidatePath.claimRef.uid == activePath.claimRef.uid)))",message="succeeded restore requires active data to equal verified candidates"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.activationStartedAt) || has(self.activationStartedAt)",message="activation history cannot be removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.candidateData) || has(self.candidateData)",message="candidate data cannot be removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.candidateVerification) || has(self.candidateVerification)",message="candidate verification cannot be removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.activeData) || has(self.activeData)",message="active data cannot be removed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.previousData) || has(self.previousData)",message="previous data cannot be removed"
type GameRestoreStatus struct {
	DataOperationStatus `json:",inline"`
	// ActivationStartedAt is set once immediately before the first mutation
	// that can redirect active data. Its presence makes rollback obligations
	// durable even after the phase becomes Failed or Cancelled.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="activation start time is immutable"
	ActivationStartedAt *metav1.Time `json:"activationStartedAt,omitempty"`
	// +optional
	CandidateVerification *CandidateDataVerification `json:"candidateVerification,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="candidate data is immutable"
	CandidateData []DataPathIdentity `json:"candidateData,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="active data is immutable"
	ActiveData []DataPathIdentity `json:"activeData,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="previous data is immutable"
	PreviousData []DataPathIdentity `json:"previousData,omitempty"`
}

// GameBackup requests one durable cold backup.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gb
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.source.name`
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.fence) || (self.status.fence.gameServer.name == self.spec.source.name && self.status.fence.gameServer.uid == self.spec.source.uid && self.status.fence.gameServer.desiredState == 'Stopped' && ((self.spec.source.desiredState == 'Running' && self.status.fence.gameServer.generation == self.spec.source.generation + 1) || (self.spec.source.desiredState == 'Stopped' && self.status.fence.gameServer.generation == self.spec.source.generation)))",message="cold data fence must match the exact operation-owned stopped generation"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.runtime) || (has(self.status.fence) && self.status.runtime.gameServer.name == self.spec.source.name && self.status.runtime.gameServer.uid == self.spec.source.uid && ((self.spec.restartPolicy == 'RestorePreviousState' && self.spec.source.desiredState == 'Running' && self.status.runtime.gameServer.desiredState == 'Running' && self.status.runtime.gameServer.generation == self.status.fence.gameServer.generation + 1) || ((self.spec.restartPolicy != 'RestorePreviousState' || self.spec.source.desiredState == 'Stopped') && self.status.runtime.gameServer.desiredState == 'Stopped' && self.status.runtime.gameServer.generation == self.status.fence.gameServer.generation)))",message="runtime disposition must match the exact operation-owned final generation"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.artifact) || (self.status.artifact.provenance.backupRef.name == self.metadata.name && self.status.artifact.provenance.repositorySecretRef.name == self.spec.repositorySecretRef.name && self.status.artifact.provenance.repositorySecretRef.uid == self.spec.repositorySecretRef.uid && self.status.artifact.provenance.repositorySecretRef.resourceVersion == self.spec.repositorySecretRef.resourceVersion)",message="artifact provenance must match the backup operation and repository"
type GameBackup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GameBackupSpec   `json:"spec"`
	Status GameBackupStatus `json:"status,omitempty"`
}

// GameBackupList is a list of GameBackup objects.
// +kubebuilder:object:root=true
type GameBackupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GameBackup `json:"items"`
}

// GameRestore requests an isolated restore and verified atomic activation.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gr
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.target.name`
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.fence) || (self.status.fence.gameServer.name == self.spec.target.name && self.status.fence.gameServer.uid == self.spec.target.uid && self.status.fence.gameServer.desiredState == 'Stopped' && ((self.spec.target.desiredState == 'Running' && self.status.fence.gameServer.generation == self.spec.target.generation + 1) || (self.spec.target.desiredState == 'Stopped' && self.status.fence.gameServer.generation == self.spec.target.generation)))",message="cold data fence must match the exact operation-owned stopped generation"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.runtime) || (has(self.status.fence) && self.status.runtime.gameServer.name == self.spec.target.name && self.status.runtime.gameServer.uid == self.spec.target.uid && ((self.spec.restartPolicy == 'RestorePreviousState' && self.spec.target.desiredState == 'Running' && self.status.runtime.gameServer.desiredState == 'Running' && self.status.runtime.gameServer.generation == self.status.fence.gameServer.generation + 1) || ((self.spec.restartPolicy != 'RestorePreviousState' || self.spec.target.desiredState == 'Stopped') && self.status.runtime.gameServer.desiredState == 'Stopped' && self.status.runtime.gameServer.generation == self.status.fence.gameServer.generation)))",message="runtime disposition must match the exact operation-owned final generation"
// +kubebuilder:validation:XValidation:rule="!has(self.status) || !has(self.status.artifact) || (self.status.artifact.provenance.backupRef.name == self.spec.backupRef.name && self.status.artifact.provenance.backupRef.uid == self.spec.backupRef.uid && self.status.artifact.provenance.repositorySecretRef.name == self.spec.repositorySecretRef.name && self.status.artifact.provenance.repositorySecretRef.uid == self.spec.repositorySecretRef.uid && self.status.artifact.provenance.repositorySecretRef.resourceVersion == self.spec.repositorySecretRef.resourceVersion)",message="restore artifact provenance must match the exact backup and repository"
type GameRestore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GameRestoreSpec   `json:"spec"`
	Status GameRestoreStatus `json:"status,omitempty"`
}

// GameRestoreList is a list of GameRestore objects.
// +kubebuilder:object:root=true
type GameRestoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GameRestore `json:"items"`
}

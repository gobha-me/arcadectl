// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ArcadeOperationAction is ordinary administrator intent. There is deliberately
// no unsafe-no-backup action: that exception remains a distinct Kubernetes
// administrator boundary, not a bearer API capability.
// +kubebuilder:validation:Enum=server.create;server.configure;server.start;server.stop;server.restart;server.update;world.backup;world.restore;server.decommission;world.destroy.preview;world.destroy.confirm;world.destroy.cancel
type ArcadeOperationAction string

const (
	OperationServerCreate        ArcadeOperationAction = "server.create"
	OperationServerConfigure     ArcadeOperationAction = "server.configure"
	OperationServerStart         ArcadeOperationAction = "server.start"
	OperationServerStop          ArcadeOperationAction = "server.stop"
	OperationServerRestart       ArcadeOperationAction = "server.restart"
	OperationServerUpdate        ArcadeOperationAction = "server.update"
	OperationWorldBackup         ArcadeOperationAction = "world.backup"
	OperationWorldRestore        ArcadeOperationAction = "world.restore"
	OperationServerDecommission  ArcadeOperationAction = "server.decommission"
	OperationWorldDestroyPreview ArcadeOperationAction = "world.destroy.preview"
	OperationWorldDestroyConfirm ArcadeOperationAction = "world.destroy.confirm"
	OperationWorldDestroyCancel  ArcadeOperationAction = "world.destroy.cancel"
)

// ArcadeOperationPhase is durable status, not the lifetime of an HTTP request.
// Credential expiry or rotation does not cancel an already admitted receipt.
// +kubebuilder:validation:Enum=Accepted;Planning;Running;AwaitingConfirmation;Verifying;Deleting;Succeeded;Failed;Cancelled
type ArcadeOperationPhase string

const (
	OperationPhaseAccepted             ArcadeOperationPhase = "Accepted"
	OperationPhasePlanning             ArcadeOperationPhase = "Planning"
	OperationPhaseRunning              ArcadeOperationPhase = "Running"
	OperationPhaseAwaitingConfirmation ArcadeOperationPhase = "AwaitingConfirmation"
	OperationPhaseVerifying            ArcadeOperationPhase = "Verifying"
	OperationPhaseDeleting             ArcadeOperationPhase = "Deleting"
	OperationPhaseSucceeded            ArcadeOperationPhase = "Succeeded"
	OperationPhaseFailed               ArcadeOperationPhase = "Failed"
	OperationPhaseCancelled            ArcadeOperationPhase = "Cancelled"
)

// OperationAdmission contains non-secret audit correlation only. It is not a
// serialized authorization capability and is never re-authenticated by workers.
type OperationAdmission struct {
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.-]{1,64}$`
	PrincipalID string `json:"principalID"`
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.-]{1,64}$`
	CredentialID string `json:"credentialID"`
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{32}$`
	RequestID           string      `json:"requestID"`
	AdmittedAt          metav1.Time `json:"admittedAt"`
	CredentialExpiresAt metav1.Time `json:"credentialExpiresAt"`
}

// OperationImageResolution freezes the winner of concurrent version selection.
// The original request digest excludes this server-produced resolution, so
// retries return the winner rather than resolving a mutable tag again.
type OperationImageResolution struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Repository string `json:"repository"`
	// +optional
	// +kubebuilder:validation:MaxLength=128
	Tag string `json:"tag,omitempty"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	Digest     string      `json:"digest"`
	ResolvedAt metav1.Time `json:"resolvedAt"`
	// +kubebuilder:validation:Enum=registry-v1;digest-v1
	ResolverVersion string `json:"resolverVersion"`
}

// OperationImageInput selects an exact digest OR an adapter-approved version.
// No caller-supplied repository, registry, tag, command, or URL is accepted.
// +kubebuilder:validation:XValidation:rule="has(self.digest) != has(self.version)",message="select exactly one digest or version"
type OperationImageInput struct {
	// +optional
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	Digest string `json:"digest,omitempty"`
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	Version    string                   `json:"version,omitempty"`
	Resolution OperationImageResolution `json:"resolution"`
}

// OperationRetainedWorldSelector requires durable original identity rather than
// the existence or identity of a later same-name GameServer.
type OperationRetainedWorldSelector struct {
	DecommissionOperationRef ExactLocalReference `json:"decommissionOperationRef"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	SnapshotDigest string `json:"snapshotDigest"`
}

// OperationServerIntent is a bounded, fully typed future GameServer spec.
// Canonical settings are stored as a string, not preserve-unknown JSON fields,
// so admission can prove complete receipt/plan immutability with CEL equality.
type OperationServerIntent struct {
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Game string `json:"game"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ImageDigest  string       `json:"imageDigest"`
	DesiredState DesiredState `json:"desiredState"`
	Compute      ComputeSpec  `json:"compute"`
	Storage      StorageSpec  `json:"storage"`
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=65536
	SettingsJSON string `json:"settingsJSON"`
}

type OperationCreateInput struct {
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Game         string       `json:"game"`
	DesiredState DesiredState `json:"desiredState"`
	Compute      ComputeSpec  `json:"compute"`
	Storage      StorageSpec  `json:"storage"`
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=65536
	SettingsJSON string `json:"settingsJSON"`
	// +optional
	RetainedWorld *OperationRetainedWorldSelector `json:"retainedWorld,omitempty"`
}

type OperationConfigureInput struct {
	// +optional
	Compute *ComputeSpec `json:"compute,omitempty"`
	// +optional
	Storage *StorageSpec `json:"storage,omitempty"`
	// +optional
	// +kubebuilder:validation:MinLength=2
	// +kubebuilder:validation:MaxLength=65536
	SettingsJSON *string `json:"settingsJSON,omitempty"`
}

type OperationBackupInput struct {
	// RepositorySecretName is resolved once, controller-side, to immutable exact
	// UID/resourceVersion evidence before any child operation is created.
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$`
	RepositorySecretName string        `json:"repositorySecretName"`
	RestartPolicy        RestartPolicy `json:"restartPolicy"`
}

type OperationRestoreInput struct {
	BackupRef     ExactLocalReference `json:"backupRef"`
	RestartPolicy RestartPolicy       `json:"restartPolicy"`
}

type OperationDestroyInput struct {
	BackupRef ExactLocalReference `json:"backupRef"`
	// +optional
	RetainedWorld *OperationRetainedWorldSelector `json:"retainedWorld,omitempty"`
}

type OperationDestroyCommand struct {
	ParentOperationRef ExactLocalReference `json:"parentOperationRef"`
	DestroyRef         ExactLocalReference `json:"destroyRef"`
	// +optional
	// +kubebuilder:validation:MinLength=16
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_-]+$`
	Challenge string `json:"challenge,omitempty"`
}

// OperationRequest is the typed request union. The translator also validates
// action/field consistency before planning: direct Kubernetes administrators
// cannot accidentally turn an invalid receipt into another operation.
type OperationRequest struct {
	// Precondition is the canonical original If-Match predicate, or "absent"
	// for create with If-None-Match:*. It remains stable when current state changes.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_.:"-]+$`
	Precondition string `json:"precondition"`
	// +optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	ServerName string `json:"serverName,omitempty"`
	// +optional
	Target *ExactGameServerReference `json:"target,omitempty"`
	// +optional
	Create *OperationCreateInput `json:"create,omitempty"`
	// +optional
	Configure *OperationConfigureInput `json:"configure,omitempty"`
	// +optional
	Image *OperationImageInput `json:"image,omitempty"`
	// +optional
	Backup *OperationBackupInput `json:"backup,omitempty"`
	// +optional
	Restore *OperationRestoreInput `json:"restore,omitempty"`
	// +optional
	Destroy *OperationDestroyInput `json:"destroy,omitempty"`
	// +optional
	DestroyCommand *OperationDestroyCommand `json:"destroyCommand,omitempty"`
}

// ArcadeOperationSpec is an immutable idempotency/admission receipt. Raw keys,
// credentials, authentication claims, raw HTTP bodies, and authorization capabilities are never
// persisted. Only an API-authenticated and audited create (or a separately
// trusted Kubernetes administrator) admits a receipt.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="operation admission and request are immutable"
type ArcadeOperationSpec struct {
	// +kubebuilder:validation:Enum=v1
	Version   string                `json:"version"`
	Action    ArcadeOperationAction `json:"action"`
	Admission OperationAdmission    `json:"admission"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	KeyDigest string `json:"keyDigest"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	RequestDigest string           `json:"requestDigest"`
	Request       OperationRequest `json:"request"`
}

// OperationPlan freezes all name resolutions before side effects. Later name
// reuse or Secret replacement must fail, never follow the replacement.
type OperationPlan struct {
	// +optional
	Server *ExactGameServerReference `json:"server,omitempty"`
	// +optional
	ServerIntent *OperationServerIntent `json:"serverIntent,omitempty"`
	// +optional
	Data *RetainedDataReference `json:"data,omitempty"`
	// +optional
	RepositorySecretRef *ExactSecretReference `json:"repositorySecretRef,omitempty"`
	// +optional
	BackupRef *ExactLocalReference `json:"backupRef,omitempty"`
	// +optional
	DestroyRef *ExactLocalReference `json:"destroyRef,omitempty"`
}

type OperationChildReference struct {
	// +kubebuilder:validation:Enum=GameServer;GameBackup;GameRestore;GameDestroy
	Kind                string `json:"kind"`
	ExactLocalReference `json:",inline"`
	// +kubebuilder:validation:Minimum=1
	Generation int64 `json:"generation"`
}

// OperationServerTransition is a write-ahead journal. An atomic GameServer
// metadata marker names this exact receipt UID and step alongside the spec
// patch; generation/state alone cannot attribute another actor's mutation.
type OperationServerTransition struct {
	// +kubebuilder:validation:Enum=Apply;Stop;Start
	Step string `json:"step"`
	// +kubebuilder:validation:Minimum=1
	FromGeneration int64 `json:"fromGeneration"`
	// +kubebuilder:validation:Minimum=1
	ToGeneration int64        `json:"toGeneration"`
	DesiredState DesiredState `json:"desiredState"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	SpecDigest  string      `json:"specDigest"`
	RequestedAt metav1.Time `json:"requestedAt"`
}

type OperationRetainedWorld struct {
	Target GameDestroyTarget `json:"target"`
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	SnapshotDigest string `json:"snapshotDigest"`
}

// OperationFailure is bounded controller-authored guidance, never a raw error.
type OperationFailure struct {
	// +kubebuilder:validation:Enum=invalid_request;target_changed;operation_conflict;invalid_reference;secret_unavailable;unsupported;image_unavailable;validation_failed;worker_failed;verification_failed;too_late;confirmation_expired;child_changed;api_unavailable;receipt_invalid
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	Message string `json:"message"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	SuggestedAction string `json:"suggestedAction"`
}

// ArcadeOperationStatus is maintained only by the translator. A destroy parent
// keeps following its native child while confirm/cancel command receipts settle.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.plan) || (has(self.plan) && self.plan == oldSelf.plan)",message="operation plan cannot be cleared or changed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.child) || (has(self.child) && self.child == oldSelf.child)",message="operation child cannot be cleared or changed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.retainedWorld) || (has(self.retainedWorld) && self.retainedWorld == oldSelf.retainedWorld)",message="retained world snapshot cannot be cleared or changed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.transitions) || (has(self.transitions) && oldSelf.transitions.all(entry, self.transitions.exists(current, current == entry)))",message="operation journal cannot be removed or changed"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.phase) || !(oldSelf.phase in ['Succeeded', 'Failed', 'Cancelled']) || self == oldSelf",message="terminal operation status is immutable"
type ArcadeOperationStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	Phase ArcadeOperationPhase `json:"phase,omitempty"`
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`
	// +optional
	Plan *OperationPlan `json:"plan,omitempty"`
	// +optional
	Child *OperationChildReference `json:"child,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=3
	// +listType=map
	// +listMapKey=step
	Transitions []OperationServerTransition `json:"transitions,omitempty"`
	// +optional
	RetainedWorld *OperationRetainedWorld `json:"retainedWorld,omitempty"`
	// +optional
	DestroyPreview *GameDestroyPreview `json:"destroyPreview,omitempty"`
	// +optional
	Failure *OperationFailure `json:"failure,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ArcadeOperation is the durable admission/idempotency ledger. API RBAC cannot
// update/delete receipts or write status. Deleting a receipt never owns/deletes
// a GameServer, its retained PVCs, or a backup artifact.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.status) || has(self.status)",message="operation status cannot be removed"
// +kubebuilder:resource:shortName=ao
// +kubebuilder:printcolumn:name="Action",type=string,JSONPath=`.spec.action`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
type ArcadeOperation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ArcadeOperationSpec   `json:"spec"`
	Status            ArcadeOperationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ArcadeOperationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ArcadeOperation `json:"items"`
}

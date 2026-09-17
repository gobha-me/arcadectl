// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DesiredState is the administrator's durable power intent.
// +kubebuilder:validation:Enum=Running;Stopped
type DesiredState string

const (
	// DesiredStateRunning requests an active game workload.
	DesiredStateRunning DesiredState = "Running"
	// DesiredStateStopped requests retained data without active compute.
	DesiredStateStopped DesiredState = "Stopped"
)

// GameServerPhase summarizes observed lifecycle state.
// +kubebuilder:validation:Enum=Pending;Starting;Ready;Stopping;Stopped;Failed
type GameServerPhase string

const (
	PhasePending  GameServerPhase = "Pending"
	PhaseStarting GameServerPhase = "Starting"
	PhaseReady    GameServerPhase = "Ready"
	PhaseStopping GameServerPhase = "Stopping"
	PhaseStopped  GameServerPhase = "Stopped"
	PhaseFailed   GameServerPhase = "Failed"
)

// Stable GameServer condition types. Every observed status contains this
// complete set in this order so consumers never have to infer stale state.
const (
	ConditionSpecValid          = "SpecValid"
	ConditionStorageReady       = "StorageReady"
	ConditionConfigurationReady = "ConfigurationReady"
	ConditionWorkloadReady      = "WorkloadReady"
	ConditionNetworkReady       = "NetworkReady"
	ConditionReady              = "Ready"
)

// Stable GameServer condition reasons. Messages may become more specific,
// but automation should depend only on these bounded reason codes.
const (
	ReasonValid                         = "Valid"
	ReasonInvalidSpec                   = "InvalidSpec"
	ReasonControllerMisconfigured       = "ControllerMisconfigured"
	ReasonClaimsReady                   = "ClaimsReady"
	ReasonClaimsProvisioning            = "ClaimsProvisioning"
	ReasonClaimExpansionPending         = "ClaimExpansionPending"
	ReasonStorageOperationFailed        = "StorageOperationFailed"
	ReasonRetainedDataReferenceRequired = "RetainedDataReferenceRequired"
	ReasonRetainedDataMissing           = "RetainedDataMissing"
	ReasonRetainedDataConflict          = "RetainedDataConflict"
	ReasonConfigurationReady            = "ConfigurationReady"
	ReasonConfigurationOperationFailed  = "ConfigurationOperationFailed"
	ReasonWorkloadAvailable             = "WorkloadAvailable"
	ReasonWorkloadProgressing           = "WorkloadProgressing"
	ReasonWorkloadUnavailable           = "WorkloadUnavailable"
	ReasonWorkloadOperationFailed       = "WorkloadOperationFailed"
	ReasonPlayerEndpointReady           = "PlayerEndpointReady"
	ReasonPlayerEndpointPending         = "PlayerEndpointPending"
	ReasonNetworkOperationFailed        = "NetworkOperationFailed"
	ReasonResourceCollision             = "ResourceCollision"
	ReasonBlocked                       = "Blocked"
	ReasonRuntimeStopping               = "RuntimeStopping"
	ReasonRuntimeStopped                = "RuntimeStopped"
	ReasonReady                         = "Ready"
	ReasonStoragePending                = "StoragePending"
	ReasonWorkloadPending               = "WorkloadPending"
	ReasonReconcileFailed               = "ReconcileFailed"
)

// RetainedDataClaimReference pins one adapter path to one exact local PVC.
// The namespace is always the containing GameServer namespace.
type RetainedDataClaimReference struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`
	Path     string              `json:"path"`
	ClaimRef ExactLocalReference `json:"claimRef"`
}

// RetainedDataReference is explicit authority to reattach one complete
// retained data set. Identity must match every referenced claim's durable
// data-identity label; Claims must cover every adapter-declared path exactly.
type RetainedDataReference struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`
	Identity string `json:"identity"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=path
	Claims []RetainedDataClaimReference `json:"claims"`
}

// ComputeSpec bounds CPU and memory assigned to the game container.
type ComputeSpec struct {
	CPURequest    resource.Quantity `json:"cpuRequest"`
	CPULimit      resource.Quantity `json:"cpuLimit"`
	MemoryRequest resource.Quantity `json:"memoryRequest"`
	MemoryLimit   resource.Quantity `json:"memoryLimit"`
}

// StorageSpec describes each adapter-declared persistent data claim. The same
// size and storage class are applied independently to every persistent path.
type StorageSpec struct {
	Size resource.Quantity `json:"size"`
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`
	// Reattach explicitly selects a complete retained data set. When omitted,
	// the controller creates data for this GameServer identity and refuses to
	// adopt claims retained by an earlier same-name GameServer.
	// +optional
	Reattach *RetainedDataReference `json:"reattach,omitempty"`
}

// GameServerSpec is the validated desired state accepted by the controller.
type GameServerSpec struct {
	// Game selects a curated adapter from the installed catalog.
	// +kubebuilder:validation:Pattern=`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="game is immutable"
	Game string `json:"game"`

	// ImageDigest is resolved by the authenticated API before this resource is
	// created or updated. Workloads never launch a mutable tag.
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	ImageDigest string `json:"imageDigest"`

	// +kubebuilder:default=Stopped
	DesiredState DesiredState `json:"desiredState"`

	Compute ComputeSpec `json:"compute"`
	Storage StorageSpec `json:"storage"`

	// Settings must satisfy the selected adapter's bounded JSON Schema. They
	// cannot contain credentials; secret references get a separate contract.
	// +kubebuilder:pruning:PreserveUnknownFields
	Settings runtime.RawExtension `json:"settings"`
}

// ObservedEndpoint reports a reachable player endpoint without exposing
// administrator-only or internal ports.
type ObservedEndpoint struct {
	// +kubebuilder:validation:Pattern=`^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$`
	Name string `json:"name"`
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol string `json:"protocol"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9:][a-z0-9.:-]*$`
	Address string `json:"address"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// GameServerStatus is controller-owned observed state.
type GameServerStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	Phase GameServerPhase `json:"phase,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=name
	Endpoints []ObservedEndpoint `json:"endpoints,omitempty"`
}

// GameServer declares one durable game-server identity.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=gs
// +kubebuilder:printcolumn:name="Game",type=string,JSONPath=`.spec.game`
// +kubebuilder:printcolumn:name="Desired",type=string,JSONPath=`.spec.desiredState`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:validation:XValidation:rule="(!has(self.spec.storage.reattach) && !has(oldSelf.spec.storage.reattach)) || (has(self.spec.storage.reattach) && has(oldSelf.spec.storage.reattach) && self.spec.storage.reattach == oldSelf.spec.storage.reattach)",message="reattach authority is immutable for a GameServer identity; delete the stopped GameServer and recreate it to select retained data"
type GameServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GameServerSpec   `json:"spec"`
	Status GameServerStatus `json:"status,omitempty"`
}

// GameServerList is a list of GameServer objects.
// +kubebuilder:object:root=true
type GameServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GameServer `json:"items"`
}

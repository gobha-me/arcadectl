// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package v1 defines the versioned ordinary-administrator HTTP contract.
// It contains no Kubernetes mutation client or unsafe-destruction request.
package v1

import "encoding/json"

const Version = "v1"

// Self binds a verified client context to the stable administrator and namespace.
type Self struct {
	Version      string `json:"version"`
	PrincipalID  string `json:"principalId"`
	CredentialID string `json:"credentialId"`
	ExpiresAt    string `json:"expiresAt"`
	Namespace    string `json:"namespace"`
}

type Compute struct {
	CPURequest    string `json:"cpuRequest"`
	CPULimit      string `json:"cpuLimit"`
	MemoryRequest string `json:"memoryRequest"`
	MemoryLimit   string `json:"memoryLimit"`
}
type Storage struct {
	Size             string  `json:"size"`
	StorageClassName *string `json:"storageClassName,omitempty"`
}
type Image struct {
	Digest  string `json:"digest,omitempty"`
	Version string `json:"version,omitempty"`
}
type ExactReference struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}
type RetainedSelector struct {
	DecommissionOperationRef ExactReference `json:"decommissionOperationRef"`
	SnapshotDigest           string         `json:"snapshotDigest"`
}
type CreateRequest struct {
	Version       string            `json:"version"`
	Name          string            `json:"name"`
	Game          string            `json:"game"`
	Image         Image             `json:"image"`
	DesiredState  string            `json:"desiredState"`
	Compute       Compute           `json:"compute"`
	Storage       Storage           `json:"storage"`
	Settings      json.RawMessage   `json:"settings"`
	RetainedWorld *RetainedSelector `json:"retainedWorld,omitempty"`
}
type ConfigureRequest struct {
	Version  string          `json:"version"`
	Compute  *Compute        `json:"compute,omitempty"`
	Storage  *Storage        `json:"storage,omitempty"`
	Settings json.RawMessage `json:"settings,omitempty"`
}
type EmptyRequest struct {
	Version string `json:"version"`
}
type UpdateRequest struct {
	Version string `json:"version"`
	Image   Image  `json:"image"`
}
type BackupRequest struct {
	Version              string `json:"version"`
	RepositorySecretName string `json:"repositorySecretName"`
	RestartPolicy        string `json:"restartPolicy"`
}
type RestoreRequest struct {
	Version       string         `json:"version"`
	BackupRef     ExactReference `json:"backupRef"`
	RestartPolicy string         `json:"restartPolicy"`
}
type DestroyRequest struct {
	Version   string         `json:"version"`
	BackupRef ExactReference `json:"backupRef"`
}
type ConfirmRequest struct {
	Version    string         `json:"version"`
	DestroyRef ExactReference `json:"destroyRef"`
	Challenge  string         `json:"challenge"`
}
type CancelRequest struct {
	Version    string         `json:"version"`
	DestroyRef ExactReference `json:"destroyRef"`
}
type Error struct {
	Version         string `json:"version"`
	Code            string `json:"code"`
	OperationID     string `json:"operationID,omitempty"`
	Retryable       bool   `json:"retryable,omitempty"`
	SuggestedAction string `json:"suggestedAction,omitempty"`
}
type Condition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	ObservedGeneration int64  `json:"observedGeneration"`
}
type Endpoint struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int32  `json:"port"`
}
type Server struct {
	Version            string          `json:"version"`
	Name               string          `json:"name"`
	UID                string          `json:"uid"`
	Generation         int64           `json:"generation"`
	Game               string          `json:"game"`
	ImageDigest        string          `json:"imageDigest"`
	DesiredState       string          `json:"desiredState"`
	Compute            Compute         `json:"compute"`
	Storage            Storage         `json:"storage"`
	Settings           json.RawMessage `json:"settings"`
	Phase              string          `json:"phase"`
	ObservedGeneration int64           `json:"observedGeneration"`
	Conditions         []Condition     `json:"conditions"`
	Endpoints          []Endpoint      `json:"endpoints"`
}
type ServerList struct {
	Version string   `json:"version"`
	Items   []Server `json:"items"`
}
type OperationChild struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}
type Failure struct {
	Code            string `json:"code"`
	Retryable       bool   `json:"retryable"`
	Message         string `json:"message"`
	SuggestedAction string `json:"suggestedAction"`
}
type DestroyPreview struct {
	Target          DestroyTarget  `json:"target"`
	BackupRef       ExactReference `json:"backupRef"`
	Challenge       string         `json:"challenge"`
	ExpiresAt       string         `json:"expiresAt"`
	RestoreGuidance string         `json:"restoreGuidance"`
}

// DestroyTarget is derived from immutable original identity evidence, never live names.
type DestroyTarget struct {
	Namespace      string          `json:"namespace"`
	OriginalServer ExactReference  `json:"originalServer"`
	Game           string          `json:"game"`
	DataIdentity   string          `json:"dataIdentity"`
	Claims         []RetainedClaim `json:"claims"`
}
type Operation struct {
	Version            string          `json:"version"`
	OperationID        string          `json:"operationID"`
	UID                string          `json:"uid"`
	Generation         int64           `json:"generation"`
	Action             string          `json:"action"`
	Phase              string          `json:"phase"`
	ObservedGeneration int64           `json:"observedGeneration"`
	StartedAt          string          `json:"startedAt,omitempty"`
	CompletedAt        string          `json:"completedAt,omitempty"`
	Child              *OperationChild `json:"child,omitempty"`
	Failure            *Failure        `json:"failure,omitempty"`
	DestroyPreview     *DestroyPreview `json:"destroyPreview,omitempty"`
	PollURL            string          `json:"pollURL"`
}
type OperationList struct {
	Version string      `json:"version"`
	Items   []Operation `json:"items"`
}
type RetainedClaim struct {
	Path     string         `json:"path"`
	ClaimRef ExactReference `json:"claimRef"`
}
type RetainedWorld struct {
	Version        string          `json:"version"`
	OperationID    string          `json:"operationID"`
	OperationUID   string          `json:"operationUID"`
	OriginalServer ExactReference  `json:"originalServer"`
	Game           string          `json:"game"`
	DataIdentity   string          `json:"dataIdentity"`
	Claims         []RetainedClaim `json:"claims"`
	SnapshotDigest string          `json:"snapshotDigest"`
}
type NativeOperation struct {
	Version            string          `json:"version"`
	Kind               string          `json:"kind"`
	Name               string          `json:"name"`
	UID                string          `json:"uid"`
	Generation         int64           `json:"generation"`
	Phase              string          `json:"phase"`
	ObservedGeneration int64           `json:"observedGeneration"`
	CompletedAt        string          `json:"completedAt,omitempty"`
	Conditions         []Condition     `json:"conditions"`
	DestroyPreview     *DestroyPreview `json:"destroyPreview,omitempty"`
}

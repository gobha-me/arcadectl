// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package clilifecycle prepares ordinary lifecycle HTTP intents. It never
// submits a mutation and has no Kubernetes client or workload authority.
package clilifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/cliintent"
)

var ErrInvalidInput = errors.New("invalid lifecycle input")
var ErrInvalidReference = errors.New("invalid lifecycle reference")

type Input struct {
	Action               string           `json:"action"`
	Name                 string           `json:"name,omitempty"`
	Game                 string           `json:"game,omitempty"`
	Image                adminv1.Image    `json:"image"`
	DesiredState         string           `json:"desiredState,omitempty"`
	Compute              *adminv1.Compute `json:"compute,omitempty"`
	Storage              *adminv1.Storage `json:"storage,omitempty"`
	Settings             json.RawMessage  `json:"settings,omitempty"`
	RetainedOperationID  string           `json:"retainedOperationID,omitempty"`
	BackupName           string           `json:"backupName,omitempty"`
	RepositorySecretName string           `json:"repositorySecretName,omitempty"`
	RestartPolicy        string           `json:"restartPolicy,omitempty"`
}

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var subdomainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
var uidPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var quantityPattern = regexp.MustCompile(`^\+?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[numkKMGTPE]|[KMGTPE]i|[eE][+-]?[0-9]+)?$`)

func subdomain(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !subdomainLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
func quantity(value string) bool {
	return len(value) <= 64 && quantityPattern.MatchString(value)
}
func normalized(input Input) (Input, error) {
	hasImage := input.Image.Digest != "" || input.Image.Version != ""
	if hasImage && ((input.Image.Digest == "") == (input.Image.Version == "") || input.Image.Digest != "" && !digestPattern.MatchString(input.Image.Digest) || input.Image.Version != "" && !versionPattern.MatchString(input.Image.Version)) {
		return Input{}, ErrInvalidInput
	}
	if input.Compute != nil {
		copy := *input.Compute
		input.Compute = &copy
		for _, value := range []string{copy.CPURequest, copy.CPULimit, copy.MemoryRequest, copy.MemoryLimit} {
			if !quantity(value) {
				return Input{}, ErrInvalidInput
			}
		}
	}
	if input.Storage != nil {
		copy := *input.Storage
		if !quantity(copy.Size) {
			return Input{}, ErrInvalidInput
		}
		if copy.StorageClassName != nil {
			value := *copy.StorageClassName
			if value != "" && !subdomain(value) {
				return Input{}, ErrInvalidInput
			}
			copy.StorageClassName = &value
		}
		input.Storage = &copy
	}
	if input.Settings != nil {
		value, err := canonicaljson.CanonicalJSON(input.Settings)
		if err != nil || len(value) == 0 || value[0] != '{' {
			return Input{}, ErrInvalidInput
		}
		input.Settings = value
	}
	if input.RetainedOperationID != "" && !labelPattern.MatchString(input.RetainedOperationID) || input.BackupName != "" && !subdomain(input.BackupName) || input.RepositorySecretName != "" && !subdomain(input.RepositorySecretName) {
		return Input{}, ErrInvalidInput
	}
	if input.Action == "world.destroy.preview" && input.RetainedOperationID != "" {
		if input.Name != "" {
			return Input{}, ErrInvalidInput
		}
	} else if !labelPattern.MatchString(input.Name) {
		return Input{}, ErrInvalidInput
	}
	switch input.Action {
	case "server.create":
		if input.DesiredState == "" {
			input.DesiredState = "Stopped"
		}
		if !labelPattern.MatchString(input.Game) || !hasImage || input.Compute == nil || input.Storage == nil || input.Settings == nil || input.DesiredState != "Stopped" && input.DesiredState != "Running" || input.BackupName != "" || input.RepositorySecretName != "" || input.RestartPolicy != "" {
			return Input{}, ErrInvalidInput
		}
	case "server.configure":
		if input.Compute == nil && input.Storage == nil && input.Settings == nil || hasImage || input.Game != "" || input.DesiredState != "" || input.RetainedOperationID != "" || input.BackupName != "" || input.RepositorySecretName != "" || input.RestartPolicy != "" {
			return Input{}, ErrInvalidInput
		}
	case "server.update":
		if !hasImage || input.Game != "" || input.DesiredState != "" || input.Compute != nil || input.Storage != nil || input.Settings != nil || input.RetainedOperationID != "" || input.BackupName != "" || input.RepositorySecretName != "" || input.RestartPolicy != "" {
			return Input{}, ErrInvalidInput
		}
	case "world.backup", "world.restore", "world.destroy.preview":
		if hasImage || input.Game != "" || input.DesiredState != "" || input.Compute != nil || input.Storage != nil || input.Settings != nil {
			return Input{}, ErrInvalidInput
		}
		if input.Action == "world.backup" {
			if input.RepositorySecretName == "" || input.BackupName != "" || input.RetainedOperationID != "" {
				return Input{}, ErrInvalidInput
			}
		} else if input.BackupName == "" || input.RepositorySecretName != "" || input.Action == "world.restore" && input.RetainedOperationID != "" {
			return Input{}, ErrInvalidInput
		}
		if input.Action == "world.destroy.preview" {
			if input.RestartPolicy != "" {
				return Input{}, ErrInvalidInput
			}
		} else {
			if input.RestartPolicy == "" {
				input.RestartPolicy = "LeaveStopped"
			}
			if input.RestartPolicy != "LeaveStopped" && input.RestartPolicy != "RestorePreviousState" {
				return Input{}, ErrInvalidInput
			}
		}
	case "server.start", "server.stop", "server.restart", "server.decommission":
		if hasImage || input.Game != "" || input.DesiredState != "" || input.Compute != nil || input.Storage != nil || input.Settings != nil || input.RetainedOperationID != "" || input.BackupName != "" || input.RepositorySecretName != "" || input.RestartPolicy != "" {
			return Input{}, ErrInvalidInput
		}
	default:
		return Input{}, ErrInvalidInput
	}
	return input, nil
}

// Fingerprint freezes canonical caller intent before live state is read. It
// deliberately includes no resolved ETag, UID or registry digest for a version.
func Fingerprint(input Input) ([]byte, error) {
	input, err := normalized(input)
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(input)
	if err != nil {
		return nil, ErrInvalidInput
	}
	value, err = canonicaljson.CanonicalJSON(value)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return value, nil
}

// Prepare binds a new intent only. A saved attempt must replay its already
// prepared bytes and condition instead of calling Prepare again on retry.
func Prepare(ctx context.Context, client *adminclient.Client, input Input) (cliintent.Intent, error) {
	if _, err := Fingerprint(input); err != nil {
		return cliintent.Intent{}, err
	}
	input, err := normalized(input)
	if err != nil {
		return cliintent.Intent{}, err
	}
	if client == nil || !labelPattern.MatchString(client.Identity().Namespace) || client.Identity().PrincipalID != "admin" {
		return cliintent.Intent{}, ErrInvalidReference
	}
	intent := cliintent.Intent{Action: input.Action, Method: "POST"}
	var body any
	var retained *adminv1.RetainedSelector
	if input.RetainedOperationID != "" {
		world := adminv1.RetainedWorld{}
		etag, err := client.Read(ctx, "/v1/retained-worlds/"+input.RetainedOperationID, &world)
		if err != nil {
			return intent, err
		}
		if !validRetained(world, input.RetainedOperationID) || etag != fmt.Sprintf(`"retained:%s:%s"`, world.OperationUID, world.SnapshotDigest) || input.Action == "server.create" && world.Game != input.Game {
			return intent, ErrInvalidReference
		}
		retained = &adminv1.RetainedSelector{DecommissionOperationRef: adminv1.ExactReference{Name: world.OperationID, UID: world.OperationUID}, SnapshotDigest: world.SnapshotDigest}
		if input.Action == "world.destroy.preview" {
			intent.Path = "/v1/retained-worlds/" + world.OperationID + "/destroy"
			intent.Conditional.IfMatch = etag
		}
	}
	if input.Action != "server.create" && intent.Path == "" {
		server := adminv1.Server{}
		etag, err := client.Read(ctx, "/v1/servers/"+input.Name, &server)
		if err != nil {
			return intent, err
		}
		if server.Version != "v1" || server.Name != input.Name || !uidPattern.MatchString(server.UID) || server.Generation < 1 || etag != fmt.Sprintf(`"server:%s:%d"`, server.UID, server.Generation) {
			return intent, ErrInvalidReference
		}
		intent.Conditional.IfMatch = etag
		intent.Path = "/v1/servers/" + input.Name
	}
	switch input.Action {
	case "server.create":
		intent.Path = "/v1/servers"
		intent.Conditional.IfNoneMatch = true
		body = adminv1.CreateRequest{Version: "v1", Name: input.Name, Game: input.Game, Image: input.Image, DesiredState: input.DesiredState, Compute: *input.Compute, Storage: *input.Storage, Settings: input.Settings, RetainedWorld: retained}
	case "server.configure":
		intent.Method = "PATCH"
		body = adminv1.ConfigureRequest{Version: "v1", Compute: input.Compute, Storage: input.Storage, Settings: input.Settings}
	case "server.update":
		intent.Path += "/update"
		body = adminv1.UpdateRequest{Version: "v1", Image: input.Image}
	case "server.start", "server.stop", "server.restart", "server.decommission":
		intent.Path += "/" + strings.TrimPrefix(input.Action, "server.")
		body = adminv1.EmptyRequest{Version: "v1"}
	case "world.backup":
		intent.Path += "/backup"
		body = adminv1.BackupRequest{Version: "v1", RepositorySecretName: input.RepositorySecretName, RestartPolicy: input.RestartPolicy}
	case "world.restore", "world.destroy.preview":
		backup := adminv1.NativeOperation{}
		if _, err := client.Read(ctx, "/v1/backups/"+input.BackupName, &backup); err != nil {
			return intent, err
		}
		if backup.Version != "v1" || backup.Kind != "GameBackup" || backup.Name != input.BackupName || !uidPattern.MatchString(backup.UID) || backup.Generation < 1 || backup.ObservedGeneration != backup.Generation || backup.Phase != "Succeeded" {
			return intent, ErrInvalidReference
		}
		ref := adminv1.ExactReference{Name: backup.Name, UID: backup.UID}
		if input.Action == "world.restore" {
			intent.Path += "/restore"
			body = adminv1.RestoreRequest{Version: "v1", BackupRef: ref, RestartPolicy: input.RestartPolicy}
		} else {
			if retained == nil {
				intent.Path += "/destroy"
			}
			body = adminv1.DestroyRequest{Version: "v1", BackupRef: ref}
		}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return intent, ErrInvalidInput
	}
	intent.Body, err = canonicaljson.CanonicalJSON(encoded)
	if err != nil {
		return intent, ErrInvalidInput
	}
	return intent, nil
}

func validRetained(world adminv1.RetainedWorld, id string) bool {
	if world.Version != "v1" || world.OperationID != id || !uidPattern.MatchString(world.OperationUID) || !labelPattern.MatchString(world.OriginalServer.Name) || !uidPattern.MatchString(world.OriginalServer.UID) || !labelPattern.MatchString(world.Game) || !labelPattern.MatchString(world.DataIdentity) || !digestPattern.MatchString(world.SnapshotDigest) || len(world.Claims) == 0 || len(world.Claims) > 16 {
		return false
	}
	paths, names, uids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, claim := range world.Claims {
		if !labelPattern.MatchString(claim.Path) || !subdomain(claim.ClaimRef.Name) || !uidPattern.MatchString(claim.ClaimRef.UID) || paths[claim.Path] || names[claim.ClaimRef.Name] || uids[claim.ClaimRef.UID] {
			return false
		}
		paths[claim.Path], names[claim.ClaimRef.Name], uids[claim.ClaimRef.UID] = true, true, true
	}
	return true
}

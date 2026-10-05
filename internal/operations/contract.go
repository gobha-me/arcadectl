// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package operations shares pure receipt validation and identity rules between
// the authenticated HTTP boundary and its normal-controller translator.
// It owns no Kubernetes mutation client and no authentication credentials.
package operations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/receiptid"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

var ErrInvalid = errors.New("invalid operation request")

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identityPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

const MaxJSONBytes = canonicaljson.MaxBytes

// CanonicalJSON preserves the original operations error contract.
func CanonicalJSON(input []byte) ([]byte, error) {
	value, err := canonicaljson.CanonicalJSON(input)
	if err != nil {
		return nil, ErrInvalid
	}
	return value, nil
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func KeyDigest(namespace, principal, key string) (string, error) {
	value, err := receiptid.KeyDigest(namespace, principal, key)
	if err != nil {
		return "", ErrInvalid
	}
	return value, nil
}

func ReceiptName(namespace, principal, key string) (string, error) {
	digest, err := KeyDigest(namespace, principal, key)
	if err != nil {
		return "", err
	}
	return NameForKeyDigest(digest)
}

func NameForKeyDigest(digest string) (string, error) {
	value, err := receiptid.NameForKeyDigest(digest)
	if err != nil {
		return "", ErrInvalid
	}
	return value, nil
}

// RequestDigest covers the original typed input and original precondition, not
// server-produced resolutions. Target state and command parent UID are bound
// from the already hashed ETag only after deterministic receipt readback.
func RequestDigest(action arcade.ArcadeOperationAction, request arcade.OperationRequest) (string, error) {
	copy := request.DeepCopy()
	copy.Target = nil
	if copy.Image != nil {
		copy.Image.Resolution = arcade.OperationImageResolution{}
	}
	if copy.DestroyCommand != nil {
		copy.DestroyCommand.ParentOperationRef.UID = ""
	}
	data, err := json.Marshal(struct {
		Version string                       `json:"version"`
		Action  arcade.ArcadeOperationAction `json:"action"`
		Request *arcade.OperationRequest     `json:"request"`
	}{"v1", action, copy})
	if err != nil {
		return "", ErrInvalid
	}
	return hashBytes(data), nil
}

func ChildName(receiptUID types.UID, kind string) string {
	prefix := map[string]string{"GameServer": "server", "GameBackup": "backup", "GameRestore": "restore", "GameDestroy": "destroy"}[kind]
	if prefix == "" || receiptUID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("arcadectl/child/v1\x00" + string(receiptUID) + "\x00" + kind))
	return prefix + "-" + hex.EncodeToString(sum[:20])
}

func ServerIntent(spec arcade.GameServerSpec) (arcade.OperationServerIntent, error) {
	settings, err := CanonicalJSON(spec.Settings.Raw)
	if err != nil {
		return arcade.OperationServerIntent{}, err
	}
	copy := spec.DeepCopy()
	return arcade.OperationServerIntent{Game: copy.Game, ImageDigest: copy.ImageDigest, DesiredState: copy.DesiredState, Compute: copy.Compute, Storage: copy.Storage, SettingsJSON: string(settings)}, nil
}

func ServerSpec(intent arcade.OperationServerIntent) (arcade.GameServerSpec, error) {
	settings, err := CanonicalJSON([]byte(intent.SettingsJSON))
	if err != nil {
		return arcade.GameServerSpec{}, err
	}
	copy := intent.DeepCopy()
	return arcade.GameServerSpec{Game: copy.Game, ImageDigest: copy.ImageDigest, DesiredState: copy.DesiredState, Compute: copy.Compute, Storage: copy.Storage, Settings: runtime.RawExtension{Raw: settings}}, nil
}

func SpecDigest(spec arcade.GameServerSpec) (string, error) {
	intent, err := ServerIntent(spec)
	if err != nil {
		return "", err
	}
	if intent.Storage.Reattach != nil {
		sort.Slice(intent.Storage.Reattach.Claims, func(i, j int) bool {
			return intent.Storage.Reattach.Claims[i].Path < intent.Storage.Reattach.Claims[j].Path
		})
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return "", ErrInvalid
	}
	return hashBytes(encoded), nil
}

func RetainedSnapshotDigest(target arcade.GameDestroyTarget) (string, error) {
	if !validReference(target.GameServer) || target.Game == "" || len(target.Data.Claims) == 0 || len(target.Data.Claims) > 16 || len(validation.IsDNS1123Label(target.Data.Identity)) != 0 {
		return "", ErrInvalid
	}
	copy := target.DeepCopy()
	paths, names, uids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, claim := range copy.Data.Claims {
		if len(validation.IsDNS1123Label(claim.Path)) != 0 || !validReference(claim.ClaimRef) || paths[claim.Path] || names[claim.ClaimRef.Name] || uids[claim.ClaimRef.UID] {
			return "", ErrInvalid
		}
		paths[claim.Path], names[claim.ClaimRef.Name], uids[claim.ClaimRef.UID] = true, true, true
	}
	sort.Slice(copy.Data.Claims, func(i, j int) bool { return copy.Data.Claims[i].Path < copy.Data.Claims[j].Path })
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", ErrInvalid
	}
	return hashBytes(encoded), nil
}

type Precondition struct {
	Kind, UID, SnapshotDigest string
	Generation                int64
}

func ParsePrecondition(value string) (Precondition, error) {
	if value == "absent" {
		return Precondition{Kind: "absent"}, nil
	}
	if len(value) < 3 || len(value) > 512 || value[0] != '"' || value[len(value)-1] != '"' {
		return Precondition{}, ErrInvalid
	}
	parts := strings.Split(value[1:len(value)-1], ":")
	if len(parts) == 3 && (parts[0] == "server" || parts[0] == "operation") && identityPattern.MatchString(parts[1]) {
		generation, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil || generation < 1 || strconv.FormatInt(generation, 10) != parts[2] {
			return Precondition{}, ErrInvalid
		}
		return Precondition{Kind: parts[0], UID: parts[1], Generation: generation}, nil
	}
	if len(parts) == 4 && parts[0] == "retained" && identityPattern.MatchString(parts[1]) && digestPattern.MatchString(parts[2]+":"+parts[3]) {
		return Precondition{Kind: parts[0], UID: parts[1], SnapshotDigest: parts[2] + ":" + parts[3]}, nil
	}
	return Precondition{}, ErrInvalid
}

func validReference(ref arcade.ExactLocalReference) bool {
	return ref.Namespace == nil && len(validation.IsDNS1123Subdomain(ref.Name)) == 0 && identityPattern.MatchString(ref.UID)
}

func validRestart(value arcade.RestartPolicy) bool {
	return value == arcade.RestartLeaveStopped || value == arcade.RestartRestorePreviousState
}

// ValidateRequest validates the complete frozen request, including exact
// precondition-to-target binding. Adapter/planner validation follows separately.
func ValidateRequest(action arcade.ArcadeOperationAction, request arcade.OperationRequest) error {
	precondition, err := ParsePrecondition(request.Precondition)
	if err != nil {
		return ErrInvalid
	}
	payloads := 0
	for _, present := range []bool{request.Create != nil, request.Configure != nil, request.Backup != nil, request.Restore != nil, request.Destroy != nil, request.DestroyCommand != nil} {
		if present {
			payloads++
		}
	}
	live := request.Target != nil
	if live {
		target := request.Target
		if precondition.Kind != "server" || !validReference(target.ExactLocalReference) || target.Name != request.ServerName || target.UID != precondition.UID || target.Generation != precondition.Generation || (target.DesiredState != arcade.DesiredStateRunning && target.DesiredState != arcade.DesiredStateStopped) {
			return ErrInvalid
		}
	}
	if request.ServerName != "" && len(validation.IsDNS1123Label(request.ServerName)) != 0 {
		return ErrInvalid
	}
	if request.Create != nil && request.Create.Storage.Reattach != nil {
		return ErrInvalid
	}
	if request.Configure != nil && request.Configure.Storage != nil && request.Configure.Storage.Reattach != nil {
		return ErrInvalid
	}
	if request.Image != nil {
		image := request.Image
		if (image.Digest == "") == (image.Version == "") || !digestPattern.MatchString(image.Resolution.Digest) || image.Resolution.Repository == "" || len(image.Resolution.Repository) > 256 || image.Resolution.ResolvedAt.IsZero() {
			return ErrInvalid
		}
		if image.Digest != "" && (!digestPattern.MatchString(image.Digest) || image.Digest != image.Resolution.Digest || image.Resolution.ResolverVersion != "digest-v1" || image.Resolution.Tag != "") {
			return ErrInvalid
		}
		if image.Version != "" && (len(image.Version) > 64 || image.Resolution.ResolverVersion != "registry-v1" || image.Resolution.Tag == "") {
			return ErrInvalid
		}
	}
	if request.Image != nil && action != arcade.OperationServerCreate && action != arcade.OperationServerUpdate {
		return ErrInvalid
	}
	switch action {
	case arcade.OperationServerCreate:
		if payloads != 1 || request.Create == nil || request.Image == nil || live || request.ServerName == "" || precondition.Kind != "absent" {
			return ErrInvalid
		}
		input := request.Create
		if input.Game == "" || len(validation.IsDNS1123Label(input.Game)) != 0 || (input.DesiredState != arcade.DesiredStateRunning && input.DesiredState != arcade.DesiredStateStopped) {
			return ErrInvalid
		}
		if _, err := CanonicalJSON([]byte(input.SettingsJSON)); err != nil {
			return ErrInvalid
		}
		if input.RetainedWorld != nil && !validRetainedSelector(*input.RetainedWorld) {
			return ErrInvalid
		}
	case arcade.OperationServerConfigure:
		if payloads != 1 || request.Configure == nil || !live {
			return ErrInvalid
		}
		input := request.Configure
		if input.Compute == nil && input.Storage == nil && input.SettingsJSON == nil {
			return ErrInvalid
		}
		if input.SettingsJSON != nil {
			if _, err := CanonicalJSON([]byte(*input.SettingsJSON)); err != nil {
				return ErrInvalid
			}
		}
	case arcade.OperationServerStart, arcade.OperationServerStop, arcade.OperationServerRestart, arcade.OperationServerDecommission:
		if payloads != 0 || !live {
			return ErrInvalid
		}
	case arcade.OperationServerUpdate:
		if payloads != 0 || !live || request.Image == nil {
			return ErrInvalid
		}
	case arcade.OperationWorldBackup:
		if payloads != 1 || request.Backup == nil || !live || len(validation.IsDNS1123Subdomain(request.Backup.RepositorySecretName)) != 0 || !validRestart(request.Backup.RestartPolicy) {
			return ErrInvalid
		}
	case arcade.OperationWorldRestore:
		if payloads != 1 || request.Restore == nil || !live || !validReference(request.Restore.BackupRef) || !validRestart(request.Restore.RestartPolicy) {
			return ErrInvalid
		}
	case arcade.OperationWorldDestroyPreview:
		if payloads != 1 || request.Destroy == nil || !validReference(request.Destroy.BackupRef) {
			return ErrInvalid
		}
		if request.Destroy.RetainedWorld != nil {
			selector := request.Destroy.RetainedWorld
			if live || request.ServerName != "" || !validRetainedSelector(*selector) || precondition.Kind != "retained" || selector.DecommissionOperationRef.UID != precondition.UID || selector.SnapshotDigest != precondition.SnapshotDigest {
				return ErrInvalid
			}
		} else if !live {
			return ErrInvalid
		}
	case arcade.OperationWorldDestroyConfirm, arcade.OperationWorldDestroyCancel:
		command := request.DestroyCommand
		if payloads != 1 || command == nil || live || request.ServerName != "" || precondition.Kind != "operation" || !validReference(command.ParentOperationRef) || command.ParentOperationRef.UID != precondition.UID || !validReference(command.DestroyRef) {
			return ErrInvalid
		}
		if action == arcade.OperationWorldDestroyConfirm {
			if len(command.Challenge) < 16 || len(command.Challenge) > 128 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(command.Challenge) {
				return ErrInvalid
			}
		} else if command.Challenge != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func validRetainedSelector(selector arcade.OperationRetainedWorldSelector) bool {
	return validReference(selector.DecommissionOperationRef) && digestPattern.MatchString(selector.SnapshotDigest)
}

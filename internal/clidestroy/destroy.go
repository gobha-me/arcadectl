// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package clidestroy prepares exact, fail-closed ordinary destroy commands.
// It owns no credential, persistence, retry, or Kubernetes capability.
package clidestroy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/cliintent"
)

var (
	ErrInvalidPreview = errors.New("destroy preview is unavailable or invalid")
	ErrPreviewChanged = errors.New("destroy preview changed during confirmation")
	ErrExpired        = errors.New("destroy preview has expired")
	ErrPrompt         = errors.New("destroy confirmation was not completed")
)

var (
	operationIDPattern = regexp.MustCompile(`^ao-[a-z2-7]{52}$`)
	namePattern        = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$`)
	uidPattern         = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	labelPattern       = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	challengePattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

const (
	actionConfirm = "world.destroy.confirm"
	actionCancel  = "world.destroy.cancel"
)

// Prompt displays the complete immutable preview and obtains fresh interactive
// confirmation. The caller supplies the real-TTY implementation.
type Prompt func(context.Context, adminv1.DestroyPreview) error

type Client interface {
	Identity() adminclient.Identity
	Read(context.Context, string, any) (string, error)
}

type observedDestroy struct {
	parent     adminv1.Operation
	parentETag string
	native     adminv1.NativeOperation
}

func validReference(reference adminv1.ExactReference) bool {
	if !namePattern.MatchString(reference.Name) || uidPattern.MatchString(reference.UID) == false {
		return false
	}
	for _, label := range strings.Split(reference.Name, ".") {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validPreview(preview *adminv1.DestroyPreview) bool {
	if preview == nil || !challengePattern.MatchString(preview.Challenge) ||
		!validReference(preview.Target.OriginalServer) || !validReference(preview.BackupRef) ||
		!labelPattern.MatchString(preview.Target.Namespace) || !labelPattern.MatchString(preview.Target.Game) ||
		!labelPattern.MatchString(preview.Target.DataIdentity) || len(preview.Target.Claims) == 0 || len(preview.Target.Claims) > 16 ||
		!safeGuidance(preview.RestoreGuidance) {
		return false
	}
	paths := make(map[string]struct{}, len(preview.Target.Claims))
	names := make(map[string]struct{}, len(preview.Target.Claims))
	uids := make(map[string]struct{}, len(preview.Target.Claims))
	for _, claim := range preview.Target.Claims {
		if !labelPattern.MatchString(claim.Path) || !validReference(claim.ClaimRef) {
			return false
		}
		if _, found := paths[claim.Path]; found {
			return false
		}
		if _, found := names[claim.ClaimRef.Name]; found {
			return false
		}
		if _, found := uids[claim.ClaimRef.UID]; found {
			return false
		}
		paths[claim.Path] = struct{}{}
		names[claim.ClaimRef.Name] = struct{}{}
		uids[claim.ClaimRef.UID] = struct{}{}
	}
	return true
}

func safeGuidance(value string) bool {
	if len(value) == 0 || len(value) > 1024 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func normalizedPreview(preview *adminv1.DestroyPreview) *adminv1.DestroyPreview {
	if preview == nil {
		return nil
	}
	copy := *preview
	copy.Target.Claims = append([]adminv1.RetainedClaim(nil), preview.Target.Claims...)
	sort.Slice(copy.Target.Claims, func(i, j int) bool {
		if copy.Target.Claims[i].Path != copy.Target.Claims[j].Path {
			return copy.Target.Claims[i].Path < copy.Target.Claims[j].Path
		}
		if copy.Target.Claims[i].ClaimRef.Name != copy.Target.Claims[j].ClaimRef.Name {
			return copy.Target.Claims[i].ClaimRef.Name < copy.Target.Claims[j].ClaimRef.Name
		}
		return copy.Target.Claims[i].ClaimRef.UID < copy.Target.Claims[j].ClaimRef.UID
	})
	return &copy
}

func operationETag(uid string, generation int64) string {
	return `"operation:` + uid + `:` + strconv.FormatInt(generation, 10) + `"`
}

func readDestroy(ctx context.Context, client Client, parentID string) (observedDestroy, error) {
	if client == nil || !operationIDPattern.MatchString(parentID) {
		return observedDestroy{}, ErrInvalidPreview
	}
	var parent adminv1.Operation
	etag, err := client.Read(ctx, "/v1/operations/"+parentID, &parent)
	if err != nil {
		return observedDestroy{}, err
	}
	if parent.Version != adminv1.Version || parent.OperationID != parentID || !uidPattern.MatchString(parent.UID) || parent.Generation < 1 ||
		parent.ObservedGeneration != parent.Generation ||
		parent.Action != "world.destroy.preview" || parent.Child == nil || parent.Child.Kind != "GameDestroy" ||
		!validReference(adminv1.ExactReference{Name: parent.Child.Name, UID: parent.Child.UID}) || parent.Child.Generation < 1 ||
		etag != operationETag(parent.UID, parent.Generation) {
		return observedDestroy{}, ErrInvalidPreview
	}
	var native adminv1.NativeOperation
	if _, err := client.Read(ctx, "/v1/destroys/"+parent.Child.Name, &native); err != nil {
		return observedDestroy{}, err
	}
	if native.Version != adminv1.Version || native.Kind != "GameDestroy" || native.Name != parent.Child.Name ||
		native.UID != parent.Child.UID || native.Generation != parent.Child.Generation ||
		native.ObservedGeneration != native.Generation {
		return observedDestroy{}, ErrInvalidPreview
	}
	return observedDestroy{parent: parent, parentETag: etag, native: native}, nil
}

func currentConfirm(observed observedDestroy, namespace string, now time.Time) (*adminv1.DestroyPreview, error) {
	if observed.parent.Phase != "AwaitingConfirmation" || observed.native.Phase != "Preview" ||
		!validPreview(observed.parent.DestroyPreview) || !validPreview(observed.native.DestroyPreview) {
		return nil, ErrInvalidPreview
	}
	parent := normalizedPreview(observed.parent.DestroyPreview)
	native := normalizedPreview(observed.native.DestroyPreview)
	if !reflect.DeepEqual(parent, native) || parent.Target.Namespace != namespace {
		return nil, ErrInvalidPreview
	}
	expires, err := time.Parse(time.RFC3339Nano, parent.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != parent.ExpiresAt || !expires.After(now.UTC()) {
		return nil, ErrExpired
	}
	return parent, nil
}

func canonicalBody(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidPreview
	}
	result, err := canonicaljson.CanonicalJSON(raw)
	if err != nil {
		return nil, ErrInvalidPreview
	}
	return result, nil
}

// PrepareConfirm reads and cross-checks the parent and native operation,
// prompts using their exact immutable inventory, then repeats every read and
// comparison. It returns no intent if anything changes while the operator is
// reviewing the preview.
func PrepareConfirm(ctx context.Context, client Client, parentID string, prompt Prompt) (cliintent.Intent, error) {
	if prompt == nil || client == nil {
		return cliintent.Intent{}, ErrPrompt
	}
	identity := client.Identity()
	before, err := readDestroy(ctx, client, parentID)
	if err != nil {
		return cliintent.Intent{}, err
	}
	preview, err := currentConfirm(before, identity.Namespace, time.Now())
	if err != nil {
		return cliintent.Intent{}, err
	}
	shown := normalizedPreview(preview)
	if err := prompt(ctx, *shown); err != nil {
		return cliintent.Intent{}, errors.Join(ErrPrompt, err)
	}
	after, err := readDestroy(ctx, client, parentID)
	if err != nil {
		return cliintent.Intent{}, err
	}
	if client.Identity() != identity {
		return cliintent.Intent{}, ErrPreviewChanged
	}
	current, err := currentConfirm(after, identity.Namespace, time.Now())
	if err != nil {
		return cliintent.Intent{}, err
	}
	if before.parentETag != after.parentETag || before.parent.UID != after.parent.UID ||
		before.parent.Generation != after.parent.Generation || !reflect.DeepEqual(preview, current) ||
		!reflect.DeepEqual(before.parent.Child, after.parent.Child) {
		return cliintent.Intent{}, ErrPreviewChanged
	}
	destroyRef := adminv1.ExactReference{Name: after.native.Name, UID: after.native.UID}
	body, err := canonicalBody(adminv1.ConfirmRequest{Version: adminv1.Version, DestroyRef: destroyRef, Challenge: current.Challenge})
	if err != nil {
		return cliintent.Intent{}, err
	}
	return cliintent.Intent{Action: actionConfirm, Method: "POST", Path: "/v1/destroy-operations/" + parentID + "/confirm", Body: body,
		Conditional: adminclient.Conditional{IfMatch: after.parentETag}, ParentOperationID: parentID, DestroyPreview: current, DestroyRef: &destroyRef}, nil
}

func cancellable(observed observedDestroy) bool {
	if observed.parent.Phase == "Succeeded" || observed.parent.Phase == "Failed" || observed.parent.Phase == "Cancelled" ||
		observed.native.Phase == "Deleting" || observed.native.Phase == "Succeeded" || observed.native.Phase == "Failed" || observed.native.Phase == "Cancelled" {
		return false
	}
	switch observed.native.Phase {
	case "Pending", "Preview", "Verifying":
		return true
	default:
		return false
	}
}

// PrepareCancel prepares a distinct exact cancellation intent. Admission is
// not evidence that cancellation won its race with confirmation or deletion.
func PrepareCancel(ctx context.Context, client Client, parentID string) (cliintent.Intent, error) {
	observed, err := readDestroy(ctx, client, parentID)
	if err != nil {
		return cliintent.Intent{}, err
	}
	if !cancellable(observed) {
		return cliintent.Intent{}, ErrInvalidPreview
	}
	destroyRef := adminv1.ExactReference{Name: observed.native.Name, UID: observed.native.UID}
	body, err := canonicalBody(adminv1.CancelRequest{Version: adminv1.Version, DestroyRef: destroyRef})
	if err != nil {
		return cliintent.Intent{}, err
	}
	return cliintent.Intent{Action: actionCancel, Method: "POST", Path: "/v1/destroy-operations/" + parentID + "/cancel", Body: body,
		Conditional: adminclient.Conditional{IfMatch: observed.parentETag}, ParentOperationID: parentID, DestroyPreview: normalizedPreview(observed.parent.DestroyPreview), DestroyRef: &destroyRef}, nil
}

// IsConfirm reports whether an intent requires the destructive replay prompt.
func IsConfirm(intent cliintent.Intent) bool {
	return intent.Method == "POST" && intent.Action == actionConfirm
}

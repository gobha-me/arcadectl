// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package clidestroy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliintent"
	"github.com/gobha-me/arcadectl/internal/receiptid"
)

type destroyClient struct {
	identity adminclient.Identity
	parent   adminv1.Operation
	native   adminv1.NativeOperation
	etag     string
	reads    int
	change   func(*destroyClient)
}

var destroyParentID, _ = receiptid.ReceiptName("arcadectl-system", "admin", "destroy-parent-fixture")

func (client *destroyClient) Identity() adminclient.Identity { return client.identity }
func (client *destroyClient) Read(_ context.Context, path string, output any) (string, error) {
	client.reads++
	if client.change != nil && client.reads == 3 {
		client.change(client)
	}
	switch value := output.(type) {
	case *adminv1.Operation:
		if path != "/v1/operations/"+destroyParentID {
			return "", errors.New("unexpected path")
		}
		*value = client.parent
		return client.etag, nil
	case *adminv1.NativeOperation:
		if path != "/v1/destroys/native-destroy" {
			return "", errors.New("unexpected path")
		}
		*value = client.native
		return "", nil
	default:
		return "", errors.New("unexpected output")
	}
}

func destroyFixture() *destroyClient {
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	preview := &adminv1.DestroyPreview{Target: adminv1.DestroyTarget{Namespace: "arcadectl-system", OriginalServer: adminv1.ExactReference{Name: "factory", UID: "server-uid"}, Game: "factorio", DataIdentity: "factory-world",
		Claims: []adminv1.RetainedClaim{{Path: "world", ClaimRef: adminv1.ExactReference{Name: "factory-world", UID: "claim-uid"}}}}, BackupRef: adminv1.ExactReference{Name: "backup", UID: "backup-uid"},
		Challenge: "challenge-1234567890", ExpiresAt: expires, RestoreGuidance: "restore the exact backup first"}
	return &destroyClient{identity: adminclient.Identity{Namespace: "arcadectl-system"}, etag: `"operation:parent-uid:1"`,
		parent: adminv1.Operation{Version: "v1", OperationID: destroyParentID, UID: "parent-uid", Generation: 1, ObservedGeneration: 1, Action: "world.destroy.preview", Phase: "AwaitingConfirmation",
			Child: &adminv1.OperationChild{Kind: "GameDestroy", Name: "native-destroy", UID: "destroy-uid", Generation: 1}, DestroyPreview: preview},
		native: adminv1.NativeOperation{Version: "v1", Kind: "GameDestroy", Name: "native-destroy", UID: "destroy-uid", Generation: 1, ObservedGeneration: 1, Phase: "Preview", DestroyPreview: normalizedPreview(preview)}}
}

func TestPrepareConfirmCrossChecksAndRereadsExactPreview(t *testing.T) {
	client := destroyFixture()
	prompts := 0
	intent, err := PrepareConfirm(context.Background(), client, destroyParentID, func(_ context.Context, preview adminv1.DestroyPreview) error {
		prompts++
		if preview.Target.OriginalServer.UID != "server-uid" || preview.Target.Claims[0].ClaimRef.UID != "claim-uid" || preview.BackupRef.UID != "backup-uid" {
			t.Fatal("prompt lost exact destroy identities")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if prompts != 1 || client.reads != 4 || intent.Action != actionConfirm || intent.Path != "/v1/destroy-operations/"+destroyParentID+"/confirm" || intent.Conditional.IfMatch != client.etag || intent.DestroyRef == nil || intent.DestroyRef.UID != "destroy-uid" {
		t.Fatalf("unexpected intent: %#v prompts=%d reads=%d", intent, prompts, client.reads)
	}
	var body adminv1.ConfirmRequest
	if err := json.Unmarshal(intent.Body, &body); err != nil || body.Challenge != client.parent.DestroyPreview.Challenge || body.DestroyRef.UID != "destroy-uid" {
		t.Fatalf("unexpected body: %#v %v", body, err)
	}
}

func TestPrepareConfirmFailsClosedBeforeAndAfterPrompt(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*destroyClient)
		want   error
	}{
		{"stale parent", func(client *destroyClient) { client.parent.ObservedGeneration = 0 }, ErrInvalidPreview},
		{"foreign namespace", func(client *destroyClient) {
			client.parent.DestroyPreview.Target.Namespace = "other"
			client.native.DestroyPreview.Target.Namespace = "other"
		}, ErrInvalidPreview},
		{"noncanonical expiry", func(client *destroyClient) {
			value := time.Now().Add(time.Hour).Format("2006-01-02T15:04:05-07:00")
			client.parent.DestroyPreview.ExpiresAt = value
			client.native.DestroyPreview.ExpiresAt = value
		}, ErrExpired},
		{"unsafe terminal guidance", func(client *destroyClient) {
			client.parent.DestroyPreview.RestoreGuidance = "restore\x1b[2J"
			client.native.DestroyPreview.RestoreGuidance = "restore\x1b[2J"
		}, ErrInvalidPreview},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := destroyFixture()
			test.change(client)
			called := false
			_, err := PrepareConfirm(context.Background(), client, destroyParentID, func(context.Context, adminv1.DestroyPreview) error { called = true; return nil })
			if !errors.Is(err, test.want) || called {
				t.Fatalf("error=%v prompt=%v", err, called)
			}
		})
	}
	client := destroyFixture()
	client.change = func(value *destroyClient) {
		copy := normalizedPreview(value.parent.DestroyPreview)
		copy.Target.Claims[0].ClaimRef.UID = "replacement-uid"
		value.parent.DestroyPreview = copy
		value.native.DestroyPreview = normalizedPreview(copy)
	}
	_, err := PrepareConfirm(context.Background(), client, destroyParentID, func(context.Context, adminv1.DestroyPreview) error { return nil })
	if !errors.Is(err, ErrPreviewChanged) {
		t.Fatalf("post-prompt drift error=%v", err)
	}
}

func TestPrepareConfirmDoesNotLetPromptMutateFrozenInventory(t *testing.T) {
	client := destroyFixture()
	before := normalizedPreview(client.parent.DestroyPreview)
	intent, err := PrepareConfirm(context.Background(), client, destroyParentID, func(_ context.Context, preview adminv1.DestroyPreview) error {
		preview.Target.Claims[0].ClaimRef.UID = "prompt-mutated"
		return nil
	})
	if err != nil || !reflect.DeepEqual(intent.DestroyPreview, before) {
		t.Fatal("prompt callback mutated the frozen preview")
	}
}

func TestPrepareConfirmPreservesSafePromptCauseWithoutIntent(t *testing.T) {
	client := destroyFixture()
	promptCause := errors.New("safe timeout")
	intent, err := PrepareConfirm(context.Background(), client, destroyParentID, func(context.Context, adminv1.DestroyPreview) error { return promptCause })
	if !errors.Is(err, ErrPrompt) || !errors.Is(err, promptCause) || !reflect.DeepEqual(intent, cliintent.Intent{}) || client.reads != 2 {
		t.Fatalf("prompt cause or no-intent contract lost: intent=%#v err=%v reads=%d", intent, err, client.reads)
	}
}

func TestPrepareCancelIsExactButDoesNotClaimRollback(t *testing.T) {
	client := destroyFixture()
	client.parent.Phase = "Verifying"
	client.native.Phase = "Verifying"
	intent, err := PrepareCancel(context.Background(), client, destroyParentID)
	if err != nil || intent.Action != actionCancel || intent.ParentOperationID != destroyParentID || intent.DestroyRef == nil || intent.DestroyRef.UID != "destroy-uid" {
		t.Fatalf("cancel intent=%#v err=%v", intent, err)
	}
	client.native.Phase = "Deleting"
	if _, err := PrepareCancel(context.Background(), client, destroyParentID); !errors.Is(err, ErrInvalidPreview) {
		t.Fatalf("deleting cancel error=%v", err)
	}
}

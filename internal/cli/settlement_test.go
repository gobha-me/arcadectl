// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliattempt"
	"github.com/gobha-me/arcadectl/internal/cliintent"
	"github.com/gobha-me/arcadectl/internal/receiptid"
)

type settlementClient struct {
	identity adminclient.Identity
	submits  int
}

func (client *settlementClient) Identity() adminclient.Identity { return client.identity }
func (client *settlementClient) Read(context.Context, string, any) (string, error) {
	return "", &adminclient.Error{Code: "not_found", HTTPStatus: 404}
}
func (client *settlementClient) Submit(_ context.Context, _, _ string, _ []byte, key string, _ adminclient.Conditional) (adminv1.Operation, error) {
	client.submits++
	id, err := receiptid.ReceiptName(client.identity.Namespace, client.identity.PrincipalID, key)
	if err != nil {
		return adminv1.Operation{}, err
	}
	return adminv1.Operation{Version: "v1", OperationID: id, UID: "receipt-uid", Generation: 1, ObservedGeneration: 1, Action: "server.stop", Phase: "Succeeded", CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), PollURL: "/v1/operations/" + id}, nil
}

func TestSettlementPreservesContextClassificationRecoveryIDsAndAdmittedJournal(t *testing.T) {
	for _, cause := range []string{"deadline", "cancelled"} {
		for _, observed := range []string{"receipt", "parent"} {
			t.Run(cause+"/"+observed, func(t *testing.T) {
				base := t.TempDir()
				if os.Chmod(base, 0700) != nil {
					t.Fatal("private settlement fixture unavailable")
				}
				state := filepath.Join(base, "attempts")
				store, err := cliattempt.OpenStore(state, true)
				if err != nil {
					t.Fatal("private settlement journal unavailable")
				}
				defer store.Close()
				identity := adminclient.Identity{Origin: "https://api.example.test", CAHash: "sha256:" + strings.Repeat("a", 64), PrincipalID: "admin", Namespace: "arcadectl-system"}
				client := &settlementClient{identity: identity}
				result, err := store.Submit(context.Background(), client, identity, "server.stop/factory", []byte(`{"intent":"stop"}`), func() (cliintent.Intent, error) {
					return cliintent.Intent{Action: "server.stop", Method: "POST", Path: "/v1/servers/factory/stop", Body: []byte(`{"version":"v1"}`), Conditional: adminclient.Conditional{IfMatch: `"server:server-uid:1"`}}, nil
				})
				if err != nil || result.State != cliattempt.StateAdmitted || result.Operation == nil || client.submits != 1 {
					t.Fatal("initial exact settlement admission unavailable")
				}
				operationID := result.ExpectedOperationID
				if observed == "parent" {
					operationID, err = receiptid.ReceiptName(identity.Namespace, identity.PrincipalID, "parent-fixture-key")
					if err != nil || operationID == result.ExpectedOperationID {
						t.Fatal("distinct parent settlement identity unavailable")
					}
				}
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				wantCode, wantExit := "timeout", 5
				if cause == "cancelled" {
					cancel()
					ctx, cancel = context.WithCancel(context.Background())
					cancel()
					wantCode, wantExit = "interrupted", 130
				}
				defer cancel()
				err = settleAttempt(ctx, store, identity, result, operationID)
				if err == nil {
					t.Fatal("expired settlement context released an admitted attempt")
				}
				safe := classify(err)
				if safe.code != wantCode || safe.exit != wantExit || safe.attemptID != result.AttemptID || safe.operationID != operationID {
					t.Fatal("settlement lost timeout/interrupt classification or exact recovery IDs")
				}
				contents, err := os.ReadFile(filepath.Join(state, result.AttemptID+".json"))
				var persisted struct {
					State string `json:"state"`
				}
				if err != nil || json.Unmarshal(contents, &persisted) != nil || persisted.State != string(cliattempt.StateAdmitted) || client.submits != 1 {
					t.Fatal("failed settlement mutated the journal or resubmitted work")
				}
				if err := settleAttempt(context.Background(), store, identity, result, operationID); err != nil || client.submits != 1 {
					t.Fatal("fresh local settlement could not resolve without submission")
				}
			})
		}
	}
}

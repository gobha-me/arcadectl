// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cliattempt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliintent"
	"github.com/gobha-me/arcadectl/internal/receiptid"
)

type attemptClient struct {
	mu         sync.Mutex
	identity   adminclient.Identity
	action     string
	operations map[string]adminv1.Operation
	readErr    error
	submitErr  error
	reads      int
	submits    int
	lastBody   []byte
	lastKey    string
}

func (client *attemptClient) Identity() adminclient.Identity { return client.identity }
func (client *attemptClient) Read(_ context.Context, path string, output any) (string, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.reads++
	if client.readErr != nil {
		return "", client.readErr
	}
	id := strings.TrimPrefix(path, "/v1/operations/")
	operation, found := client.operations[id]
	if !found {
		return "", &adminclient.Error{Code: "not_found", HTTPStatus: 404}
	}
	value, ok := output.(*adminv1.Operation)
	if !ok {
		return "", errors.New("unexpected output")
	}
	*value = operation
	return `"operation:` + operation.UID + `:1"`, nil
}
func (client *attemptClient) Submit(_ context.Context, _, _ string, body []byte, key string, _ adminclient.Conditional) (adminv1.Operation, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.submits++
	client.lastBody = append([]byte(nil), body...)
	client.lastKey = key
	if client.submitErr != nil {
		return adminv1.Operation{}, client.submitErr
	}
	id, _ := receiptid.ReceiptName(client.identity.Namespace, client.identity.PrincipalID, key)
	operation := adminv1.Operation{Version: "v1", OperationID: id, UID: "operation-uid", Generation: 1, Action: client.action, Phase: "Accepted", PollURL: "/v1/operations/" + id}
	client.operations[id] = operation
	return operation, nil
}

func attemptIdentity() adminclient.Identity {
	return adminclient.Identity{Origin: "https://api.example.test", CAHash: "sha256:" + strings.Repeat("a", 64), PrincipalID: "admin", Namespace: "arcadectl-system"}
}

func openAttemptStore(t *testing.T) (*Store, string) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "attempts")
	store, err := OpenStore(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, directory
}

func lifecycleIntent() cliintent.Intent {
	return cliintent.Intent{Action: "server.start", Method: "POST", Path: "/v1/servers/factory/start", Body: []byte(`{"version":"v1"}`), Conditional: adminclient.Conditional{IfMatch: `"server:server-uid:1"`}}
}

func confirmIntent() cliintent.Intent {
	parentID, _ := receiptid.ReceiptName("arcadectl-system", "admin", "destroy-parent-fixture")
	preview := &adminv1.DestroyPreview{Target: adminv1.DestroyTarget{Namespace: "arcadectl-system", OriginalServer: adminv1.ExactReference{Name: "factory", UID: "server-uid"}, Game: "factorio", DataIdentity: "factory-world",
		Claims: []adminv1.RetainedClaim{{Path: "world", ClaimRef: adminv1.ExactReference{Name: "factory-world", UID: "claim-uid"}}}}, BackupRef: adminv1.ExactReference{Name: "backup", UID: "backup-uid"},
		Challenge: "challenge-1234567890", ExpiresAt: "2099-01-01T00:00:00Z", RestoreGuidance: "restore first"}
	ref := adminv1.ExactReference{Name: "native-destroy", UID: "destroy-uid"}
	return cliintent.Intent{Action: "world.destroy.confirm", Method: "POST", Path: "/v1/destroy-operations/" + parentID + "/confirm",
		Body: []byte(`{"challenge":"challenge-1234567890","destroyRef":{"name":"native-destroy","uid":"destroy-uid"},"version":"v1"}`), Conditional: adminclient.Conditional{IfMatch: `"operation:parent-uid:1"`},
		ParentOperationID: parentID, DestroyPreview: preview, DestroyRef: &ref}
}

func TestSubmitPersistsBeforeOneSubmissionAndDiscoversWinnerBeforePrepare(t *testing.T) {
	store, directory := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "server.start", operations: map[string]adminv1.Operation{}}
	prepares := 0
	prepare := func() (cliintent.Intent, error) { prepares++; return lifecycleIntent(), nil }
	result, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"server":"factory"}`), prepare)
	if err != nil || result.Operation == nil || result.State != StateAdmitted || prepares != 1 || client.submits != 1 {
		t.Fatalf("first submit result=%#v err=%v prepares=%d submits=%d", result, err, prepares, client.submits)
	}
	stat, err := os.Stat(filepath.Join(directory, recordName(result.AttemptID)))
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("private attempt mode=%v err=%v", stat, err)
	}
	second, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"server":"factory"}`), prepare)
	if err != nil || second.AttemptID != result.AttemptID || second.Operation == nil || prepares != 1 || client.submits != 1 || client.reads != 1 {
		t.Fatalf("winner lookup result=%#v err=%v prepares=%d reads=%d submits=%d", second, err, prepares, client.reads, client.submits)
	}
	if _, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"server":"other"}`), prepare); !errors.Is(err, ErrPendingIntent) || prepares != 1 {
		t.Fatalf("changed unresolved intent error=%v prepares=%d", err, prepares)
	}
}

func TestConcurrentSameIntentHasOnePreparationAndOneSubmission(t *testing.T) {
	store, _ := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "server.start", operations: map[string]adminv1.Operation{}}
	var prepares atomic.Int32
	prepare := func() (cliintent.Intent, error) {
		prepares.Add(1)
		return lifecycleIntent(), nil
	}
	results := make(chan Result, 2)
	errorsOut := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"server":"factory"}`), prepare)
			results <- result
			errorsOut <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatalf("concurrent submit failed: %v", err)
		}
	}
	var attemptID string
	for result := range results {
		if result.Operation == nil || result.State != StateAdmitted {
			t.Fatalf("concurrent result=%#v", result)
		}
		if attemptID == "" {
			attemptID = result.AttemptID
		} else if result.AttemptID != attemptID {
			t.Fatalf("concurrent calls used different attempts: %s and %s", attemptID, result.AttemptID)
		}
	}
	if prepares.Load() != 1 || client.submits != 1 {
		t.Fatalf("prepares=%d submits=%d", prepares.Load(), client.submits)
	}
}

func TestHeldScopeLockPreservesDeadlineAndCancellationWithoutSubmission(t *testing.T) {
	for _, action := range []string{"submit", "resume", "resolve"} {
		for _, cause := range []string{"deadline", "cancelled", "already-expired"} {
			t.Run(action+"/"+cause, func(t *testing.T) {
				store, _ := openAttemptStore(t)
				identity := attemptIdentity()
				client := &attemptClient{identity: identity, action: "server.start", operations: map[string]adminv1.Operation{}}
				prepares := 0
				prepare := func() (cliintent.Intent, error) { prepares++; return lifecycleIntent(), nil }
				result, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"start"}`), prepare)
				if err != nil || result.State != StateAdmitted {
					t.Fatal("initial journal fixture unavailable")
				}
				lock, err := store.files.Lock(context.Background(), headName(identity, "server.start/factory"))
				if err != nil {
					t.Fatal("held scope lock fixture unavailable")
				}
				defer lock.Close()

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
				want := context.DeadlineExceeded
				if cause == "cancelled" {
					cancel()
					ctx, cancel = context.WithCancel(context.Background())
					timer := time.AfterFunc(10*time.Millisecond, cancel)
					defer timer.Stop()
					want = context.Canceled
				} else if cause == "already-expired" {
					cancel()
					ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				}
				defer cancel()
				switch action {
				case "submit":
					_, err = store.Submit(ctx, client, identity, "server.start/factory", []byte(`{"intent":"start"}`), prepare)
				case "resume":
					_, err = store.Resume(ctx, client, identity, result.AttemptID, nil)
				case "resolve":
					err = store.Resolve(ctx, identity, result.AttemptID)
				}
				if !errors.Is(err, ErrStorage) || !errors.Is(err, want) {
					t.Fatal("blocked journal lock lost storage or context classification")
				}
				if client.submits != 1 || client.reads != 0 || prepares != 1 {
					t.Fatal("blocked scope lock prepared, read, or posted an intent")
				}
				stored, _, err := store.readRecord(result.AttemptID)
				if err != nil || stored.State != StateAdmitted {
					t.Fatal("blocked lock changed the existing durable attempt")
				}
			})
		}
	}
}

func TestAmbiguousAttemptRequiresExplicitPromptedExactResume(t *testing.T) {
	store, _ := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "world.destroy.confirm", operations: map[string]adminv1.Operation{}, submitErr: &adminclient.Error{Code: "ambiguous_submission", Ambiguous: true}}
	prepares := 0
	result, err := store.Submit(context.Background(), client, identity, "world.destroy.confirm/parent", []byte(`{"parent":"parent"}`), func() (cliintent.Intent, error) {
		prepares++
		return confirmIntent(), nil
	})
	if !errors.Is(err, ErrResumeRequired) || result.State != StateUncertain || prepares != 1 || client.submits != 1 {
		t.Fatalf("ambiguous result=%#v err=%v", result, err)
	}
	if _, err := store.Submit(context.Background(), client, identity, "world.destroy.confirm/parent", []byte(`{"parent":"parent"}`), func() (cliintent.Intent, error) {
		prepares++
		return confirmIntent(), nil
	}); !errors.Is(err, ErrResumeRequired) || prepares != 1 || client.submits != 1 {
		t.Fatalf("implicit retry occurred err=%v prepares=%d submits=%d", err, prepares, client.submits)
	}
	client.submitErr = nil
	promptCause := errors.New("safe prompt cause")
	if _, err := store.Resume(context.Background(), client, identity, result.AttemptID, func(context.Context, Review) error { return promptCause }); !errors.Is(err, ErrPrompt) || !errors.Is(err, promptCause) || client.submits != 1 {
		t.Fatalf("prompt cause lost or replayed err=%v submits=%d", err, client.submits)
	}
	prompts := 0
	resumed, err := store.Resume(context.Background(), client, identity, result.AttemptID, func(_ context.Context, review Review) error {
		prompts++
		if review.DestroyPreview == nil || review.DestroyPreview.Challenge != "challenge-1234567890" || review.DestroyRef == nil || review.DestroyRef.UID != "destroy-uid" ||
			review.ParentOperationUID != "parent-uid" || review.Conditional.IfMatch != `"operation:parent-uid:1"` {
			t.Fatal("resume prompt lost frozen identities")
		}
		return nil
	})
	if err != nil || resumed.Operation == nil || resumed.State != StateAdmitted || prompts != 1 || client.submits != 2 || string(client.lastBody) != string(confirmIntent().Body) {
		t.Fatalf("resume result=%#v err=%v prompts=%d submits=%d", resumed, err, prompts, client.submits)
	}
	if resumed.Action != "world.destroy.confirm" || resumed.ParentOperationID == "" || resumed.ParentOperationUID != "parent-uid" || resumed.DestroyRef == nil || resumed.DestroyRef.UID != "destroy-uid" {
		t.Fatalf("resume lost parent pins: %#v", resumed)
	}
}

func TestOrdinaryResumePromptCauseSurvivesWithoutPost(t *testing.T) {
	store, _ := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "server.start", operations: map[string]adminv1.Operation{}, submitErr: &adminclient.Error{Code: "ambiguous_submission", Ambiguous: true}}
	result, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"start"}`), func() (cliintent.Intent, error) { return lifecycleIntent(), nil })
	if !errors.Is(err, ErrResumeRequired) || client.submits != 1 {
		t.Fatalf("initial ambiguous result=%#v err=%v submits=%d", result, err, client.submits)
	}
	client.submitErr = nil
	promptCause := errors.New("safe ordinary replay refusal")
	_, err = store.Resume(context.Background(), client, identity, result.AttemptID, func(context.Context, Review) error { return promptCause })
	if !errors.Is(err, ErrPrompt) || !errors.Is(err, promptCause) || client.submits != 1 {
		t.Fatalf("ordinary prompt cause lost or replayed err=%v submits=%d", err, client.submits)
	}
}

func TestMalformedNotFoundResponseNeverAuthorizesFrozenPost(t *testing.T) {
	store, _ := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "world.destroy.confirm", operations: map[string]adminv1.Operation{}, submitErr: &adminclient.Error{Code: "ambiguous_submission", Ambiguous: true}}
	result, err := store.Submit(context.Background(), client, identity, "world.destroy.confirm/parent", []byte(`{"parent":"parent"}`), func() (cliintent.Intent, error) { return confirmIntent(), nil })
	if !errors.Is(err, ErrResumeRequired) || client.submits != 1 {
		t.Fatalf("initial ambiguous result=%#v err=%v submits=%d", result, err, client.submits)
	}
	client.submitErr = nil
	client.readErr = &adminclient.Error{Code: "invalid_response", HTTPStatus: 404}
	prompted := false
	_, err = store.Resume(context.Background(), client, identity, result.AttemptID, func(context.Context, Review) error {
		prompted = true
		return nil
	})
	var apiError *adminclient.Error
	if !errors.As(err, &apiError) || apiError.Code != "invalid_response" || prompted || client.submits != 1 {
		t.Fatalf("malformed 404 authorized replay err=%v prompt=%v submits=%d", err, prompted, client.submits)
	}
}

func TestResumeDiscoversReceiptWithoutPromptOrSecondPost(t *testing.T) {
	store, _ := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "world.destroy.confirm", operations: map[string]adminv1.Operation{}, submitErr: &adminclient.Error{Code: "ambiguous_submission", Ambiguous: true}}
	result, err := store.Submit(context.Background(), client, identity, "world.destroy.confirm/parent", []byte(`{"parent":"parent"}`), func() (cliintent.Intent, error) { return confirmIntent(), nil })
	if !errors.Is(err, ErrResumeRequired) {
		t.Fatal(err)
	}
	client.submitErr = nil
	client.operations[result.ExpectedOperationID] = adminv1.Operation{Version: "v1", OperationID: result.ExpectedOperationID, UID: "operation-uid", Generation: 1, Action: "world.destroy.confirm", Phase: "Accepted", PollURL: "/v1/operations/" + result.ExpectedOperationID}
	prompted := false
	resumed, err := store.Resume(context.Background(), client, identity, result.AttemptID, func(context.Context, Review) error { prompted = true; return nil })
	if err != nil || resumed.Operation == nil || prompted || client.submits != 1 {
		t.Fatalf("discovery replayed result=%#v err=%v prompt=%v submits=%d", resumed, err, prompted, client.submits)
	}
}

func TestAdmittedReceiptLossOrReplacementCanNeverReplay(t *testing.T) {
	store, _ := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "world.destroy.confirm", operations: map[string]adminv1.Operation{}}
	result, err := store.Submit(context.Background(), client, identity, "world.destroy.confirm/parent", []byte(`{"parent":"parent"}`), func() (cliintent.Intent, error) { return confirmIntent(), nil })
	if err != nil || result.Operation == nil || client.submits != 1 {
		t.Fatalf("initial admission result=%#v err=%v submits=%d", result, err, client.submits)
	}
	delete(client.operations, result.ExpectedOperationID)
	if _, err := store.Resume(context.Background(), client, identity, result.AttemptID, func(context.Context, Review) error {
		t.Fatal("admitted missing receipt prompted for replay")
		return nil
	}); !errors.Is(err, ErrReceiptMissing) || client.submits != 1 {
		t.Fatalf("missing admitted receipt error=%v submits=%d", err, client.submits)
	}
	client.operations[result.ExpectedOperationID] = adminv1.Operation{Version: "v1", OperationID: result.ExpectedOperationID, UID: "replacement-uid", Generation: 1, Action: "world.destroy.confirm", Phase: "Accepted", PollURL: "/v1/operations/" + result.ExpectedOperationID}
	if _, err := store.Resume(context.Background(), client, identity, result.AttemptID, nil); !errors.Is(err, ErrContextChanged) || client.submits != 1 {
		t.Fatalf("replacement admitted receipt error=%v submits=%d", err, client.submits)
	}
}

func TestDefiniteRejectionIsDurableAndNeverRefreshesBindings(t *testing.T) {
	store, _ := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "server.start", operations: map[string]adminv1.Operation{}, submitErr: &adminclient.Error{Code: "idempotency_conflict", HTTPStatus: 409}}
	prepares := 0
	prepare := func() (cliintent.Intent, error) { prepares++; return lifecycleIntent(), nil }
	result, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"start"}`), prepare)
	var apiError *adminclient.Error
	if !errors.As(err, &apiError) || result.State != StateRejected || result.FailureCode != "idempotency_conflict" || result.FailureHTTPStatus != 409 {
		t.Fatalf("rejection result=%#v err=%v", result, err)
	}
	second, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"start"}`), prepare)
	if !errors.Is(err, ErrRejected) || second.AttemptID != result.AttemptID || second.FailureCode != "idempotency_conflict" || prepares != 1 || client.submits != 1 {
		t.Fatalf("rejection retried result=%#v err=%v prepares=%d submits=%d", second, err, prepares, client.submits)
	}
	if err := store.Resolve(context.Background(), identity, result.AttemptID); err != nil {
		t.Fatalf("explicit rejection resolution failed: %v", err)
	}
	client.submitErr = nil
	third, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"replacement"}`), prepare)
	if err != nil || third.AttemptID == result.AttemptID || prepares != 2 || client.submits != 2 {
		t.Fatalf("explicit replacement result=%#v err=%v prepares=%d submits=%d", third, err, prepares, client.submits)
	}
}

func TestResolveAllowsFreshUniqueAttemptButNeverOverwritesHistory(t *testing.T) {
	store, directory := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "server.start", operations: map[string]adminv1.Operation{}}
	first, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"one"}`), func() (cliintent.Intent, error) { return lifecycleIntent(), nil })
	if err != nil || store.Resolve(context.Background(), identity, first.AttemptID) != nil {
		t.Fatal(err)
	}
	second, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"two"}`), func() (cliintent.Intent, error) { return lifecycleIntent(), nil })
	if err != nil || second.AttemptID == first.AttemptID || second.ExpectedOperationID == first.ExpectedOperationID {
		t.Fatalf("fresh attempt result=%#v err=%v", second, err)
	}
	for _, attemptID := range []string{first.AttemptID, second.AttemptID} {
		if _, err := os.Stat(filepath.Join(directory, recordName(attemptID))); err != nil {
			t.Fatalf("attempt history %s missing: %v", attemptID, err)
		}
	}
}

func TestContextDriftAndUnresolvedResolveFailClosed(t *testing.T) {
	store, _ := openAttemptStore(t)
	identity := attemptIdentity()
	client := &attemptClient{identity: identity, action: "server.start", operations: map[string]adminv1.Operation{}, submitErr: &adminclient.Error{Code: "ambiguous_submission", Ambiguous: true}}
	result, _ := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"same"}`), func() (cliintent.Intent, error) { return lifecycleIntent(), nil })
	if err := store.Resolve(context.Background(), identity, result.AttemptID); !errors.Is(err, ErrResumeRequired) {
		t.Fatalf("uncertain attempt resolved: %v", err)
	}
	changed := identity
	changed.CAHash = "sha256:" + strings.Repeat("b", 64)
	client.identity = changed
	if _, err := store.Resume(context.Background(), client, changed, result.AttemptID, nil); !errors.Is(err, ErrContextChanged) {
		t.Fatalf("context drift error=%v", err)
	}
}

func TestPrivateEnvelopeIsStrictButCanExceedRequestCanonicalizerLimit(t *testing.T) {
	var decoded head
	if err := strictDecode([]byte(`{"version":"v1","attemptId":"first","attemptId":"second"}`), &decoded); !errors.Is(err, ErrStorage) {
		t.Fatalf("duplicate private state accepted: %v", err)
	}
	type largeEnvelope struct {
		Payload string `json:"payload"`
	}
	want := largeEnvelope{Payload: strings.Repeat("a", 70*1024)}
	contents, err := marshal(want)
	if err != nil {
		t.Fatalf("bounded envelope above request limit rejected: %v", err)
	}
	var got largeEnvelope
	if err := strictDecode(contents, &got); err != nil || got != want {
		t.Fatalf("bounded envelope did not round trip: %v", err)
	}
}

func TestFrozenDestroyReviewMustMatchSubmittedBody(t *testing.T) {
	intent := confirmIntent()
	intent.Body = []byte(`{"challenge":"different-challenge","destroyRef":{"name":"native-destroy","uid":"destroy-uid"},"version":"v1"}`)
	if _, err := intentFrom(intent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mismatched destroy prompt and body accepted: %v", err)
	}
	intent = confirmIntent()
	intent.DestroyPreview.RestoreGuidance = "restore\x1b[2J"
	if _, err := intentFrom(intent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe persisted prompt text accepted: %v", err)
	}
}

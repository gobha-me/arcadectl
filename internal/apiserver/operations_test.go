// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/operations"
	platformgame "github.com/gobha-me/arcadectl/internal/platform/game"
	platformimage "github.com/gobha-me/arcadectl/internal/platform/image"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type operationTestAuth struct{ expires time.Time }

func (auth operationTestAuth) Authenticate(_ context.Context, token string) (adminauth.Principal, error) {
	if token != testToken {
		return adminauth.Principal{}, adminauth.ErrUnauthorized
	}
	return adminauth.Principal{ID: "admin", CredentialID: "credential", Roles: []adminauth.Role{adminauth.RoleAdministrator}, ExpiresAt: auth.expires}, nil
}

type operationTestStore struct {
	client.Client
	mu                   sync.Mutex
	gets, lists, creates int
	createError          error
	commitBeforeError    bool
	beforeGet            func(client.ObjectKey, client.Object)
	getError             func(client.ObjectKey, client.Object) error
}

func (store *operationTestStore) Get(ctx context.Context, key client.ObjectKey, value client.Object, options ...client.GetOption) error {
	store.mu.Lock()
	store.gets++
	hook := store.beforeGet
	injected := store.getError
	store.mu.Unlock()
	if hook != nil {
		hook(key, value)
	}
	if injected != nil {
		if err := injected(key, value); err != nil {
			return err
		}
	}
	return store.Client.Get(ctx, key, value, options...)
}
func (store *operationTestStore) List(ctx context.Context, value client.ObjectList, options ...client.ListOption) error {
	store.mu.Lock()
	store.lists++
	store.mu.Unlock()
	return store.Client.List(ctx, value, options...)
}
func (store *operationTestStore) CreateReceipt(ctx context.Context, value *arcadev1.ArcadeOperation) error {
	store.mu.Lock()
	store.creates++
	failure, commit := store.createError, store.commitBeforeError
	store.mu.Unlock()
	if failure != nil && !commit {
		return failure
	}
	value.UID = "receipt-uid"
	value.Generation = 1
	if err := store.Client.Create(ctx, value); err != nil {
		return err
	}
	return failure
}
func (store *operationTestStore) counts() (int, int, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.gets, store.lists, store.creates
}

type operationTestResolver struct {
	mu           sync.Mutex
	calls        int
	digests      []string
	wrongTag     bool
	afterResolve func()
}

func (resolver *operationTestResolver) Resolve(_ context.Context, definition platformgame.Definition, version string) (platformimage.Resolution, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls++
	digest := "sha256:" + strings.Repeat("1", 64)
	if len(resolver.digests) > 0 {
		digest = resolver.digests[(resolver.calls-1)%len(resolver.digests)]
	}
	tag, err := platformgame.ResolveVersionTag(definition, version)
	if err != nil {
		return platformimage.Resolution{}, err
	}
	if resolver.wrongTag {
		tag = "incorrect-curated-tag"
	}
	if resolver.afterResolve != nil {
		resolver.afterResolve()
	}
	return platformimage.Resolution{Repository: definition.ImageRepository, Tag: tag, Digest: digest}, nil
}

func operationFixture(t *testing.T, objects ...client.Object) (*Server, *operationTestStore, *operationTestResolver, *bytes.Buffer) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := arcadev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	store := &operationTestStore{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()}
	resolver := &operationTestResolver{}
	audit := &bytes.Buffer{}
	boundary, err := New(Config{Authenticator: operationTestAuth{expires: testNow.Add(time.Hour)}, Authorizer: AdministratorAuthorizer{}, Audit: NewJSONAudit(audit), Namespace: "arcadectl-system", Clock: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := catalog.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.RegisterOperations(OperationsConfig{Store: store, Catalog: catalog, Resolver: resolver}); err != nil {
		t.Fatal(err)
	}
	return boundary, store, resolver, audit
}
func operationHTTP(boundary *Server, method, path, key, precondition, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("Content-Type", "application/json")
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if precondition == "*" {
		request.Header.Set("If-None-Match", "*")
	} else if precondition != "" {
		request.Header.Set("If-Match", precondition)
	}
	response := httptest.NewRecorder()
	boundary.ServeHTTP(response, request)
	return response
}
func testCreateBody(image string) string {
	return `{"version":"v1","name":"factory","game":"factorio","image":` + image + `,"desiredState":"Stopped","compute":{"cpuRequest":"50m","cpuLimit":"1","memoryRequest":"64Mi","memoryLimit":"256Mi"},"storage":{"size":"512Mi","storageClassName":"world-retain"},"settings":{"name":"API world","visibility":"private"}}`
}
func operationTestServer(t *testing.T) *arcadev1.GameServer {
	t.Helper()
	var input adminv1.CreateRequest
	if err := json.Unmarshal([]byte(testCreateBody(`{"digest":"sha256:`+strings.Repeat("1", 64)+`"}`)), &input); err != nil {
		t.Fatal(err)
	}
	compute, err := computeInput(input.Compute)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := storageInput(input.Storage)
	if err != nil {
		t.Fatal(err)
	}
	return &arcadev1.GameServer{ObjectMeta: metav1.ObjectMeta{Name: "factory", Namespace: "arcadectl-system", UID: "server-uid", Generation: 4}, Spec: arcadev1.GameServerSpec{Game: input.Game, ImageDigest: input.Image.Digest, DesiredState: arcadev1.DesiredStateStopped, Compute: compute, Storage: storage, Settings: jsonSettings(string(input.Settings))}}
}
func TestOperationAuthDenialHasZeroValidationReadOrMutationEffects(t *testing.T) {
	boundary, store, resolver, audit := operationFixture(t)
	body := &unreadBody{}
	request := httptest.NewRequest("POST", "/v1/servers", nil)
	request.Body = body
	request.Header.Set("Authorization", "Bearer SECRET-CANARY")
	request.Header.Set("Idempotency-Key", "SECRET-CANARY")
	response := httptest.NewRecorder()
	boundary.ServeHTTP(response, request)
	gets, lists, creates := store.counts()
	if response.Code != 401 || body.reads != 0 || gets != 0 || lists != 0 || creates != 0 || resolver.calls != 0 {
		t.Fatalf("unauthorized request effects status=%d body=%d get=%d list=%d create=%d", response.Code, body.reads, gets, lists, creates)
	}
	if strings.Contains(audit.String(), "SECRET-CANARY") {
		t.Fatal("authentication denial logged caller input")
	}
}
func TestOperationCreateRetryBeforeLiveValidationAndVersionResolution(t *testing.T) {
	boundary, store, resolver, audit := operationFixture(t)
	key := "private-idempotency-canary"
	body := testCreateBody(`{"version":"2.0.72"}`)
	first := operationHTTP(boundary, "POST", "/v1/servers", key, "*", body)
	if first.Code != 202 {
		t.Fatalf("admit status=%d body=%s", first.Code, first.Body.String())
	}
	server := operationTestServer(t)
	if err := store.Client.Create(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	resolver.mu.Lock()
	resolver.digests = []string{"sha256:" + strings.Repeat("2", 64)}
	resolver.mu.Unlock()
	retry := operationHTTP(boundary, "POST", "/v1/servers", key, "*", body)
	if retry.Code != 200 || first.Body.String() != retry.Body.String() || resolver.calls != 1 {
		t.Fatalf("retry did not return admitted winner status=%d resolutions=%d", retry.Code, resolver.calls)
	}
	conflict := operationHTTP(boundary, "POST", "/v1/servers", key, "*", strings.Replace(body, "API world", "Different world", 1))
	if conflict.Code != 409 || !strings.Contains(conflict.Body.String(), "idempotency_conflict") {
		t.Fatal("changed original request reused key")
	}
	if strings.Contains(audit.String(), key) || strings.Contains(first.Body.String(), key) {
		t.Fatal("raw idempotency key escaped")
	}
	list := &arcadev1.ArcadeOperationList{}
	if err := store.Client.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Spec.Request.Image.Resolution.Digest != "sha256:"+strings.Repeat("1", 64) {
		t.Fatal("version winner was not frozen")
	}
	serialized, _ := json.Marshal(list)
	if bytes.Contains(serialized, []byte(key)) || bytes.Contains(serialized, []byte(testToken)) {
		t.Fatal("receipt persisted secret transport material")
	}
}
func TestOperationConcurrentVersionTagMoveReturnsOneReceipt(t *testing.T) {
	boundary, store, resolver, _ := operationFixture(t)
	resolver.digests = []string{"sha256:" + strings.Repeat("1", 64), "sha256:" + strings.Repeat("2", 64)}
	const count = 8
	responses := make(chan *httptest.ResponseRecorder, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- operationHTTP(boundary, "POST", "/v1/servers", "concurrent-key", "*", testCreateBody(`{"version":"2.0.72"}`))
		}()
	}
	wait.Wait()
	close(responses)
	winner := ""
	for response := range responses {
		if response.Code != 200 && response.Code != 202 {
			t.Fatalf("concurrent status=%d body=%s", response.Code, response.Body.String())
		}
		var value adminv1.Operation
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if winner == "" {
			winner = value.OperationID
		}
		if value.OperationID != winner {
			t.Fatal("concurrent duplicate receipt")
		}
	}
	list := &arcadev1.ArcadeOperationList{}
	_ = store.Client.List(context.Background(), list)
	if len(list.Items) != 1 {
		t.Fatalf("receipts=%d", len(list.Items))
	}
}

func TestOperationVersionSelectionRejectsInvalidInputAndResolverTagDrift(t *testing.T) {
	for _, test := range []struct {
		name, version string
		wrongTag      bool
		status, calls int
	}{
		{"invalid version", "SECRET-CANARY/latest", false, 400, 0},
		{"uncurated alias", "latest", false, 400, 0},
		{"wrong curated tag", "2.0.72", true, 503, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			boundary, store, resolver, audit := operationFixture(t)
			resolver.wrongTag = test.wrongTag
			image, _ := json.Marshal(adminv1.Image{Version: test.version})
			response := operationHTTP(boundary, "POST", "/v1/servers", "version-policy-key", "*", testCreateBody(string(image)))
			_, _, creates := store.counts()
			if response.Code != test.status || resolver.calls != test.calls || creates != 0 {
				t.Fatalf("status=%d resolves=%d creates=%d body=%s", response.Code, resolver.calls, creates, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "SECRET-CANARY") || strings.Contains(audit.String(), "SECRET-CANARY") {
				t.Fatal("invalid version escaped bounded guidance")
			}
		})
	}
}

func TestOperationConcurrentWinnerRecoveredAfterLiveGenerationChanged(t *testing.T) {
	server := operationTestServer(t)
	boundary, store, _, _ := operationFixture(t, server)
	first := operationHTTP(boundary, "POST", "/v1/servers/factory/start", "state-race-key", serverETag(server), `{"version":"v1"}`)
	if first.Code != 202 {
		t.Fatal(first.Body.String())
	}
	list := &arcadev1.ArcadeOperationList{}
	if err := store.Client.List(context.Background(), list); err != nil || len(list.Items) != 1 {
		t.Fatal("missing initial receipt")
	}
	winner := list.Items[0].DeepCopy()
	if err := store.Client.Delete(context.Background(), winner); err != nil {
		t.Fatal(err)
	}
	store.beforeGet = func(_ client.ObjectKey, value client.Object) {
		if _, ok := value.(*arcadev1.GameServer); !ok {
			return
		}
		store.mu.Lock()
		store.beforeGet = nil
		store.mu.Unlock()
		winner.ResourceVersion = ""
		if err := store.Client.Create(context.Background(), winner); err != nil {
			t.Fatal(err)
		}
		current := &arcadev1.GameServer{}
		if err := store.Client.Get(context.Background(), client.ObjectKeyFromObject(server), current); err != nil {
			t.Fatal(err)
		}
		current.Generation = 5
		if err := store.Client.Update(context.Background(), current); err != nil {
			t.Fatal(err)
		}
	}
	retry := operationHTTP(boundary, "POST", "/v1/servers/factory/start", "state-race-key", serverETag(server), `{"version":"v1"}`)
	if retry.Code != 200 || retry.Body.String() != first.Body.String() {
		t.Fatalf("concurrent winner was hidden by changed generation: %d %s", retry.Code, retry.Body.String())
	}
}
func TestOperationAmbiguousCreateRecoversOrReturnsExactRetryIdentity(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "committed"}[committed], func(t *testing.T) {
			boundary, store, _, audit := operationFixture(t)
			store.createError = errors.New("SECRET-CANARY Kubernetes error")
			store.commitBeforeError = committed
			response := operationHTTP(boundary, "POST", "/v1/servers", "ambiguous-key", "*", testCreateBody(`{"digest":"sha256:`+strings.Repeat("1", 64)+`"}`))
			if committed && response.Code != 200 {
				t.Fatalf("committed recovery status=%d", response.Code)
			}
			if !committed {
				var value adminv1.Error
				_ = json.Unmarshal(response.Body.Bytes(), &value)
				name, _ := operations.ReceiptName("arcadectl-system", "admin", "ambiguous-key")
				if response.Code != 503 || value.Code != "commit_unknown" || value.OperationID != name || !value.Retryable {
					t.Fatalf("unknown commit=%s", response.Body.String())
				}
			}
			if strings.Contains(response.Body.String(), "SECRET-CANARY") || strings.Contains(audit.String(), "SECRET-CANARY") {
				t.Fatal("raw create failure escaped")
			}
		})
	}
}
func TestOperationStrictBodiesAndPreconditionsHaveNoCreates(t *testing.T) {
	tests := []struct {
		name, path, body, etag string
		status                 int
	}{
		{"missing precondition", "/v1/servers/factory/start", `{"version":"v1"}`, "", 428},
		{"weak precondition", "/v1/servers/factory/start", `{"version":"v1"}`, `W/"server:server-uid:4"`, 400},
		{"stale generation", "/v1/servers/factory/start", `{"version":"v1"}`, `"server:server-uid:3"`, 412},
		{"duplicate version", "/v1/servers/factory/start", `{"version":"v1","version":"v1"}`, `"server:server-uid:4"`, 400},
		{"trailing body", "/v1/servers/factory/start", `{"version":"v1"}{}`, `"server:server-uid:4"`, 400},
		{"unsafe field", "/v1/servers/factory/destroy", `{"version":"v1","unsafeNoBackup":true}`, `"server:server-uid:4"`, 400},
		{"raw reattach", "/v1/servers/factory", `{"version":"v1","storage":{"size":"1Gi","reattach":{"identity":"SECRET-CANARY"}}}`, `"server:server-uid:4"`, 400},
		{"future version", "/v1/servers/factory/start", `{"version":"v2"}`, `"server:server-uid:4"`, 400},
		{"undocumented query", "/v1/servers/factory/start?namespace=other", `{"version":"v1"}`, `"server:server-uid:4"`, 400},
		{"nested duplicate", "/v1/servers/factory", `{"version":"v1","settings":{"name":"world","name":"SECRET-CANARY"}}`, `"server:server-uid:4"`, 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			boundary, store, _, audit := operationFixture(t, operationTestServer(t))
			method := "POST"
			if test.path == "/v1/servers/factory" {
				method = "PATCH"
			}
			response := operationHTTP(boundary, method, test.path, "validation-key", test.etag, test.body)
			_, _, creates := store.counts()
			if response.Code != test.status || creates != 0 {
				t.Fatalf("status=%d creates=%d body=%s", response.Code, creates, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "SECRET-CANARY") || strings.Contains(audit.String(), "SECRET-CANARY") {
				t.Fatal("validation reflected body")
			}
		})
	}
}
func TestOperationLiveMutationReceiptsAndExactETag(t *testing.T) {
	for _, action := range []string{"start", "stop", "restart", "decommission"} {
		t.Run(action, func(t *testing.T) {
			server := operationTestServer(t)
			boundary, store, _, _ := operationFixture(t, server)
			read := operationHTTP(boundary, "GET", "/v1/servers/factory", "", "", "")
			if read.Code != 200 || read.Header().Get("ETag") != serverETag(server) {
				t.Fatal("server exact UID/generation ETag missing")
			}
			response := operationHTTP(boundary, "POST", "/v1/servers/factory/"+action, "mutation-key", read.Header().Get("ETag"), `{"version":"v1"}`)
			if response.Code != 202 {
				t.Fatalf("mutation=%d %s", response.Code, response.Body.String())
			}
			current := &arcadev1.GameServer{}
			_ = store.Client.Get(context.Background(), client.ObjectKeyFromObject(server), current)
			if current.Generation != 4 || current.Spec.DesiredState != arcadev1.DesiredStateStopped {
				t.Fatal("API mutated native GameServer instead of receipt")
			}
			list := &arcadev1.ArcadeOperationList{}
			_ = store.Client.List(context.Background(), list)
			if len(list.Items) != 1 || list.Items[0].Spec.Request.Target.UID != "server-uid" || list.Items[0].Spec.Request.Precondition != serverETag(server) {
				t.Fatal("admission did not pin exact target")
			}
		})
	}
}
func TestOperationDurableStatusRetainedIdentityAndCredentialExpiry(t *testing.T) {
	target := arcadev1.GameDestroyTarget{GameServer: arcadev1.ExactLocalReference{Name: "factory", UID: "original-server-uid"}, Game: "factorio", Data: arcadev1.RetainedDataReference{Identity: "data-original", Claims: []arcadev1.RetainedDataClaimReference{{Path: "saves", ClaimRef: arcadev1.ExactLocalReference{Name: "original-world", UID: "original-world-uid"}}}}}
	digest, err := operations.RetainedSnapshotDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &arcadev1.ArcadeOperation{ObjectMeta: metav1.ObjectMeta{Name: "decommission-original", Namespace: "arcadectl-system", UID: "decommission-uid", Generation: 1}, Spec: arcadev1.ArcadeOperationSpec{Action: arcadev1.OperationServerDecommission}, Status: arcadev1.ArcadeOperationStatus{Phase: arcadev1.OperationPhaseSucceeded, ObservedGeneration: 1, RetainedWorld: &arcadev1.OperationRetainedWorld{Target: target, SnapshotDigest: digest}}}
	boundary, store, _, _ := operationFixture(t, receipt, operationTestServer(t))
	response := operationHTTP(boundary, "GET", "/v1/retained-worlds/decommission-original", "", "", "")
	var world adminv1.RetainedWorld
	_ = json.Unmarshal(response.Body.Bytes(), &world)
	if response.Code != 200 || world.OriginalServer.UID != "original-server-uid" || response.Header().Get("ETag") != retainedETag(receipt) {
		t.Fatalf("retained identity followed replacement %s", response.Body.String())
	}
	requestBody := `{"version":"v1","backupRef":{"name":"native-backup","uid":"backup-uid"}}`
	admit := operationHTTP(boundary, "POST", "/v1/retained-worlds/decommission-original/destroy", "retained-key", response.Header().Get("ETag"), requestBody)
	if admit.Code != 202 {
		t.Fatalf("retained destroy status=%d %s", admit.Code, admit.Body.String())
	}
	list := &arcadev1.ArcadeOperationList{}
	_ = store.Client.List(context.Background(), list)
	var admitted *arcadev1.ArcadeOperation
	for index := range list.Items {
		if list.Items[index].Spec.Action == arcadev1.OperationWorldDestroyPreview {
			admitted = &list.Items[index]
		}
	}
	if admitted == nil || admitted.Spec.Request.Target != nil || admitted.Spec.Request.Destroy.RetainedWorld.DecommissionOperationRef.UID != "decommission-uid" {
		t.Fatal("retained destroy gained replacement-server authority")
	}
	boundary.clock = func() time.Time { return testNow.Add(2 * time.Hour) }
	expired := operationHTTP(boundary, "GET", "/v1/operations/"+admitted.Name, "", "", "")
	if expired.Code != 401 {
		t.Fatal("expired credentials polled receipt")
	}
	persisted := &arcadev1.ArcadeOperation{}
	if err := store.Client.Get(context.Background(), types.NamespacedName{Namespace: "arcadectl-system", Name: admitted.Name}, persisted); err != nil {
		t.Fatal("credential expiry cancelled admitted receipt")
	}
}

func TestOperationCredentialExpiryDuringResolutionPreservesAdmission(t *testing.T) {
	boundary, store, resolver, _ := operationFixture(t)
	now := testNow
	boundary.clock = func() time.Time { return now }
	resolver.afterResolve = func() { now = testNow.Add(2 * time.Hour) }
	response := operationHTTP(boundary, "POST", "/v1/servers", "expiry-during-resolution", "*", testCreateBody(`{"version":"2.0.72"}`))
	if response.Code != 202 {
		t.Fatalf("valid admitted request was cancelled on later expiry: %d %s", response.Code, response.Body.String())
	}
	list := &arcadev1.ArcadeOperationList{}
	if err := store.Client.List(context.Background(), list); err != nil || len(list.Items) != 1 {
		t.Fatal("admitted receipt absent")
	}
	admission := list.Items[0].Spec.Admission
	if !admission.AdmittedAt.Time.Equal(testNow) || !admission.AdmittedAt.Before(&admission.CredentialExpiresAt) {
		t.Fatal("post-resolution expiry misrepresented admission time")
	}
	if !list.Items[0].Spec.Request.Image.Resolution.ResolvedAt.Time.Equal(now) {
		t.Fatal("resolution completion timestamp was not frozen truthfully")
	}
}
func TestOperationReadStatusSuppressesWorkerAndKubernetesText(t *testing.T) {
	receipt := &arcadev1.ArcadeOperation{ObjectMeta: metav1.ObjectMeta{Name: "status-operation", Namespace: "arcadectl-system", UID: "receipt-uid", Generation: 1}, Spec: arcadev1.ArcadeOperationSpec{Action: arcadev1.OperationWorldRestore}, Status: arcadev1.ArcadeOperationStatus{Phase: arcadev1.OperationPhaseFailed, Failure: &arcadev1.OperationFailure{Code: "verification_failed", Message: "SECRET-CANARY raw restic", SuggestedAction: "SECRET-CANARY endpoint"}}}
	backup := &arcadev1.GameBackup{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "arcadectl-system", UID: "backup-uid", Generation: 1}, Status: arcadev1.GameBackupStatus{DataOperationStatus: arcadev1.DataOperationStatus{Phase: arcadev1.DataPhaseFailed, Conditions: []metav1.Condition{{Type: "Complete", Status: metav1.ConditionFalse, Reason: "SECRET-CANARY", Message: "SECRET-CANARY repository"}}}}}
	boundary, _, _, audit := operationFixture(t, receipt, backup)
	for _, path := range []string{"/v1/operations/status-operation", "/v1/backups/backup"} {
		response := operationHTTP(boundary, "GET", path, "", "", "")
		contents, _ := io.ReadAll(response.Body)
		if response.Code != 200 || strings.Contains(string(contents), "SECRET-CANARY") {
			t.Fatalf("unsafe status projection=%s", contents)
		}
	}
	if strings.Contains(audit.String(), "SECRET-CANARY") {
		t.Fatal("status read audit leaked raw text")
	}
}

func TestOperationRetryableProgressDoesNotInviteReplacementIntent(t *testing.T) {
	for _, code := range []string{"operation_conflict", "api_unavailable", "worker_failed"} {
		output := operationOutput(&arcadev1.ArcadeOperation{Status: arcadev1.ArcadeOperationStatus{Phase: arcadev1.OperationPhaseRunning, Failure: &arcadev1.OperationFailure{Code: code, Retryable: true, Message: "SECRET-CANARY", SuggestedAction: "SECRET-CANARY"}}})
		encoded, _ := json.Marshal(output)
		if output.Phase != "Running" || !output.Failure.Retryable || strings.Contains(string(encoded), "SECRET-CANARY") || strings.Contains(output.Failure.Message, "could not complete") || !strings.Contains(output.Failure.SuggestedAction, "Continue polling this exact receipt") || strings.Contains(output.Failure.SuggestedAction, "new Idempotency-Key") {
			t.Fatal("active progress was projected as terminal or invited a replacement intent")
		}
	}
}

func TestOperationIntegralSettingsCanonicalRetry(t *testing.T) {
	for _, configure := range []bool{false, true} {
		boundary, _, _, _ := operationFixture(t)
		if configure {
			boundary, _, _, _ = operationFixture(t, operationTestServer(t))
		}
		path, method, precondition := "/v1/servers", "POST", "*"
		var first adminv1.Operation
		for index, numeric := range []string{"20", "20.0", "2e1"} {
			body := strings.Replace(testCreateBody(`{"digest":"sha256:`+strings.Repeat("1", 64)+`"}`), `"settings":{"name":"API world","visibility":"private"}`, `"settings":{"name":"API world","visibility":"private","maxPlayers":`+numeric+`}`, 1)
			if configure {
				path, method, precondition = "/v1/servers/factory", "PATCH", serverETag(operationTestServer(t))
				body = `{"version":"v1","settings":{"name":"Integral settings","visibility":"private","maxPlayers":` + numeric + `}}`
			}
			response := operationHTTP(boundary, method, path, "integral-settings", precondition, body)
			want := 200
			if index == 0 {
				want = 202
			}
			var receipt adminv1.Operation
			_ = json.Unmarshal(response.Body.Bytes(), &receipt)
			if response.Code != want || (index > 0 && receipt.OperationID != first.OperationID) {
				t.Fatalf("equivalent typed integral setting rejected: %d", response.Code)
			}
			first = receipt
		}
	}
}

func TestOperationRetainedReadTransientRecheckIsRetryable(t *testing.T) {
	target := arcadev1.GameDestroyTarget{GameServer: arcadev1.ExactLocalReference{Name: "factory", UID: "original-server-uid"}, Game: "factorio", Data: arcadev1.RetainedDataReference{Identity: "data-original", Claims: []arcadev1.RetainedDataClaimReference{{Path: "world", ClaimRef: arcadev1.ExactLocalReference{Name: "original-world", UID: "original-world-uid"}}}}}
	digest, err := operations.RetainedSnapshotDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &arcadev1.ArcadeOperation{ObjectMeta: metav1.ObjectMeta{Name: "decommission-original", Namespace: "arcadectl-system", UID: "decommission-uid", Generation: 1}, Spec: arcadev1.ArcadeOperationSpec{Action: arcadev1.OperationServerDecommission}, Status: arcadev1.ArcadeOperationStatus{Phase: arcadev1.OperationPhaseSucceeded, ObservedGeneration: 1, RetainedWorld: &arcadev1.OperationRetainedWorld{Target: target, SnapshotDigest: digest}}}
	boundary, store, _, audit := operationFixture(t, receipt)
	gets := 0
	store.getError = func(key client.ObjectKey, _ client.Object) error {
		if key.Name == receipt.Name {
			gets++
			if gets == 2 {
				return errors.New("SECRET-CANARY transport failure")
			}
		}
		return nil
	}
	response := operationHTTP(boundary, "GET", "/v1/retained-worlds/"+receipt.Name, "", "", "")
	var problem adminv1.Error
	_ = json.Unmarshal(response.Body.Bytes(), &problem)
	if response.Code != 503 || problem.Code != "api_unavailable" || !problem.Retryable || strings.Contains(response.Body.String()+audit.String(), "SECRET-CANARY") {
		t.Fatal("transient retained evidence lookup was reported as a permanent identity rejection")
	}
}

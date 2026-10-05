// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/apiserver"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/cli"
	"github.com/gobha-me/arcadectl/internal/operations"
	platformgame "github.com/gobha-me/arcadectl/internal/platform/game"
	platformimage "github.com/gobha-me/arcadectl/internal/platform/image"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const integrationNamespace = "isolated-games"
const integrationRawCanary = "RAW-WORKER-SECRET-CANARY"

type integrationAuth struct {
	mu         sync.Mutex
	credential adminauth.Credential
}

func (auth *integrationAuth) Authenticate(_ context.Context, token string) (adminauth.Principal, error) {
	auth.mu.Lock()
	defer auth.mu.Unlock()
	if token != auth.credential.Token {
		return adminauth.Principal{}, adminauth.ErrUnauthorized
	}
	return adminauth.Principal{ID: "admin", CredentialID: auth.credential.Bundle.CredentialID, ExpiresAt: auth.credential.Bundle.ExpiresAt, Roles: []adminauth.Role{adminauth.RoleAdministrator}}, nil
}

type integrationAudit struct {
	mu     sync.Mutex
	events []apiserver.AuditEvent
}

func (audit *integrationAudit) Record(event apiserver.AuditEvent) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.events = append(audit.events, event)
	return nil
}

// This fixture publishes controller outcomes, not simulated workload effects.
// The real HTTP admission path can write only its immutable receipt.
type integrationReceiptStore struct {
	client.Client
	mu          sync.Mutex
	phase       arcade.ArcadeOperationPhase
	observed    int64
	created     []*arcade.ArcadeOperation
	afterCreate func(*arcade.ArcadeOperation) error
}

func (store *integrationReceiptStore) CreateReceipt(ctx context.Context, receipt *arcade.ArcadeOperation) error {
	store.mu.Lock()
	receipt.UID = types.UID(fmt.Sprintf("receipt-%d", len(store.created)+1))
	receipt.Generation = 1
	receipt.Status.Phase = store.phase
	receipt.Status.ObservedGeneration = store.observed
	now := metav1.NewTime(time.Now().UTC())
	receipt.Status.StartedAt = &now
	if command := receipt.Spec.Request.DestroyCommand; command != nil {
		receipt.Status.Child = &arcade.OperationChildReference{Kind: "GameDestroy", ExactLocalReference: command.DestroyRef, Generation: 1}
	}
	if store.phase == arcade.OperationPhaseSucceeded || store.phase == arcade.OperationPhaseFailed || store.phase == arcade.OperationPhaseCancelled {
		receipt.Status.CompletedAt = &now
	}
	if store.phase == arcade.OperationPhaseFailed {
		receipt.Status.Failure = &arcade.OperationFailure{Code: "verification_failed", Message: integrationRawCanary, SuggestedAction: integrationRawCanary}
	}
	if store.phase == arcade.OperationPhaseRunning {
		receipt.Status.Failure = &arcade.OperationFailure{Code: "api_unavailable", Retryable: true, Message: integrationRawCanary, SuggestedAction: integrationRawCanary}
	}
	err := store.Client.Create(ctx, receipt)
	if err == nil {
		store.created = append(store.created, receipt.DeepCopy())
	}
	hook := store.afterCreate
	store.mu.Unlock()
	if err == nil && hook != nil {
		return hook(receipt)
	}
	return err
}
func (store *integrationReceiptStore) outcomes(phase arcade.ArcadeOperationPhase, observed int64) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.phase, store.observed = phase, observed
}
func (store *integrationReceiptStore) receipts() []*arcade.ArcadeOperation {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]*arcade.ArcadeOperation, len(store.created))
	for i := range store.created {
		result[i] = store.created[i].DeepCopy()
	}
	return result
}

type integrationResolver struct {
	mu    sync.Mutex
	calls int
}

func (resolver *integrationResolver) Resolve(_ context.Context, definition platformgame.Definition, version string) (platformimage.Resolution, error) {
	tag, err := platformgame.ResolveVersionTag(definition, version)
	if err != nil {
		return platformimage.Resolution{}, err
	}
	resolver.mu.Lock()
	resolver.calls++
	resolver.mu.Unlock()
	return platformimage.Resolution{Repository: definition.ImageRepository, Tag: tag, Digest: "sha256:" + strings.Repeat("1", 64)}, nil
}

type integrationFixture struct {
	store                                               *integrationReceiptStore
	auth                                                *integrationAuth
	audit                                               *integrationAudit
	resolver                                            *integrationResolver
	server                                              *httptest.Server
	config, state, caFile, credentialFile, settingsFile string
	mu                                                  sync.Mutex
	postPaths                                           []string
	beforeMutation                                      func()
	credentialCanaries                                  []string
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	credential, err := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := arcade.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	class := "world-retain"
	serverObject := &arcade.GameServer{ObjectMeta: metav1.ObjectMeta{Name: "factory", Namespace: integrationNamespace, UID: "server-uid", Generation: 4}, Spec: arcade.GameServerSpec{Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("1", 64), DesiredState: arcade.DesiredStateStopped, Compute: arcade.ComputeSpec{CPURequest: resource.MustParse("50m"), CPULimit: resource.MustParse("1"), MemoryRequest: resource.MustParse("64Mi"), MemoryLimit: resource.MustParse("256Mi")}, Storage: arcade.StorageSpec{Size: resource.MustParse("512Mi"), StorageClassName: &class}, Settings: runtime.RawExtension{Raw: []byte(`{"name":"CLI world","visibility":"private"}`)}}, Status: arcade.GameServerStatus{Phase: arcade.PhaseStopped, ObservedGeneration: 4}}
	backup := &arcade.GameBackup{ObjectMeta: metav1.ObjectMeta{Name: "original-backup", Namespace: integrationNamespace, UID: "backup-uid", Generation: 1}, Status: arcade.GameBackupStatus{DataOperationStatus: arcade.DataOperationStatus{Phase: arcade.DataPhaseSucceeded, ObservedGeneration: 1, CompletedAt: &metav1.Time{Time: time.Now().UTC()}}}}
	fixture := &integrationFixture{auth: &integrationAuth{credential: credential}, audit: &integrationAudit{}, resolver: &integrationResolver{}}
	fixture.store = &integrationReceiptStore{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(serverObject, backup).Build(), phase: arcade.OperationPhaseSucceeded, observed: 1}
	boundary, err := apiserver.New(apiserver.Config{Authenticator: fixture.auth, Authorizer: apiserver.AdministratorAuthorizer{}, Audit: fixture.audit, Namespace: integrationNamespace})
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := catalog.Builtins()
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.RegisterOperations(apiserver.OperationsConfig{Store: fixture.store, Catalog: definitions, Resolver: fixture.resolver}); err != nil {
		t.Fatal(err)
	}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		var hook func()
		if r.Method == "POST" || r.Method == "PATCH" {
			fixture.postPaths = append(fixture.postPaths, r.Method+" "+r.URL.Path)
			hook = fixture.beforeMutation
			fixture.beforeMutation = nil
		}
		fixture.mu.Unlock()
		if hook != nil {
			hook()
		}
		boundary.ServeHTTP(w, r)
	}))
	t.Cleanup(fixture.server.Close)
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	fixture.config, fixture.state = filepath.Join(base, "config"), filepath.Join(base, "state")
	fixture.caFile, fixture.credentialFile, fixture.settingsFile = filepath.Join(base, "ca.pem"), filepath.Join(base, "credential.json"), filepath.Join(base, "settings.json")
	if err := os.WriteFile(fixture.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.settingsFile, []byte(`{"name":"CLI world","visibility":"private"}`), 0600); err != nil {
		t.Fatal(err)
	}
	fixture.writeCredential(t, credential)
	code, out, stderr := fixture.run(t, "--output", "json", "login", "fixture", "--api", fixture.server.URL, "--ca-file", fixture.caFile, "--credential-file", fixture.credentialFile)
	if code != 0 || !strings.Contains(out, `"principalId":"admin"`) || stderr != "" {
		t.Fatalf("real API login failed code=%d", code)
	}
	return fixture
}
func (fixture *integrationFixture) writeCredential(t *testing.T, credential adminauth.Credential) {
	t.Helper()
	contents, err := adminauth.MarshalClientCredential(adminauth.ClientCredential{Version: "v1", CredentialID: credential.Bundle.CredentialID, Serial: credential.Bundle.Serial, ExpiresAt: credential.Bundle.ExpiresAt, Token: credential.Token})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.credentialFile, contents, 0600); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.credentialCanaries = append(fixture.credentialCanaries, credential.Token, credential.Bundle.TokenSHA256)
	fixture.mu.Unlock()
}
func (fixture *integrationFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, stderr bytes.Buffer
	code := cli.Run(context.Background(), args, cli.Options{In: strings.NewReader(""), Out: &out, Err: &stderr, ConfigDir: fixture.config, StateDir: fixture.state, PollInterval: time.Millisecond})
	fixture.assertSafe(t, out.String()+stderr.String())
	return code, out.String(), stderr.String()
}
func (fixture *integrationFixture) assertSafe(t *testing.T, output string) {
	t.Helper()
	fixture.mu.Lock()
	canaries := append([]string{integrationRawCanary}, fixture.credentialCanaries...)
	fixture.mu.Unlock()
	fixture.audit.mu.Lock()
	audit, _ := json.Marshal(fixture.audit.events)
	fixture.audit.mu.Unlock()
	for _, canary := range canaries {
		if strings.Contains(output+string(audit), canary) {
			t.Fatal("CLI or real API audit exposed secret/raw diagnostic canary")
		}
	}
}
func (fixture *integrationFixture) mutationCount() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return len(fixture.postPaths)
}
func (fixture *integrationFixture) recordState(t *testing.T, id string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(fixture.state, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		State string `json:"state"`
	}
	if json.Unmarshal(contents, &value) != nil {
		t.Fatal("invalid private attempt record")
	}
	return value.State
}
func decodeIntegrationJSON(t *testing.T, contents string) map[string]json.RawMessage {
	t.Helper()
	value := map[string]json.RawMessage{}
	if json.Unmarshal([]byte(contents), &value) != nil {
		t.Fatal("CLI did not return one versioned JSON object")
	}
	return value
}
func integrationField(t *testing.T, contents, name string) string {
	t.Helper()
	var result string
	if json.Unmarshal(decodeIntegrationJSON(t, contents)[name], &result) != nil || result == "" {
		t.Fatalf("missing safe CLI field %s", name)
	}
	return result
}
func (fixture *integrationFixture) publish(t *testing.T, id string, phase arcade.ArcadeOperationPhase, observed int64) {
	t.Helper()
	value := &arcade.ArcadeOperation{}
	key := types.NamespacedName{Namespace: integrationNamespace, Name: id}
	if err := fixture.store.Client.Get(context.Background(), key, value); err != nil {
		t.Fatal(err)
	}
	value.Status.Phase = phase
	value.Status.ObservedGeneration = observed
	if phase == arcade.OperationPhaseSucceeded || phase == arcade.OperationPhaseCancelled {
		value.Status.Failure = nil
	}
	if phase == arcade.OperationPhaseSucceeded || phase == arcade.OperationPhaseFailed || phase == arcade.OperationPhaseCancelled {
		now := metav1.Now()
		value.Status.CompletedAt = &now
	}
	if err := fixture.store.Client.Update(context.Background(), value); err != nil {
		t.Fatal(err)
	}
}

func TestCLIIntegrationRealAPILifecycleMappings(t *testing.T) {
	for _, action := range []string{"create", "configure", "start", "stop", "restart", "update", "backup", "restore", "decommission"} {
		t.Run(action, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			args := []string{"--output", "json", "server", action, "factory"}
			wantAction := "server." + action
			switch action {
			case "create":
				server := &arcade.GameServer{ObjectMeta: metav1.ObjectMeta{Name: "factory", Namespace: integrationNamespace}}
				if err := fixture.store.Client.Delete(context.Background(), server); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--game", "factorio", "--image-version", "2.0.72", "--cpu-request", "50m", "--cpu-limit", "1", "--memory-request", "64Mi", "--memory-limit", "256Mi", "--storage-size", "512Mi", "--storage-class", "world-retain", "--settings-file", fixture.settingsFile)
			case "configure":
				args = append(args, "--settings-file", fixture.settingsFile)
			case "update":
				args = append(args, "--image-version", "2.0.72")
			case "backup":
				args = append(args, "--repository-secret", "recovery-repository")
				wantAction = "world.backup"
			case "restore":
				args = append(args, "--backup", "original-backup")
				wantAction = "world.restore"
			}
			code, out, stderr := fixture.run(t, args...)
			if code != 0 || stderr != "" {
				t.Fatalf("lifecycle command failed code=%d", code)
			}
			var operation adminv1.Operation
			if json.Unmarshal([]byte(out), &operation) != nil || operation.Action != wantAction || operation.Phase != "Succeeded" || operation.ObservedGeneration != operation.Generation {
				t.Fatal("CLI did not mirror exact current real API receipt")
			}
			receipts := fixture.store.receipts()
			if len(receipts) != 1 || fixture.mutationCount() != 1 {
				t.Fatal("CLI did not admit exactly one receipt")
			}
			request := receipts[0].Spec.Request
			if receipts[0].Spec.Admission.PrincipalID != "admin" || receipts[0].Namespace != integrationNamespace {
				t.Fatal("receipt escaped verified principal/namespace")
			}
			if action == "create" {
				if request.Create == nil || request.Create.DesiredState != arcade.DesiredStateStopped || request.Image == nil || request.Image.Version != "2.0.72" || request.Image.Resolution.Digest != "sha256:"+strings.Repeat("1", 64) {
					t.Fatal("create defaults or server-side version freeze were lost")
				}
			}
			if action == "configure" {
				if request.Configure == nil || request.Configure.SettingsJSON == nil || *request.Configure.SettingsJSON != `{"name":"CLI world","visibility":"private"}` {
					t.Fatal("configure was not exact replacement JSON")
				}
			}
			if action == "backup" {
				if request.Backup == nil || request.Backup.RestartPolicy != arcade.RestartLeaveStopped || request.Backup.RepositorySecretName != "recovery-repository" {
					t.Fatal("backup default/name-only credential binding lost")
				}
			}
			if action == "restore" {
				if request.Restore == nil || request.Restore.RestartPolicy != arcade.RestartLeaveStopped || request.Restore.BackupRef.Name != "original-backup" || request.Restore.BackupRef.UID != "backup-uid" {
					t.Fatal("restore native backup UID or cold default lost")
				}
			}
		})
	}
}

func TestCLIIntegrationFailedAdmittedIntentCanBeFollowedByFreshIntent(t *testing.T) {
	fixture := newIntegrationFixture(t)
	fixture.store.outcomes(arcade.OperationPhaseFailed, 1)
	code, _, stderr := fixture.run(t, "--output", "json", "server", "backup", "factory", "--repository-secret", "recovery-repository")
	if code != 6 || integrationField(t, stderr, "code") != "operation_failed" {
		t.Fatalf("failed current receipt exit=%d", code)
	}
	id := integrationField(t, stderr, "attemptID")
	if fixture.recordState(t, id) != "resolved" {
		t.Fatal("verified terminal failure permanently fenced the action")
	}
	fixture.store.outcomes(arcade.OperationPhaseSucceeded, 1)
	code, _, _ = fixture.run(t, "--output", "json", "server", "backup", "factory", "--repository-secret", "corrected-repository")
	if code != 0 || len(fixture.store.receipts()) != 2 || fixture.mutationCount() != 2 {
		t.Fatal("fresh corrected intent did not use a new receipt")
	}
	receipts := fixture.store.receipts()
	if receipts[0].Name == receipts[1].Name || receipts[0].Spec.KeyDigest == receipts[1].Spec.KeyDigest {
		t.Fatal("terminal failure retry reused its old key")
	}
}

func TestCLIIntegrationDefinitiveRejectionRequiresExplicitResolve(t *testing.T) {
	fixture := newIntegrationFixture(t)
	fixture.mu.Lock()
	fixture.beforeMutation = func() {
		server := &arcade.GameServer{}
		key := types.NamespacedName{Namespace: integrationNamespace, Name: "factory"}
		if fixture.store.Client.Get(context.Background(), key, server) != nil {
			panic("fixture server unavailable")
		}
		server.Generation++
		if fixture.store.Client.Update(context.Background(), server) != nil {
			panic("fixture server update failed")
		}
	}
	fixture.mu.Unlock()
	code, _, stderr := fixture.run(t, "--output", "json", "server", "start", "factory")
	if code != 4 {
		t.Fatalf("stale ETag was not definitively rejected code=%d", code)
	}
	id := integrationField(t, stderr, "attemptID")
	if fixture.recordState(t, id) != "rejected" || len(fixture.store.receipts()) != 0 {
		t.Fatal("rejected intent admitted effects")
	}
	code, _, _ = fixture.run(t, "--output", "json", "server", "start", "factory")
	if code != 4 || fixture.mutationCount() != 1 {
		t.Fatal("rejected attempt was automatically replayed")
	}
	code, out, _ := fixture.run(t, "--output", "json", "operation", "resolve", id)
	if code != 0 || integrationField(t, out, "state") != "resolved" || fixture.mutationCount() != 1 {
		t.Fatal("explicit rejection resolution submitted a mutation")
	}
	code, _, _ = fixture.run(t, "--output", "json", "server", "start", "factory")
	if code != 0 || fixture.mutationCount() != 2 || len(fixture.store.receipts()) != 1 {
		t.Fatal("explicit new intent could not bind the fresh ETag")
	}
}

func TestCLIIntegrationNoWaitAttemptIsDiscoverableAndRunningResolveIsRefused(t *testing.T) {
	for _, output := range []string{"json", "human"} {
		t.Run(output, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			fixture.store.outcomes(arcade.OperationPhaseRunning, 1)
			code, out, _ := fixture.run(t, "--output", output, "--no-wait", "server", "start", "factory")
			if code != 0 {
				t.Fatal("no-wait admission failed")
			}
			var id, operationID string
			if output == "json" {
				id = integrationField(t, out, "attemptID")
				operationID = integrationField(t, out, "operationID")
			} else {
				for _, field := range strings.Fields(out) {
					if strings.HasPrefix(field, "attempt-") {
						id = strings.TrimSuffix(field, ";")
					}
				}
				receipts := fixture.store.receipts()
				operationID = receipts[0].Name
			}
			if id == "" || operationID == "" || fixture.recordState(t, id) != "admitted" {
				t.Fatal("no-wait did not expose a durable recoverable attempt")
			}
			code, _, _ = fixture.run(t, "--output", "json", "operation", "resolve", id)
			if code != 4 || fixture.recordState(t, id) != "admitted" || fixture.mutationCount() != 1 {
				t.Fatal("running intent was released or replayed")
			}
			fixture.publish(t, operationID, arcade.OperationPhaseSucceeded, 1)
			code, _, _ = fixture.run(t, "--output", "json", "operation", "wait", operationID)
			if code != 0 || fixture.mutationCount() != 1 {
				t.Fatal("observation wait wrote a mutation")
			}
			code, _, _ = fixture.run(t, "--output", "json", "operation", "resolve", id)
			if code != 0 || fixture.recordState(t, id) != "resolved" || fixture.mutationCount() != 1 {
				t.Fatal("exact completed intent could not be safely released")
			}
		})
	}
}

func TestCLIIntegrationObservationTimeoutAndStaleTerminalKeepIntentActive(t *testing.T) {
	for _, phase := range []arcade.ArcadeOperationPhase{arcade.OperationPhaseRunning, arcade.OperationPhaseSucceeded} {
		t.Run(string(phase), func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			observed := int64(1)
			if phase == arcade.OperationPhaseSucceeded {
				observed = 0
			}
			fixture.store.outcomes(phase, observed)
			code, admission, _ := fixture.run(t, "--output", "json", "--no-wait", "server", "start", "factory")
			if code != 0 {
				t.Fatal("initial receipt admission failed")
			}
			admittedID := integrationField(t, admission, "attemptID")
			code, _, stderr := fixture.run(t, "--output", "json", "--timeout", "250ms", "server", "start", "factory")
			if code != 5 || integrationField(t, stderr, "code") != "timeout" || !strings.Contains(stderr, "does not cancel") {
				t.Fatalf("non-current or running receipt settled code=%d", code)
			}
			id := integrationField(t, stderr, "attemptID")
			operationID := integrationField(t, stderr, "operationID")
			if id != admittedID || fixture.recordState(t, id) != "admitted" || fixture.mutationCount() != 1 || len(fixture.store.receipts()) != 1 {
				t.Fatal("observation timeout cancelled or replaced admitted work")
			}
			code, _, _ = fixture.run(t, "--output", "json", "operation", "resolve", id)
			if code != 4 || fixture.recordState(t, id) != "admitted" {
				t.Fatal("running/stale terminal attempt was released")
			}
			fixture.publish(t, operationID, arcade.OperationPhaseSucceeded, 1)
			code, _, _ = fixture.run(t, "--output", "json", "operation", "resume", id)
			if code != 0 || fixture.recordState(t, id) != "resolved" || fixture.mutationCount() != 1 {
				t.Fatal("exact admitted receipt recovery replayed a mutation")
			}
		})
	}
}

func TestCLIIntegrationSameNameReplacementCannotReleaseAttempt(t *testing.T) {
	fixture := newIntegrationFixture(t)
	fixture.store.outcomes(arcade.OperationPhaseRunning, 1)
	code, out, _ := fixture.run(t, "--output", "json", "--no-wait", "server", "start", "factory")
	if code != 0 {
		t.Fatal("admission failed")
	}
	id, operationID := integrationField(t, out, "attemptID"), integrationField(t, out, "operationID")
	old := &arcade.ArcadeOperation{}
	if err := fixture.store.Client.Get(context.Background(), types.NamespacedName{Namespace: integrationNamespace, Name: operationID}, old); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Client.Delete(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	replacement := old.DeepCopy()
	replacement.UID = "replacement-uid"
	replacement.ResourceVersion = ""
	replacement.Status.Phase = arcade.OperationPhaseSucceeded
	now := metav1.Now()
	replacement.Status.CompletedAt = &now
	if err := fixture.store.Client.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	code, _, _ = fixture.run(t, "--output", "json", "operation", "resolve", id)
	if code != 4 || fixture.recordState(t, id) != "admitted" || fixture.mutationCount() != 1 {
		t.Fatal("same-name replacement released original local fence")
	}
	code, _, _ = fixture.run(t, "--output", "json", "operation", "resume", id)
	if code != 4 || fixture.mutationCount() != 1 {
		t.Fatal("replacement receipt authorized mutation replay")
	}
}

func TestCLIIntegrationCredentialRotationKeepsPrincipalAndAdmittedReceipt(t *testing.T) {
	fixture := newIntegrationFixture(t)
	fixture.store.outcomes(arcade.OperationPhaseRunning, 1)
	code, out, _ := fixture.run(t, "--output", "json", "--no-wait", "server", "start", "factory")
	if code != 0 {
		t.Fatal("admission failed")
	}
	id, operationID := integrationField(t, out, "attemptID"), integrationField(t, out, "operationID")
	original := fixture.store.receipts()[0]
	rotated, err := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fixture.writeCredential(t, rotated)
	fixture.auth.mu.Lock()
	fixture.auth.credential = rotated
	fixture.auth.mu.Unlock()
	code, out, _ = fixture.run(t, "--output", "json", "--no-wait", "server", "start", "factory")
	if code != 0 || integrationField(t, out, "attemptID") != id || integrationField(t, out, "operationID") != operationID || fixture.mutationCount() != 1 {
		t.Fatal("rotation re-keyed or cancelled admitted intent")
	}
	fixture.publish(t, operationID, arcade.OperationPhaseSucceeded, 1)
	code, _, _ = fixture.run(t, "--output", "json", "operation", "resume", id)
	if code != 0 || fixture.recordState(t, id) != "resolved" {
		t.Fatal("stable administrator could not recover admitted work after rotation")
	}
	current := &arcade.ArcadeOperation{}
	if err := fixture.store.Client.Get(context.Background(), types.NamespacedName{Namespace: integrationNamespace, Name: operationID}, current); err != nil {
		t.Fatal(err)
	}
	if current.UID != original.UID || current.Spec.Admission.CredentialID != original.Spec.Admission.CredentialID || current.Spec.Admission.CredentialID == rotated.Bundle.CredentialID || current.Spec.Admission.PrincipalID != "admin" {
		t.Fatal("rotation rewrote admission identity")
	}
}

func TestCLIIntegrationContextMetadataAndHumanJSONRedaction(t *testing.T) {
	fixture := newIntegrationFixture(t)
	for _, args := range [][]string{{"--output", "json", "context", "list"}, {"--output", "json", "context", "current"}, {"context", "use", "fixture"}, {"--output", "json", "server", "status", "factory"}, {"server", "status", "factory"}} {
		code, out, stderr := fixture.run(t, args...)
		if code != 0 || out == "" || stderr != "" {
			t.Fatal("context/status command failed")
		}
	}
	fixture.store.outcomes(arcade.OperationPhaseFailed, 1)
	code, _, stderr := fixture.run(t, "server", "backup", "factory", "--repository-secret", "recovery-repository")
	if code != 6 || !strings.Contains(stderr, "reason=verification_failed") || strings.Contains(stderr, "RAW-WORKER") {
		t.Fatal("human output lost bounded failure guidance or exposed raw worker text")
	}
	code, _, _ = fixture.run(t, "context", "remove", "fixture")
	if code != 0 || fixture.mutationCount() != 1 {
		t.Fatal("context metadata removal affected cluster state")
	}
	for _, path := range []string{fixture.credentialFile, fixture.caFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("context removal deleted external credential/CA")
		}
	}
}

func TestCLIIntegrationTimeoutBoundsAttemptLocksBeforeSubmissionAndRecovery(t *testing.T) {
	fixture := newIntegrationFixture(t)
	fixture.store.outcomes(arcade.OperationPhaseRunning, 1)
	code, out, _ := fixture.run(t, "--output", "json", "--no-wait", "server", "start", "factory")
	if code != 0 {
		t.Fatal("initial receipt admission failed")
	}
	id := integrationField(t, out, "attemptID")
	files, err := privatefs.Open(fixture.state, false)
	if err != nil {
		t.Fatal("private attempt fixture unavailable")
	}
	defer files.Close()
	entries, err := os.ReadDir(fixture.state)
	if err != nil {
		t.Fatal("private attempt inventory unavailable")
	}
	head := ""
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "head-") && strings.HasSuffix(entry.Name(), ".json") {
			if head != "" {
				t.Fatal("unexpected extra attempt scope")
			}
			head = entry.Name()
		}
	}
	if head == "" {
		t.Fatal("private scope head missing")
	}
	lock, err := files.Lock(context.Background(), head)
	if err != nil {
		t.Fatal("held scope fixture unavailable")
	}
	defer lock.Close()
	for _, args := range [][]string{{"server", "start", "factory"}, {"operation", "resume", id}, {"operation", "resolve", id}} {
		bounded := append([]string{"--output", "json", "--timeout", "150ms"}, args...)
		code, _, stderr := fixture.run(t, bounded...)
		if code != 5 || integrationField(t, stderr, "code") != "timeout" || fixture.mutationCount() != 1 || fixture.recordState(t, id) != "admitted" {
			t.Fatal("lock wait escaped command deadline, re-posted, or changed journal state")
		}
	}
}

func (fixture *integrationFixture) destroyParent(t *testing.T) string {
	t.Helper()
	parentID := "ao-" + strings.Repeat("c", 52)
	target := arcade.GameDestroyTarget{GameServer: arcade.ExactLocalReference{Name: "factory", UID: "server-uid"}, Game: "factorio", Data: arcade.RetainedDataReference{Identity: "original-world", Claims: []arcade.RetainedDataClaimReference{{Path: "world", ClaimRef: arcade.ExactLocalReference{Name: "world-claim", UID: "claim-uid"}}}}}
	backup := arcade.ExactLocalReference{Name: "original-backup", UID: "backup-uid"}
	digest, err := operations.RetainedSnapshotDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	preview := &arcade.GameDestroyPreview{Challenge: "abcdefghijklmnop", ExpiresAt: metav1.NewTime(time.Now().UTC().Add(time.Minute)), RestoreGuidance: integrationRawCanary}
	parent := &arcade.ArcadeOperation{ObjectMeta: metav1.ObjectMeta{Name: parentID, Namespace: integrationNamespace, UID: "parent-uid", Generation: 1}, Spec: arcade.ArcadeOperationSpec{Version: "v1", Action: arcade.OperationWorldDestroyPreview}, Status: arcade.ArcadeOperationStatus{Phase: arcade.OperationPhaseAwaitingConfirmation, ObservedGeneration: 1, Plan: &arcade.OperationPlan{BackupRef: &backup}, Child: &arcade.OperationChildReference{Kind: "GameDestroy", ExactLocalReference: arcade.ExactLocalReference{Name: "destroy-child", UID: "destroy-uid"}, Generation: 1}, RetainedWorld: &arcade.OperationRetainedWorld{Target: target, SnapshotDigest: digest}, DestroyPreview: preview}}
	native := &arcade.GameDestroy{ObjectMeta: metav1.ObjectMeta{Name: "destroy-child", Namespace: integrationNamespace, UID: "destroy-uid", Generation: 1}, Spec: arcade.GameDestroySpec{Mode: arcade.DestroyModeVerifiedBackup, Target: target, BackupRef: &backup, RepositorySecretRef: &arcade.ExactSecretReference{ExactLocalReference: arcade.ExactLocalReference{Name: "recovery-repository", UID: "repository-uid"}, ResourceVersion: "1"}}, Status: arcade.GameDestroyStatus{Phase: arcade.DestroyPhasePreview, ObservedGeneration: 1, Preview: preview}}
	for _, value := range []client.Object{parent, native} {
		if err := fixture.store.Client.Create(context.Background(), value); err != nil {
			t.Fatal(err)
		}
	}
	return parentID
}

func TestCLIIntegrationCancelSettlementDistinguishesCommandFromParent(t *testing.T) {
	for _, scenario := range []string{"cancelled", "too-late", "parent-replaced", "child-replaced"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			parentID := fixture.destroyParent(t)
			fixture.store.mu.Lock()
			fixture.store.afterCreate = func(receipt *arcade.ArcadeOperation) error {
				if receipt.Spec.Action != arcade.OperationWorldDestroyCancel {
					return fmt.Errorf("unexpected fixture action")
				}
				parent := &arcade.ArcadeOperation{}
				ctx := context.Background()
				if err := fixture.store.Client.Get(ctx, types.NamespacedName{Namespace: integrationNamespace, Name: parentID}, parent); err != nil {
					return err
				}
				parent.Status.Phase = arcade.OperationPhaseCancelled
				if scenario != "cancelled" {
					parent.Status.Phase = arcade.OperationPhaseSucceeded
				}
				now := metav1.Now()
				parent.Status.CompletedAt = &now
				if scenario == "child-replaced" {
					parent.Status.Child.UID = "replacement-child-uid"
				}
				if scenario == "parent-replaced" {
					if err := fixture.store.Client.Delete(ctx, parent); err != nil {
						return err
					}
					parent.UID, parent.ResourceVersion = "replacement-parent-uid", ""
					return fixture.store.Client.Create(ctx, parent)
				}
				return fixture.store.Client.Update(ctx, parent)
			}
			fixture.store.mu.Unlock()
			code, out, stderr := fixture.run(t, "--output", "json", "destroy", "cancel", parentID)
			if len(fixture.store.receipts()) != 1 || fixture.mutationCount() != 1 {
				t.Fatal("cancel command did not admit exactly one receipt")
			}
			if scenario == "cancelled" {
				if code != 0 || integrationField(t, out, "phase") != "Cancelled" {
					t.Fatalf("successful command plus cancelled parent exit=%d", code)
				}
			} else {
				want := 4
				if scenario == "too-late" {
					want = 6
				}
				if code != want {
					t.Fatalf("cancel settlement identity/late result exit=%d want=%d", code, want)
				}
				if scenario == "too-late" && integrationField(t, stderr, "reason") != "too_late" {
					t.Fatal("deleted parent was presented as successful cancellation")
				}
				attemptID := integrationField(t, stderr, "attemptID")
				state := fixture.recordState(t, attemptID)
				if scenario == "too-late" && state != "resolved" || scenario != "too-late" && state != "admitted" {
					t.Fatal("cancel settlement released the wrong authority")
				}
			}
		})
	}
}

func integrationTerminal(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("integration terminal unavailable")
	}
	master := os.NewFile(uintptr(fd), "integration-terminal")
	t.Cleanup(func() { _ = master.Close() })
	if unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0) != nil {
		t.Fatal("integration terminal unlock failed")
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal("integration terminal identity unavailable")
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal("integration terminal slave unavailable")
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func TestCLIIntegrationTLSAndTerminalConfirmComposeAtMutationBoundary(t *testing.T) {
	for _, scenario := range []string{"exact", "piped", "wrong", "queued", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newIntegrationFixture(t)
			parentID := fixture.destroyParent(t)
			fixture.store.mu.Lock()
			fixture.store.afterCreate = func(receipt *arcade.ArcadeOperation) error {
				if receipt.Spec.Action != arcade.OperationWorldDestroyConfirm {
					return fmt.Errorf("unexpected fixture confirmation action")
				}
				ctx := context.Background()
				parent := &arcade.ArcadeOperation{}
				if err := fixture.store.Client.Get(ctx, types.NamespacedName{Namespace: integrationNamespace, Name: parentID}, parent); err != nil {
					return err
				}
				parent.Status.Phase = arcade.OperationPhaseSucceeded
				now := metav1.Now()
				parent.Status.CompletedAt = &now
				return fixture.store.Client.Update(ctx, parent)
			}
			fixture.store.mu.Unlock()
			if scenario == "piped" {
				var out, stderr bytes.Buffer
				code := cli.Run(context.Background(), []string{"--output", "json", "destroy", "confirm", parentID}, cli.Options{In: strings.NewReader("abcdefghijklmnop\n"), Out: &out, Err: &stderr, ConfigDir: fixture.config, StateDir: fixture.state})
				fixture.assertSafe(t, out.String()+stderr.String())
				if code != 2 || fixture.mutationCount() != 0 || len(fixture.store.receipts()) != 0 {
					t.Fatal("piped challenge authorized a confirmation")
				}
				return
			}
			master, slave := integrationTerminal(t)
			if scenario == "queued" {
				if _, err := master.Write([]byte("abcdefghijklmnop\n")); err != nil {
					t.Fatal("queued fixture input unavailable")
				}
				// Ensure the prior line is actually readable before the command starts;
				// a scheduling race must not masquerade as fresh typed confirmation.
				fds := []unix.PollFd{{Fd: int32(slave.Fd()), Events: unix.POLLIN}}
				if n, err := unix.Poll(fds, 1000); err != nil || n == 0 || fds[0].Revents&unix.POLLIN == 0 {
					t.Fatal("prior line did not reach terminal input queue")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			var out bytes.Buffer
			done := make(chan int, 1)
			timeout := "500ms"
			if scenario == "exact" || scenario == "wrong" {
				timeout = "2s"
			}
			go func() {
				done <- cli.Run(ctx, []string{"--output", "json", "--timeout", timeout, "destroy", "confirm", parentID}, cli.Options{In: slave, Out: &out, Err: slave, ConfigDir: fixture.config, StateDir: fixture.state, PollInterval: time.Millisecond})
			}()
			var display bytes.Buffer
			for !strings.Contains(display.String(), "Type exactly abcdefghijklmnop: ") {
				if ctx.Err() != nil {
					t.Fatal("fresh complete confirmation inventory did not appear")
				}
				fds := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
				n, err := unix.Poll(fds, 50)
				if err == unix.EINTR {
					continue
				}
				if err != nil {
					t.Fatal("integration prompt polling failed")
				}
				if n == 0 {
					continue
				}
				var chunk [4096]byte
				read, err := unix.Read(int(master.Fd()), chunk[:])
				if err != nil || read == 0 || display.Len()+read > 16384 {
					t.Fatal("integration prompt unavailable or unbounded")
				}
				display.Write(chunk[:read])
			}
			for _, identity := range []string{"namespace " + integrationNamespace, "factory uid=server-uid", "world-claim uid=claim-uid", "original-backup uid=backup-uid"} {
				if !strings.Contains(display.String(), identity) {
					t.Fatal("prompt omitted immutable original inventory before accepting input")
				}
			}
			if scenario == "exact" || scenario == "wrong" {
				line := "abcdefghijklmnop\n"
				if scenario == "wrong" {
					line = "not-the-current-challenge\n"
				}
				if _, err := master.Write([]byte(line)); err != nil {
					t.Fatal("fresh integration confirmation input unavailable")
				}
			}
			var code int
			select {
			case code = <-done:
			case <-ctx.Done():
				t.Fatal("real CLI prompt exceeded bounded observation deadline")
			}
			// Drain already-written terminal output after command completion, without
			// leaving a reader goroutine or ever displaying private diagnostics.
			for {
				fds := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
				n, err := unix.Poll(fds, 10)
				if err == unix.EINTR {
					continue
				}
				if err != nil || n == 0 {
					break
				}
				var chunk [4096]byte
				read, err := unix.Read(int(master.Fd()), chunk[:])
				if err != nil || read == 0 || display.Len()+read > 16384 {
					t.Fatal("terminal result unavailable or unbounded")
				}
				display.Write(chunk[:read])
			}
			fixture.assertSafe(t, out.String()+display.String())
			if scenario == "exact" {
				if code != 0 || fixture.mutationCount() != 1 || len(fixture.store.receipts()) != 1 {
					t.Fatalf("fresh exact terminal challenge failed code=%d", code)
				}
				receipt := fixture.store.receipts()[0]
				command := receipt.Spec.Request.DestroyCommand
				if command == nil || command.ParentOperationRef.Name != parentID || command.ParentOperationRef.UID != "parent-uid" || command.DestroyRef.Name != "destroy-child" || command.DestroyRef.UID != "destroy-uid" || command.Challenge != "abcdefghijklmnop" || receipt.Spec.Request.Precondition != `"operation:parent-uid:1"` {
					t.Fatal("composed confirmation lost exact UID/challenge/ETag evidence")
				}
				if integrationField(t, out.String(), "phase") != "Succeeded" {
					t.Fatal("confirmation returned before exact parent settlement")
				}
			} else {
				want := 2
				if scenario == "queued" || scenario == "timeout" {
					want = 5
				}
				if code != want || fixture.mutationCount() != 0 || len(fixture.store.receipts()) != 0 {
					t.Fatalf("unapproved terminal input wrote a confirmation code=%d want=%d", code, want)
				}
			}
		})
	}
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package clilifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/adminclient"
)

func createInput() Input {
	class := "world-retain"
	return Input{Action: "server.create", Name: "factory", Game: "factorio", Image: adminv1.Image{Digest: "sha256:" + strings.Repeat("a", 64)}, Compute: &adminv1.Compute{CPURequest: "50m", CPULimit: "1", MemoryRequest: "64Mi", MemoryLimit: "256Mi"}, Storage: &adminv1.Storage{Size: "512Mi", StorageClassName: &class}, Settings: json.RawMessage(`{"maxPlayers":20,"visibility":"private"}`)}
}

var retainedID = "ao-" + strings.Repeat("a", 52)

type lifecycleFixture struct {
	client                *adminclient.Client
	server                adminv1.Server
	backup                adminv1.NativeOperation
	world                 adminv1.RetainedWorld
	serverETag, worldETag string
	mu                    sync.Mutex
	paths                 []string
}

func newLifecycleFixture(t *testing.T) *lifecycleFixture {
	t.Helper()
	credential, err := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	initial := createInput()
	fixture := &lifecycleFixture{
		server:     adminv1.Server{Version: "v1", Name: "factory", UID: "server-uid", Generation: 4, Game: "factorio", ImageDigest: initial.Image.Digest, DesiredState: "Stopped", Compute: *initial.Compute, Storage: *initial.Storage, Settings: initial.Settings, Phase: "Stopped", ObservedGeneration: 4},
		backup:     adminv1.NativeOperation{Version: "v1", Kind: "GameBackup", Name: "backup.example", UID: "backup-uid", Generation: 1, ObservedGeneration: 1, Phase: "Succeeded", CompletedAt: time.Now().UTC().Format(time.RFC3339Nano)},
		world:      adminv1.RetainedWorld{Version: "v1", OperationID: retainedID, OperationUID: "retained-uid", OriginalServer: adminv1.ExactReference{Name: "old-factory", UID: "old-server-uid"}, Game: "factorio", DataIdentity: "old-world", SnapshotDigest: "sha256:" + strings.Repeat("b", 64), Claims: []adminv1.RetainedClaim{{Path: "world", ClaimRef: adminv1.ExactReference{Name: "old-world-claim", UID: "claim-uid"}}}},
		serverETag: `"server:server-uid:4"`, worldETag: `"retained:retained-uid:sha256:` + strings.Repeat("b", 64) + `"`,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+credential.Token {
			t.Error("preparation used a mutation or wrong authentication")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/auth/self" {
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "v1", "principalId": "admin", "credentialId": credential.Bundle.CredentialID, "expiresAt": credential.Bundle.ExpiresAt.UTC().Format(time.RFC3339Nano), "namespace": "isolated-games"})
			return
		}
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		fixture.paths = append(fixture.paths, r.URL.Path)
		switch r.URL.Path {
		case "/v1/servers/factory":
			w.Header().Set("ETag", fixture.serverETag)
			_ = json.NewEncoder(w).Encode(fixture.server)
		case "/v1/backups/backup.example":
			_ = json.NewEncoder(w).Encode(fixture.backup)
		case "/v1/retained-worlds/" + retainedID:
			w.Header().Set("ETag", fixture.worldETag)
			_ = json.NewEncoder(w).Encode(fixture.world)
		default:
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(adminv1.Error{Version: "v1", Code: "not_found"})
		}
	}))
	t.Cleanup(server.Close)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	caPath, credentialPath := filepath.Join(directory, "ca.pem"), filepath.Join(directory, "credential.json")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	private, err := adminauth.MarshalClientCredential(adminauth.ClientCredential{Version: "v1", CredentialID: credential.Bundle.CredentialID, Serial: credential.Bundle.Serial, ExpiresAt: credential.Bundle.ExpiresAt, Token: credential.Token})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credentialPath, private, 0600); err != nil {
		t.Fatal(err)
	}
	fixture.client, err = adminclient.Load(adminclient.ContextConfig{Version: "v1", Name: "fixture", APIOrigin: server.URL, TLSServerName: "127.0.0.1", CAFile: caPath, CredentialFile: credentialPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fixture.client.Close)
	if _, err := fixture.client.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestLifecyclePrepareTypedRoutesAndExactReferences(t *testing.T) {
	for _, action := range []string{"server.create", "server.configure", "server.start", "server.stop", "server.restart", "server.update", "server.decommission", "world.backup", "world.restore", "world.destroy.preview", "retained-create", "retained-destroy"} {
		t.Run(action, func(t *testing.T) {
			fixture := newLifecycleFixture(t)
			input := Input{Action: action, Name: "factory"}
			wantMethod, wantPath, wantETag := "POST", "/v1/servers/factory", fixture.serverETag
			var wantBody any
			wantReads := []string{"/v1/servers/factory"}
			switch action {
			case "server.create", "retained-create":
				input = createInput()
				request := adminv1.CreateRequest{Version: "v1", Name: input.Name, Game: input.Game, Image: input.Image, DesiredState: "Stopped", Compute: *input.Compute, Storage: *input.Storage, Settings: input.Settings}
				wantPath, wantETag, wantReads = "/v1/servers", "", nil
				if action == "retained-create" {
					input.RetainedOperationID = retainedID
					request.RetainedWorld = &adminv1.RetainedSelector{DecommissionOperationRef: adminv1.ExactReference{Name: fixture.world.OperationID, UID: fixture.world.OperationUID}, SnapshotDigest: fixture.world.SnapshotDigest}
					wantReads = []string{"/v1/retained-worlds/" + retainedID}
				}
				wantBody = request
			case "server.configure":
				input.Settings = json.RawMessage(`{"maxPlayers":25}`)
				wantMethod = "PATCH"
				wantBody = adminv1.ConfigureRequest{Version: "v1", Settings: input.Settings}
			case "server.update":
				input.Image = adminv1.Image{Version: "2.0.73"}
				wantPath += "/update"
				wantBody = adminv1.UpdateRequest{Version: "v1", Image: input.Image}
			case "world.backup":
				input.RepositorySecretName = "repository.example"
				wantPath += "/backup"
				wantBody = adminv1.BackupRequest{Version: "v1", RepositorySecretName: input.RepositorySecretName, RestartPolicy: "LeaveStopped"}
			case "world.restore", "world.destroy.preview", "retained-destroy":
				input.BackupName = "backup.example"
				ref := adminv1.ExactReference{Name: fixture.backup.Name, UID: fixture.backup.UID}
				if action == "world.restore" {
					wantPath += "/restore"
					wantBody = adminv1.RestoreRequest{Version: "v1", BackupRef: ref, RestartPolicy: "LeaveStopped"}
				} else {
					wantBody = adminv1.DestroyRequest{Version: "v1", BackupRef: ref}
					wantPath += "/destroy"
				}
				if action == "retained-destroy" {
					input.Action = "world.destroy.preview"
					input.Name = ""
					input.RetainedOperationID = retainedID
					wantETag = fixture.worldETag
					wantPath = "/v1/retained-worlds/" + retainedID + "/destroy"
					wantReads = []string{"/v1/retained-worlds/" + retainedID}
				}
				wantReads = append(wantReads, "/v1/backups/backup.example")
			default:
				wantPath += "/" + strings.TrimPrefix(action, "server.")
				wantBody = adminv1.EmptyRequest{Version: "v1"}
			}
			before, err := Fingerprint(input)
			if err != nil {
				t.Fatal(err)
			}
			intent, err := Prepare(context.Background(), fixture.client, input)
			if err != nil {
				t.Fatal(err)
			}
			if intent.Action != input.Action || intent.Method != wantMethod || intent.Path != wantPath || intent.Conditional.IfMatch != wantETag || intent.Conditional.IfNoneMatch != (input.Action == "server.create") {
				t.Fatal("intent route/conditional mismatch")
			}
			encoded, err := json.Marshal(wantBody)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			if json.Unmarshal(intent.Body, &got) != nil || json.Unmarshal(encoded, &want) != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("typed intent body mismatch")
			}
			fixture.mu.Lock()
			reads := append([]string(nil), fixture.paths...)
			fixture.mu.Unlock()
			if !reflect.DeepEqual(reads, wantReads) {
				t.Fatalf("read routes: %v", reads)
			}
			after, err := Fingerprint(input)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("preparation changed caller fingerprint")
			}
		})
	}
}

func TestLifecycleFingerprintCanonicalCallerDefaultsAndSettings(t *testing.T) {
	input := createInput()
	first, err := Fingerprint(input)
	if err != nil {
		t.Fatal(err)
	}
	input.DesiredState = "Stopped"
	input.Settings = json.RawMessage(`{"visibility":"private","maxPlayers":2e1}`)
	second, err := Fingerprint(input)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("equivalent/default caller intent changed fingerprint")
	}
	if input.DesiredState != "Stopped" || string(input.Settings) != `{"visibility":"private","maxPlayers":2e1}` {
		t.Fatal("caller input mutated")
	}
	for _, action := range []string{"world.backup", "world.restore"} {
		input := Input{Action: action, Name: "factory", RepositorySecretName: "repository"}
		if action == "world.restore" {
			input.RepositorySecretName = ""
			input.BackupName = "backup"
		}
		first, err := Fingerprint(input)
		if err != nil {
			t.Fatal(err)
		}
		input.RestartPolicy = "LeaveStopped"
		second, err := Fingerprint(input)
		if err != nil || !bytes.Equal(first, second) {
			t.Fatal("recovery default changed fingerprint")
		}
		input.RestartPolicy = "RestorePreviousState"
		third, err := Fingerprint(input)
		if err != nil || bytes.Equal(first, third) {
			t.Fatal("explicit restart intent not fingerprinted")
		}
	}
}

func TestLifecycleReferenceNameSyntaxMatchesBoundedAPIContract(t *testing.T) {
	for _, name := range []string{"repository.example", strings.Repeat("a", 128)} {
		if _, err := Fingerprint(Input{Action: "world.backup", Name: "factory", RepositorySecretName: name}); err != nil {
			t.Fatal("bounded API subdomain name was rejected")
		}
	}
	for _, name := range []string{"a..b", "a.-b", "a.b-", strings.Repeat("a", 254)} {
		if _, err := Fingerprint(Input{Action: "world.backup", Name: "factory", RepositorySecretName: name}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid or unbounded API reference name was accepted")
		}
	}
}

func TestLifecycleInvalidInputRejectedBeforeLiveReads(t *testing.T) {
	fixture := newLifecycleFixture(t)
	for _, input := range []Input{
		{Action: "server.start", Name: "../factory"}, {Action: "server.configure", Name: "factory"}, {Action: "server.update", Name: "factory"},
		{Action: "world.restore", Name: "factory"}, {Action: "world.backup", Name: "factory"}, {Action: "world.destroy.preview", Name: "factory", RetainedOperationID: retainedID, BackupName: "backup.example"},
		{Action: "server.start", Name: "factory", Game: "factorio"}, {Action: "server.stop", Name: "factory", Image: adminv1.Image{Digest: "sha256:" + strings.Repeat("a", 64)}},
		{Action: "world.restore", Name: "factory", BackupName: "backup.example", RestartPolicy: "Always"}, {Action: "world.destroy.unsafe", Name: "factory"},
		{Action: "server.configure", Name: "factory", Settings: json.RawMessage(`{"a":1,"\u0061":2}`)}, {Action: "server.configure", Name: "factory", Settings: json.RawMessage(`[]`)},
		{Action: "server.configure", Name: "factory", Settings: json.RawMessage(`{"a":"` + strings.Repeat("x", 65536) + `"}`)},
		{Action: "server.configure", Name: "factory", Storage: &adminv1.Storage{Size: "-1Gi"}},
	} {
		if _, err := Fingerprint(input); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid fingerprint accepted")
		}
		if _, err := Prepare(context.Background(), fixture.client, input); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid preparation accepted")
		}
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.paths) != 0 {
		t.Fatal("invalid caller intent performed live reads")
	}
}

func TestLifecyclePrepareRejectsUnboundLiveReferences(t *testing.T) {
	for _, scenario := range []string{"server-name", "server-uid", "server-generation", "server-etag", "backup-kind", "backup-uid", "backup-generation", "backup-stale", "backup-running", "world-id", "world-digest", "world-etag", "world-game", "world-claims"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newLifecycleFixture(t)
			input := Input{Action: "world.restore", Name: "factory", BackupName: "backup.example"}
			fixture.mu.Lock()
			switch scenario {
			case "server-name":
				fixture.server.Name = "replacement"
			case "server-uid":
				fixture.server.UID = "bad/uid"
			case "server-generation":
				fixture.server.Generation = 0
			case "server-etag":
				fixture.serverETag = `"server:replacement:4"`
			case "backup-kind":
				fixture.backup.Kind = "GameRestore"
			case "backup-uid":
				fixture.backup.UID = "bad/uid"
			case "backup-generation":
				fixture.backup.Generation = 0
			case "backup-stale":
				fixture.backup.ObservedGeneration = 0
			case "backup-running":
				fixture.backup.Phase = "Running"
			default:
				input = createInput()
				input.RetainedOperationID = retainedID
				switch scenario {
				case "world-id":
					fixture.world.OperationID = "replacement"
				case "world-digest":
					fixture.world.SnapshotDigest = "bad-digest"
				case "world-etag":
					fixture.worldETag = `"retained:replacement:sha256:` + strings.Repeat("b", 64) + `"`
				case "world-game":
					fixture.world.Game = "other-game"
				case "world-claims":
					fixture.world.Claims = append(fixture.world.Claims, fixture.world.Claims[0])
				}
			}
			fixture.mu.Unlock()
			if _, err := Prepare(context.Background(), fixture.client, input); err == nil {
				t.Fatal("unbound live reference accepted")
			}
		})
	}
}

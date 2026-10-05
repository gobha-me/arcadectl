// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cliattempt

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliintent"
)

func TestUnsupportedTLSResponseKeepsJournalUncertainAndFenced(t *testing.T) {
	for _, status := range []int{201, 307} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			generated, err := adminauth.GenerateCredential(time.Now().UTC(), time.Hour)
			if err != nil {
				t.Fatal("private TLS credential fixture unavailable")
			}
			credential := adminauth.ClientCredential{Version: "v1", CredentialID: generated.Bundle.CredentialID, Serial: generated.Bundle.Serial, ExpiresAt: generated.Bundle.ExpiresAt, Token: generated.Token}
			var mutations, redirects atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Header.Get("Authorization") != "Bearer "+credential.Token {
					t.Error("TLS fixture received an unauthenticated request")
					w.WriteHeader(401)
					_ = json.NewEncoder(w).Encode(adminv1.Error{Version: "v1", Code: "unauthenticated"})
					return
				}
				if r.URL.Path == "/v1/auth/self" {
					_ = json.NewEncoder(w).Encode(adminv1.Self{Version: "v1", PrincipalID: "admin", CredentialID: credential.CredentialID, ExpiresAt: credential.ExpiresAt.UTC().Format(time.RFC3339Nano), Namespace: "arcadectl-system"})
					return
				}
				if r.URL.Path == "/redirected" {
					redirects.Add(1)
				}
				if r.Method == "POST" {
					mutations.Add(1)
					w.Header().Set("Location", "/redirected")
					w.WriteHeader(status)
					_ = json.NewEncoder(w).Encode(adminv1.Error{Version: "v1", Code: "invalid_request"})
					return
				}
				w.WriteHeader(404)
				_ = json.NewEncoder(w).Encode(adminv1.Error{Version: "v1", Code: "not_found"})
			}))
			t.Cleanup(server.Close)
			base := t.TempDir()
			if os.Chmod(base, 0700) != nil {
				t.Fatal("private TLS fixture directory unavailable")
			}
			caFile, credentialFile := filepath.Join(base, "ca.pem"), filepath.Join(base, "credential.json")
			contents, err := adminauth.MarshalClientCredential(credential)
			if err != nil || os.WriteFile(credentialFile, contents, 0600) != nil || os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600) != nil {
				t.Fatal("private TLS fixture files unavailable")
			}
			client, err := adminclient.Load(adminclient.ContextConfig{Version: "v1", Name: "fixture", APIOrigin: server.URL, CAFile: caFile, CredentialFile: credentialFile})
			if err != nil {
				t.Fatal("private TLS client unavailable")
			}
			t.Cleanup(client.Close)
			identity, err := client.Verify(context.Background())
			if err != nil {
				t.Fatal("private TLS identity unavailable")
			}
			store, _ := openAttemptStore(t)
			prepares := 0
			prepare := func() (cliintent.Intent, error) { prepares++; return lifecycleIntent(), nil }
			result, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"start"}`), prepare)
			if !errors.Is(err, ErrResumeRequired) || result.State != StateUncertain || result.ExpectedOperationID == "" || mutations.Load() != 1 || redirects.Load() != 0 {
				t.Fatal("unsupported TLS response was treated as known rejection")
			}
			if err := store.Resolve(context.Background(), identity, result.AttemptID); !errors.Is(err, ErrResumeRequired) {
				t.Fatal("unsupported response released a scope without terminal evidence")
			}
			repeated, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"start"}`), prepare)
			if !errors.Is(err, ErrResumeRequired) || repeated.AttemptID != result.AttemptID || prepares != 1 || mutations.Load() != 1 {
				t.Fatal("repeating uncertain intent refreshed or resubmitted it")
			}
			if _, err := store.Submit(context.Background(), client, identity, "server.start/factory", []byte(`{"intent":"different"}`), prepare); !errors.Is(err, ErrPendingIntent) || prepares != 1 || mutations.Load() != 1 {
				t.Fatal("unsupported response allowed replacement intent")
			}
			if _, err := store.Resume(context.Background(), client, identity, result.AttemptID, func(context.Context, Review) error { return ErrPrompt }); !errors.Is(err, ErrPrompt) || mutations.Load() != 1 || redirects.Load() != 0 {
				t.Fatal("read-only recovery implicitly replayed unsupported response")
			}
		})
	}
}

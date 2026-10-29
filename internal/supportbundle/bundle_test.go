// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package supportbundle

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
)

type bundleReader struct {
	server      adminv1.Server
	paths       []string
	serverReads int
	oldAPI      bool
	failVersion bool
	change      func(*adminv1.Server)
}

func newBundleReader() *bundleReader {
	return &bundleReader{server: adminv1.Server{Version: "v1", Name: "factory", UID: "server-uid", Generation: 4, ObservedGeneration: 3,
		DesiredState: "Stopped", Phase: "Failed", ImageDigest: "sha256:" + strings.Repeat("a", 64), Game: "SECRET-CANARY-game",
		Settings:  json.RawMessage(`{"bearerToken":"SECRET-CANARY-token","secret":{"data":"SECRET-CANARY-secret"},"password":"SECRET-CANARY-password","repositoryCredentials":"SECRET-CANARY-repository","saveContents":"SECRET-CANARY-save"}`),
		Endpoints: []adminv1.Endpoint{{Name: "SECRET-CANARY-endpoint", Address: "SECRET-CANARY-address"}},
		Conditions: []adminv1.Condition{
			{Type: "Ready", Status: "False", Reason: "SECRET-CANARY-reason", ObservedGeneration: 3},
			{Type: "SECRET-CANARY-type", Status: "False", Reason: "Ready", ObservedGeneration: 4},
			{Type: "StorageReady", Status: "False", Reason: "RetainedDataConflict", ObservedGeneration: 3},
		}}}
}

func (r *bundleReader) Read(ctx context.Context, path string, out any) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.paths = append(r.paths, path)
	switch path {
	case "/v1/servers/factory":
		r.serverReads++
		value := r.server
		if r.serverReads == 2 && r.change != nil {
			r.change(&value)
		}
		*out.(*adminv1.Server) = value
	case "/v1/version":
		if r.oldAPI {
			return "", &adminclient.Error{HTTPStatus: 404, Code: "not_found"}
		}
		if r.failVersion {
			return "", &adminclient.Error{HTTPStatus: 401, Code: "unauthenticated"}
		}
		*out.(*adminv1.ComponentVersion) = adminv1.ComponentVersion{Version: "v1", SourceSHA: "unknown", GoVersion: "go1.26.10", OS: "linux", Arch: "amd64"}
	default:
		return "", errors.New("unexpected diagnostic scope")
	}
	return "", nil
}

func TestSupportBundleRedactionIsAnAllowlistAndReadsOneServerOnly(t *testing.T) {
	reader := newBundleReader()
	got, err := Collect(context.Background(), reader, "games", "factory")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil || strings.Contains(string(encoded), "SECRET-CANARY") {
		t.Fatal("a supported private input path escaped the projection")
	}
	if !reflect.DeepEqual(reader.paths, []string{"/v1/servers/factory", "/v1/version", "/v1/servers/factory"}) {
		t.Fatal("bundle read an operation, another server, logs, events, or credentials")
	}
	if !got.Partial || got.SchemaVersion != "arcadectl.support/v1" || got.Server.ObservedGeneration != 3 || got.Server.Generation != 4 || got.API == nil {
		t.Fatal("scope, component identity or stale generation evidence was lost")
	}
	if len(got.Server.Conditions) != 2 || got.Server.Conditions[0].Type != "StorageReady" || got.Server.Conditions[1].Reason != "Unknown" {
		t.Fatal("condition order or closed reason projection drifted")
	}
	var raw struct {
		Server map[string]any `json:"server"`
	}
	if json.Unmarshal(encoded, &raw) != nil || len(raw.Server) != 8 {
		t.Fatal("server projection gained an unreviewed output field")
	}
	second, err := Collect(context.Background(), newBundleReader(), "games", "factory")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := json.Marshal(second)
	if string(encoded) != string(other) {
		t.Fatal("unchanged observations produced nondeterministic output")
	}
}

func TestSupportBundleRefusesChangedTargetAndAuthenticationFailure(t *testing.T) {
	for _, change := range []func(*adminv1.Server){func(s *adminv1.Server) { s.UID = "replacement-uid" }, func(s *adminv1.Server) { s.Generation++ }} {
		reader := newBundleReader()
		reader.change = change
		got, err := Collect(context.Background(), reader, "games", "factory")
		if !errors.Is(err, ErrTargetChanged) || got.SchemaVersion != "" {
			t.Fatal("identity drift emitted a misleading partial result")
		}
	}
	reader := newBundleReader()
	reader.failVersion = true
	if got, err := Collect(context.Background(), reader, "games", "factory"); err == nil || got.SchemaVersion != "" || len(reader.paths) != 2 {
		t.Fatal("authentication failure became an old-API omission")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Collect(ctx, newBundleReader(), "games", "factory"); !errors.Is(err, context.Canceled) {
		t.Fatal("collection ignored its caller's lifetime")
	}
}

func TestSupportBundleOldAPIIsExplicitlyPartial(t *testing.T) {
	reader := newBundleReader()
	reader.oldAPI = true
	got, err := Collect(context.Background(), reader, "games", "factory")
	if err != nil || got.API != nil || !got.Partial {
		t.Fatal("old API unexpectedly gained component evidence")
	}
	found := false
	for _, value := range got.Omissions {
		found = found || value == "api_version_not_supported"
	}
	if !found {
		t.Fatal("missing component evidence was silently omitted")
	}
}

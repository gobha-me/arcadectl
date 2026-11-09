// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adminclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
)

func TestComponentVersionResponseRejectsUnboundedBuildClaims(t *testing.T) {
	base := adminv1.ComponentVersion{Version: "v1", SourceSHA: "unknown", GoVersion: "go1.26.10", OS: "linux", Arch: "amd64"}
	if !destinationMatches("ComponentVersion", &base) || validateResponse(&base) != nil {
		t.Fatal("bounded development version rejected")
	}
	known := base
	known.SourceSHA, known.SourceEpoch = strings.Repeat("a", 40), 1793300400
	if validateResponse(&known) != nil {
		t.Fatal("exact source build claim rejected")
	}
	for _, corrupt := range []func(*adminv1.ComponentVersion){
		func(v *adminv1.ComponentVersion) { v.SourceSHA = "SECRET-CANARY" },
		func(v *adminv1.ComponentVersion) { v.SourceEpoch = 1 },
		func(v *adminv1.ComponentVersion) { v.GoVersion = "SECRET-CANARY" },
		func(v *adminv1.ComponentVersion) { v.OS = "linux\nSECRET-CANARY" },
		func(v *adminv1.ComponentVersion) { v.Arch = strings.Repeat("a", 17) },
	} {
		value := base
		corrupt(&value)
		if validateResponse(&value) == nil {
			t.Fatal("unbounded component version crossed client validation")
		}
	}
	if decodeResponse([]byte(`{"version":"v1","sourceSha":"unknown","sourceEpoch":0,"goVersion":"go1.26.10","os":"linux","arch":"amd64","secret":"SECRET-CANARY"}`), &base) == nil {
		t.Fatal("unknown component data crossed strict decoding")
	}
}

func TestComponentVersionRecognizesOnlyTheExactLegacy404(t *testing.T) {
	for _, test := range []struct {
		name, path, body string
		status           int
		legacy           bool
	}{
		{"legacy version", "/v1/version", "404 page not found", 404, true},
		{"other read", "/v1/servers/factory", "404 page not found", 404, false},
		{"private malformed body", "/v1/version", "SECRET-CANARY", 404, false},
		{"authentication failure", "/v1/version", "404 page not found", 401, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, _, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, credential adminauth.ClientCredential) {
				http.Error(w, test.body, test.status)
			})
			client := verifiedClient(t, config)
			var out any = &adminv1.ComponentVersion{}
			if test.path != "/v1/version" {
				out = &adminv1.Server{}
			}
			_, err := client.Read(context.Background(), test.path, out)
			var remote *Error
			if !errors.As(err, &remote) {
				t.Fatal("read did not produce a bounded protocol classification")
			}
			if test.legacy {
				if remote.Code != "not_found" || remote.HTTPStatus != 404 || remote.Ambiguous {
					t.Fatal("actual legacy router response was not recognized")
				}
			} else if remote.Code != "invalid_response" {
				t.Fatal("legacy exception escaped its exact read/path/status/body scope")
			}
		})
	}
}

func TestLegacyVersionExceptionDoesNotWeakenMutationOrMalformedJSON(t *testing.T) {
	config, _, _ := clientFixture(t, func(w http.ResponseWriter, r *http.Request, credential adminauth.ClientCredential) {
		if r.URL.Path == "/v1/version" {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"version":"v1","secret":"SECRET-CANARY"}`)
			return
		}
		http.NotFound(w, r)
	})
	client := verifiedClient(t, config)
	_, err := client.Read(context.Background(), "/v1/version", &adminv1.ComponentVersion{})
	var remote *Error
	if !errors.As(err, &remote) || remote.Code != "invalid_response" || remote.HTTPStatus != 404 {
		t.Fatal("malformed JSON 404 became valid endpoint-absence evidence")
	}
	_, err = client.Submit(context.Background(), "POST", "/v1/servers/factory/stop", stopBody(), "legacy-response", Conditional{IfMatch: `"server:original-uid:2"`})
	if !errors.As(err, &remote) || remote.Code != "invalid_response" || !remote.Ambiguous || remote.OperationID == "" {
		t.Fatal("plain mutation response became rejection evidence or lost its original receipt")
	}
}

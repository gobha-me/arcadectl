// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/buildinfo"
)

type denyComponentVersion struct{}

func (denyComponentVersion) Authorize(context.Context, adminauth.Principal, Action) error {
	return ErrForbidden
}

func TestComponentVersionUsesAuthenticatedReadAndNoKubernetesAuthority(t *testing.T) {
	boundary, store, _, audit := operationFixture(t)
	response := operationHTTP(boundary, "GET", "/v1/version", "", "", "")
	if response.Code != 200 || response.Header().Get("ETag") != "" {
		t.Fatal("component version did not use the ordinary uncached read boundary")
	}
	var got adminv1.ComponentVersion
	if json.Unmarshal(response.Body.Bytes(), &got) != nil || got.Version != "v1" || got.SourceSHA != buildinfo.Current().SourceSHA || got.SourceEpoch != buildinfo.Current().SourceEpoch || got.GoVersion != buildinfo.Current().GoVersion {
		t.Fatal("component build claim was not bound to this process")
	}
	request := httptest.NewRequest("GET", "/v1/version", nil)
	unauthenticated := httptest.NewRecorder()
	boundary.ServeHTTP(unauthenticated, request)
	if unauthenticated.Code != 401 {
		t.Fatal("version metadata bypassed authentication")
	}
	query := operationHTTP(boundary, "GET", "/v1/version?token=SECRET-CANARY", "", "", "")
	if query.Code != 400 || strings.Contains(query.Body.String()+audit.String(), "SECRET-CANARY") {
		t.Fatal("version route accepted or reflected arbitrary query data")
	}
	if gets, lists, creates := store.counts(); gets != 0 || lists != 0 || creates != 0 {
		t.Fatal("component version acquired Kubernetes authority")
	}
	boundary.authorizer = denyComponentVersion{}
	if denied := operationHTTP(boundary, "GET", "/v1/version", "", "", ""); denied.Code != 403 {
		t.Fatal("component metadata bypassed authorization")
	}
}

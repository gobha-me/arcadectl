// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestOpenAPITracksTypedGuardedRoutesAndStrictSchemas(t *testing.T) {
	contents, err := OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(contents, &document) != nil {
		t.Fatal("invalid generated document")
	}
	paths := document["paths"].(map[string]any)
	ids := map[string]bool{}
	for _, route := range Routes() {
		path := paths[route.Path].(map[string]any)
		entry := path[strings.ToLower(route.Method)].(map[string]any)
		if entry["x-arcadectl-action"] != route.Action {
			t.Fatal("OpenAPI action drift")
		}
		id := entry["operationId"].(string)
		if ids[id] {
			t.Fatal("duplicate OpenAPI operation ID")
		}
		ids[id] = true
		if len(entry["security"].([]any)) != 1 {
			t.Fatal("unguarded OpenAPI route")
		}
		if route.RequestSchema != "" {
			headers := map[string]bool{}
			for _, item := range entry["parameters"].([]any) {
				parameter := item.(map[string]any)
				if parameter["in"] == "header" && parameter["required"] == true {
					headers[parameter["name"].(string)] = true
				}
			}
			expected := "If-Match"
			if route.Action == "server.create" {
				expected = "If-None-Match"
			}
			if !headers[expected] || !headers["Idempotency-Key"] {
				t.Fatal("mutation contract lacks required precondition/idempotency header")
			}
		}
	}
	schemas := document["components"].(map[string]any)["schemas"].(map[string]any)
	for name, raw := range schemas {
		if name == "Settings" {
			continue
		}
		value := raw.(map[string]any)
		if value["additionalProperties"] != false {
			t.Fatalf("schema %s allows unknown fields", name)
		}
	}
	image := schemas["Image"].(map[string]any)
	version := image["properties"].(map[string]any)["version"].(map[string]any)
	if version["maxLength"] != float64(64) || version["enum"] != nil {
		t.Fatal("adapter version confused with API version")
	}
	if len(image["oneOf"].([]any)) != 2 {
		t.Fatal("image digest/version exclusivity absent")
	}
	storageClass := schemas["Storage"].(map[string]any)["properties"].(map[string]any)["storageClassName"].(map[string]any)
	repositorySecret := schemas["BackupRequest"].(map[string]any)["properties"].(map[string]any)["repositorySecretName"].(map[string]any)
	if !regexp.MustCompile(storageClass["pattern"].(string)).MatchString("") || regexp.MustCompile(repositorySecret["pattern"].(string)).MatchString("") {
		t.Fatal("explicit no-class storage or nonempty repository secret schema contract drift")
	}
	if bytes.Contains(contents, []byte("unsafeNoBackup")) || bytes.Contains(contents, []byte(`"reattach"`)) {
		t.Fatal("ordinary API schema exposes unsafe/raw reattach")
	}
}

func TestGeneratedOpenAPIHasNoDrift(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate schema fixture")
	}
	expected, err := os.ReadFile(filepath.Join(filepath.Dir(source), "openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("OpenAPI drift: run hack/generate-openapi.sh")
	}
}

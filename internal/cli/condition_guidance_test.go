// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

func TestServerConditionsRenderSafeGuidanceWithoutChangingV1JSON(t *testing.T) {
	server := adminv1.Server{Name: "factory", Generation: 3, Conditions: []adminv1.Condition{
		{Type: "StorageReady", Status: "False", Reason: "RetainedDataConflict", ObservedGeneration: 2},
		{Type: "NetworkReady", Status: "False", Reason: "PlayerEndpointPending", ObservedGeneration: 3},
		{Type: "Ready", Status: "Unknown", Reason: "Unknown", ObservedGeneration: 3},
	}}
	var output bytes.Buffer
	app := application{options: Options{Out: &output}, output: "human"}
	if app.emit(server) != nil {
		t.Fatal("human status failed")
	}
	for _, expected := range []string{"reason=RetainedDataConflict observed=2", "exact claim UIDs", "LoadBalancer support", "Ask the cluster administrator to inspect"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatal("condition identity, freshness, or safe next action missing")
		}
	}
	output.Reset()
	app.output = "json"
	if app.emit(server) != nil {
		t.Fatal("JSON status failed")
	}
	var decoded struct {
		Conditions []map[string]any `json:"conditions"`
	}
	if json.Unmarshal(output.Bytes(), &decoded) != nil || len(decoded.Conditions) != 3 {
		t.Fatal("condition JSON was lost")
	}
	for _, condition := range decoded.Conditions {
		if len(condition) != 4 || condition["type"] == nil || condition["status"] == nil || condition["reason"] == nil || condition["observedGeneration"] == nil {
			t.Fatal("v1 condition wire shape changed")
		}
	}
}

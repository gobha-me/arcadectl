// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/supportbundle"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestDiagnoseUsesRealAuthenticatedAPIWithoutMutationOrState(t *testing.T) {
	fixture := newIntegrationFixture(t)
	server := &arcade.GameServer{}
	key := client.ObjectKey{Namespace: integrationNamespace, Name: "factory"}
	if err := fixture.store.Get(context.Background(), key, server); err != nil {
		t.Fatal(err)
	}
	server.Spec.Settings = runtime.RawExtension{Raw: []byte(`{"password":"RAW-WORKER-SECRET-CANARY","bearerToken":"RAW-WORKER-SECRET-CANARY","saveContents":"RAW-WORKER-SECRET-CANARY"}`)}
	server.Annotations = map[string]string{"private": integrationRawCanary}
	if err := fixture.store.Update(context.Background(), server); err != nil {
		t.Fatal(err)
	}
	foreign := server.DeepCopy()
	foreign.ObjectMeta = metav1.ObjectMeta{Name: "factory", Namespace: "unrelated-games", UID: "unrelated-private-uid", Generation: 4}
	if err := fixture.store.Create(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := fixture.run(t, "server", "diagnose", "factory", "--output", "json")
	if code != 0 || stderr != "" || strings.Contains(out, "unrelated-private-uid") {
		t.Fatal("scoped diagnostic failed or disclosed another namespace")
	}
	var got supportbundle.Bundle
	if json.Unmarshal([]byte(out), &got) != nil || !got.Partial || got.API == nil || got.Server.UID != "server-uid" || got.Namespace != integrationNamespace {
		t.Fatal("real API bundle lost its identity or explicit partial scope")
	}
	if fixture.mutationCount() != 0 || len(fixture.store.receipts()) != 0 {
		t.Fatal("diagnostics submitted a lifecycle intent")
	}
	if _, err := os.Stat(fixture.state); !os.IsNotExist(err) {
		t.Fatal("diagnostics created local mutation-attempt state")
	}
	code, second, stderr := fixture.run(t, "server", "diagnose", "factory", "--output", "json")
	if code != 0 || stderr != "" || second != out {
		t.Fatal("unchanged real API reads were not deterministic")
	}
}

func TestDiagnoseHumanOutputKeepsPartialReadOnlyRedaction(t *testing.T) {
	fixture := newIntegrationFixture(t)
	server := &arcade.GameServer{}
	key := client.ObjectKey{Namespace: integrationNamespace, Name: "factory"}
	if err := fixture.store.Get(t.Context(), key, server); err != nil {
		t.Fatal(err)
	}
	server.Spec.Settings = runtime.RawExtension{Raw: []byte(`{"password":"PRIVATE-DIAGNOSTIC-SETTINGS-CANARY"}`)}
	server.Annotations = map[string]string{"private": integrationRawCanary}
	if err := fixture.store.Update(t.Context(), server); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := fixture.run(t, "server", "diagnose", "factory")
	if code != 0 || stderr != "" || !strings.HasPrefix(out, "partial support bundle server=factory uid=server-uid ") || !strings.Contains(out, "omitted=") {
		t.Fatal("human diagnostic lost its identity or explicit partial scope")
	}
	if strings.Contains(out, integrationRawCanary) || strings.Contains(out, "PRIVATE-DIAGNOSTIC-SETTINGS-CANARY") {
		t.Fatal("human diagnostic disclosed private server inputs")
	}
	if fixture.mutationCount() != 0 || len(fixture.store.receipts()) != 0 {
		t.Fatal("human diagnostics submitted a lifecycle intent")
	}
	if _, err := os.Stat(fixture.state); !os.IsNotExist(err) {
		t.Fatal("human diagnostics created local mutation-attempt state")
	}
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToSchemeRegistersGameServer(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme() error = %v", err)
	}
	object, err := scheme.New(GroupVersion.WithKind("GameServer"))
	if err != nil {
		t.Fatalf("create registered GameServer: %v", err)
	}
	if _, ok := object.(*GameServer); !ok {
		t.Fatalf("registered object type = %T, want *GameServer", object)
	}
}

func TestDeepCopyIsolatesSettings(t *testing.T) {
	t.Parallel()

	original := &GameServer{Spec: GameServerSpec{Settings: runtime.RawExtension{Raw: []byte(`{"name":"original"}`)}}}
	clone := original.DeepCopy()
	clone.Spec.Settings.Raw[9] = 'X'
	if string(original.Spec.Settings.Raw) != `{"name":"original"}` {
		t.Fatal("DeepCopy() aliased settings bytes")
	}
}

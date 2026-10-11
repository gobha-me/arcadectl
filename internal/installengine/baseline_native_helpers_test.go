//go:build envtest || kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The fixture's acknowledged native UID proves matching behavior only. There
// is no production journal/effect receipt here, so it cannot certify durable
// ownership or recovery and must not replace the signed executable gates.
func installStandaloneBaselineContract(t *testing.T, ctx context.Context, access *HTTPAccess, namespace, profile string) (*installbaseline.Plan, map[installstate.Key]*unstructured.Unstructured) {
	t.Helper()
	manifest, payload, err := installbaseline.Build(strings.Repeat("a", 40), 1)
	if err != nil {
		t.Fatal("reviewed baseline fixture build failed")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x35}, ed25519.SeedSize))
	signature, err := installbaseline.Sign(manifest, key)
	if err != nil {
		t.Fatal("baseline fixture signing failed")
	}
	verified, err := installbaseline.Verify(manifest, signature, payload, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("baseline fixture authentication failed")
	}
	plan, err := installbaseline.Compile(verified, namespace, profile)
	if err != nil {
		t.Fatal("baseline fixture semantic compilation failed")
	}
	contract, err := installcontract.NewBaseline(plan)
	if err != nil {
		t.Fatal("baseline matching contract unavailable")
	}
	acknowledgements := map[installstate.Key]*unstructured.Unstructured{}
	for _, resource := range plan.Resources() {
		object := resource.Object
		address := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Name: object.GetName()}
		template, err := contract.Template(address, false)
		if err != nil || template.Hash() != resource.TemplateSHA256 {
			t.Fatal("baseline parameterized template identity changed")
		}
		candidate, err := template.Candidate(strings.Repeat("b", 32))
		if err != nil {
			t.Fatal("baseline fixture candidate unavailable")
		}
		admitted, err := access.Create(ctx, address, candidate, true)
		if err != nil || template.MatchAdmitted(admitted) != nil {
			t.Fatal("native baseline dry run differs from reviewed defaults")
		}
		ack, err := access.Create(ctx, address, candidate, false)
		if err != nil || ack == nil || ack.GetUID() == "" || template.MatchLive(ack, ack.GetUID()) != nil {
			t.Fatal("native baseline create acknowledgement differs from reviewed contract")
		}
		acknowledgements[address] = ack.DeepCopy()
		live, err := access.Get(ctx, address)
		if err != nil || template.MatchLive(live, ack.GetUID()) != nil || live.GetAnnotations()[installstate.MutationAnnotation] != strings.Repeat("b", 32) {
			t.Fatal("native baseline independent readback differs from its original acknowledgement")
		}
	}
	return plan, acknowledgements
}

func baselineDenial(err error, family, namespace string) bool {
	if err == nil || (!apierrors.IsForbidden(err) && !apierrors.IsInvalid(err)) {
		return false
	}
	name := "arcadectl-identity-" + family + "-" + namespace
	return strings.Contains(err.Error(), "ValidatingAdmissionPolicy '"+name+"'") &&
		strings.Contains(err.Error(), "binding '"+name+"'") && strings.Contains(err.Error(), installbaseline.DenialMessage)
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installbaseline

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"
)

func TestCompileClosedBaselineAndIndependentIdentities(t *testing.T) {
	manifest, signature, payload, key := fixtureArtifact(t)
	verified, err := Verify(manifest, signature, payload, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("artifact fixture authentication failed")
	}
	for _, profile := range supportedProfiles() {
		var previousHash string
		for _, namespace := range []string{"arcadectl-system", "isolated-baseline"} {
			plan, err := Compile(verified, namespace, profile)
			if err != nil || !plan.IsTrusted() || plan.Namespace() != namespace || plan.Profile() != profile || plan.Digest() != digest(manifest) {
				t.Fatal("sealed baseline plan identity failed")
			}
			resources := plan.Resources()
			if len(resources) != ResourceCount {
				t.Fatal("baseline resource inventory is not closed")
			}
			for _, resource := range resources {
				body := encodeFixture(t, resource.Object)
				if resource.TemplateSHA256 != digest(body) || resource.Object.GetNamespace() != "" {
					t.Fatal("baseline template hash or cluster scope is incorrect")
				}
			}
			if previousHash == resources[0].TemplateSHA256 {
				t.Fatal("parameterized namespace did not change template identity")
			}
			previousHash = resources[0].TemplateSHA256
			resources[0].Object.SetName("caller-substitution")
			resources[1].TemplateSHA256 = "caller-substitution"
			metadata, _ := plan.Manifest()
			metadata.Profiles[0] = "caller-substitution"
			again, err := Compile(verified, namespace, profile)
			freshMetadata, metadataErr := plan.Manifest()
			if err != nil || metadataErr != nil || !reflect.DeepEqual(again.Resources(), plan.Resources()) || !reflect.DeepEqual(freshMetadata.Profiles, supportedProfiles()) {
				t.Fatal("caller mutation changed a sealed baseline plan")
			}
		}
	}
}

func TestCompileRejectsAuthenticButUnreviewedPayloads(t *testing.T) {
	manifest, _, payload, key := fixtureArtifact(t)
	var objects []json.RawMessage
	if json.Unmarshal(payload, &objects) != nil || len(objects) != ResourceCount {
		t.Fatal("reviewed payload fixture decode failed")
	}
	reordered := append([]json.RawMessage{}, objects...)
	reordered[0], reordered[2] = reordered[2], reordered[0]
	extra := append(append([]json.RawMessage{}, objects...), objects[0])
	for _, candidate := range [][]byte{
		bytes.ReplaceAll(payload, []byte(`"failurePolicy":"Fail"`), []byte(`"failurePolicy":"Ignore"`)),
		bytes.ReplaceAll(payload, []byte(`"Deny"`), []byte(`"Warn"`)),
		bytes.ReplaceAll(payload, []byte("arcadectl-system"), []byte("isolated-baseline")),
		encodeFixture(t, reordered), encodeFixture(t, extra), encodeFixture(t, objects[:len(objects)-1]),
	} {
		if bytes.Equal(payload, candidate) {
			t.Fatal("unreviewed fixture did not change payload bytes")
		}
		metadata, _ := ParseManifest(manifest)
		metadata.PayloadSize, metadata.PayloadSHA256 = len(candidate), digest(candidate)
		changedManifest := encodeFixture(t, metadata)
		signature, err := Sign(changedManifest, key)
		if err != nil {
			t.Fatal("authorized unreviewed fixture signing failed")
		}
		verified, err := Verify(changedManifest, signature, candidate, key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal("authorized bounded bytes failed authentication")
		}
		if _, err := Compile(verified, "isolated-baseline", "kubernetes-1.37.0"); err != ErrInvalid {
			t.Fatal("authenticated arbitrary policy became an authorized plan")
		}
	}
}

func TestCompileRejectsInvalidBindingAndUnverifiedZeroValues(t *testing.T) {
	manifest, signature, payload, key := fixtureArtifact(t)
	verified, err := Verify(manifest, signature, payload, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("artifact fixture authentication failed")
	}
	for _, namespace := range []string{"", "default", "kube-system", "../escape", "MixedCase", "two.names"} {
		if _, err := Compile(verified, namespace, "kubernetes-1.37.0"); err != ErrInvalid {
			t.Fatal("baseline plan escaped selected namespace contract")
		}
	}
	for _, profile := range []string{"", "kubernetes-1.35.0", "kubernetes-1.36.0", "kubernetes-1.37.1"} {
		if _, err := Compile(verified, "isolated-baseline", profile); err != ErrInvalid {
			t.Fatal("baseline accepted an unreviewed profile")
		}
	}
	for _, zero := range []*Verified{nil, {}} {
		if _, err := Compile(zero, "isolated-baseline", "kubernetes-1.37.0"); err != ErrUnverified {
			t.Fatal("unverified bytes became a trusted plan")
		}
	}
	for _, zero := range []*Plan{nil, {}} {
		if zero.IsTrusted() || zero.Namespace() != "" || zero.Profile() != "" || zero.Digest() != "" || zero.Resources() != nil {
			t.Fatal("zero plan is trusted")
		}
		if _, err := zero.Manifest(); err != ErrUnverified {
			t.Fatal("zero plan declaration did not refuse")
		}
	}
}

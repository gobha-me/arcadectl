// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installbaseline

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const testSource = "54d6c11445cd76aa52914cc785b5450add01b2a5"

func fixtureArtifact(t *testing.T) ([]byte, []byte, []byte, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x39}, ed25519.SeedSize))
	manifest, payload, err := Build(testSource, 1791500000)
	if err != nil {
		t.Fatal("reviewed artifact build failed")
	}
	signature, err := Sign(manifest, key)
	if err != nil {
		t.Fatal("fixture signing failed")
	}
	return manifest, signature, payload, key
}

func encodeFixture(t *testing.T, value any) []byte {
	t.Helper()
	body, err := canonicalEncode(value)
	if err != nil {
		t.Fatal("canonical fixture encoding failed")
	}
	return body
}

func TestArtifactReproducibilityAndExternalTrust(t *testing.T) {
	manifest, signature, payload, key := fixtureArtifact(t)
	againManifest, againPayload, err := Build(testSource, 1791500000)
	if err != nil || !bytes.Equal(manifest, againManifest) || !bytes.Equal(payload, againPayload) {
		t.Fatal("artifact is not reproducible")
	}
	againSignature, err := Sign(manifest, key)
	if err != nil || !bytes.Equal(signature, againSignature) {
		t.Fatal("artifact signature is not deterministic")
	}
	verified, err := Verify(manifest, signature, payload, key.Public().(ed25519.PublicKey))
	if err != nil || !verified.IsVerified() {
		t.Fatal("external-key artifact verification failed")
	}
	metadata, err := verified.Manifest()
	if err != nil || metadata.SourceSHA != testSource || metadata.BaselineVersion != Version || metadata.PayloadSHA256 != digest(payload) || metadata.PayloadSize != len(payload) {
		t.Fatal("verified declaration does not match bounded bytes")
	}
	if got, err := verified.Digest(); err != nil || got != digest(manifest) {
		t.Fatal("artifact identity does not bind the manifest")
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := Verify(manifest, signature, payload, other); err != ErrSignature {
		t.Fatal("artifact accepted an unrelated trust root")
	}
}

func TestArtifactRejectsTamperingAndDomainReplay(t *testing.T) {
	manifest, signature, payload, key := fixtureArtifact(t)
	public := key.Public().(ed25519.PublicKey)
	metadata, _ := ParseManifest(manifest)
	metadata.SourceSHA = strings.Repeat("a", 40)
	changedManifest := encodeFixture(t, metadata)
	if _, err := Verify(changedManifest, signature, payload, public); err != ErrSignature {
		t.Fatal("modified authenticated declaration was accepted")
	}
	changedPayload := bytes.Clone(payload)
	changedPayload[len(changedPayload)-1] ^= 1
	if _, err := Verify(manifest, signature, changedPayload, public); err != ErrInvalid {
		t.Fatal("modified payload was accepted")
	}
	for _, mutate := range []func(*signatureEnvelope){
		func(e *signatureEnvelope) { e.Version = "v2" },
		func(e *signatureEnvelope) { e.Algorithm = "none" },
		func(e *signatureEnvelope) { e.PublicKeySHA256 = strings.Repeat("0", 64) },
		func(e *signatureEnvelope) { e.Signature = "%%%" },
		func(e *signatureEnvelope) { e.Signature = base64.StdEncoding.EncodeToString(make([]byte, 63)) },
		func(e *signatureEnvelope) { e.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		func(e *signatureEnvelope) { e.Signature += "\n" },
	} {
		var envelope signatureEnvelope
		if json.Unmarshal(signature, &envelope) != nil {
			t.Fatal("fixture envelope decode failed")
		}
		mutate(&envelope)
		if _, err := Verify(manifest, encodeFixture(t, envelope), payload, public); err != ErrSignature {
			t.Fatal("invalid signature envelope was accepted")
		}
	}
	// A signature under the real runtime-package domain cannot authenticate a
	// security baseline, even with the same external key and declaration bytes.
	replay := signatureEnvelope{FormatVersion, "Ed25519", digest(public), base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("arcadectl/install-package/v1\x00"), manifest...)))}
	if _, err := Verify(manifest, encodeFixture(t, replay), payload, public); err != ErrSignature {
		t.Fatal("runtime-package signature was replayed as a security baseline")
	}
	brokenKey := bytes.Clone(key)
	brokenKey[ed25519.SeedSize] ^= 1
	if _, err := Sign(manifest, brokenKey); err != ErrSignature {
		t.Fatal("inconsistent signing key was accepted")
	}
	for _, size := range []int{0, 31, 32, 63, 65} {
		if _, err := Sign(manifest, make([]byte, size)); err != ErrSignature {
			t.Fatal("wrong-size signing key was accepted")
		}
	}
}

func TestArtifactCanonicalClosedManifest(t *testing.T) {
	manifest, signature, payload, key := fixtureArtifact(t)
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.FormatVersion = "v2" },
		func(m *Manifest) { m.BaselineVersion = "unreviewed" },
		func(m *Manifest) { m.SourceSHA = strings.Repeat("A", 40) },
		func(m *Manifest) { m.SourceSHA = "../escape" },
		func(m *Manifest) { m.SourceEpoch = 0 },
		func(m *Manifest) { m.SourceEpoch = 253402300800 },
		func(m *Manifest) { m.Profiles = []string{"kubernetes-1.37.0", "kubernetes-1.35.8"} },
		func(m *Manifest) { m.Profiles = []string{"kubernetes-1.37.0"} },
		func(m *Manifest) { m.Profiles = append(m.Profiles, "unsupported") },
		func(m *Manifest) { m.PayloadSize = 0 },
		func(m *Manifest) { m.PayloadSize = MaxPayloadBytes + 1 },
		func(m *Manifest) { m.PayloadSHA256 = strings.Repeat("A", 64) },
	} {
		metadata, _ := ParseManifest(manifest)
		mutate(&metadata)
		body := encodeFixture(t, metadata)
		if _, err := ParseManifest(body); err != ErrInvalid {
			t.Fatal("invalid manifest declaration was accepted")
		}
		if _, err := Sign(body, key); err != ErrInvalid {
			t.Fatal("invalid manifest declaration was signed")
		}
	}
	for _, body := range [][]byte{
		append(bytes.Clone(manifest), '\n'), append([]byte(" "), manifest...), append(bytes.Clone(manifest), []byte("{}")...),
		bytes.Replace(manifest, []byte(`"formatVersion":"v1"`), []byte(`"formatVersion":"v1","formatVersion":"v1"`), 1),
		bytes.Replace(manifest, []byte(`"formatVersion":"v1"`), []byte(`"extra":"must-not-echo","formatVersion":"v1"`), 1),
	} {
		if _, err := ParseManifest(body); err != ErrInvalid {
			t.Fatal("noncanonical or open manifest was accepted")
		}
	}
	var envelope map[string]any
	if json.Unmarshal(signature, &envelope) != nil {
		t.Fatal("fixture envelope decode failed")
	}
	envelope["extra"] = "must-not-echo"
	if _, err := Verify(manifest, encodeFixture(t, envelope), payload, key.Public().(ed25519.PublicKey)); err != ErrSignature {
		t.Fatal("open signature envelope was accepted")
	}
}

func TestArtifactBoundsBeforeAllocation(t *testing.T) {
	manifest, signature, payload, key := fixtureArtifact(t)
	public := key.Public().(ed25519.PublicKey)
	for _, input := range []struct {
		manifest, signature, payload, key []byte
		expected                          error
	}{
		{nil, signature, payload, public, ErrInvalid},
		{make([]byte, MaxManifestBytes+1), signature, payload, public, ErrInvalid},
		{manifest, nil, payload, public, ErrSignature},
		{manifest, make([]byte, MaxSignatureBytes+1), payload, public, ErrSignature},
		{manifest, signature, nil, public, ErrInvalid},
		{manifest, signature, make([]byte, MaxPayloadBytes+1), public, ErrInvalid},
		{manifest, signature, payload, nil, ErrSignature},
		{manifest, signature, payload, make([]byte, ed25519.PublicKeySize+1), ErrSignature},
	} {
		if _, err := Verify(input.manifest, input.signature, input.payload, input.key); err != input.expected {
			t.Fatal("artifact byte bound did not fail closed")
		}
		if allocations := testing.AllocsPerRun(10, func() { _, _ = Verify(input.manifest, input.signature, input.payload, input.key) }); allocations != 0 {
			t.Fatal("out-of-bounds artifact was copied before rejection")
		}
	}
	// Authentication may accept bounded signed arbitrary bytes. Compile is the
	// independent semantic boundary; maximum-size bytes must not bypass it.
	maximum := make([]byte, MaxPayloadBytes)
	metadata, _ := ParseManifest(manifest)
	metadata.PayloadSize, metadata.PayloadSHA256 = len(maximum), digest(maximum)
	manifest = encodeFixture(t, metadata)
	signature, err := Sign(manifest, key)
	if err != nil {
		t.Fatal("maximum-size signed fixture failed")
	}
	verified, err := Verify(manifest, signature, maximum, public)
	if err != nil {
		t.Fatal("bounded authenticated payload was incorrectly rejected")
	}
	if _, err := Compile(verified, "isolated-baseline", "kubernetes-1.37.0"); err != ErrInvalid {
		t.Fatal("bounded arbitrary signed payload became a trusted plan")
	}
}

func TestVerifiedArtifactDefensiveCopiesAndZeroValues(t *testing.T) {
	manifest, signature, payload, key := fixtureArtifact(t)
	originalManifest, originalPayload := bytes.Clone(manifest), bytes.Clone(payload)
	public := key.Public().(ed25519.PublicKey)
	verified, err := Verify(manifest, signature, payload, public)
	if err != nil {
		t.Fatal("artifact fixture verification failed")
	}
	for _, body := range [][]byte{manifest, signature, payload, public} {
		body[0] ^= 1
	}
	metadata, _ := verified.Manifest()
	metadata.Profiles[0] = "caller-substitution"
	for _, accessor := range []func() ([]byte, error){verified.ManifestBytes, verified.Payload} {
		body, err := accessor()
		if err != nil {
			t.Fatal("verified accessor failed")
		}
		body[0] ^= 1
	}
	gotManifest, _ := verified.ManifestBytes()
	gotPayload, _ := verified.Payload()
	gotMetadata, _ := verified.Manifest()
	if !bytes.Equal(gotManifest, originalManifest) || !bytes.Equal(gotPayload, originalPayload) || !reflect.DeepEqual(gotMetadata.Profiles, supportedProfiles()) {
		t.Fatal("caller changed sealed verified bytes")
	}
	for _, zero := range []*Verified{nil, {}} {
		if zero.IsVerified() {
			t.Fatal("zero artifact is verified")
		}
		if _, err := zero.Manifest(); err != ErrUnverified {
			t.Fatal("zero manifest accessor did not refuse")
		}
		if _, err := zero.ManifestBytes(); err != ErrUnverified {
			t.Fatal("zero manifest bytes accessor did not refuse")
		}
		if _, err := zero.Payload(); err != ErrUnverified {
			t.Fatal("zero payload accessor did not refuse")
		}
		if _, err := zero.Digest(); err != ErrUnverified {
			t.Fatal("zero digest accessor did not refuse")
		}
	}
}

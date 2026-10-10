// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installpackage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
)

func fixtureMetadata() Manifest {
	m := Manifest{FormatVersion: FormatVersion, RendererVersion: RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("a", 40), SourceEpoch: 1791223200,
		Images:        Images{Controller: "registry.example/arcadectl-controller@sha256:" + strings.Repeat("b", 64), API: "registry.example/arcadectl-api@sha256:" + strings.Repeat("c", 64)},
		Profiles:      []Profile{{ID: "kubernetes-1.37.0", KubernetesVersion: "1.37.0", PodSecurityVersion: "v1.37"}, {ID: "kubernetes-1.35.8", KubernetesVersion: "1.35.8", PodSecurityVersion: "v1.35"}},
		Prerequisites: []string{"restricted-pods", "api-tls"},
		Predecessors:  []Predecessor{{ID: "issue-26", PackageSHA256: strings.Repeat("2", 64), SourceSHA: strings.Repeat("d", 40), Images: Images{Controller: "registry.example/previous-controller@sha256:" + strings.Repeat("e", 64), API: "registry.example/previous-api@sha256:" + strings.Repeat("f", 64)}, Namespace: "arcadectl-system", ProfileIDs: []string{"kubernetes-1.37.0", "kubernetes-1.35.8"}}},
	}
	for _, name := range CanonicalCRDNames() {
		m.CRDs = append(m.CRDs, CRD{Name: name, SchemaSHA256: strings.Repeat("1", 64), StorageVersion: "v1alpha1", ServedVersions: []string{"v1alpha1"}, ConversionStrategy: "None"})
	}
	slices.Reverse(m.CRDs)
	return m
}
func fixturePayloads() map[string][]byte {
	return map[string][]byte{AnchorsPath: []byte("anchors\n"), APIPath: []byte("api\n"), ControllerPath: []byte("controller\n")}
}
func fixtureKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}
func publicKey(key ed25519.PrivateKey) ed25519.PublicKey { return key.Public().(ed25519.PublicKey) }
func canonical(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func manifestFixture(t *testing.T) []byte {
	t.Helper()
	body, err := Build(fixtureMetadata(), fixturePayloads())
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestBuildDeterministicAndDoesNotMutateInput(t *testing.T) {
	input := fixtureMetadata()
	before, _ := json.Marshal(input)
	profiles := slices.Clone(input.Profiles)
	prerequisites := slices.Clone(input.Prerequisites)
	names := make([]string, len(input.CRDs))
	for i, c := range input.CRDs {
		names[i] = c.Name
	}
	first, err := Build(input, fixturePayloads())
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("first build mutated caller metadata")
	}
	slices.Reverse(input.Profiles)
	slices.Reverse(input.Prerequisites)
	slices.Reverse(input.CRDs)
	before, _ = json.Marshal(input)
	second, err := Build(input, fixturePayloads())
	after, _ = json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("second build mutated caller metadata")
	}
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("reproducibility failed: %v", err)
	}
	slices.Reverse(input.Profiles)
	slices.Reverse(input.Prerequisites)
	slices.Reverse(input.CRDs)
	if !slices.Equal(input.Profiles, profiles) || !slices.Equal(input.Prerequisites, prerequisites) {
		t.Fatal("build sorted caller slices")
	}
	for i, c := range input.CRDs {
		if c.Name != names[i] {
			t.Fatal("build changed caller CRDs")
		}
	}
	parsed, err := ParseManifest(first)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Files[0].Path != AnchorsPath || parsed.Files[1].Path != APIPath || parsed.Files[2].Path != ControllerPath {
		t.Fatal("files not canonical sorted")
	}
	parsed, err = ParseManifest(first)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.EqualFunc(parsed.CRDs, []CRD{{Name: CanonicalCRDNames()[0]}, {Name: CanonicalCRDNames()[1]}, {Name: CanonicalCRDNames()[2]}, {Name: CanonicalCRDNames()[3]}, {Name: CanonicalCRDNames()[4]}}, func(a, b CRD) bool { return a.Name == b.Name }) {
		t.Fatal("wrong canonical CRD set")
	}
}

func TestImageReferenceGrammar(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("b", 64)
	for _, repository := range []string{"registry.example/:bad", "registry.example/api:::bad", "registry.example:0/api", "registry.example:65536/api", "registry.example:abc/api", "registry..example/api", "registry.example/api:", "registry.example/a./api", "registry.example//api", "registry.example/a:tag/api"} {
		if validImage(repository + digest) {
			t.Fatalf("invalid image repository accepted: %s", repository)
		}
	}
	for _, repository := range []string{"api", "api:rc.1", "registry.example/api", "localhost:5000/org/api", "registry.example:443/org/a__b-c.d:rc.1"} {
		if !validImage(repository + digest) {
			t.Fatalf("valid image repository rejected: %s", repository)
		}
	}
}

func TestBuildPreservesNestedCallerSlices(t *testing.T) {
	input := fixtureMetadata()
	encoded, _ := json.Marshal(input)
	var before Manifest
	if json.Unmarshal(encoded, &before) != nil {
		t.Fatal("copy fixture")
	}
	if _, err := Build(input, fixturePayloads()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input, before) {
		t.Fatal("build changed nested caller slices")
	}
}

func TestBuildRejectsInvalidContracts(t *testing.T) {
	cases := map[string]func(*Manifest){
		"format": func(m *Manifest) { m.FormatVersion = "v2" }, "renderer": func(m *Manifest) { m.RendererVersion = "v9" }, "version": func(m *Manifest) { m.PackageVersion = "01.2.3" },
		"source": func(m *Manifest) { m.SourceSHA = strings.Repeat("0", 40) }, "epoch": func(m *Manifest) { m.SourceEpoch = 0 }, "far epoch": func(m *Manifest) { m.SourceEpoch = 253402300800 },
		"zero controller": func(m *Manifest) { m.Images.Controller = "registry.example/image@sha256:" + strings.Repeat("0", 64) }, "tag": func(m *Manifest) { m.Images.API = "api:latest" }, "path image": func(m *Manifest) { m.Images.API = "registry.example/../api@sha256:" + strings.Repeat("a", 64) },
		"profile duplicate": func(m *Manifest) { m.Profiles = append(m.Profiles, m.Profiles[0]) }, "security version": func(m *Manifest) { m.Profiles[0].PodSecurityVersion = "latest" }, "profile prerelease": func(m *Manifest) { m.Profiles[0].KubernetesVersion = "1.37.0-alpha" },
		"prerequisite duplicate": func(m *Manifest) { m.Prerequisites = append(m.Prerequisites, m.Prerequisites[0]) }, "prerequisite controls": func(m *Manifest) { m.Prerequisites = []string{"token\nCANARY"} },
		"missing CRD": func(m *Manifest) { m.CRDs = m.CRDs[:4] }, "wrong CRD": func(m *Manifest) { m.CRDs[0].Name = "foreign.example" }, "CRD duplicate": func(m *Manifest) { m.CRDs[1] = m.CRDs[0] }, "CRD digest": func(m *Manifest) { m.CRDs[0].SchemaSHA256 = strings.Repeat("0", 64) }, "conversion": func(m *Manifest) { m.CRDs[0].ConversionStrategy = "Webhook" }, "storage version": func(m *Manifest) { m.CRDs[0].StorageVersion = "v2" }, "served version": func(m *Manifest) { m.CRDs[0].ServedVersions = []string{"v1alpha1", "v2"} },
		"predecessor source": func(m *Manifest) { m.Predecessors[0].SourceSHA = m.SourceSHA }, "predecessor image": func(m *Manifest) { m.Predecessors[0].Images.API = "old:latest" }, "predecessor namespace": func(m *Manifest) { m.Predecessors[0].Namespace = "custom" }, "predecessor unknown profile": func(m *Manifest) { m.Predecessors[0].ProfileIDs = []string{"unknown"} }, "predecessor duplicate": func(m *Manifest) { m.Predecessors = append(m.Predecessors, m.Predecessors[0]) },
		"missing predecessor package": func(m *Manifest) { m.Predecessors[0].PackageSHA256 = "" }, "zero predecessor package": func(m *Manifest) { m.Predecessors[0].PackageSHA256 = strings.Repeat("0", 64) },
		"caller file": func(m *Manifest) { m.Files = []File{{Path: APIPath}} }, "oversize metadata": func(m *Manifest) { m.Profiles[0].ID = strings.Repeat("x", MaxManifestBytes) }, "oversize list": func(m *Manifest) { m.Profiles = make([]Profile, 9) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixtureMetadata()
			mutate(&m)
			_, err := Build(m, fixturePayloads())
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted invalid contract: %v", err)
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Fatal("error reflected contents")
			}
		})
	}
	m := fixtureMetadata()
	m.Predecessors = nil
	if _, err := Build(m, fixturePayloads()); err != nil {
		t.Fatal("first package without predecessor rejected")
	}
}

func TestPayloadPathAndBounds(t *testing.T) {
	for _, path := range []string{"../api.yaml", "/api.yaml", "manifests/../api.yaml", "manifests//api.yaml", "manifests/api.yaml/", "manifests/api.yaml\x00", "secret.yaml"} {
		t.Run(path, func(t *testing.T) {
			p := fixturePayloads()
			delete(p, APIPath)
			p[path] = []byte("CANARY")
			if _, err := Build(fixtureMetadata(), p); !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe path accepted")
			}
		})
	}
	for _, scenario := range []string{"extra", "missing", "empty", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			p := fixturePayloads()
			switch scenario {
			case "extra":
				p["manifest.json"] = []byte("x")
			case "missing":
				delete(p, APIPath)
			case "empty":
				p[APIPath] = nil
			case "oversize":
				p[APIPath] = make([]byte, MaxPayloadBytes+1)
			}
			if _, err := Build(fixtureMetadata(), p); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid payload map accepted")
			}
		})
	}
	p := fixturePayloads()
	p[APIPath] = bytes.Repeat([]byte{'x'}, MaxPayloadBytes)
	if _, err := Build(fixtureMetadata(), p); err != nil {
		t.Fatal("valid maximum rejected")
	}
}

func TestManifestStrictCanonical(t *testing.T) {
	body := manifestFixture(t)
	var fields map[string]any
	if json.Unmarshal(body, &fields) != nil {
		t.Fatal("fixture decode")
	}
	unknown := map[string]any{}
	for k, v := range fields {
		unknown[k] = v
	}
	unknown["untrusted"] = true
	cased := map[string]any{}
	for k, v := range fields {
		cased[k] = v
	}
	cased["FormatVersion"] = cased["formatVersion"]
	delete(cased, "formatVersion")
	without := map[string]any{}
	for k, v := range fields {
		without[k] = v
	}
	delete(without, "predecessors")
	null := map[string]any{}
	for k, v := range fields {
		null[k] = v
	}
	null["predecessors"] = nil
	inputs := [][]byte{nil, []byte("{}"), append(bytes.Clone(body), '\n'), append(bytes.Clone(body), body...), bytes.Replace(body, []byte(`"formatVersion":"v1"`), []byte(`"formatVersion":"v1","formatVersion":"v1"`), 1), canonical(t, unknown), canonical(t, cased), canonical(t, without), canonical(t, null), bytes.Replace(body, []byte(`"sourceEpoch":1791223200`), []byte(`"sourceEpoch":1791223200.0`), 1), bytes.Repeat([]byte{' '}, MaxManifestBytes+1)}
	for i, input := range inputs {
		if _, err := ParseManifest(input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("noncanonical input %d accepted", i)
		}
	}
	m, err := ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(m.Files)
	if _, err := ParseManifest(canonical(t, m)); !errors.Is(err, ErrInvalid) {
		t.Fatal("unsorted file entries accepted")
	}
	m, err = ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	m.Files[1] = m.Files[0]
	if _, err := ParseManifest(canonical(t, m)); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate file entries accepted")
	}
	m, err = ParseManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	m.Files[0].Size = MaxPayloadBytes + 1
	if _, err := ParseManifest(canonical(t, m)); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize declaration accepted")
	}
}

func TestSignVerifyAndDefensiveCloning(t *testing.T) {
	manifest := manifestFixture(t)
	key := fixtureKey()
	signature, err := Sign(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Sign(manifest, key)
	if err != nil || !bytes.Equal(signature, again) {
		t.Fatal("signature not reproducible")
	}
	payloads := fixturePayloads()
	verified, err := Verify(manifest, signature, payloads, publicKey(key))
	if err != nil || !verified.IsVerified() {
		t.Fatalf("verify failed: %v", err)
	}
	digest, err := verified.Digest()
	if err != nil || digest != hash(manifest) {
		t.Fatal("wrong package digest")
	}
	expectedManifest := bytes.Clone(manifest)
	expectedAPI := bytes.Clone(payloads[APIPath])
	manifest[0] = 'x'
	payloads[APIPath][0] = 'x'
	payloads[APIPath] = []byte("replaced")
	delete(payloads, ControllerPath)
	got, err := verified.ManifestBytes()
	if err != nil || !bytes.Equal(got, expectedManifest) {
		t.Fatal("retained caller manifest")
	}
	got[0] = 'y'
	got, err = verified.Payload(APIPath)
	if err != nil || !bytes.Equal(got, expectedAPI) {
		t.Fatal("retained caller payload")
	}
	got[0] = 'y'
	got, _ = verified.ManifestBytes()
	if !bytes.Equal(got, expectedManifest) {
		t.Fatal("manifest getter leaked bytes")
	}
	got, _ = verified.Payload(APIPath)
	if !bytes.Equal(got, expectedAPI) {
		t.Fatal("payload getter leaked bytes")
	}
	m, _ := verified.Manifest()
	m.CRDs[0].ServedVersions[0] = "changed"
	m.Predecessors[0].ProfileIDs[0] = "changed"
	m.Profiles[0].ID = "changed"
	fresh, _ := verified.Manifest()
	if fresh.CRDs[0].ServedVersions[0] != "v1alpha1" || fresh.Predecessors[0].ProfileIDs[0] != "kubernetes-1.35.8" || fresh.Profiles[0].ID == "changed" {
		t.Fatal("metadata getter leaked nested slices")
	}
	if _, err := verified.Payload("../secret"); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown payload accessible")
	}
	for _, empty := range []*VerifiedPackage{nil, {}} {
		if empty.IsVerified() {
			t.Fatal("zero package verified")
		}
		if _, err := empty.Manifest(); !errors.Is(err, ErrUnverified) {
			t.Fatal("zero metadata accepted")
		}
		if _, err := empty.ManifestBytes(); !errors.Is(err, ErrUnverified) {
			t.Fatal("zero bytes accepted")
		}
		if _, err := empty.Payload(APIPath); !errors.Is(err, ErrUnverified) {
			t.Fatal("zero payload accepted")
		}
		if _, err := empty.Digest(); !errors.Is(err, ErrUnverified) {
			t.Fatal("zero digest accepted")
		}
	}
}

func TestAuthenticationNegatives(t *testing.T) {
	manifest := manifestFixture(t)
	key := fixtureKey()
	signature, err := Sign(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	for _, external := range []ed25519.PublicKey{nil, make([]byte, 31), make([]byte, 33), publicKey(other)} {
		if _, err := Verify(manifest, signature, fixturePayloads(), external); !errors.Is(err, ErrSignature) {
			t.Fatal("wrong external key accepted")
		}
	}
	for _, private := range []ed25519.PrivateKey{nil, make([]byte, 63), make([]byte, 65), make([]byte, 64)} {
		if _, err := Sign(manifest, private); !errors.Is(err, ErrSignature) {
			t.Fatal("invalid private key accepted")
		}
	}
	if _, err := Sign([]byte("{\"CANARY\":1}"), key); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "CANARY") {
		t.Fatal("invalid signing metadata accepted/reflected")
	}
	m, _ := ParseManifest(manifest)
	m.SourceEpoch++
	altered := canonical(t, m)
	if _, err := Verify(altered, signature, fixturePayloads(), publicKey(key)); !errors.Is(err, ErrSignature) {
		t.Fatal("tampered manifest accepted")
	}
	tampered := fixturePayloads()
	tampered[APIPath][0] = 'X'
	if _, err := Verify(manifest, signature, tampered, publicKey(key)); !errors.Is(err, ErrInvalid) {
		t.Fatal("tampered payload accepted")
	}
	for _, scenario := range []string{"undeclared", "missing", "traversal", "empty", "oversize", "wrong size"} {
		t.Run(scenario, func(t *testing.T) {
			payloads := fixturePayloads()
			switch scenario {
			case "undeclared":
				payloads["private-key"] = []byte("CANARY")
			case "missing":
				delete(payloads, APIPath)
			case "traversal":
				delete(payloads, APIPath)
				payloads["../api.yaml"] = []byte("CANARY")
			case "empty":
				payloads[APIPath] = nil
			case "oversize":
				payloads[APIPath] = make([]byte, MaxPayloadBytes+1)
			case "wrong size":
				payloads[APIPath] = []byte("api\nextra")
			}
			if _, err := Verify(manifest, signature, payloads, publicKey(key)); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid verification payload map accepted")
			}
		})
	}
	var envelope signatureEnvelope
	if json.Unmarshal(signature, &envelope) != nil {
		t.Fatal("decode signature")
	}
	var unknown map[string]any
	if json.Unmarshal(signature, &unknown) != nil {
		t.Fatal("decode signature")
	}
	unknown["publicKey"] = "bundled-key-CANARY"
	inputs := [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxSignatureBytes+1), append(bytes.Clone(signature), '\n'), append(bytes.Clone(signature), signature...), bytes.Replace(signature, []byte(`"algorithm":"Ed25519"`), []byte(`"algorithm":"Ed25519","algorithm":"Ed25519"`), 1), canonical(t, unknown)}
	for _, mutate := range []func(*signatureEnvelope){func(e *signatureEnvelope) { e.Version = "v2" }, func(e *signatureEnvelope) { e.Algorithm = "RSA" }, func(e *signatureEnvelope) { e.PublicKeySHA256 = hash(publicKey(other)) }, func(e *signatureEnvelope) { e.Signature = "CANARY" }, func(e *signatureEnvelope) { e.Signature = strings.Repeat("A", 88) }, func(e *signatureEnvelope) { e.Signature += "\n" }} {
		changed := envelope
		mutate(&changed)
		inputs = append(inputs, canonical(t, changed))
	}
	for i, input := range inputs {
		if _, err := Verify(manifest, input, fixturePayloads(), publicKey(key)); !errors.Is(err, ErrSignature) || strings.Contains(err.Error(), "CANARY") {
			t.Fatalf("invalid envelope %d accepted/reflected: %v", i, err)
		}
	}
	// A valid Ed25519 signature over the wrong domain must not authenticate.
	envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest))
	if _, err := Verify(manifest, canonical(t, envelope), fixturePayloads(), publicKey(key)); !errors.Is(err, ErrSignature) {
		t.Fatal("unseparated signature accepted")
	}
}

func TestCanonicalCRDNamesAreDefensive(t *testing.T) {
	names := CanonicalCRDNames()
	names[0] = "foreign.example"
	if CanonicalCRDNames()[0] != "arcadeoperations.arcade.gobha.me" {
		t.Fatal("canonical CRD names leaked mutable storage")
	}
}

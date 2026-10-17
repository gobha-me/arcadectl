// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/config"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func fixture(t *testing.T, legacy bool) (installpackage.Manifest, map[string][]byte) {
	t.Helper()
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	payloads, crds, err := RenderPayloads(images, legacy)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("c", 40)
	if legacy {
		source = LegacySourceSHA
	}
	return installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: source, SourceEpoch: 1791223200, Images: images, Profiles: SupportedProfiles(legacy), Prerequisites: RequiredPrerequisites(), CRDs: crds}, payloads
}
func authenticated(t *testing.T, metadata installpackage.Manifest, payloads map[string][]byte) *installpackage.VerifiedPackage {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	body, err := installpackage.Build(metadata, payloads)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := installpackage.Sign(body, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(body, signature, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}
func mustCompile(t *testing.T, legacy bool, namespace, profile string) *Plan {
	t.Helper()
	metadata, payloads := fixture(t, legacy)
	plan, err := Compile(authenticated(t, metadata, payloads), namespace, profile)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func TestDeterministicPayloadAndCRDDeclarations(t *testing.T) {
	if !legacyAssetsMatch() {
		t.Fatal("embedded configs no longer match the exact predecessor source; preserve old inputs separately rather than relabeling current templates")
	}
	metadata, payloads := fixture(t, false)
	for range 4 {
		again, crds, err := RenderPayloads(metadata.Images, false)
		if err != nil || !reflect.DeepEqual(payloads, again) || !reflect.DeepEqual(metadata.CRDs, crds) {
			t.Fatal("renderer is not deterministic")
		}
	}
	objects, err := decodeRendered(payloads[installpackage.AnchorsPath])
	if err != nil {
		t.Fatal(err)
	}
	declarationsByName := map[string]installpackage.CRD{}
	for _, c := range metadata.CRDs {
		declarationsByName[c.Name] = c
	}
	for _, object := range objects {
		if object.GetKind() != "CustomResourceDefinition" {
			continue
		}
		var crd apiextensions.CustomResourceDefinition
		body, _ := json.Marshal(object.Object)
		if json.Unmarshal(body, &crd) != nil {
			t.Fatal("typed CRD decode")
		}
		schema, _ := json.Marshal(crd.Spec.Versions[0].Schema)
		sum := sha256.Sum256(schema)
		if declarationsByName[crd.Name].SchemaSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("schema declaration differs from typed spec")
		}
	}
	if len(declarationsByName) != 5 {
		t.Fatal("wrong CRD count")
	}
	// Detect unexpected divergence of the separately generated namespace input.
	namespace, err := config.Installation.ReadFile("install/namespace.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(namespace, []byte(DefaultNamespace)) {
		t.Fatal("canonical namespace missing")
	}
}
func TestNamespacePlanConsistentAndDefensive(t *testing.T) {
	for _, namespace := range []string{DefaultNamespace, "test-games", strings.Repeat("a", 63)} {
		plan := mustCompile(t, false, namespace, Profile135)
		if !plan.IsTrusted() || plan.Namespace() != namespace || plan.Profile().PodSecurityVersion != "v1.35" {
			t.Fatal("wrong plan identity")
		}
		resources := plan.Resources()
		if len(resources) != 38 {
			t.Fatalf("resources=%d", len(resources))
		}
		retained := 0
		policies := 0
		clusterNames := map[string]bool{}
		for _, resource := range resources {
			object := resource.Object
			if resource.Retained {
				retained++
			}
			if resource.Phase == Policies {
				policies++
			}
			if object.GetKind() == "Deployment" && object.GetName() == "arcadectl-api" {
				containers, _, _ := unstructured.NestedSlice(object.Object, "spec", "template", "spec", "containers")
				ports := containers[0].(map[string]any)["ports"].([]any)
				if _, ok := ports[0].(map[string]any)["containerPort"].(int64); !ok {
					t.Fatal("numeric rendering lost Kubernetes int64 semantics")
				}
			}
			if object.GetNamespace() != "" && object.GetNamespace() != namespace {
				t.Fatal("wrong object namespace")
			}
			if object.GetKind() == "Namespace" && (object.GetName() != namespace || object.GetLabels()["pod-security.kubernetes.io/enforce-version"] != "v1.35") {
				t.Fatal("wrong namespace/PSA")
			}
			if object.GetKind() == "CustomResourceDefinition" {
				if !strings.HasSuffix(object.GetName(), ".arcade.gobha.me") {
					t.Fatal("CRD renamed")
				}
				continue
			}
			if object.GetNamespace() == "" && object.GetKind() != "Namespace" {
				clusterNames[object.GetName()] = true
				if len(object.GetName()) > 63 {
					t.Fatal("unbounded cluster name")
				}
				if namespace != DefaultNamespace && strings.HasSuffix(object.GetName(), "-gate") {
					t.Fatal("custom cluster resource not renamed")
				}
			}
			body, _ := json.Marshal(object.Object)
			if namespace != DefaultNamespace && bytes.Contains(body, []byte("system:serviceaccount:"+DefaultNamespace+":")) {
				t.Fatal("stale CEL principal")
			}
			if bytes.Contains(body, []byte("hostPath")) || bytes.Contains(body, []byte("privileged")) || object.GetKind() == "Secret" || len(object.GetOwnerReferences()) != 0 {
				t.Fatal("unsafe or GC-dependent resource")
			}
			if object.GetKind() == "RoleBinding" || object.GetKind() == "ClusterRoleBinding" {
				subjects, _, _ := unstructured.NestedSlice(object.Object, "subjects")
				for _, s := range subjects {
					subject := s.(map[string]any)
					if subject["kind"] == "ServiceAccount" && subject["namespace"] != namespace {
						t.Fatal("stale RBAC subject")
					}
				}
			}
		}
		if retained != 18 || policies != 12 {
			t.Fatalf("retained=%d policies=%d", retained, policies)
		}
		for _, r := range resources {
			object := r.Object
			if object.GetKind() == "ValidatingAdmissionPolicyBinding" {
				policy, _, _ := unstructured.NestedString(object.Object, "spec", "policyName")
				selected, _, _ := unstructured.NestedString(object.Object, "spec", "matchResources", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name")
				if !clusterNames[policy] || selected != namespace {
					t.Fatal("broken policy reference/selector")
				}
			}
			if object.GetKind() == "ClusterRoleBinding" || object.GetKind() == "RoleBinding" {
				kind, _, _ := unstructured.NestedString(object.Object, "roleRef", "kind")
				name, _, _ := unstructured.NestedString(object.Object, "roleRef", "name")
				if kind == "ClusterRole" && !clusterNames[name] {
					t.Fatal("broken cluster roleRef")
				}
			}
		}
		resources[0].Object.SetName("mutated")
		if plan.Resources()[0].Object.GetName() != namespace {
			t.Fatal("resource accessor leaks mutations")
		}
		metadata := plan.Manifest()
		metadata.CRDs[0].ServedVersions[0] = "broken"
		if plan.Manifest().CRDs[0].ServedVersions[0] != "v1alpha1" {
			t.Fatal("metadata accessor leaks mutations")
		}
	}
}
func TestPredecessorUsesExactOldAPITemplate(t *testing.T) {
	old := mustCompile(t, true, DefaultNamespace, Profile137)
	current := mustCompile(t, false, DefaultNamespace, Profile137)
	for _, test := range []struct {
		plan   *Plan
		legacy bool
	}{{old, true}, {current, false}} {
		for _, r := range test.plan.Resources() {
			if r.Object.GetKind() != "Deployment" || r.Object.GetName() != "arcadectl-api" {
				continue
			}
			containers, _, _ := unstructured.NestedSlice(r.Object.Object, "spec", "template", "spec", "containers")
			container := containers[0].(map[string]any)
			_, hasArgs := container["args"]
			env := container["env"].([]any)
			if hasArgs == test.legacy || (len(env) == 2) != test.legacy {
				t.Fatal("wrong current/predecessor API flags/env")
			}
			if !test.legacy {
				if !reflect.DeepEqual(container["args"], []any{"--namespace=$(POD_NAMESPACE)"}) {
					t.Fatal("wrong trusted namespace flag")
				}
			}
		}
	}
}
func TestAuthenticatedArbitraryYAMLIsNotAuthorized(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(installpackage.Manifest, map[string][]byte) (installpackage.Manifest, map[string][]byte)
	}{
		{"whitespace", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			p[installpackage.APIPath] = append(p[installpackage.APIPath], '\n')
			return m, p
		}},
		{"unknown object", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			p[installpackage.APIPath] = append(p[installpackage.APIPath], []byte("---\n{\"apiVersion\":\"v1\",\"kind\":\"Secret\",\"metadata\":{\"name\":\"inline\"},\"data\":{}}\n")...)
			return m, p
		}},
		{"widened RBAC", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			p[installpackage.APIPath] = bytes.ReplaceAll(p[installpackage.APIPath], []byte(`"get","list","watch","create"`), []byte(`"*"`))
			return m, p
		}},
		{"sidecar", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			objects, _ := decodeRendered(p[installpackage.APIPath])
			d := objects[len(objects)-1]
			containers, _, _ := unstructured.NestedSlice(d.Object, "spec", "template", "spec", "containers")
			containers = append(containers, map[string]any{"name": "injected", "image": "evil"})
			_ = unstructured.SetNestedSlice(d.Object, containers, "spec", "template", "spec", "containers")
			p[installpackage.APIPath], _ = encodeObjects(objects)
			return m, p
		}},
		{"hostpath", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			p[installpackage.APIPath] = bytes.ReplaceAll(p[installpackage.APIPath], []byte(`"volumes":[`), []byte(`"volumes":[{"name":"host","hostPath":{"path":"/"}},`))
			return m, p
		}},
		{"privileged", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			p[installpackage.APIPath] = bytes.ReplaceAll(p[installpackage.APIPath], []byte(`"allowPrivilegeEscalation":false`), []byte(`"allowPrivilegeEscalation":true,"privileged":true`))
			return m, p
		}},
		{"schema", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			p[installpackage.AnchorsPath] = bytes.ReplaceAll(p[installpackage.AnchorsPath], []byte(`"game is immutable"`), []byte(`"game is mutable"`))
			return m, p
		}},
		{"CRD metadata", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			m.CRDs[0].SchemaSHA256 = strings.Repeat("d", 64)
			return m, p
		}},
		{"image metadata", func(m installpackage.Manifest, p map[string][]byte) (installpackage.Manifest, map[string][]byte) {
			m.Images.API = "registry.example/api@sha256:" + strings.Repeat("e", 64)
			return m, p
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata, payloads := fixture(t, false)
			original := append([]byte(nil), payloads[installpackage.APIPath]...)
			metadata, payloads = test.mutate(metadata, payloads)
			if test.name != "CRD metadata" && test.name != "image metadata" && test.name != "schema" && bytes.Equal(original, payloads[installpackage.APIPath]) {
				t.Fatal("tamper fixture did not change bytes")
			}
			pkg := authenticated(t, metadata, payloads)
			if !pkg.IsVerified() {
				t.Fatal("fixture not authenticated")
			}
			if _, err := Compile(pkg, DefaultNamespace, Profile137); !errors.Is(err, ErrInvalid) {
				t.Fatalf("signed arbitrary resources accepted: %v", err)
			}
		})
	}
}
func TestCompileRejectsUnsupportedDeclarations(t *testing.T) {
	metadata, payloads := fixture(t, false)
	for _, namespace := range []string{"", "default", "kube-system", "kube-public", "kube-node-lease", "kube-custom", "Bad", "a.b", strings.Repeat("a", 64)} {
		if _, err := Compile(authenticated(t, metadata, payloads), namespace, Profile137); err == nil {
			t.Fatalf("accepted reserved/invalid namespace %q", namespace)
		}
	}
	if _, err := Compile(authenticated(t, metadata, payloads), DefaultNamespace, "unproven"); err == nil {
		t.Fatal("unsupported profile accepted")
	}
	metadata.Profiles[0].KubernetesVersion = "1.35.7"
	if _, err := Compile(authenticated(t, metadata, payloads), DefaultNamespace, Profile135); err == nil {
		t.Fatal("mismatched profile declaration accepted")
	}
	legacyMetadata, legacyPayloads := fixture(t, true)
	for _, test := range []struct{ namespace, profile string }{{"custom", Profile137}, {DefaultNamespace, Profile135}} {
		if _, err := Compile(authenticated(t, legacyMetadata, legacyPayloads), test.namespace, test.profile); err == nil {
			t.Fatal("unsupported predecessor namespace/profile accepted")
		}
	}
	for _, pkg := range []*installpackage.VerifiedPackage{nil, {}} {
		if _, err := Compile(pkg, DefaultNamespace, Profile137); !errors.Is(err, installpackage.ErrUnverified) {
			t.Fatal("unverified input accepted")
		}
	}
	var zero Plan
	if zero.IsTrusted() || (*Plan)(nil).IsTrusted() {
		t.Fatal("zero/nil plan trusted")
	}
	metadata, payloads = fixture(t, false)
	metadata.Predecessors = []installpackage.Predecessor{{ID: "issue-26", PackageSHA256: strings.Repeat("e", 64), SourceSHA: LegacySourceSHA, Images: metadata.Images, Namespace: DefaultNamespace, ProfileIDs: []string{Profile137}}}
	if _, err := Compile(authenticated(t, metadata, payloads), DefaultNamespace, Profile137); err != nil {
		t.Fatal(err)
	}
	metadata.Predecessors[0].ProfileIDs = []string{Profile135}
	if _, err := Compile(authenticated(t, metadata, payloads), DefaultNamespace, Profile137); err == nil {
		t.Fatal("uncertified predecessor profile accepted")
	}
}
func TestRenderRejectsInvalidImages(t *testing.T) {
	metadata, _ := fixture(t, false)
	for _, image := range []string{"mutable:latest", "example.invalid/x@sha256:" + strings.Repeat("0", 64), "x\nkind: Secret", strings.Repeat("a", 513)} {
		images := metadata.Images
		images.API = image
		if _, _, err := RenderPayloads(images, false); err == nil {
			t.Fatalf("accepted image %q", image)
		}
	}
}

func TestPrerequisitesCannotBeOmittedOrInvented(t *testing.T) {
	for _, declarations := range [][]string{{"api-tls"}, {"unsupported-prerequisite"}} {
		metadata, payloads := fixture(t, false)
		metadata.Prerequisites = declarations
		if _, err := Compile(authenticated(t, metadata, payloads), DefaultNamespace, Profile137); !errors.Is(err, ErrInvalid) {
			t.Fatal("incomplete/invented prerequisites accepted")
		}
	}
	declarations := RequiredPrerequisites()
	declarations[0] = "changed"
	if RequiredPrerequisites()[0] != "api-tls" {
		t.Fatal("prerequisites leaked mutable storage")
	}
}

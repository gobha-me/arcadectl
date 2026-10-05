// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

func testContract(t *testing.T, legacy bool) *Contract {
	t.Helper()
	namespace, profile := "isolated-install", installrender.Profile135
	if legacy {
		namespace, profile = installrender.DefaultNamespace, installrender.Profile137
	}
	return testContractVariant(t, legacy, namespace, profile, "a", "b")
}

func testContractVariant(t *testing.T, legacy bool, namespace, profile, controllerDigest, apiDigest string) *Contract {
	t.Helper()
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat(controllerDigest, 64), API: "registry.example/api@sha256:" + strings.Repeat(apiDigest, 64)}
	payloads, crds, err := installrender.RenderPayloads(images, legacy)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Repeat("c", 40)
	if legacy {
		source = installrender.LegacySourceSHA
	}
	body, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: source, SourceEpoch: 1, Images: images, Profiles: installrender.SupportedProfiles(legacy), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	signature, err := installpackage.Sign(body, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(body, signature, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installrender.Compile(pkg, namespace, profile)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(plan)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustTemplate(t *testing.T, c *Contract, kind, name string, paused bool) *Template {
	t.Helper()
	for key := range c.resources {
		if key.Kind != kind || name != "" && key.Name != name {
			continue
		}
		template, err := c.Template(key, paused)
		if err != nil {
			t.Fatal(err)
		}
		return template
	}
	t.Fatal("missing template")
	return nil
}

func liveObject(t *testing.T, template *Template) *unstructured.Unstructured {
	t.Helper()
	o := template.expected.DeepCopyObject()
	m, _ := meta.Accessor(o)
	m.SetUID("original-uid")
	m.SetResourceVersion("42")
	m.SetGeneration(1)
	a := m.GetAnnotations()
	if a == nil {
		a = map[string]string{}
	}
	a[installstate.MutationAnnotation] = strings.Repeat("a", 32)
	if template.key.Kind == "Deployment" {
		a["deployment.kubernetes.io/revision"] = "1"
	}
	m.SetAnnotations(a)
	switch v := o.(type) {
	case *corev1.Service:
		v.Spec.ClusterIP = "10.96.0.8"
		v.Spec.ClusterIPs = []string{v.Spec.ClusterIP}
		v.Spec.IPFamilies = []corev1.IPFamily{corev1.IPv4Protocol}
	case *corev1.Namespace:
		delete(v.Annotations, installstate.MutationAnnotation)
		v.Labels["kubernetes.io/metadata.name"] = v.Name
	case *crdv1.CustomResourceDefinition:
		v.Status = crdv1.CustomResourceDefinitionStatus{StoredVersions: []string{"v1alpha1"}, AcceptedNames: v.Spec.Names, Conditions: []crdv1.CustomResourceDefinitionCondition{{Type: crdv1.Established, Status: crdv1.ConditionTrue}, {Type: crdv1.NamesAccepted, Status: crdv1.ConditionTrue}}}
	}
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
	if err != nil {
		t.Fatal(err)
	}
	return &unstructured.Unstructured{Object: object}
}

func namespaceJournal(t *testing.T, template *Template) (*unstructured.Unstructured, *installstate.Snapshot) {
	t.Helper()
	live := liveObject(t, template)
	doc := installstate.Document{Version: installstate.Version, InstallationID: strings.Repeat("a", 32), Namespace: template.key.Name, NamespaceUID: live.GetUID(), ProfileID: template.contract.plan.Profile().ID, Revision: 1, Mode: installstate.Install, Stage: installstate.Preparing, TargetPackage: template.contract.plan.Digest(), Resources: []installstate.Resource{{Key: template.key, UID: live.GetUID(), TemplateSHA256: template.Hash(), Retained: true, Phase: installrender.Anchors}}}
	body, err := installstate.Encode(doc, template.contract.plan)
	if err != nil {
		t.Fatal(err)
	}
	a := live.GetAnnotations()
	if a == nil {
		a = map[string]string{}
	}
	a[installstate.Annotation] = string(body)
	a[installstate.BootstrapAnnotation] = doc.InstallationID
	live.SetAnnotations(a)
	var namespace corev1.Namespace
	if runtime.DefaultUnstructuredConverter.FromUnstructured(live.Object, &namespace) != nil {
		t.Fatal("namespace decode")
	}
	client := fake.NewClientset(&namespace)
	store, err := installstate.New(client.CoreV1().Namespaces(), template.contract.plan)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Load(context.Background(), installstate.Anchor{Namespace: doc.Namespace, UID: doc.NamespaceUID, InstallationID: doc.InstallationID})
	if err != nil {
		t.Fatal(err)
	}
	return live, snapshot
}

func TestEveryReviewedResourceAndFrozenPredecessorMatches(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		c := testContract(t, legacy)
		if len(c.resources) != 38 {
			t.Fatal("incomplete contract")
		}
		for key := range c.resources {
			template, err := c.Template(key, false)
			if err != nil {
				t.Fatal(err)
			}
			if key.Kind == "Namespace" {
				live, snapshot := namespaceJournal(t, template)
				if err := template.MatchNamespace(live, snapshot); err != nil {
					t.Fatalf("namespace: %v", err)
				}
				continue
			}
			live := liveObject(t, template)
			if err := template.MatchLive(live, "original-uid"); err != nil {
				t.Fatalf("%s: %v", key.String(), err)
			}
			if err := template.MatchAdmitted(live); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(template.resource.Object.Object)
			sum := sha256.Sum256(body)
			if template.Hash() != hex.EncodeToString(sum[:]) {
				t.Fatal("template hash does not cover exact signed desired fields")
			}
			candidate, err := template.Candidate(strings.Repeat("b", 32))
			if err != nil {
				t.Fatal(err)
			}
			candidate.SetName("caller-changed")
			if template.Key().Name == "caller-changed" || template.resource.Object.GetName() == "caller-changed" {
				t.Fatal("template aliases candidate")
			}
		}
	}
}

func TestWholeContractRejectsUnsignedBehaviorEvenOnMatchingDryRuns(t *testing.T) {
	c := testContract(t, false)
	for _, tc := range []struct {
		kind, name string
		change     func(*unstructured.Unstructured)
	}{
		{"Deployment", "arcadectl-api", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "ClusterFirstWithHostNet", "spec", "template", "spec", "dnsPolicy")
		}},
		{"Deployment", "arcadectl-api", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, true, "spec", "template", "spec", "hostNetwork")
		}},
		{"Deployment", "arcadectl-api", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, true, "spec", "template", "spec", "enableServiceLinks")
		}},
		{"Deployment", "arcadectl-api", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "evil", "spec", "template", "spec", "serviceAccountName")
		}},
		{"Deployment", "arcadectl-api", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "wrong", "spec", "template", "spec", "serviceAccount")
		}},
		{"Deployment", "arcadectl-api", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "RollingUpdate", "spec", "strategy", "type")
		}},
		{"Deployment", "arcadectl-api", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, map[string]any{"maxSurge": int64(1)}, "spec", "strategy", "rollingUpdate")
		}},
		{"Deployment", "arcadectl-controller", func(o *unstructured.Unstructured) {
			containers, _, _ := unstructured.NestedSlice(o.Object, "spec", "template", "spec", "containers")
			for _, e := range containers[0].(map[string]any)["env"].([]any) {
				env := e.(map[string]any)
				if env["name"] == "BACKUP_WORKER_IMAGE" {
					env["value"] = "unsigned-worker"
				}
			}
			_ = unstructured.SetNestedSlice(o.Object, containers, "spec", "template", "spec", "containers")
		}},
		{"Deployment", "arcadectl-api", func(o *unstructured.Unstructured) {
			items, _, _ := unstructured.NestedSlice(o.Object, "spec", "template", "spec", "containers")
			items = append(items, map[string]any{"name": "unsigned-sidecar", "image": "evil"})
			_ = unstructured.SetNestedSlice(o.Object, items, "spec", "template", "spec", "containers")
		}},
		{"Role", "", func(o *unstructured.Unstructured) {
			rules, _, _ := unstructured.NestedSlice(o.Object, "rules")
			rules = append(rules, map[string]any{"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"*"}})
			_ = unstructured.SetNestedSlice(o.Object, rules, "rules")
		}},
		{"RoleBinding", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "foreign", "roleRef", "name")
		}},
		{"ClusterRole", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, map[string]any{}, "aggregationRule")
		}},
		{"Service", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedStringSlice(o.Object, []string{"203.0.113.3"}, "spec", "externalIPs")
		}},
		{"Service", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "NodePort", "spec", "type")
		}},
		{"Service", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "PreferClose", "spec", "trafficDistribution")
		}},
		{"ServiceAccount", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedSlice(o.Object, []any{map[string]any{"name": "foreign"}}, "imagePullSecrets")
		}},
		{"ValidatingAdmissionPolicy", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "Ignore", "spec", "failurePolicy")
		}},
		{"ValidatingAdmissionPolicyBinding", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedStringSlice(o.Object, []string{"Warn"}, "spec", "validationActions")
		}},
		{"CustomResourceDefinition", "", func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "Webhook", "spec", "conversion", "strategy")
		}},
		{"CustomResourceDefinition", "", func(o *unstructured.Unstructured) {
			versions, _, _ := unstructured.NestedSlice(o.Object, "spec", "versions")
			versions[0].(map[string]any)["schema"].(map[string]any)["openAPIV3Schema"].(map[string]any)["unsignedUnknownField"] = "raw-canary"
			_ = unstructured.SetNestedSlice(o.Object, versions, "spec", "versions")
		}},
	} {
		template := mustTemplate(t, c, tc.kind, tc.name, false)
		live := liveObject(t, template)
		tc.change(live)
		// The exact same unsigned mutation in dry-run and actual output remains
		// invalid. Equality between these two is deliberately not the oracle.
		if err := template.MatchAdmitted(live); err == nil || strings.Contains(err.Error(), "raw-canary") {
			t.Fatalf("unsigned admitted %s accepted", tc.kind)
		}
		if err := template.MatchLive(live.DeepCopy(), "original-uid"); err == nil {
			t.Fatalf("unsigned live %s accepted", tc.kind)
		}
	}
}

func TestHealthyMetadataCannotHideOwnershipOrUnknownFields(t *testing.T) {
	c := testContract(t, false)
	template := mustTemplate(t, c, "Deployment", "arcadectl-api", false)
	for _, change := range []func(*unstructured.Unstructured){
		func(o *unstructured.Unstructured) {
			o.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Secret", Name: "parent", UID: "parent"}})
		},
		func(o *unstructured.Unstructured) { o.SetFinalizers([]string{"foregroundDeletion"}) },
		func(o *unstructured.Unstructured) { now := metav1.Now(); o.SetDeletionTimestamp(&now) },
		func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			a["arbitrary"] = "raw-canary"
			o.SetAnnotations(a)
		},
		func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			a["deployment.kubernetes.io/revision"] = "001"
			o.SetAnnotations(a)
		},
		func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			a[installstate.MutationAnnotation] = "bad"
			o.SetAnnotations(a)
		},
		func(o *unstructured.Unstructured) { o.Object["unsigned"] = "raw-canary" },
		func(o *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(o.Object, "raw-canary", "metadata", "unsigned")
		},
	} {
		live := liveObject(t, template)
		change(live)
		if err := template.MatchLive(live, "original-uid"); err == nil || strings.Contains(err.Error(), "raw-canary") {
			t.Fatal("metadata drift was ignored or reflected")
		}
	}
	live := liveObject(t, template)
	if err := template.MatchLive(live, "replacement"); !errors.Is(err, ErrIdentity) {
		t.Fatal("original UID not pinned")
	}
	live.SetResourceVersion("")
	if err := template.MatchLive(live, "original-uid"); !errors.Is(err, ErrIdentity) {
		t.Fatal("missing live RV accepted")
	}
}

func TestControllerQuiesceAndCompleteUpdateTemplates(t *testing.T) {
	c := testContract(t, false)
	for _, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller"} {
		ready := mustTemplate(t, c, "Deployment", name, false)
		paused := mustTemplate(t, c, "Deployment", name, true)
		live := liveObject(t, ready)
		candidate, err := paused.UpdateCandidate(ready, live, "original-uid", strings.Repeat("b", 32))
		if err != nil {
			t.Fatal(err)
		}
		replicas, _, _ := unstructured.NestedInt64(candidate.Object, "spec", "replicas")
		if replicas != 0 || candidate.GetUID() != live.GetUID() || candidate.GetResourceVersion() != live.GetResourceVersion() || paused.Hash() == ready.Hash() {
			t.Fatal("quiesce candidate lost identity or desired-state hash")
		}
		if err := ready.MatchLive(liveObject(t, paused), "original-uid"); !errors.Is(err, ErrDrift) {
			t.Fatal("paused state accepted as ready signed state")
		}
		if _, err := ready.UpdateCandidate(paused, liveObject(t, paused), "original-uid", strings.Repeat("c", 32)); err != nil {
			t.Fatal("ready recovery did not preserve complete template")
		}
	}
	api := mustTemplate(t, c, "Deployment", "arcadectl-api", false)
	if _, err := c.Template(api.Key(), true); !errors.Is(err, ErrInvalid) {
		t.Fatal("API scale-to-zero substituted for admission deletion")
	}
	live := liveObject(t, api)
	_ = unstructured.SetNestedField(live.Object, live.GetNamespace(), "spec", "template", "spec", "serviceAccount") // wrong alias must fail
	if _, err := api.UpdateCandidate(api, live, "original-uid", strings.Repeat("a", 32)); err == nil {
		t.Fatal("unsigned previous template copied into update")
	}
	if _, err := (&Template{}).UpdateCandidate(&Template{}, nil, "", ""); err == nil {
		t.Fatal("zero update template accepted")
	}
}

func TestServiceAllocationAndUpdatePreserveOnlyReviewedFields(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Service", "", false)
	for _, ip := range []string{"10.96.0.8", "fd00::8"} {
		live := liveObject(t, template)
		_ = unstructured.SetNestedField(live.Object, ip, "spec", "clusterIP")
		_ = unstructured.SetNestedStringSlice(live.Object, []string{ip}, "spec", "clusterIPs")
		family := "IPv4"
		if strings.Contains(ip, ":") {
			family = "IPv6"
		}
		_ = unstructured.SetNestedStringSlice(live.Object, []string{family}, "spec", "ipFamilies")
		if err := template.MatchLive(live, "original-uid"); err != nil {
			t.Fatal(err)
		}
		candidate, err := template.UpdateCandidate(template, live, "original-uid", strings.Repeat("a", 32))
		if err != nil {
			t.Fatal(err)
		}
		actualIP, _, _ := unstructured.NestedString(candidate.Object, "spec", "clusterIP")
		if actualIP != ip {
			t.Fatal("original allocation discarded")
		}
	}
	for _, ip := range []string{"None", "0.0.0.0", "127.0.0.1", "::", "::1", "224.0.0.1", "::ffff:10.96.0.8"} {
		live := liveObject(t, template)
		_ = unstructured.SetNestedField(live.Object, ip, "spec", "clusterIP")
		_ = unstructured.SetNestedStringSlice(live.Object, []string{ip}, "spec", "clusterIPs")
		if err := template.MatchLive(live, "original-uid"); err == nil {
			t.Fatal("unsafe or headless allocation accepted")
		}
	}
}

func TestReviewedQuantityAndServiceAccountAliasNormalization(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Deployment", "arcadectl-api", false)
	live := liveObject(t, template)
	_ = unstructured.SetNestedField(live.Object, "arcadectl-api", "spec", "template", "spec", "serviceAccount")
	containers, _, _ := unstructured.NestedSlice(live.Object, "spec", "template", "spec", "containers")
	containers[0].(map[string]any)["resources"].(map[string]any)["limits"].(map[string]any)["cpu"] = "1000m"
	containers[0].(map[string]any)["resources"].(map[string]any)["requests"].(map[string]any)["memory"] = "67108864"
	_ = unstructured.SetNestedSlice(live.Object, containers, "spec", "template", "spec", "containers")
	if err := template.MatchLive(live, "original-uid"); err != nil {
		t.Fatal("semantically equivalent quantity or exact serviceAccount alias rejected")
	}
	var deployment appsv1.Deployment
	if runtime.DefaultUnstructuredConverter.FromUnstructured(live.Object, &deployment) != nil {
		t.Fatal("decode")
	}
	deployment.Spec.RevisionHistoryLimit = ptr.To[int32](99)
	o, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(&deployment)
	if err := template.MatchLive(&unstructured.Unstructured{Object: o}, "original-uid"); !errors.Is(err, ErrDrift) {
		t.Fatal("unreviewed default accepted")
	}
}

func TestNamespaceRequiresExactSealedJournalBytes(t *testing.T) {
	template := mustTemplate(t, testContract(t, false), "Namespace", "", false)
	live, snapshot := namespaceJournal(t, template)
	body := snapshot.Bytes()
	body[0] = 'x'
	if bytes.Equal(body, snapshot.Bytes()) || (*installstate.Snapshot)(nil).Bytes() != nil {
		t.Fatal("journal bytes alias or unsafe zero snapshot")
	}
	if err := template.MatchAdmitted(live); !errors.Is(err, ErrIdentity) {
		t.Fatal("namespace dynamic annotation exemptions accepted without journal")
	}
	for _, change := range []func(*unstructured.Unstructured){
		func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			a[installstate.Annotation] += " "
			o.SetAnnotations(a)
		},
		func(o *unstructured.Unstructured) {
			a := o.GetAnnotations()
			a[installstate.BootstrapAnnotation] = strings.Repeat("b", 32)
			o.SetAnnotations(a)
		},
		func(o *unstructured.Unstructured) { o.SetResourceVersion("superseded") },
		func(o *unstructured.Unstructured) { o.SetUID(types.UID("replacement")) },
		func(o *unstructured.Unstructured) {
			labels := o.GetLabels()
			labels["pod-security.kubernetes.io/enforce"] = "privileged"
			o.SetLabels(labels)
		},
	} {
		candidate := live.DeepCopy()
		change(candidate)
		if err := template.MatchNamespace(candidate, snapshot); err == nil {
			t.Fatal("namespace journal, identity or PSA drift ignored")
		}
	}
}

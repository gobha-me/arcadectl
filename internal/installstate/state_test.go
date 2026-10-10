// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func testPlan(t *testing.T) *installrender.Plan {
	t.Helper()
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	payloads, crds, err := installrender.RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("c", 40), SourceEpoch: 1, Images: images, Profiles: installrender.SupportedProfiles(false), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}, payloads)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	signature, err := installpackage.Sign(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := installpackage.Verify(manifest, signature, payloads, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installrender.Compile(pkg, "isolated-install", installrender.Profile135)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func initialDocument(plan *installrender.Plan) Document {
	return Document{Version: Version, InstallationID: strings.Repeat("a", 32), Namespace: plan.Namespace(), NamespaceUID: "namespace-uid", ProfileID: plan.Profile().ID, Revision: 1, Mode: Install, Stage: Preparing, TargetPackage: plan.Digest(), Resources: []Resource{{Key: Key{"v1", "Namespace", "", plan.Namespace()}, UID: "namespace-uid", TemplateSHA256: strings.Repeat("b", 64), Retained: true, Phase: installrender.Anchors}}}
}

func testNamespace(plan *installrender.Plan, d Document) *corev1.Namespace {
	labels := map[string]string{}
	for _, mode := range []string{"enforce", "audit", "warn"} {
		labels["pod-security.kubernetes.io/"+mode] = "restricted"
		labels["pod-security.kubernetes.io/"+mode+"-version"] = plan.Profile().PodSecurityVersion
	}
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: plan.Namespace(), UID: d.NamespaceUID, ResourceVersion: "1", Labels: labels, Annotations: map[string]string{BootstrapAnnotation: d.InstallationID}}, Spec: corev1.NamespaceSpec{Finalizers: []corev1.FinalizerName{corev1.FinalizerKubernetes}}}
}

func TestJournalCanonicalBoundsAndTrustedAddresses(t *testing.T) {
	plan := testPlan(t)
	d := initialDocument(plan)
	body, err := Encode(d, plan)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Decode(body, plan)
	if err != nil || !reflect.DeepEqual(d, again) {
		t.Fatal("canonical roundtrip changed ownership")
	}
	for _, mutate := range []func(*Document){
		func(d *Document) { d.NamespaceUID = "" },
		func(d *Document) { d.Namespace = "foreign" },
		func(d *Document) { d.InstallationID = "../secret" },
		func(d *Document) { d.ActivePackage = strings.Repeat("e", 64) },
		func(d *Document) { d.Resources = nil },
		func(d *Document) { d.Resources = []Resource{} },
		func(d *Document) { d.Resources[0].Key.Kind = "Secret" },
		func(d *Document) { d.Resources[0].UID = "replacement" },
		func(d *Document) { d.Resources[0].Retained = false },
		func(d *Document) { d.Resources[0].TemplateSHA256 = "private-token" },
		func(d *Document) { d.Revision = 9007199254740992 },
		func(d *Document) { d.Stage = Complete },
	} {
		candidate := initialDocument(plan)
		mutate(&candidate)
		if _, err := Encode(candidate, plan); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid ownership metadata accepted")
		}
	}
	for _, bad := range [][]byte{append([]byte(" "), body...), append(bytes.Clone(body), '\n'), bytes.Replace(body, []byte(`"version":"v1"`), []byte(`"version":"v1","secret":"canary"`), 1), bytes.Replace(body, []byte(`"revision":1`), []byte(`"revision":1,"revision":1`), 1), bytes.Repeat([]byte("x"), MaxBytes+1)} {
		if _, err := Decode(bad, plan); !errors.Is(err, ErrInvalid) {
			t.Fatal("noncanonical or unknown data accepted")
		}
	}
	if _, err := Decode(body); !errors.Is(err, ErrInvalid) {
		t.Fatal("journal decoded without trusted address contract")
	}
	if _, err := Encode(d, &installrender.Plan{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero renderer plan trusted")
	}
}

func TestPendingIntentCannotDeleteRetentionOrChangeIdentity(t *testing.T) {
	plan := testPlan(t)
	d := initialDocument(plan)
	d.Stage = Applying
	var runtimeResource Resource
	for _, r := range plan.Resources() {
		if r.Object.GetKind() == "ServiceAccount" {
			runtimeResource = Resource{Key: Key{r.Object.GetAPIVersion(), r.Object.GetKind(), r.Object.GetNamespace(), r.Object.GetName()}, UID: "service-account-uid", TemplateSHA256: strings.Repeat("c", 64), Retained: r.Retained, Phase: r.Phase}
			break
		}
	}
	d.Resources = append(d.Resources, runtimeResource)
	SortResources(d.Resources)
	d.Pending = &Pending{Action: Delete, Key: runtimeResource.Key, CreateNonce: strings.Repeat("e", 32), BeforeUID: runtimeResource.UID, BeforeResourceVersion: "10", BeforeSHA256: runtimeResource.TemplateSHA256}
	if _, err := Encode(d, plan); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Document){
		func(d *Document) { d.Pending.BeforeUID = "replacement" },
		func(d *Document) { d.Pending.BeforeResourceVersion = "" },
		func(d *Document) { d.Pending.AfterSHA256 = strings.Repeat("f", 64) },
		func(d *Document) { d.Pending.Key = Key{"v1", "Namespace", "", plan.Namespace()} },
		func(d *Document) { d.Pending.CreateNonce = "" },
	} {
		var candidate Document
		if err := jsonCopy(d, &candidate); err != nil {
			t.Fatal(err)
		}
		mutate(&candidate)
		if _, err := Encode(candidate, plan); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid pending deletion accepted")
		}
	}
	settled := d
	settled.Revision++
	settled.Pending = nil
	settled.Resources = slicesWithout(d.Resources, runtimeResource.Key)
	if !validTransition(d, settled) {
		t.Fatal("exact pending deletion could not settle")
	}
	settled.Resources[0].UID = "foreign"
	if validTransition(d, settled) {
		t.Fatal("settlement changed unrelated ownership")
	}
	// A retained policy cannot become a delete intent, even in recovery.
	for _, r := range plan.Resources() {
		if r.Retained && r.Object.GetKind() != "Namespace" {
			retained := Resource{Key: Key{r.Object.GetAPIVersion(), r.Object.GetKind(), r.Object.GetNamespace(), r.Object.GetName()}, UID: "retained-uid", TemplateSHA256: strings.Repeat("f", 64), Retained: true, Phase: r.Phase}
			d = initialDocument(plan)
			d.Stage = Applying
			d.Resources = append(d.Resources, retained)
			SortResources(d.Resources)
			d.Pending = &Pending{Action: Delete, Key: retained.Key, CreateNonce: strings.Repeat("e", 32), BeforeUID: retained.UID, BeforeResourceVersion: "2", BeforeSHA256: retained.TemplateSHA256}
			if _, err := Encode(d, plan); !errors.Is(err, ErrInvalid) {
				t.Fatal("retained anchor deletion authorized")
			}
			break
		}
	}
}

func slicesWithout(input []Resource, key Key) []Resource {
	result := make([]Resource, 0, len(input))
	for _, r := range input {
		if r.Key != key {
			result = append(result, r)
		}
	}
	return result
}

// namespaceServer enforces real API UID/RV CAS semantics absent from the fake
// client's default tracker, and can lose a response before or after commit.
type namespaceServer struct {
	live                  *corev1.Namespace
	updates               int
	creates               int
	failCreate            bool
	commitOnCreateFailure bool
	beforeCreate          func()
	failUpdate            bool
	commitOnFailure       bool
	failGet               bool
}

func (server *namespaceServer) client() *fake.Clientset {
	client := fake.NewClientset()
	client.PrependReactor("*", "namespaces", func(action clienttesting.Action) (bool, runtime.Object, error) {
		switch action.GetVerb() {
		case "get":
			if server.failGet {
				return true, nil, errors.New("unreadable")
			}
			if server.live == nil {
				return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, action.(clienttesting.GetAction).GetName())
			}
			return true, server.live.DeepCopy(), nil
		case "create":
			server.creates++
			if server.beforeCreate != nil {
				server.beforeCreate()
			}
			if server.live != nil {
				return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "namespaces"}, server.live.Name)
			}
			created := action.(clienttesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
			created.UID, created.ResourceVersion = "namespace-uid", "1"
			created.Spec.Finalizers = []corev1.FinalizerName{corev1.FinalizerKubernetes}
			if !server.failCreate || server.commitOnCreateFailure {
				server.live = created
			}
			if server.failCreate {
				return true, nil, errors.New("lost create response")
			}
			return true, created.DeepCopy(), nil
		case "update":
			server.updates++
			next := action.(clienttesting.UpdateAction).GetObject().(*corev1.Namespace)
			if next.UID != server.live.UID || next.ResourceVersion != server.live.ResourceVersion {
				return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, next.Name, errors.New("changed"))
			}
			next = next.DeepCopy()
			next.ResourceVersion = server.live.ResourceVersion + "1"
			if !server.failUpdate || server.commitOnFailure {
				server.live = next
			}
			if server.failUpdate {
				return true, nil, errors.New("lost response")
			}
			return true, next.DeepCopy(), nil
		}
		return true, nil, errors.New("unexpected action")
	})
	return client
}

func TestNamespaceCASCorrelatesLostResponsesWithoutRetry(t *testing.T) {
	plan := testPlan(t)
	d := initialDocument(plan)
	anchor := Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}
	for _, test := range []struct {
		name                     string
		fail, commit, unreadable bool
		want                     error
	}{
		{"normal", false, false, false, nil},
		{"lost-committed", true, true, false, nil},
		{"lost-uncommitted", true, false, false, ErrOutcomeUnknown},
		{"lost-unreadable", true, true, true, ErrOutcomeUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := &namespaceServer{live: testNamespace(plan, d)}
			store, err := New(server.client().CoreV1().Namespaces(), plan)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := store.Bind(context.Background(), anchor, d)
			if err != nil {
				t.Fatal(err)
			}
			next := snapshot.Document()
			next.Revision++
			next.Stage = Applying
			server.failUpdate, server.commitOnFailure, server.failGet = test.fail, test.commit, test.unreadable
			result, err := store.Commit(context.Background(), snapshot, next)
			if !errors.Is(err, test.want) || server.updates != 2 {
				t.Fatalf("commit=%v, calls=%d", err, server.updates)
			}
			if test.want == nil && (result == nil || result.Document().Revision != 2) {
				t.Fatal("confirmed snapshot missing")
			}
		})
	}
}

func TestNamespaceReplacementConflictAndSnapshotCopies(t *testing.T) {
	if (&Snapshot{}).ResourceVersion() != "" || (&Snapshot{}).Anchor() != (Anchor{}) {
		t.Fatal("zero snapshot manufactured observation")
	}
	plan := testPlan(t)
	d := initialDocument(plan)
	anchor := Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}
	server := &namespaceServer{live: testNamespace(plan, d)}
	store, err := New(server.client().CoreV1().Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Bind(context.Background(), anchor, d)
	if err != nil {
		t.Fatal(err)
	}
	copy := snapshot.Document()
	copy.Resources[0].UID = "tampered"
	if snapshot.Document().Resources[0].UID != anchor.UID {
		t.Fatal("snapshot exposed mutable ownership")
	}
	next := snapshot.Document()
	next.Revision++
	next.Stage = Applying
	server.live.ResourceVersion = "foreign-update"
	if _, err := store.Commit(context.Background(), snapshot, next); !errors.Is(err, ErrConflict) {
		t.Fatal("CAS conflict was retried or swallowed")
	}
	server.live.UID = "replacement"
	if _, err := store.Load(context.Background(), anchor); !errors.Is(err, ErrOwnership) {
		t.Fatal("namespace replacement adopted by name")
	}
	if _, err := store.Bind(context.Background(), anchor, d); !errors.Is(err, ErrOwnership) {
		t.Fatal("foreign namespace rebound")
	}
}

func TestNamespaceSecurityAndJournalTamperingFailClosed(t *testing.T) {
	plan := testPlan(t)
	d := initialDocument(plan)
	anchor := Anchor{d.Namespace, d.NamespaceUID, d.InstallationID}
	for _, mutate := range []func(*corev1.Namespace){
		func(n *corev1.Namespace) { n.Labels["pod-security.kubernetes.io/enforce"] = "privileged" },
		func(n *corev1.Namespace) { n.Labels["pod-security.kubernetes.io/warn-version"] = "latest" },
		func(n *corev1.Namespace) { n.DeletionTimestamp = &metav1.Time{Time: metav1.Now().Time} },
		func(n *corev1.Namespace) { n.OwnerReferences = []metav1.OwnerReference{{UID: "foreign"}} },
		func(n *corev1.Namespace) { n.Annotations[Annotation] = `{"secret":"canary"}` },
		func(n *corev1.Namespace) { n.Spec.Finalizers = append(n.Spec.Finalizers, "foreign/finalizer") },
	} {
		server := &namespaceServer{live: testNamespace(plan, d)}
		store, err := New(server.client().CoreV1().Namespaces(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Bind(context.Background(), anchor, d); err != nil {
			t.Fatal(err)
		}
		mutate(server.live)
		if _, err := store.Load(context.Background(), anchor); !errors.Is(err, ErrOwnership) {
			t.Fatal("unsafe or tampered anchor accepted")
		}
		if server.updates != 1 {
			t.Fatal("read-only rejection mutated namespace")
		}
	}
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"
)

func testPlan(t *testing.T) *installrender.Plan {
	t.Helper()
	images := installpackage.Images{Controller: "registry.example/controller@sha256:" + strings.Repeat("a", 64), API: "registry.example/api@sha256:" + strings.Repeat("b", 64)}
	payloads, crds, err := installrender.RenderPayloads(images, false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := installpackage.Build(installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.1.0-rc.1", SourceSHA: strings.Repeat("c", 40), SourceEpoch: 1, Images: images, Profiles: installrender.SupportedProfiles(false), Prerequisites: installrender.RequiredPrerequisites(), CRDs: crds}, payloads)
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
	plan, err := installrender.Compile(pkg, "isolated-install", installrender.Profile135)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

type fixture struct {
	o        *Observer
	anchor   installstate.Anchor
	core     *kubefake.Clientset
	dynamic  *dynamicfake.FakeDynamicClient
	metadata *metadatafake.FakeMetadataClient
	objects  map[string]*metav1.PartialObjectMetadata
	lists    map[string][]unstructured.Unstructured
	secrets  []metav1.PartialObjectMetadata
	cs       []collection
}

func address(resource, namespace, name string) string { return resource + "/" + namespace + "/" + name }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	plan := testPlan(t)
	doc := installstate.Document{Version: installstate.Version, InstallationID: strings.Repeat("a", 32), Namespace: plan.Namespace(), NamespaceUID: "namespace-uid", ProfileID: plan.Profile().ID, Revision: 1, Mode: installstate.Install, Stage: installstate.Preparing, TargetPackage: plan.Digest(), Resources: []installstate.Resource{{Key: installstate.Key{APIVersion: "v1", Kind: "Namespace", Name: plan.Namespace()}, UID: "namespace-uid", TemplateSHA256: strings.Repeat("b", 64), Retained: true, Phase: installrender.Anchors}}}
	body, err := installstate.Encode(doc, plan)
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: plan.Namespace(), UID: doc.NamespaceUID, ResourceVersion: "1", Labels: map[string]string{}, Annotations: map[string]string{installstate.BootstrapAnnotation: doc.InstallationID, installstate.Annotation: string(body)}}, Spec: corev1.NamespaceSpec{Finalizers: []corev1.FinalizerName{corev1.FinalizerKubernetes}}}
	for _, mode := range []string{"enforce", "audit", "warn"} {
		ns.Labels["pod-security.kubernetes.io/"+mode] = "restricted"
		ns.Labels["pod-security.kubernetes.io/"+mode+"-version"] = plan.Profile().PodSecurityVersion
	}
	f := &fixture{core: kubefake.NewClientset(ns), anchor: installstate.Anchor{Namespace: plan.Namespace(), UID: doc.NamespaceUID, InstallationID: doc.InstallationID}, objects: map[string]*metav1.PartialObjectMetadata{}, lists: map[string][]unstructured.Unstructured{}}
	f.cs = append(collections(&installsafety.Snapshot{}), runtimeCollections(&installsafety.RuntimeSnapshot{})...)
	kinds := map[schema.GroupVersionResource]string{}
	for _, c := range f.cs {
		gv, _ := schema.ParseGroupVersion(c.gv)
		kinds[gv.WithResource(c.resource)] = c.kind + "List"
	}
	f.dynamic = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), kinds)
	f.dynamic.PrependReactor("*", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
		if action.GetVerb() != "list" {
			t.Fatal("observer used a dynamic mutation or full Secret GET")
		}
		if action.GetResource().Resource == "secrets" {
			t.Fatal("full Secret list requested")
		}
		la := action.(clienttesting.ListActionImpl)
		// client-go's root fake action drops Limit; direct page and HTTP tests
		// cover it for cluster lists. Namespaced fake actions preserve options.
		if la.ListOptions.LabelSelector != "" || la.ListOptions.FieldSelector != "" || la.ListOptions.ResourceVersion != "" || action.GetNamespace() != "" && la.ListOptions.Limit != pageLimit {
			t.Fatal("untrusted list options")
		}
		for _, c := range f.cs {
			if c.resource != action.GetResource().Resource {
				continue
			}
			if c.namespaced && action.GetNamespace() != plan.Namespace() || !c.namespaced && action.GetNamespace() != "" {
				t.Fatal("wrong list scope")
			}
			return true, &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": c.gv, "kind": c.kind + "List", "metadata": map[string]any{"resourceVersion": "20"}}, Items: f.lists[c.resource]}, nil
		}
		return true, nil, errors.New("unexpected resource")
	})
	f.metadata = metadatafake.NewSimpleMetadataClient(runtime.NewScheme())
	f.metadata.PrependReactor("*", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
		switch action.GetVerb() {
		case "list":
			if action.GetResource().Resource != "secrets" || action.GetNamespace() != plan.Namespace() {
				t.Fatal("wrong metadata list scope")
			}
			list := &metav1.List{ListMeta: metav1.ListMeta{ResourceVersion: "20"}}
			for i := range f.secrets {
				list.Items = append(list.Items, runtime.RawExtension{Object: f.secrets[i].DeepCopy()})
			}
			return true, list, nil
		case "get":
			ga := action.(clienttesting.GetAction)
			object := f.objects[address(action.GetResource().Resource, action.GetNamespace(), ga.GetName())]
			if object == nil {
				return true, nil, errors.New("raw-canary missing owner")
			}
			return true, object.DeepCopy(), nil
		default:
			t.Fatal("observer mutated metadata")
		}
		return true, nil, errors.New("invalid verb")
	})
	f.objects[address("namespaces", "", plan.Namespace())] = &metav1.PartialObjectMetadata{ObjectMeta: publicMetadata(ns)}
	journal, err := installstate.New(f.core.CoreV1().Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	f.o, err = NewWithClients(Clients{Dynamic: f.dynamic, Metadata: f.metadata, Discovery: func(_ context.Context, gv string) (*metav1.APIResourceList, error) {
		g := newOwnerGraph(&Observer{plan: plan}, nil, f.cs)
		list := &metav1.APIResourceList{GroupVersion: gv}
		for key, name := range g.names {
			if !strings.HasPrefix(key, gv+"/") {
				continue
			}
			kind := strings.TrimPrefix(key, gv+"/")
			list.APIResources = append(list.APIResources, metav1.APIResource{Name: name, Kind: kind, Namespaced: g.scopes[key], Verbs: metav1.Verbs{"get", "list"}})
		}
		return list, nil
	}}, journal, plan)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) claim(name string, owners ...metav1.OwnerReference) {
	o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "PersistentVolumeClaim"}}
	o.SetName(name)
	o.SetNamespace(f.anchor.Namespace)
	o.SetUID(types.UID("uid-" + name))
	o.SetResourceVersion("30")
	o.SetOwnerReferences(owners)
	f.lists["persistentvolumeclaims"] = append(f.lists["persistentvolumeclaims"], *o)
}

func (f *fixture) owner(resource, kind, name string, owners ...metav1.OwnerReference) {
	f.objects[address(resource, f.anchor.Namespace, name)] = &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.anchor.Namespace, UID: types.UID("uid-" + name), ResourceVersion: "30", OwnerReferences: owners, Annotations: map[string]string{"private": "secret-canary"}}}
}

func owner(kind, name string) metav1.OwnerReference {
	gv := "v1"
	if kind == "ReplicaSet" || kind == "Deployment" {
		gv = "apps/v1"
	}
	return metav1.OwnerReference{APIVersion: gv, Kind: kind, Name: name, UID: types.UID("uid-" + name)}
}

func TestCollectCompleteOriginalJournalAndRecursiveMetadataOnly(t *testing.T) {
	f := newFixture(t)
	f.claim("world", owner("ConfigMap", "parent"))
	f.owner("configmaps", "ConfigMap", "parent", owner("Secret", "grandparent"))
	f.owner("secrets", "Secret", "grandparent")
	f.secrets = append(f.secrets, *f.objects[address("secrets", f.anchor.Namespace, "grandparent")].DeepCopy())
	observation, err := f.o.Collect(context.Background(), f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	s := observation.Snapshot()
	if !observation.Journal().Document().Resources[0].Retained || len(s.Owners) != 3 || len(s.Claims.Items) != 1 || len(s.Secrets.Items) != 1 || s.GameServers.ResourceVersion != "20" || s.Secrets.ResourceVersion != "20" {
		t.Fatal("missing complete or recursive evidence")
	}
	if s.Secrets.Items[0].Annotations != nil || s.Owners[0].Metadata.Annotations != nil {
		t.Fatal("private annotations crossed observation boundary")
	}
	s.Claims.Items[0].Name = "changed"
	s.Owners[0].Metadata.UID = "changed"
	s.Secrets.Items[0].Name = "changed"
	if observation.Snapshot().Claims.Items[0].Name != "world" || observation.Snapshot().Secrets.Items[0].Name != "grandparent" {
		t.Fatal("observation aliases caller changes")
	}
	if (&Observation{}).Snapshot() != nil || (*Observation)(nil).Journal() != nil {
		t.Fatal("zero observation is not safe")
	}
	for _, action := range append(f.dynamic.Actions(), f.metadata.Actions()...) {
		if action.GetVerb() != "get" && action.GetVerb() != "list" {
			t.Fatal("observation changed cluster state")
		}
	}
}

func TestCollectRuntimeClosureIsCompleteAndDefensivelyCopied(t *testing.T) {
	f := newFixture(t)
	for _, c := range runtimeCollections(&installsafety.RuntimeSnapshot{}) {
		namespace := f.anchor.Namespace
		if !c.namespaced {
			namespace = ""
		}
		o := unstructured.Unstructured{Object: map[string]any{"apiVersion": c.gv, "kind": c.kind}}
		o.SetName("fixture-" + c.resource)
		o.SetNamespace(namespace)
		o.SetUID(types.UID("uid-" + c.resource))
		o.SetResourceVersion("30")
		f.lists[c.resource] = []unstructured.Unstructured{o}
	}
	observation, err := f.o.Collect(context.Background(), f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	r := observation.Runtime()
	if len(r.Deployments.Items) != 1 || len(r.ReplicaSets.Items) != 1 || len(r.StatefulSets.Items) != 1 || len(r.DaemonSets.Items) != 1 || len(r.ReplicationControllers.Items) != 1 || len(r.CronJobs.Items) != 1 || len(r.Attachments.Items) != 1 || r.Attachments.Items[0].Namespace != "" || len(r.EndpointSlices.Items) != 1 {
		t.Fatal("complete builtin/global attachment inventory missing")
	}
	r.Deployments.Items[0].UID, r.Attachments.Items[0].UID = "changed", "changed"
	r.EndpointSlices.Items[0].UID = "changed"
	if observation.Runtime().Deployments.Items[0].UID != "uid-deployments" || observation.Runtime().Attachments.Items[0].UID != "uid-volumeattachments" || observation.Runtime().EndpointSlices.Items[0].UID != "uid-endpointslices" || (*Observation)(nil).Runtime() != nil || (&Observation{}).Runtime() != nil {
		t.Fatal("runtime evidence aliases caller changes or zero observation")
	}
	for _, resource := range []string{"deployments", "replicasets", "statefulsets", "daemonsets", "replicationcontrollers", "cronjobs", "volumeattachments", "endpointslices"} {
		t.Run(resource, func(t *testing.T) {
			fault := newFixture(t)
			fault.dynamic.PrependReactor("list", resource, func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("PRIVATE-CANARY inaccessible runtime list")
			})
			if result, err := fault.o.Collect(context.Background(), fault.anchor); result != nil || err != ErrRead {
				t.Fatal("runtime read failure returned partial evidence")
			}
		})
	}
}

func TestCollectRefusesJournalChangeOrReplacement(t *testing.T) {
	for _, tc := range []string{"namespace-rv", "namespace-uid", "deleting", "state"} {
		t.Run(tc, func(t *testing.T) {
			f := newFixture(t)
			reads := 0
			f.core.PrependReactor("get", "namespaces", func(action clienttesting.Action) (bool, runtime.Object, error) {
				reads++
				obj, _ := f.core.Tracker().Get(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, "", f.anchor.Namespace)
				ns := obj.(*corev1.Namespace).DeepCopy()
				if reads == 2 {
					switch tc {
					case "namespace-rv":
						ns.ResourceVersion = "new"
					case "namespace-uid":
						ns.UID = "replacement"
					case "deleting":
						now := metav1.Now()
						ns.DeletionTimestamp = &now
					case "state":
						ns.Annotations[installstate.Annotation] = "untrusted-canary"
					}
				}
				return true, ns, nil
			})
			result, err := f.o.Collect(context.Background(), f.anchor)
			if result != nil || !errors.Is(err, ErrConcurrent) {
				t.Fatal("changed journal accepted")
			}
		})
	}
}

func TestCollectRefusesInvalidListAndOwnerEvidence(t *testing.T) {
	for _, tc := range []string{"owner-missing", "owner-uid", "owner-rv", "owner-deleting", "owner-cycle", "cluster-unpinned", "scope-mismatch", "discovery-ambiguous", "discovery-error", "discovery-gv", "discovery-no-get", "discovery-resource-name", "discovery-group", "duplicate", "wrong-namespace", "wrong-kind", "wrong-uid", "bad-gv", "bad-name", "unknown-spec", "casing-spec", "casing-nested-spec"} {
		t.Run(tc, func(t *testing.T) {
			f := newFixture(t)
			f.claim("world", owner("ConfigMap", "parent"))
			f.owner("configmaps", "ConfigMap", "parent")
			parent := f.objects[address("configmaps", f.anchor.Namespace, "parent")]
			discovery := f.o.clients.Discovery
			switch tc {
			case "owner-missing":
				delete(f.objects, address("configmaps", f.anchor.Namespace, "parent"))
			case "owner-uid":
				parent.UID = "replaced"
			case "owner-rv":
				parent.ResourceVersion = ""
			case "owner-deleting":
				now := metav1.Now()
				parent.DeletionTimestamp = &now
			case "owner-cycle":
				parent.OwnerReferences = []metav1.OwnerReference{owner("ConfigMap", "parent")}
			case "cluster-unpinned":
				f.lists["persistentvolumeclaims"][0].SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: "foreign", UID: "foreign"}})
			case "duplicate":
				f.lists["persistentvolumeclaims"] = append(f.lists["persistentvolumeclaims"], f.lists["persistentvolumeclaims"][0])
			case "wrong-namespace":
				f.lists["persistentvolumeclaims"][0].SetNamespace("foreign")
			case "wrong-kind":
				f.lists["persistentvolumeclaims"][0].SetKind("Secret")
			case "wrong-uid":
				f.lists["persistentvolumeclaims"][0].SetUID("")
			case "bad-gv":
				ref := owner("ConfigMap", "parent")
				ref.APIVersion = "../v1"
				f.lists["persistentvolumeclaims"][0].SetOwnerReferences([]metav1.OwnerReference{ref})
			case "bad-name":
				ref := owner("ConfigMap", "parent")
				ref.Name = "../secret"
				f.lists["persistentvolumeclaims"][0].SetOwnerReferences([]metav1.OwnerReference{ref})
			case "unknown-spec":
				f.lists["persistentvolumeclaims"][0].Object["spec"] = map[string]any{"unreviewed": "private-canary"}
			case "casing-spec":
				f.lists["persistentvolumeclaims"][0].Object["Spec"] = map[string]any{"volumeName": "private-canary"}
			case "casing-nested-spec":
				f.lists["persistentvolumeclaims"][0].Object["spec"] = map[string]any{"VolumeName": "private-canary"}
			default:
				f.o.clients.Discovery = func(ctx context.Context, gv string) (*metav1.APIResourceList, error) {
					list, _ := discovery(ctx, gv)
					if tc == "discovery-error" {
						return list, errors.New("raw-canary")
					}
					if tc == "discovery-gv" {
						list.GroupVersion = "foreign/v2"
					}
					for i := range list.APIResources {
						r := &list.APIResources[i]
						if r.Kind != "ConfigMap" {
							continue
						}
						switch tc {
						case "scope-mismatch":
							r.Namespaced = false
						case "discovery-ambiguous":
							list.APIResources = append(list.APIResources, *r)
						case "discovery-no-get":
							r.Verbs = metav1.Verbs{"list"}
						case "discovery-resource-name":
							r.Name = "secrets"
						case "discovery-group":
							r.Group = "foreign.example"
						}
						break
					}
					return list, nil
				}
			}
			result, err := f.o.Collect(context.Background(), f.anchor)
			if result != nil || err == nil || strings.Contains(err.Error(), "canary") {
				t.Fatal("invalid evidence accepted or reflected: " + tc)
			}
		})
	}
}

func TestOwnerDepthAndSharedTailBound(t *testing.T) {
	for _, length := range []int{64, 65} {
		f := newFixture(t)
		f.claim("a-world", owner("ConfigMap", "n-0"))
		for i := range length {
			refs := []metav1.OwnerReference{}
			if i+1 < length {
				refs = append(refs, owner("ConfigMap", fmt.Sprint("n-", i+1)))
			}
			f.owner("configmaps", "ConfigMap", fmt.Sprint("n-", i), refs...)
		}
		result, err := f.o.Collect(context.Background(), f.anchor)
		if length == 64 && (err != nil || result == nil) || length == 65 && (err == nil || result != nil) {
			t.Fatal("owner path bound not enforced")
		}
	}
	f := newFixture(t)
	f.claim("a-short", owner("ConfigMap", "n-32"))
	f.claim("z-long", owner("ConfigMap", "n-0"))
	for i := range 65 {
		refs := []metav1.OwnerReference{}
		if i < 64 {
			refs = append(refs, owner("ConfigMap", fmt.Sprint("n-", i+1)))
		}
		f.owner("configmaps", "ConfigMap", fmt.Sprint("n-", i), refs...)
	}
	if result, err := f.o.Collect(context.Background(), f.anchor); result != nil || !errors.Is(err, ErrOwnership) {
		t.Fatal("memoized tail bypassed total depth")
	}
}

func TestObserverConfigurationAndOriginalAnchor(t *testing.T) {
	f := newFixture(t)
	for _, config := range []*rest.Config{nil, {Host: "http://cluster.example"}, {Host: "https://cluster.example", TLSClientConfig: rest.TLSClientConfig{Insecure: true}}, {Host: "https://user:pass@cluster.example"}, {Host: "https://cluster.example?query=secret-canary"}} {
		if _, err := New(config, f.o.journal, f.o.plan); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe transport config accepted")
		}
	}
	var nilDynamic *dynamicfake.FakeDynamicClient
	clients := f.o.clients
	clients.Dynamic = nilDynamic
	if _, err := NewWithClients(clients, f.o.journal, f.o.plan); !errors.Is(err, ErrInvalid) {
		t.Fatal("typed nil client accepted")
	}
	for _, anchor := range []installstate.Anchor{{Namespace: "foreign", UID: f.anchor.UID, InstallationID: f.anchor.InstallationID}, {Namespace: f.anchor.Namespace, UID: "replacement", InstallationID: f.anchor.InstallationID}, {Namespace: f.anchor.Namespace, UID: f.anchor.UID, InstallationID: strings.Repeat("b", 32)}} {
		if result, err := f.o.Collect(context.Background(), anchor); result != nil || err == nil {
			t.Fatal("foreign original identity accepted")
		}
	}
	if len(f.dynamic.Actions()) != 0 || len(f.metadata.Actions()) != 0 {
		t.Fatal("invalid anchor caused cluster lists")
	}
}

func TestListedOwnerMustMatchRecursiveGET(t *testing.T) {
	for _, tc := range []string{"rv", "references"} {
		f := newFixture(t)
		f.claim("world", owner("Secret", "parent"))
		f.owner("secrets", "Secret", "parent")
		parent := f.objects[address("secrets", f.anchor.Namespace, "parent")]
		f.secrets = append(f.secrets, *parent.DeepCopy())
		if tc == "rv" {
			parent.ResourceVersion = "31"
		} else {
			parent.OwnerReferences = []metav1.OwnerReference{owner("ConfigMap", "different")}
		}
		if result, err := f.o.Collect(context.Background(), f.anchor); result != nil || !errors.Is(err, ErrOwnership) {
			t.Fatal("contradictory list/GET evidence accepted")
		}
	}
}

func (f *fixture) retain(t *testing.T, kind string) *metav1.PartialObjectMetadata {
	t.Helper()
	snapshot, err := f.o.journal.Load(context.Background(), f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	doc := snapshot.Document()
	for _, r := range f.o.plan.Resources() {
		if r.Object.GetKind() != kind {
			continue
		}
		key := installstate.Key{APIVersion: r.Object.GetAPIVersion(), Kind: kind, Namespace: r.Object.GetNamespace(), Name: r.Object.GetName()}
		doc.Resources = append(doc.Resources, installstate.Resource{Key: key, UID: "retained-anchor-uid", TemplateSHA256: strings.Repeat("b", 64), Retained: true, Phase: r.Phase})
		slices.SortFunc(doc.Resources, func(a, b installstate.Resource) int { return strings.Compare(a.Key.String(), b.Key.String()) })
		body, err := installstate.Encode(doc, f.o.plan)
		if err != nil {
			t.Fatal(err)
		}
		ns, err := f.core.CoreV1().Namespaces().Get(context.Background(), f.anchor.Namespace, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ns.Annotations[installstate.Annotation] = string(body)
		if err := f.core.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, ns, ""); err != nil {
			t.Fatal(err)
		}
		g := newOwnerGraph(f.o, doc.Resources, f.cs)
		resource := g.names[key.APIVersion+"/"+kind]
		object := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, UID: "retained-anchor-uid", ResourceVersion: "35"}}
		f.objects[address(resource, key.Namespace, key.Name)] = object
		if kind == "ValidatingAdmissionPolicy" {
			u := r.Object.DeepCopy()
			u.SetUID(object.UID)
			u.SetResourceVersion(object.ResourceVersion)
			f.lists[resource] = append(f.lists[resource], *u)
		}
		return object
	}
	t.Fatal("missing trusted retained kind")
	return nil
}

func TestRetainedClusterAnchorsRequireOriginalUIDAndValidScope(t *testing.T) {
	for _, kind := range []string{"CustomResourceDefinition", "ValidatingAdmissionPolicy"} {
		for _, replace := range []bool{false, true} {
			f := newFixture(t)
			retained := f.retain(t, kind)
			if replace {
				retained.UID = "replacement"
			}
			result, err := f.o.Collect(context.Background(), f.anchor)
			if replace && (result != nil || !errors.Is(err, ErrOwnership)) || !replace && (result == nil || err != nil) {
				t.Fatal("retained anchor original identity not enforced")
			}
		}
	}
	f := newFixture(t)
	retained := f.retain(t, "CustomResourceDefinition")
	retained.OwnerReferences = []metav1.OwnerReference{owner("ConfigMap", "namespaced-parent")}
	f.owner("configmaps", "ConfigMap", "namespaced-parent")
	if result, err := f.o.Collect(context.Background(), f.anchor); result != nil || !errors.Is(err, ErrOwnership) {
		t.Fatal("cluster child has namespaced owner")
	}
}

func TestGraphNodeAndAggregateEvidenceBounds(t *testing.T) {
	f := newFixture(t)
	g := newOwnerGraph(f.o, nil, f.cs)
	for i := range installsafety.MaxOwnerGraphNodes {
		name := fmt.Sprint("node-", i)
		key := installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: f.anchor.Namespace, Name: name}
		object := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: f.anchor.Namespace, UID: types.UID(name), ResourceVersion: "1"}}
		if err := g.seed(key, object); err != nil {
			t.Fatal("node bound rejected valid graph")
		}
	}
	key := installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: f.anchor.Namespace, Name: "overflow"}
	if err := g.seed(key, &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace, UID: "overflow", ResourceVersion: "1"}}); !errors.Is(err, ErrRead) || len(g.nodes) != installsafety.MaxOwnerGraphNodes {
		t.Fatal("node bound not enforced before retaining evidence")
	}
	g = newOwnerGraph(f.o, nil, f.cs)
	for range 7 {
		if err := g.charge(strings.Repeat("x", maxResponseBytes)); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.charge(strings.Repeat("x", maxResponseBytes)); !errors.Is(err, ErrRead) {
		t.Fatal("aggregate evidence budget unbounded")
	}
}

func TestWholeCollectCancellationReturnsNoPartialEvidence(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := f.o.Collect(ctx, f.anchor); result != nil || err == nil {
		t.Fatal("canceled collection accepted")
	}
	if len(f.dynamic.Actions()) != 0 || len(f.metadata.Actions()) != 0 {
		t.Fatal("canceled collection issued lists")
	}
}

func TestUnknownNamespacedOwnerUsesExactDiscoveryAndFiniteDeadline(t *testing.T) {
	f := newFixture(t)
	ref := metav1.OwnerReference{APIVersion: "storage.example/v1", Kind: "ExternalWorld", Name: "external", UID: "uid-external"}
	f.claim("world", ref)
	f.owner("externalworlds", "ExternalWorld", "external")
	previous := f.o.clients.Discovery
	customReads := 0
	f.o.clients.Discovery = func(ctx context.Context, gv string) (*metav1.APIResourceList, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > observationTimeout {
			t.Fatal("whole observation has no finite deadline")
		}
		if gv == ref.APIVersion {
			customReads++
			return &metav1.APIResourceList{GroupVersion: gv, APIResources: []metav1.APIResource{{Name: "externalworlds", Kind: "ExternalWorld", Namespaced: true, Verbs: metav1.Verbs{"get", "list"}}}}, nil
		}
		return previous(ctx, gv)
	}
	result, err := f.o.Collect(context.Background(), f.anchor)
	if err != nil || result == nil || customReads != 1 {
		t.Fatal("genuine unknown namespaced owner was blanket-rejected")
	}
	if len(result.Snapshot().Owners) != 2 {
		t.Fatal("missing custom owner evidence")
	}
}

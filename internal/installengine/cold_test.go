// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
)

func coldPVFixture() *corev1.PersistentVolume {
	return &corev1.PersistentVolume{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PersistentVolume"}, ObjectMeta: metav1.ObjectMeta{Name: "world-pv", UID: "original-pv", ResourceVersion: "1"}, Spec: corev1.PersistentVolumeSpec{
		PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "test.example", VolumeHandle: "original-handle"}},
		AccessModes:            []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
	}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}}
}

func TestColdNamedVolumeReadsAreExactAuthorizedAndNeverList(t *testing.T) {
	for _, scenario := range []string{"healthy", "denied", "missing", "malformed", "wrong-kind", "wrong-name", "namespace", "unsupported-discovery", "duplicate-claim-binding", "bad-derived-name", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			gets, auths := []string{}, []string{}
			access := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v1":
					resources := []metav1.APIResource{{Name: "persistentvolumes", Kind: "PersistentVolume", Verbs: metav1.Verbs{"get"}}}
					if scenario == "unsupported-discovery" {
						resources[0].Verbs = metav1.Verbs{"list"}
					}
					_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: "v1", APIResources: resources})
				case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
					var review authv1.SelfSubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&review) != nil {
						t.Error("invalid SSAR")
					}
					a := review.Spec.ResourceAttributes
					if r.Method != http.MethodPost || a == nil || a.Version != "v1" || a.Group != "" || a.Namespace != "" || a.Resource != "persistentvolumes" || a.Verb != "get" || a.Name == "" || a.Name == "*" || a.LabelSelector != nil || a.FieldSelector != nil {
						t.Error("unbounded volume authority")
					}
					auths = append(auths, a.Name)
					review.Status.Allowed = scenario != "denied"
					_ = json.NewEncoder(w).Encode(review)
				default:
					if r.Method != http.MethodGet || r.URL.RawQuery != "" || !strings.HasPrefix(r.URL.Path, "/api/v1/persistentvolumes/") {
						t.Error("not an exact volume GET")
					}
					name := strings.TrimPrefix(r.URL.Path, "/api/v1/persistentvolumes/")
					gets = append(gets, name)
					pv := coldPVFixture()
					pv.Name = name
					switch scenario {
					case "missing":
						w.WriteHeader(404)
						_, _ = w.Write([]byte("PRIVATE-CANARY"))
						return
					case "malformed":
						_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"PersistentVolume","kind":"PersistentVolume"}`))
						return
					case "wrong-kind":
						pv.Kind = "Secret"
					case "wrong-name":
						pv.Name = "foreign"
					case "namespace":
						pv.Namespace = "foreign"
					}
					_ = json.NewEncoder(w).Encode(pv)
				}
			})
			s := &installsafety.Snapshot{Claims: &corev1.PersistentVolumeClaimList{Items: []corev1.PersistentVolumeClaim{{Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "world-pv"}}}}}
			r := &installsafety.RuntimeSnapshot{Attachments: &storageVolumeAttachmentListForCold}
			// Distinct global attachment addresses are derived authority too,
			// deduplicated with namespace backing names before any read.
			r.Attachments = r.Attachments.DeepCopy()
			if scenario == "duplicate-claim-binding" {
				s.Claims.Items = append(s.Claims.Items, s.Claims.Items[0])
			}
			if scenario == "bad-derived-name" {
				r.Attachments.Items[0].Spec.Source.PersistentVolumeName = ptr.To("../secret")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			p := &ClusterPrerequisites{access: access}
			volumes, err := p.coldVolumes(ctx, s, r)
			if (err == nil) != (scenario == "healthy") || err != nil && (err != ErrColdSafety || volumes != nil || strings.Contains(err.Error(), "CANARY")) {
				t.Fatal("invalid named volume evidence accepted", err)
			}
			if scenario == "healthy" && !reflect.DeepEqual(gets, []string{"foreign-pv", "world-pv"}) {
				t.Fatal("source closure missing or unordered", gets)
			}
			if len(gets) > len(auths) || scenario == "denied" && len(gets) != 0 || scenario == "duplicate-claim-binding" && len(auths) != 0 || scenario == "bad-derived-name" && len(auths) != 0 {
				t.Fatal("read preceded exact derivation/authorization")
			}
		})
	}
}

// This fixture tests production HTTP clients and sealed journal reads. It is
// not native policy evaluation, physical CSI storage, kubelet or full lifecycle.
func TestColdBoundProviderBracketsWorldPolicyAndJournalIdentity(t *testing.T) {
	v := newLifecycleFixture(t)
	v.fail = AdmissionEffective
	s := v.f.snapshot
	for i := 0; i < 100; i++ {
		next, err := v.l.Step(context.Background(), s, v.opts)
		s = next
		if err != nil {
			if !errors.Is(err, ErrLifecycle) {
				t.Fatal(err)
			}
			break
		}
	}
	for key, object := range v.f.access.objects {
		if key.Kind == "ValidatingAdmissionPolicy" {
			object.Object["status"] = map[string]any{"observedGeneration": object.GetGeneration(), "typeChecking": map[string]any{}}
		}
	}
	ns, err := v.f.access.client.CoreV1().Namespaces().Get(context.Background(), v.f.plan.Namespace(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	server := arcade.GameServer{TypeMeta: metav1.TypeMeta{APIVersion: arcade.GroupVersion.String(), Kind: "GameServer"}, ObjectMeta: metav1.ObjectMeta{Name: "factory", Namespace: ns.Name, UID: "original-server", ResourceVersion: "1", Generation: 1}, Spec: arcade.GameServerSpec{
		Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("a", 64), DesiredState: arcade.DesiredStateStopped,
		Compute: arcade.ComputeSpec{CPURequest: resource.MustParse("500m"), CPULimit: resource.MustParse("2"), MemoryRequest: resource.MustParse("1Gi"), MemoryLimit: resource.MustParse("2Gi")}, Storage: arcade.StorageSpec{Size: resource.MustParse("10Gi")}, Settings: runtime.RawExtension{Raw: []byte(`{"name":"test","maxPlayers":16,"visibility":"private"}`)},
	}, Status: arcade.GameServerStatus{ObservedGeneration: 1, Phase: arcade.PhaseStopped}}
	games, _ := catalog.Builtins()
	definition, _ := games.Get("factorio")
	desired, err := platformkube.Build(&server, definition)
	if err != nil {
		t.Fatal(err)
	}
	claim := desired.DataClaims[0].Desired.DeepCopy()
	claim.APIVersion, claim.Kind = "v1", "PersistentVolumeClaim"
	claim.UID, claim.ResourceVersion = "original-claim", "1"
	claim.Spec.VolumeName = "world-pv"
	claim.Status.Phase = corev1.ClaimBound
	claim.Status.Capacity = corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}
	server.Status.ObservedData = &arcade.RetainedDataReference{Identity: desired.DataIdentity, Claims: []arcade.RetainedDataClaimReference{{Path: claim.Labels[platformkube.LabelDataPath], ClaimRef: arcade.ExactLocalReference{Name: claim.Name, UID: string(claim.UID)}}}}
	pv := coldPVFixture()
	pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: claim.Namespace, Name: claim.Name, UID: claim.UID}
	for _, scenario := range []string{"healthy", "claim-rv", "pv-rv", "pv-uid", "status-switch", "policy-rv", "namespace-rv", "namespace-uid", "journal-rv", "mount-second", "attachment-second", "missing-global-list", "leader-renewal", "unrelated-attachment-renewal"} {
		t.Run(scenario, func(t *testing.T) {
			observations, pvReads := 0, 0
			currentNS := ns.DeepCopy()
			policyChanged := false
			access := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					var review authv1.SelfSubjectAccessReview
					if json.NewDecoder(r.Body).Decode(&review) != nil {
						t.Error("invalid SSAR")
					}
					review.Status.Allowed = true
					_ = json.NewEncoder(w).Encode(review)
					return
				}
				if r.Method != http.MethodGet {
					t.Error("cold provider mutated cluster")
				}
				for _, collection := range proofCollections {
					if r.URL.Path != "/apis/"+collection.gv {
						continue
					}
					list := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: collection.gv}
					for _, item := range proofCollections {
						if item.gv == collection.gv {
							list.APIResources = append(list.APIResources, metav1.APIResource{Name: item.plural, Kind: item.kind, Namespaced: item.namespaced, Verbs: metav1.Verbs{"get", "list"}})
						}
					}
					_ = json.NewEncoder(w).Encode(list)
					return
				}
				// Exact discovery, including original retained owner GET scope.
				if r.URL.Path == "/api/v1" || r.URL.Path == "/apis/apiextensions.k8s.io/v1" {
					gv := "v1"
					if r.URL.Path != "/api/v1" {
						gv = "apiextensions.k8s.io/v1"
					}
					list := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv}
					for _, item := range []metav1.APIResource{{Name: "namespaces", Kind: "Namespace", Verbs: metav1.Verbs{"get"}}, {Name: "persistentvolumes", Kind: "PersistentVolume", Verbs: metav1.Verbs{"get"}}, {Name: "customresourcedefinitions", Kind: "CustomResourceDefinition", Verbs: metav1.Verbs{"get"}}} {
						if gv == "v1" && item.Kind != "CustomResourceDefinition" || gv != "v1" && item.Kind == "CustomResourceDefinition" {
							list.APIResources = append(list.APIResources, item)
						}
					}
					_ = json.NewEncoder(w).Encode(list)
					return
				}
				if r.URL.Path == "/api/v1/namespaces/"+ns.Name {
					copy := currentNS.DeepCopy()
					if observations >= 1 && scenario == "namespace-rv" {
						copy.ResourceVersion = "changed"
					}
					if observations >= 1 && scenario == "namespace-uid" {
						copy.UID = "replacement"
					}
					if strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata;") {
						_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: copy.ObjectMeta})
						return
					}
					copy.APIVersion, copy.Kind = "v1", "Namespace"
					_ = json.NewEncoder(w).Encode(copy)
					return
				}
				if strings.HasPrefix(r.URL.Path, "/api/v1/persistentvolumes/") {
					copy := pv.DeepCopy()
					if strings.HasSuffix(r.URL.Path, "/foreign-pv") {
						copy.Name, copy.UID = "foreign-pv", "foreign-pv-uid"
						copy.Spec.CSI.VolumeHandle = "unrelated"
						copy.ResourceVersion = string(rune('1' + observations))
						_ = json.NewEncoder(w).Encode(copy)
						return
					}
					pvReads++
					if pvReads >= 2 {
						if scenario == "pv-rv" {
							copy.ResourceVersion = "changed"
						}
						if scenario == "pv-uid" {
							copy.UID = "replacement"
						}
					}
					_ = json.NewEncoder(w).Encode(copy)
					return
				}
				for _, collection := range proofCollections {
					path := "/apis/" + collection.gv
					if collection.gv == "v1" {
						path = "/api/v1"
					}
					if collection.namespaced {
						path += "/namespaces/" + ns.Name
					}
					path += "/" + collection.plural
					if r.URL.Path != path {
						continue
					}
					if r.URL.Query().Get("limit") != "128" || r.URL.Query().Has("labelSelector") || r.URL.Query().Has("resourceVersion") {
						t.Error("incomplete or cached collection")
					}
					if collection.kind == "Secret" {
						if !strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadataList;") {
							t.Error("full Secret fallback")
						}
						_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: metav1.ListMeta{ResourceVersion: "10"}, Items: []metav1.PartialObjectMetadata{}})
						return
					}
					items := []any{}
					switch collection.kind {
					case "GameServer":
						observations++
						copy := server.DeepCopy()
						if observations >= 2 && scenario == "status-switch" {
							copy.Status.ActiveData = copy.Status.ObservedData.DeepCopy()
							copy.Status.ActiveData.Identity = "restored"
						}
						items = append(items, copy)
					case "PersistentVolumeClaim":
						copy := claim.DeepCopy()
						if observations >= 2 && scenario == "claim-rv" {
							copy.ResourceVersion = "changed"
						}
						items = append(items, copy)
					case "Lease":
						if scenario == "leader-renewal" {
							items = append(items, map[string]any{"metadata": map[string]any{"name": "arcadectl-controller-leader-election", "namespace": ns.Name, "uid": "leader", "resourceVersion": string(rune('1' + observations))}, "spec": map[string]any{"holderIdentity": "controller"}})
						}
					case "Deployment":
						if observations >= 2 && scenario == "mount-second" {
							items = append(items, map[string]any{"metadata": map[string]any{"name": "remount", "namespace": ns.Name, "uid": "remount", "resourceVersion": "1"}, "spec": map[string]any{"replicas": 0, "template": map[string]any{"spec": map[string]any{"volumes": []any{map[string]any{"name": "world", "persistentVolumeClaim": map[string]any{"claimName": claim.Name}}}}}}})
						}
					case "VolumeAttachment":
						if scenario == "missing-global-list" {
							w.WriteHeader(403)
							_, _ = w.Write([]byte("PRIVATE-CANARY"))
							return
						}
						name := ""
						if observations >= 2 && scenario == "attachment-second" {
							name = pv.Name
						}
						if scenario == "unrelated-attachment-renewal" {
							name = "foreign-pv"
						}
						if name != "" {
							items = append(items, map[string]any{"metadata": map[string]any{"name": "attachment", "uid": "attachment", "resourceVersion": string(rune('1' + observations))}, "spec": map[string]any{"attacher": "test.example", "nodeName": "node", "source": map[string]any{"persistentVolumeName": name}}, "status": map[string]any{"attached": false}})
						}
					case "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
						for key, o := range v.f.access.objects {
							if key.Kind == collection.kind {
								items = append(items, o.Object)
							}
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": collection.gv, "kind": collection.kind + "List", "metadata": map[string]any{"resourceVersion": "10"}, "items": items})
					return
				}
				for key, o := range v.f.access.objects {
					path, err := resourcePath(key, false)
					if err != nil || path != r.URL.Path {
						continue
					}
					copy := o.DeepCopy()
					if strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadata;") {
						_ = json.NewEncoder(w).Encode(metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: metav1.ObjectMeta{Name: copy.GetName(), Namespace: copy.GetNamespace(), UID: copy.GetUID(), ResourceVersion: copy.GetResourceVersion(), Generation: copy.GetGeneration(), OwnerReferences: copy.GetOwnerReferences()}})
						return
					}
					if observations >= 2 && scenario == "policy-rv" && key.Kind == "ValidatingAdmissionPolicy" {
						copy.SetResourceVersion("changed")
						policyChanged = true
					}
					if observations >= 2 && scenario == "journal-rv" {
						currentNS.ResourceVersion = "changed"
					}
					_ = json.NewEncoder(w).Encode(copy.Object)
					return
				}
				t.Error("unexpected cold route", r.URL.Path)
				w.WriteHeader(404)
			})
			store, err := installstate.New(access.Namespaces(), v.f.plan)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewWithAccess(access, store, v.f.engine.files, v.f.plan)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := NewClusterPrerequisites(engine, access)
			if err != nil {
				t.Fatal(err)
			}
			cold, err := NewClusterCold(proof)
			if err != nil {
				t.Fatal(err)
			}
			input, err := store.Load(context.Background(), s.Anchor())
			if err != nil {
				t.Fatal(err)
			}
			request := LifecycleCheck{Checkpoint: ColdSafety, Snapshot: input, Mode: installstate.Install, Target: v.f.plan, Options: LifecycleOptions{Now: time.Now().UTC()}}
			before := v.f.access.writes
			err = cold.Verify(context.Background(), request)
			valid := scenario == "healthy" || scenario == "leader-renewal" || scenario == "unrelated-attachment-renewal"
			if (err == nil) != valid || err != nil && err != ErrColdSafety || v.f.access.writes != before {
				t.Fatalf("cold bracket accepted contradictory evidence or mutated: %v; observations=%d volumes=%d", err, observations, pvReads)
			}
			if valid && (observations != 2 || pvReads != 2) {
				t.Fatal("cold proof did not repeat complete evidence")
			}
			if scenario == "policy-rv" && !policyChanged {
				t.Fatal("policy race fixture not reached")
			}
			if valid {
				request.Checkpoint = AdmissionEffective
				if cold.Verify(context.Background(), request) != ErrInvalid {
					t.Fatal("partial cold proof substituted for full admission")
				}
				engine.access = &HTTPAccess{}
				if _, err := NewClusterCold(proof); err != ErrInvalid {
					t.Fatal("foreign access accepted")
				}
			}
		})
	}
}

var storageVolumeAttachmentListForCold = storagev1.VolumeAttachmentList{Items: []storagev1.VolumeAttachment{{Spec: storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: ptr.To("foreign-pv")}}}, {Spec: storagev1.VolumeAttachmentSpec{Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: ptr.To("world-pv")}}}}}

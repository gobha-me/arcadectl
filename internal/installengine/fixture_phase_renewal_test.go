// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
)

// Materialize ready original runtime children BEFORE the existing actual
// captureInitialPhase/seal. No journal, actor capability or phase is fabricated.
func fixtureWarmPhaseFactory(t *testing.T, extraSetup ...func(*fixturePhaseTest)) func(*testing.T) *fixturePhaseTest {
	newWire := func(t *testing.T) *fixtureWireTest {
		v, snapshot := bootstrapReadyFixture(t)
		v.fail = 0
		complete := false
		for range 160 {
			next, err := v.l.Step(t.Context(), snapshot, v.opts)
			if err != nil {
				t.Fatal("genuine independent controller checkpoint unavailable", err)
			}
			snapshot = next
			count := 0
			for _, resource := range snapshot.Document().Resources {
				for _, family := range controllerFamilies {
					if resource.Key == deploymentKey(snapshot.Anchor().Namespace, family) {
						count++
					}
				}
			}
			if count == len(controllerFamilies) && snapshot.Document().Pending == nil {
				complete = true
				break
			}
		}
		if !complete {
			t.Fatal("full original controller inventory not reached")
		}
		// Each child generates its OWN private credentials through the genuine
		// lifecycle. Only Secret metadata is added to its fake read surface.
		for _, secret := range v.private.objects {
			metadata := secret.DeepCopy()
			metadata.Data, metadata.StringData = nil, nil
			metadata.APIVersion, metadata.Kind = "v1", "Secret"
			v.f.access.objects[secretKey(metadata.Namespace, metadata.Name)] = servingObject(t, metadata)
		}
		actor := newActorFixtureAtCheckpoint(t, v, snapshot)
		actor.request.Options.Now = time.Now().UTC()
		return newFixtureWireTestAtActor(t, actor)
	}
	return fixturePhaseFactoryFromWireFactory(t, newWire, func(h *fixturePhaseTest) {
		t := h.test
		base := h.f.actor.fixtureHandler
		h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
			for key, object := range h.f.actor.v.f.access.objects {
				if key.Kind != "Secret" {
					continue
				}
				path, err := privateSecretPath(key, false)
				if err != nil || path != r.URL.Path {
					continue
				}
				if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata") {
					t.Error("warm fixture requested a Secret body or mutation")
					w.WriteHeader(http.StatusForbidden)
					return true
				}
				encodeStoppedObject(t, w, r, object)
				return true
			}
			return base(w, r)
		}
		_, _, lists := readyControllerFixture(t, h.f.actor.v.f.plan)
		samples := lists["Pod"].(*corev1.PodList)
		family := 0
		for _, name := range controllerFamilies {
			key := deploymentKey(h.f.actor.request.Snapshot.Anchor().Namespace, name)
			parent := &appsv1.Deployment{}
			if decodeServing(h.f.actor.v.f.access.objects[key], parent) != nil || parent.Spec.Replicas == nil || *parent.Spec.Replicas != 1 {
				t.Fatal("original signed running Deployment unavailable")
			}
			parent.Status = appsv1.DeploymentStatus{ObservedGeneration: parent.Generation, Replicas: 1, UpdatedReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
			parent.Annotations["deployment.kubernetes.io/revision"] = "6"
			set := inertFixture(parent, "bcdfg23456", 6)
			set.CreationTimestamp = metav1.NewTime(time.Unix(100, 0).UTC())
			set.Spec.Template = *parent.Spec.Template.DeepCopy()
			set.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "bcdfg23456"
			set.Labels = maps.Clone(set.Spec.Template.Labels)
			set.Annotations[installstate.MutationAnnotation] = parent.Annotations[installstate.MutationAnnotation]
			set.Spec.Replicas = ptr.To[int32](1)
			set.Status = appsv1.ReplicaSetStatus{ObservedGeneration: set.Generation, Replicas: 1, FullyLabeledReplicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
			var pod *corev1.Pod
			for _, sample := range samples.Items {
				if strings.HasPrefix(sample.Name, parent.Name+"-") {
					pod = sample.DeepCopy()
				}
			}
			if pod == nil {
				t.Fatal("original family defaults unavailable")
			}
			pod.ObjectMeta = metav1.ObjectMeta{Name: set.Name + "-bcdfg", GenerateName: set.Name + "-", Namespace: parent.Namespace, UID: set.UID + "-pod", ResourceVersion: "10", Labels: maps.Clone(set.Spec.Template.Labels), Annotations: maps.Clone(set.Spec.Template.Annotations), OwnerReferences: fixtureOwner("apps/v1", "ReplicaSet", set.Name, set.UID)}
			lease := phaseLeaderFixture(pod, family, time.Now().UTC().Truncate(time.Microsecond))
			h.f.actor.v.f.access.objects[key] = servingObject(t, parent)
			h.extra = append(h.extra, servingObject(t, set), servingObject(t, pod), servingObject(t, &lease))
			family++
		}
		for _, setup := range extraSetup {
			setup(h)
		}
	})
}

func TestFixturePhaseOriginalWarmRenewalIdentity(t *testing.T) {
	testFixturePhaseOriginalWarmRenewalRetry(t, "renewal", "holder", "uid", "owner", "acquire")
}

func TestFixturePhaseOriginalWarmRenewalBoundsAndFloors(t *testing.T) {
	testFixturePhaseOriginalWarmRenewalRetry(t, "label", "exhaustion", "regression", "paired-regression", "renew-regression")
}

func TestFixturePhaseOriginalWarmRenewalClosure(t *testing.T) {
	testFixturePhaseOriginalWarmRenewalRetry(t, "managed-regression", "public-drift", "foreign-descendant", "list-revoked", "cancelled")
}

// Keep complete subtrees discoverable by the existing round-robin race shards;
// never split a scenario's original checkpoint, effect and observation interval.
func testFixturePhaseOriginalWarmRenewalRetry(t *testing.T, faults ...string) {
	t.Helper()
	newPhase := fixtureWarmPhaseFactory(t)
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			h := newPhase(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			expectedCreates := 0
			if fault == "renewal" || fault == "foreign-descendant" {
				// CREATE the FIRST recipe, through its real durable intent and
				// single-send wire; later slots cannot skip original predecessors.
				h.f.reply = func(w http.ResponseWriter, original *unstructured.Unstructured) {
					result := fixtureResultExample(t, h.f.wire.ledger, fixtureBackupJob, fixtureStableResult, time.Now().UTC().Truncate(time.Second).Add(-20*time.Second))
					result.SetUID(original.GetUID())
					h.f.objects[fixtureBackupJob] = result.DeepCopy()
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(result.Object)
				}
				fixtureWireAdvance(t, h.f.wire.ledger, fixtureBackupJob, fixtureCreateAttempted, "")
				if _, err := h.f.wire.create(ctx, fixtureBackupJob); err != nil {
					t.Fatal("one original fixture CREATE unavailable", err)
				}
				expectedCreates = 1
			}
			unchanged := fixturePreviewUnchanged(t, h.f)
			collections := 0
			widgets := 0
			base := h.f.actor.fixtureHandler
			h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if fault == "list-revoked" && collections == 1 && r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					body, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(body))
					var review authv1.SelfSubjectAccessReview
					if json.Unmarshal(body, &review) != nil {
						t.Error("exact review unavailable")
					}
					if a := review.Spec.ResourceAttributes; a != nil && a.Verb == "list" {
						review.Status.Allowed = false
						_ = json.NewEncoder(w).Encode(review)
						return true
					}
				}
				return base(w, r)
			}
			changed := false
			h.afterPublicGet = func(int) {
				if collections != 1 || changed {
					return
				}
				if fault == "cancelled" {
					changed = true
					cancel()
				}
				if fault == "paired-regression" {
					changed = true
					for _, object := range h.extra {
						if object.GetKind() == "Lease" {
							object.SetResourceVersion("101")
						}
					}
				}
			}
			h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
				if fault == "foreign-descendant" && source.Kind == "Widget" {
					widgets++
					if widgets == 1 {
						return rows // keep the preceding typed owner's graph intact
					}
					entry := h.f.wire.ledger.document.Entries[fixtureBackupJob]
					rows = append(rows, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "foreign-descendant", Namespace: entry.Key.Namespace, UID: "foreign-widget", ResourceVersion: "101", OwnerReferences: fixtureOwner("batch/v1", "Job", entry.Key.Name, entry.OriginalUID)}})
				}
				if fault == "public-drift" && source.Kind == "Service" && len(rows) != 0 {
					rows[0].ResourceVersion = "999"
				}
				if source.Kind != "Lease" {
					return rows
				}
				collections++
				if collections == 1 || fault == "exhaustion" || (fault == "regression" || fault == "renew-regression" || fault == "managed-regression") && collections == 2 {
					for _, object := range h.extra {
						if object.GetKind() != "Lease" {
							continue
						}
						lease := &coordinationv1.Lease{}
						if decodeServing(object, lease) != nil {
							t.Fatal("whole original Lease unavailable")
						}
						lease.ResourceVersion = strconv.Itoa(101 + collections)
						if fault == "regression" && collections == 2 {
							lease.ResourceVersion = "101"
						}
						previousRenew := lease.Spec.RenewTime.Time
						renew := metav1.NewMicroTime(time.Now().UTC().Truncate(time.Microsecond))
						lease.Spec.RenewTime = &renew
						managed := metav1.NewTime(renew.Time.Truncate(time.Second))
						if fault == "renew-regression" && collections == 2 {
							renew.Time = previousRenew.Add(-time.Second)
						}
						if fault == "managed-regression" && collections == 2 {
							managed.Time = lease.ManagedFields[0].Time.Time.Add(-time.Second)
						}
						lease.ManagedFields[0].Time = &managed
						switch fault {
						case "holder":
							lease.Spec.HolderIdentity = ptr.To("foreign-pod_10000000-0000-4000-8000-000000000099")
						case "uid":
							lease.UID = "10000000-0000-4000-8000-000000000099"
						case "owner":
							lease.OwnerReferences = fixtureOwner("v1", "Pod", "foreign", "foreign")
						case "acquire":
							lease.Spec.AcquireTime.Time = lease.Spec.AcquireTime.Time.Add(time.Second)
						case "label":
							lease.Labels = map[string]string{"untrusted": "value"}
						}
						object.Object = servingObject(t, lease).Object
					}
				}
				return rows
			}
			result, err := h.f.wire.observePhase(ctx)
			if (err == nil) != (fault == "renewal") || err != nil && (err != ErrFixtures || result != nil || h.f.wire.ledger.phaseFloor != nil) {
				t.Fatal("warm read accepted unsafe renewal or advanced a refused floor", fault, err)
			}
			wanted := 1
			if fault == "renewal" || fault == "exhaustion" {
				wanted = 3
			}
			if fault == "regression" || fault == "paired-regression" || fault == "renew-regression" || fault == "managed-regression" {
				wanted = 2
			}
			if collections != wanted {
				t.Fatal("warm read repeated wrong number of complete collections", fault, collections, wanted)
			}
			if h.f.creates != expectedCreates || h.f.deletes != 0 || h.f.seeds != 0 || h.f.previews != 0 {
				t.Fatal("observational retry replayed an effect")
			}
			unchanged()
		})
	}
}

func TestFixturePhaseWarmRenewalUnrelatedLeaseWholeClosure(t *testing.T) {
	newPhase := fixtureWarmPhaseFactory(t, func(h *fixturePhaseTest) {
		lease := &coordinationv1.Lease{TypeMeta: metav1.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: metav1.ObjectMeta{Name: "unrelated-election", Namespace: h.f.actor.request.Snapshot.Anchor().Namespace, UID: "10000000-0000-4000-8000-000000000088", ResourceVersion: "100"}, Spec: coordinationv1.LeaseSpec{HolderIdentity: ptr.To("unrelated-holder")}}
		h.extra = append(h.extra, servingObject(h.test, lease))
	})
	for _, mutate := range []bool{false, true} {
		t.Run(strconv.FormatBool(mutate), func(t *testing.T) {
			h := newPhase(t)
			unchanged := fixturePreviewUnchanged(t, h.f)
			collections := 0
			h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
				if source.Kind != "Lease" {
					return rows
				}
				collections++
				if collections != 1 {
					return rows
				}
				for _, object := range h.extra {
					if object.GetKind() != "Lease" {
						continue
					}
					lease := &coordinationv1.Lease{}
					if decodeServing(object, lease) != nil {
						t.Fatal("whole original Lease unavailable")
					}
					if lease.Name == "unrelated-election" {
						if mutate {
							lease.Spec.HolderIdentity = ptr.To("changed-unrelated-holder")
						}
					} else {
						lease.ResourceVersion = "102"
						renew := metav1.NewMicroTime(time.Now().UTC().Truncate(time.Microsecond))
						lease.Spec.RenewTime = &renew
						managed := metav1.NewTime(renew.Time.Truncate(time.Second))
						lease.ManagedFields[0].Time = &managed
					}
					object.Object = servingObject(t, lease).Object
				}
				return rows
			}
			result, err := h.f.wire.observePhase(t.Context())
			if mutate {
				if err != ErrFixtures || result != nil || collections != 1 || h.f.wire.ledger.phaseFloor != nil {
					t.Fatal("unrelated whole Lease received the original leader exception", err, collections)
				}
			} else if err != nil || result == nil || collections != 3 || h.f.wire.ledger.phaseFloor == nil {
				t.Fatal("unchanged unrelated Lease prevented bounded renewal", err, collections)
			}
			if h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 || h.f.previews != 0 {
				t.Fatal("read-only renewal replayed an effect")
			}
			unchanged()
		})
	}
}

func TestFixturePhaseWarmRenewalCompletedFloorSurvivesLaterRefusal(t *testing.T) {
	h := fixtureWarmPhaseFactory(t)(t)
	unchanged := fixturePreviewUnchanged(t, h.f)
	collections := 0
	var accepted *fixturePhaseBaseline
	h.gcRows = func(source installobserve.GCResource, rows []metav1.PartialObjectMetadata) []metav1.PartialObjectMetadata {
		if source.Kind != "Lease" {
			return rows
		}
		collections++
		if collections == 3 {
			floor := h.f.wire.ledger.phaseFloor
			if floor == nil || len(floor.Leaders) != 2 {
				t.Fatal("first complete warm pass did not publish its safety floor")
			}
			body, err := json.Marshal(floor)
			accepted = &fixturePhaseBaseline{}
			if err != nil || json.Unmarshal(body, accepted) != nil {
				t.Fatal("completed phase floor copy unavailable")
			}
			for _, leader := range accepted.Leaders {
				if leader.Row.ResourceVersion != "102" {
					t.Fatal("first complete warm pass lost its monotonic renewal")
				}
			}
		}
		if collections != 1 && collections != 3 {
			return rows
		}
		for _, object := range h.extra {
			if object.GetKind() != "Lease" {
				continue
			}
			lease := &coordinationv1.Lease{}
			if decodeServing(object, lease) != nil {
				t.Fatal("whole original Lease unavailable")
			}
			lease.ResourceVersion = strconv.Itoa(101 + collections)
			renew := metav1.NewMicroTime(time.Now().UTC().Truncate(time.Microsecond))
			lease.Spec.RenewTime = &renew
			managed := metav1.NewTime(renew.Time.Truncate(time.Second))
			lease.ManagedFields[0].Time = &managed
			if collections == 3 {
				lease.Spec.HolderIdentity = ptr.To("foreign-pod_10000000-0000-4000-8000-000000000099")
			}
			object.Object = servingObject(t, lease).Object
		}
		return rows
	}
	result, err := h.f.wire.observePhase(t.Context())
	if err != ErrFixtures || result != nil || collections != 3 || accepted == nil || !reflect.DeepEqual(accepted, h.f.wire.ledger.phaseFloor) {
		t.Fatal("later refusal erased or advanced a completed warm floor", err, collections)
	}
	if h.f.creates != 0 || h.f.deletes != 0 || h.f.seeds != 0 || h.f.previews != 0 {
		t.Fatal("later refused observation replayed an effect")
	}
	unchanged()
}

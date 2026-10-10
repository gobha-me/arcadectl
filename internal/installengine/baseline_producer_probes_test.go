// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Synthetic shape tests only; actual whole native CREATE replies on both
// supported profiles remain required before this can enter runtime authority.
func baselineProducerReply(t *testing.T, desired *unstructured.Unstructured, now time.Time) *unstructured.Unstructured {
	t.Helper()
	reply := desired.DeepCopy()
	reply.SetUID("11111111-2222-4333-8444-555555555555")
	reply.SetGeneration(1)
	reply.SetCreationTimestamp(metav1.NewTime(now.UTC().Truncate(time.Second)))
	fields, err := json.Marshal(baselineProducerLiteralFieldset(t, desired.GetKind()))
	if err != nil {
		t.Fatal("synthetic fields unavailable")
	}
	stamp := metav1.NewTime(now.UTC().Truncate(time.Second))
	reply.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "arcadectl-installer", Operation: metav1.ManagedFieldsOperationUpdate, APIVersion: desired.GetAPIVersion(), FieldsType: "FieldsV1", FieldsV1: &metav1.FieldsV1{Raw: fields}, Time: &stamp}})
	reply.Object["status"] = map[string]any{}
	return reply
}

func TestBaselineProducerConstructorsAreClosedInertAndIndependent(t *testing.T) {
	plan, nonce := fixturePlan(t), strings.Repeat("a", 32)
	for _, kind := range []string{"Job", "Deployment"} {
		desired, err := baselineProducerProbe(plan, kind, nonce)
		if err != nil || desired.GetName() != "arcadectl-identity-probe-"+nonce || len(desired.GetName()) > 63 || desired.GetNamespace() != plan.Namespace() || desired.GetUID() != "" || desired.GetResourceVersion() != "" {
			t.Fatal("closed producer constructor escaped its context")
		}
		selector, _, _ := unstructured.NestedString(desired.Object, "spec", "selector", "matchLabels", baselineProducerLabel)
		label, _, _ := unstructured.NestedString(desired.Object, "spec", "template", "metadata", "labels", baselineProducerLabel)
		account, _, _ := unstructured.NestedString(desired.Object, "spec", "template", "spec", "serviceAccountName")
		alias, _, _ := unstructured.NestedString(desired.Object, "spec", "template", "spec", "serviceAccount")
		automount, found, _ := unstructured.NestedBool(desired.Object, "spec", "template", "spec", "automountServiceAccountToken")
		if selector != desired.GetName() || label != selector || account != "default" || alias != "default" || !found || automount {
			t.Fatal("producer can acquire a reserved account/token or generated selector")
		}
		if kind == "Job" {
			suspended, _, _ := unstructured.NestedBool(desired.Object, "spec", "suspend")
			manual, _, _ := unstructured.NestedBool(desired.Object, "spec", "manualSelector")
			parallelism, present, readErr := unstructured.NestedInt64(desired.Object, "spec", "parallelism")
			if !suspended || !manual || !present || readErr != nil || parallelism != 0 {
				t.Fatal("Job lost independent inertness controls")
			}
		} else {
			replicas, present, readErr := unstructured.NestedInt64(desired.Object, "spec", "replicas")
			strategy, _, _ := unstructured.NestedString(desired.Object, "spec", "strategy", "type")
			if !present || readErr != nil || replicas != 0 || strategy != "Recreate" {
				t.Fatal("Deployment became executable or acquired generated rolling strategy")
			}
		}
		original := desired.DeepCopy()
		_ = unstructured.SetNestedField(desired.Object, "foreign", "spec", "template", "spec", "serviceAccountName")
		second, err := baselineProducerProbe(plan, kind, nonce)
		if err != nil || !reflect.DeepEqual(second.Object, original.Object) {
			t.Fatal("constructor shares mutable desired state")
		}
	}
	for _, input := range []struct {
		plan *installrender.Plan
		kind string
		run  string
	}{{nil, "Job", nonce}, {plan, "Pod", nonce}, {plan, "CronJob", nonce}, {plan, "Job", ""}, {plan, "Job", strings.Repeat("A", 32)}, {plan, "Job", nonce + "a"}} {
		if got, err := baselineProducerProbe(input.plan, input.kind, input.run); got != nil || err != ErrInvalid {
			t.Fatal("untrusted producer input accepted")
		}
	}
}

func TestBaselineProducerConstructorsSupportDefaultCustomAndAuthenticRollback(t *testing.T) {
	var plans []*installrender.Plan
	for _, profile := range []string{installrender.Profile135, installrender.Profile137} {
		for _, namespace := range []string{installrender.DefaultNamespace, "isolated-producer"} {
			plans = append(plans, fixturePlanProfile(t, namespace, profile))
		}
	}
	previous, target := lifecycleTransitionPlans(t)
	if previous.Manifest().SourceSHA != installrender.LegacySourceSHA {
		t.Fatal("rollback fixture is not the authentic frozen predecessor")
	}
	plans = append(plans, previous, target)
	for _, plan := range plans {
		for _, kind := range []string{"Job", "Deployment"} {
			if desired, err := baselineProducerProbe(plan, kind, strings.Repeat("a", 32)); err != nil || desired.GetNamespace() != plan.Namespace() {
				t.Fatal("supported default/custom/rollback producer refused")
			}
		}
	}
}

// Independent literal schema oracle: no production field-tree constructor,
// field-leaf helper or reply-derived shape is used here.
func baselineProducerLiteralFieldset(t *testing.T, kind string) map[string]any {
	t.Helper()
	const pod = `{
	 "f:metadata":{"f:labels":{".":{},"f:arcade.gobha.me/identity-probe":{}}},
	 "f:spec":{
	  "f:automountServiceAccountToken":{},"f:dnsPolicy":{},"f:enableServiceLinks":{},
	  "f:preemptionPolicy":{},"f:priority":{},"f:restartPolicy":{},"f:schedulerName":{},
	  "f:serviceAccount":{},"f:serviceAccountName":{},"f:terminationGracePeriodSeconds":{},"f:tolerations":{},
	  "f:containers":{"k:{\"name\":\"probe\"}":{
	   ".":{},"f:command":{},"f:image":{},"f:imagePullPolicy":{},"f:name":{},"f:resources":{},
	   "f:terminationMessagePath":{},"f:terminationMessagePolicy":{},
	   "f:securityContext":{".":{},"f:allowPrivilegeEscalation":{},"f:readOnlyRootFilesystem":{},"f:capabilities":{".":{},"f:drop":{}}}
	  }},
	  "f:schedulingGates":{".":{},"k:{\"name\":\"arcade.gobha.me/identity-probe\"}":{".":{},"f:name":{}}},
	  "f:securityContext":{".":{},"f:runAsGroup":{},"f:runAsNonRoot":{},"f:runAsUser":{},"f:seccompProfile":{".":{},"f:type":{}}}
	 }
	}`
	producer := `"f:suspend":{},"f:parallelism":{},"f:completions":{},"f:backoffLimit":{},"f:manualSelector":{},"f:selector":{},"f:completionMode":{},"f:podReplacementPolicy":{},`
	if kind == "Deployment" {
		producer = `"f:replicas":{},"f:selector":{},"f:revisionHistoryLimit":{},"f:progressDeadlineSeconds":{},"f:strategy":{"f:type":{}},`
	} else if kind != "Job" {
		t.Fatal("unknown literal producer schema")
	}
	body := `{"f:metadata":{"f:labels":{".":{},"f:arcade.gobha.me/identity-probe":{}}},"f:spec":{` + producer + `"f:template":` + pod + `}}`
	var fields map[string]any
	if json.Unmarshal([]byte(body), &fields) != nil {
		t.Fatal("literal producer managed-fields schema invalid")
	}
	return fields
}

func TestBaselineProducerResultsCloseWholeReplyAndNativeMetadata(t *testing.T) {
	plan, nonce := fixturePlan(t), strings.Repeat("a", 32)
	now := time.Now().UTC()
	for _, kind := range []string{"Job", "Deployment"} {
		t.Run(kind, func(t *testing.T) {
			desired, err := baselineProducerProbe(plan, kind, nonce)
			if err != nil {
				t.Fatal(err)
			}
			valid := baselineProducerReply(t, desired, now)
			if !validBaselineProducerResult(plan, kind, nonce, valid, now, now.Add(time.Second)) {
				t.Fatal("closed synthetic whole producer result refused")
			}
			for _, row := range []struct {
				name  string
				path  []string
				value any
			}{
				{"root-extra", []string{"private"}, true},
				{"foreign-version", []string{"apiVersion"}, "foreign/v1"},
				{"foreign-kind", []string{"kind"}, "CronJob"},
				{"foreign-name", []string{"metadata", "name"}, "foreign"},
				{"foreign-namespace", []string{"metadata", "namespace"}, "foreign"},
				{"non-native-uid", []string{"metadata", "uid"}, "dryrun-generated-uid"},
				{"generation", []string{"metadata", "generation"}, int64(2)},
				{"persisted-rv", []string{"metadata", "resourceVersion"}, "42"},
				{"null-rv", []string{"metadata", "resourceVersion"}, nil},
				{"empty-rv", []string{"metadata", "resourceVersion"}, ""},
				{"owner", []string{"metadata", "ownerReferences"}, []any{map[string]any{"uid": "foreign", "kind": "Secret", "apiVersion": "v1", "name": "foreign"}}},
				{"null-owner", []string{"metadata", "ownerReferences"}, nil},
				{"finalizer", []string{"metadata", "finalizers"}, []any{"foreign"}},
				{"annotation", []string{"metadata", "annotations"}, map[string]any{"foreign": "PRIVATE-CANARY"}},
				{"null-annotation", []string{"metadata", "annotations"}, nil},
				{"deleting", []string{"metadata", "deletionTimestamp"}, now.Truncate(time.Second).Format(time.RFC3339)},
				{"stale-creation", []string{"metadata", "creationTimestamp"}, now.Add(-time.Minute).Truncate(time.Second).Format(time.RFC3339)},
				{"future-creation", []string{"metadata", "creationTimestamp"}, now.Add(time.Minute).Truncate(time.Second).Format(time.RFC3339)},
				{"noncanonical-creation", []string{"metadata", "creationTimestamp"}, now.Truncate(time.Second).Format("2006-01-02T15:04:05-07:00")},
				{"status-null", []string{"status"}, nil},
				{"status-generation", []string{"status", "observedGeneration"}, int64(0)},
				{"new-account", []string{"spec", "template", "spec", "serviceAccountName"}, "arcadectl-destroy-controller"},
				{"new-alias", []string{"spec", "template", "spec", "serviceAccount"}, "arcadectl-destroy-admin"},
				{"token", []string{"spec", "template", "spec", "automountServiceAccountToken"}, true},
				{"env", []string{"spec", "template", "spec", "nodeName"}, "foreign-node"},
				{"template-null-time", []string{"spec", "template", "metadata", "creationTimestamp"}, nil},
				{"generated-selector", []string{"spec", "selector", "matchLabels", "batch.kubernetes.io/controller-uid"}, "foreign"},
				{"unknown-spec", []string{"spec", "private"}, true},
			} {
				t.Run(row.name, func(t *testing.T) {
					bad := valid.DeepCopy()
					if unstructured.SetNestedField(bad.Object, row.value, row.path...) != nil {
						t.Fatal("synthetic mutation unavailable")
					}
					if validBaselineProducerResult(plan, kind, nonce, bad, now, now.Add(time.Second)) {
						t.Fatal("altered producer result accepted")
					}
				})
			}
			for _, scenario := range []string{"status-absent", "labels-absent", "extra-manager", "wrong-manager", "wrong-operation", "wrong-api", "status-role", "extra-field", "missing-inert-field", "stale-field-time", "future-field-time", "noncanonical-field-time"} {
				t.Run(scenario, func(t *testing.T) {
					bad := valid.DeepCopy()
					fields := bad.Object["metadata"].(map[string]any)["managedFields"].([]any)
					entry := fields[0].(map[string]any)
					switch scenario {
					case "status-absent":
						delete(bad.Object, "status")
					case "labels-absent":
						unstructured.RemoveNestedField(bad.Object, "metadata", "labels")
					case "extra-manager":
						bad.Object["metadata"].(map[string]any)["managedFields"] = append(fields, fields[0])
					case "wrong-manager":
						entry["manager"] = "foreign"
					case "wrong-operation":
						entry["operation"] = "Apply"
					case "wrong-api":
						entry["apiVersion"] = "foreign/v1"
					case "status-role":
						entry["subresource"] = "status"
					case "extra-field":
						entry["fieldsV1"].(map[string]any)["f:status"] = map[string]any{}
					case "missing-inert-field":
						spec := entry["fieldsV1"].(map[string]any)["f:spec"].(map[string]any)
						if kind == "Job" {
							delete(spec, "f:parallelism")
						} else {
							delete(spec, "f:replicas")
						}
					case "stale-field-time":
						entry["time"] = now.Add(-time.Minute).Truncate(time.Second).Format(time.RFC3339)
					case "future-field-time":
						entry["time"] = now.Add(time.Minute).Truncate(time.Second).Format(time.RFC3339)
					case "noncanonical-field-time":
						entry["time"] = now.Truncate(time.Second).Format("2006-01-02T15:04:05-07:00")
					}
					if validBaselineProducerResult(plan, kind, nonce, bad, now, now.Add(time.Second)) {
						t.Fatal("malformed ownership/time/initial status accepted")
					}
				})
			}
			if validBaselineProducerResult(plan, kind, nonce, valid, time.Time{}, now) || validBaselineProducerResult(plan, kind, nonce, valid, now.Add(time.Second), now) || validBaselineProducerResult(plan, kind, nonce, nil, now, now) {
				t.Fatal("invalid request interval or absent reply accepted")
			}
			if validAdmissionProbeResult(desired, valid, now, now.Add(time.Second)) {
				t.Fatal("producer proof widened historical runtime probe authority")
			}
		})
	}
}

// FieldManager.Update and the REST creation strategy stamp independently.
// Both must be canonical and bounded by this request, but the field-manager
// stamp can precede creation when the server crosses a serialization second.
func TestBaselineProducerResultIndependentNativeTimestampOrder(t *testing.T) {
	plan, nonce := fixturePlan(t), strings.Repeat("a", 32)
	start := time.Date(2026, 10, 10, 0, 0, 0, 500000000, time.UTC)
	end := start.Add(2 * time.Second)
	for _, kind := range []string{"Job", "Deployment"} {
		t.Run(kind, func(t *testing.T) {
			desired, err := baselineProducerProbe(plan, kind, nonce)
			if err != nil {
				t.Fatal("closed timestamp probe unavailable")
			}
			reply := baselineProducerReply(t, desired, start)
			reply.SetCreationTimestamp(metav1.NewTime(start.Add(time.Second).Truncate(time.Second)))
			before := reply.DeepCopy()
			if !validBaselineProducerResult(plan, kind, nonce, reply, start, end) || !reflect.DeepEqual(reply, before) {
				t.Fatal("native field-before-creation timing refused or reply normalized")
			}
			for _, which := range []string{"stale-managed", "future-managed", "stale-created", "future-created"} {
				t.Run(which, func(t *testing.T) {
					bad := reply.DeepCopy()
					field, stamp := "creationTimestamp", start.Add(-time.Second).Truncate(time.Second)
					if strings.Contains(which, "future") {
						stamp = end.Add(2 * time.Second).Truncate(time.Second)
					}
					if strings.HasSuffix(which, "managed") {
						fields := bad.Object["metadata"].(map[string]any)["managedFields"].([]any)
						fields[0].(map[string]any)["time"] = stamp.Format(time.RFC3339)
					} else if unstructured.SetNestedField(bad.Object, stamp.Format(time.RFC3339), "metadata", field) != nil {
						t.Fatal("timestamp boundary control unavailable")
					}
					if validBaselineProducerResult(plan, kind, nonce, bad, start, end) {
						t.Fatal("out-of-request native timestamp admitted")
					}
				})
			}
		})
	}
}

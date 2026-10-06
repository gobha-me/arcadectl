// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	strictjson "sigs.k8s.io/json"
)

func TestAdmissionConfigurationRequiresEveryOriginalSignedHealthyPolicy(t *testing.T) {
	for _, scenario := range []string{"healthy", "stale-generation", "no-typechecking", "warnings", "uid", "spec", "missing-binding", "binding-target", "false-condition", "duplicate-condition", "namespace-race"} {
		t.Run(scenario, func(t *testing.T) {
			v := newLifecycleFixture(t)
			v.fail = AdmissionEffective
			s := v.f.snapshot
			stopped := false
			for i := 0; i < 100; i++ {
				next, err := v.l.Step(context.Background(), s, v.opts)
				s = next
				if err != nil {
					if !errors.Is(err, ErrLifecycle) {
						t.Fatal(err)
					}
					stopped = true
					break
				}
			}
			if !stopped {
				t.Fatal("fixture failed to reach admission barrier")
			}
			var policy, binding *unstructured.Unstructured
			for key, object := range v.f.access.objects {
				if key.Kind == "ValidatingAdmissionPolicy" {
					object.Object["status"] = map[string]any{"observedGeneration": object.GetGeneration(), "typeChecking": map[string]any{}}
					if policy == nil {
						policy = object
					}
				}
				if key.Kind == "ValidatingAdmissionPolicyBinding" && binding == nil {
					binding = object
				}
			}
			if policy == nil || binding == nil {
				t.Fatal("fixture policy set absent")
			}
			condition := map[string]any{"type": "Accepted", "status": "True", "observedGeneration": policy.GetGeneration(), "lastTransitionTime": "2026-10-05T21:00:00Z", "reason": "Accepted", "message": "public fixture"}
			switch scenario {
			case "stale-generation":
				_ = unstructured.SetNestedField(policy.Object, int64(0), "status", "observedGeneration")
			case "no-typechecking":
				unstructured.RemoveNestedField(policy.Object, "status", "typeChecking")
			case "warnings":
				_ = unstructured.SetNestedSlice(policy.Object, []any{map[string]any{"fieldRef": "spec.validations[0].expression", "warning": "PRIVATE-CANARY"}}, "status", "typeChecking", "expressionWarnings")
			case "uid":
				policy.SetUID("replacement")
			case "spec":
				_ = unstructured.SetNestedField(policy.Object, "Ignore", "spec", "failurePolicy")
			case "missing-binding":
				delete(v.f.access.objects, installstate.Key{APIVersion: binding.GetAPIVersion(), Kind: binding.GetKind(), Name: binding.GetName()})
			case "binding-target":
				_ = unstructured.SetNestedField(binding.Object, "foreign", "spec", "policyName")
			case "false-condition":
				condition["status"] = "False"
				_ = unstructured.SetNestedSlice(policy.Object, []any{condition}, "status", "conditions")
			case "duplicate-condition":
				_ = unstructured.SetNestedSlice(policy.Object, []any{condition, condition}, "status", "conditions")
			}
			namespaceReads := 0
			probeRequests := 0
			probeRace := false
			accountRace := false
			access := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					if accountRace {
						v.f.access.objects[installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: v.f.plan.Namespace(), Name: "arcadectl-controller"}].SetResourceVersion("changed-during-probes")
					}
					probeRequests++
					if r.URL.RawQuery != "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict" {
						t.Error("persistent or nonstrict probe")
					}
					body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
					var fields map[string]any
					strictErrors, decodeErr := strictjson.UnmarshalStrict(body, &fields)
					if err != nil || decodeErr != nil || len(strictErrors) != 0 {
						t.Error("malformed fixture probe")
						return
					}
					object := &unstructured.Unstructured{Object: fields}
					stem, index, negative := "", 0, false
					switch object.GetKind() {
					case "Pod":
						worker := strings.TrimSuffix(object.GetLabels()["app.kubernetes.io/name"], "-worker")
						stem, index = "arcadectl-"+worker+"-worker-gate", 1
						_, found, _ := unstructured.NestedSlice(object.Object, "spec", "schedulingGates")
						negative = !found
					case "PersistentVolumeClaim":
						stem = "arcadectl-restore-candidate-pvc-create"
						negative = strings.HasPrefix(object.GetName(), "restore-")
						if object.GetLabels()["arcade.gobha.me/data-policy"] == "retain" {
							stem = "arcadectl-retained-world-pvc-delete"
							negative = object.GetAnnotations()["arcade.gobha.me/cold-backup-uid"] != ""
						}
					case "GameDestroy":
						stem = "arcadectl-destroy-unsafe-admin"
						mode, _, _ := unstructured.NestedString(object.Object, "spec", "mode")
						negative = mode == "UnsafeNoBackup"
					default:
						t.Error("foreign probe kind")
						return
					}
					w.Header().Set("Content-Type", "application/json")
					if negative {
						policyName := probePolicyName(t, v.f.plan, stem)
						var probePolicy admissionv1.ValidatingAdmissionPolicy
						policyKey := installstate.Key{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy", Name: policyName}
						if decodeServing(v.f.access.objects[policyKey], &probePolicy) != nil {
							t.Error("fixture policy decode")
							return
						}
						bindingName := ""
						for key, value := range v.f.access.objects {
							if key.Kind == "ValidatingAdmissionPolicyBinding" {
								target, _, _ := unstructured.NestedString(value.Object, "spec", "policyName")
								if target == policyName {
									bindingName = key.Name
								}
							}
						}
						key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
						_, plural, _ := probePath(key)
						denial, err := expectedProbeDenial(key, plural, policyName, bindingName, probePolicy.Spec.Validations[index].Message)
						if err != nil {
							t.Error(err)
							return
						}
						w.WriteHeader(422)
						_ = json.NewEncoder(w).Encode(denial)
					} else {
						w.WriteHeader(201)
						_ = json.NewEncoder(w).Encode(probeResultFixture(t, object, time.Now().UTC()).Object)
					}
					if probeRace {
						policy.SetResourceVersion("changed-during-probes")
					}
					return
				}
				if r.Method != "GET" || r.URL.RawQuery != "" {
					t.Error("configuration check mutated or cached")
				}
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/v1/namespaces/"+v.f.plan.Namespace() {
					namespaceReads++
					ns, err := v.f.access.client.CoreV1().Namespaces().Get(r.Context(), v.f.plan.Namespace(), metav1.GetOptions{})
					if err != nil {
						t.Error(err)
						return
					}
					if scenario == "namespace-race" && namespaceReads > 1 {
						ns.ResourceVersion = "changed"
					}
					ns.APIVersion, ns.Kind = "v1", "Namespace"
					_ = json.NewEncoder(w).Encode(ns)
					return
				}
				for key, object := range v.f.access.objects {
					path, err := resourcePath(key, false)
					if err == nil && path == r.URL.Path {
						_ = json.NewEncoder(w).Encode(object.Object)
						return
					}
				}
				w.WriteHeader(404)
			})
			// Trusted fixture combines a sealed fake journal with actual HTTP
			// reads; it does not relax the production constructor's one-access
			// identity requirement or certify native policy status.
			a := &ClusterAdmission{prerequisites: &ClusterPrerequisites{engine: v.f.engine, access: access}}
			request := LifecycleCheck{Checkpoint: AdmissionConfigured, Snapshot: s, Mode: installstate.Install, Target: v.f.plan, Options: v.opts}
			before := v.f.access.writes
			witness, err := a.configured(context.Background(), request)
			if (err == nil) != (scenario == "healthy") || v.f.access.writes != before {
				t.Fatal("foreign/stale/incomplete configuration accepted or mutated")
			}
			if err == nil {
				if len(witness.objects) != 12 || !sameAdmissionConfiguration(witness, witness) {
					t.Fatal("configuration lost original set")
				}
				second, err := a.configured(context.Background(), request)
				if err != nil || !sameAdmissionConfiguration(witness, second) {
					t.Fatal("unchanged configuration not stable")
				}
				policy.SetResourceVersion("changed")
				third, err := a.configured(context.Background(), request)
				if err != nil || sameAdmissionConfiguration(witness, third) {
					t.Fatal("resource version change not detected")
				}
				request.Checkpoint = AdmissionEffective
				if a.VerifyConfigured(context.Background(), request) != ErrInvalid {
					t.Fatal("configuration substituted for behavior")
				}
				if a.VerifyCreateProbes(context.Background(), request) != nil || probeRequests != 12 || v.f.access.writes != before {
					t.Fatal("original six-pair CREATE proof failed or persisted/replayed")
				}
				probeRace = true
				if a.VerifyCreateProbes(context.Background(), request) != ErrAdmission {
					t.Fatal("policy version race during probes accepted")
				}
				probeRace = false
				accountRace = true
				if a.VerifyCreateProbes(context.Background(), request) != ErrAdmission {
					t.Fatal("ServiceAccount version race during probes accepted")
				}
				accountRace = false
				beforeProbes := probeRequests
				accountKey := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: v.f.plan.Namespace(), Name: "arcadectl-controller"}
				v.f.access.objects[accountKey].SetUID("foreign-same-named-account")
				if a.VerifyCreateProbes(context.Background(), request) != ErrAdmission || probeRequests != beforeProbes {
					t.Fatal("same-named foreign ServiceAccount used for probes")
				}
				delete(v.f.access.objects, accountKey)
				if a.VerifyCreateProbes(context.Background(), request) != ErrAdmission || probeRequests != beforeProbes {
					t.Fatal("missing original ServiceAccount adopted, recreated or ignored")
				}
			}
		})
	}
}

func TestAdmissionPolicyStatusIsCurrentAndClosed(t *testing.T) {
	policy := &admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{Generation: 1}, Status: admissionv1.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admissionv1.TypeChecking{}}}
	if !healthyAdmissionPolicy(policy) {
		t.Fatal("native healthy status without conditions rejected")
	}
	policy.Status.Conditions = []metav1.Condition{{Type: "Accepted", Status: metav1.ConditionTrue, ObservedGeneration: 1, LastTransitionTime: metav1.NewTime(time.Now())}}
	if !healthyAdmissionPolicy(policy) {
		t.Fatal("current positive condition rejected")
	}
	policy.Status.Conditions[0].LastTransitionTime = metav1.Time{}
	if healthyAdmissionPolicy(policy) || healthyAdmissionPolicy(nil) || sameAdmissionConfiguration(nil, nil) {
		t.Fatal("incomplete proof accepted")
	}
}

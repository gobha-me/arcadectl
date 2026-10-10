// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const baselineProducerLabel = "arcade.gobha.me/identity-probe"

// Closed dry-run-only desired constructors. No arbitrary image, account,
// object, selector or name is accepted. These are not ownership receipts or
// live workloads. The caller still owes original actor/policy/executable
// brackets and the inner nonpersistent transport before any request.
func baselineProducerProbe(plan *installrender.Plan, kind, nonce string) (*unstructured.Unstructured, error) {
	if !plan.IsTrusted() || !nonceID.MatchString(nonce) || kind != "Job" && kind != "Deployment" {
		return nil, ErrInvalid
	}
	policy := ""
	for _, resource := range plan.ResourceMetadata() {
		if resource.Kind == "ValidatingAdmissionPolicy" && (resource.Name == "arcadectl-backup-worker-gate" || strings.HasPrefix(resource.Name, "arcadectl-backup-worker-gate-")) {
			if policy != "" {
				return nil, ErrInvalid
			}
			policy = resource.Name
		}
	}
	// Reuse only the pure reviewed PodSpec/schema constructor. Worker labels
	// and its gate are deliberately NOT reused, and no worker proof is claimed.
	pod, _, _, err := admissionCreateProbe(plan, policy, "default", "arcadectl-probe-"+nonce)
	if err != nil {
		return nil, ErrInvalid
	}
	name := "arcadectl-identity-probe-" + nonce
	labels := map[string]any{baselineProducerLabel: name}
	spec := pod.Object["spec"].(map[string]any)
	spec["schedulingGates"] = []any{map[string]any{"name": baselineProducerLabel}}
	if kind == "Deployment" {
		spec["restartPolicy"] = "Always"
	}
	template := map[string]any{"metadata": map[string]any{"labels": labels}, "spec": spec}
	selector := map[string]any{"matchLabels": labels}
	version := "batch/v1"
	producer := map[string]any{
		"suspend": true, "parallelism": int64(0), "completions": int64(1), "backoffLimit": int64(0),
		"manualSelector": true, "selector": selector,
		"completionMode": "NonIndexed", "podReplacementPolicy": "TerminatingOrFailed", "template": template,
	}
	if kind == "Deployment" {
		version = "apps/v1"
		producer = map[string]any{
			"replicas": int64(0), "selector": selector, "template": template,
			"strategy":             map[string]any{"type": "Recreate"},
			"revisionHistoryLimit": int64(10), "progressDeadlineSeconds": int64(600),
		}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": version, "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": plan.Namespace(), "labels": labels}, "spec": producer,
	}}, nil
}

// Pure complete positive-result validation, NOT endpoint-only success,
// ownership, persistent acknowledgement or effect authority. Desired shape and
// managed-field trees are rebuilt from trusted inputs, never from the reply.
// This separate contract does not change the historical runtime probe recipe.
func validBaselineProducerResult(plan *installrender.Plan, kind, nonce string, result *unstructured.Unstructured, start, end time.Time) bool {
	expected, err := baselineProducerProbe(plan, kind, nonce)
	if err != nil || result == nil || start.IsZero() || end.Before(start) || start.Year() < 1 || end.Year() > 9999 || result.GetAPIVersion() != expected.GetAPIVersion() || result.GetKind() != kind {
		return false
	}
	for key := range result.Object {
		if key != "apiVersion" && key != "kind" && key != "metadata" && key != "spec" && key != "status" {
			return false
		}
	}
	if !reflect.DeepEqual(result.Object["spec"], expected.Object["spec"]) || !reflect.DeepEqual(result.Object["status"], map[string]any{}) {
		return false
	}
	var metadata metav1.ObjectMeta
	if kind == "Job" {
		var job batchv1.Job
		if decodeServing(result, &job) != nil {
			return false
		}
		metadata = job.ObjectMeta
	} else {
		var deployment appsv1.Deployment
		if decodeServing(result, &deployment) != nil {
			return false
		}
		metadata = deployment.ObjectMeta
	}
	if !nativeFixtureUID(string(metadata.UID)) || metadata.Name != expected.GetName() || metadata.Namespace != expected.GetNamespace() || metadata.Generation != 1 || len(metadata.ManagedFields) != 1 {
		return false
	}
	earliest, latest := start.UTC().Truncate(time.Second), end.UTC().Add(time.Second)
	fields := baselineProducerFieldset(expected)
	if fields == nil {
		return false
	}
	entry := metadata.ManagedFields[0]
	// Field-manager updates precede REST creation metadata stamping. These
	// independent native timestamps can straddle a second boundary; validate
	// each against this request below, without inventing a relative order.
	if entry.Time == nil || entry.Time.IsZero() {
		return false
	}
	created := metadata.CreationTimestamp.UTC().Format(time.RFC3339)
	managed := entry.Time.UTC().Format(time.RFC3339)
	if !fixtureResultTime(created, earliest, latest) || !fixtureResultTime(managed, earliest, latest) {
		return false
	}
	wantMetadata := map[string]any{
		"name": expected.GetName(), "namespace": expected.GetNamespace(), "labels": expected.Object["metadata"].(map[string]any)["labels"],
		"uid": string(metadata.UID), "generation": int64(1), "creationTimestamp": created,
		"managedFields": []any{map[string]any{
			"manager": "arcadectl-installer", "operation": "Update", "apiVersion": expected.GetAPIVersion(),
			"fieldsType": "FieldsV1", "fieldsV1": fields, "time": managed,
		}},
	}
	// Raw equality also closes absent/null/zero optionals, extra ownership
	// roles, noncanonical timestamps, generated selectors and server mutations.
	return reflect.DeepEqual(result.Object["metadata"], wantMetadata)
}

func baselineProducerFieldset(expected *unstructured.Unstructured) map[string]any {
	if expected == nil || expected.GetKind() != "Job" && expected.GetKind() != "Deployment" {
		return nil
	}
	template, found, err := unstructured.NestedMap(expected.Object, "spec", "template")
	if err != nil || !found {
		return nil
	}
	pod := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": template["metadata"], "spec": template["spec"]}}
	podFields := admissionProbeFieldset(pod)
	if podFields == nil {
		return nil
	}
	spec := fixtureFieldLeaves("suspend", "parallelism", "completions", "backoffLimit", "manualSelector", "selector", "completionMode", "podReplacementPolicy")
	if expected.GetKind() == "Deployment" {
		spec = fixtureFieldLeaves("replicas", "selector", "revisionHistoryLimit", "progressDeadlineSeconds")
		spec["f:strategy"] = fixtureFieldLeaves("type")
	}
	spec["f:template"] = podFields
	return map[string]any{"f:spec": spec, "f:metadata": map[string]any{"f:labels": fixtureFieldLeaves(".", baselineProducerLabel)}}
}

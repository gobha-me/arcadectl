// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestBaselineBehaviorNegativeProducerClosedVariants(t *testing.T) {
	plan := fixturePlan(t)
	nonce := strings.Repeat("a", 32)
	for _, kind := range []string{"Job", "Deployment"} {
		base, err := baselineProducerProbe(plan, kind, nonce)
		if err != nil {
			t.Fatal("reviewed inert probe unavailable")
		}
		for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
			for _, variant := range []baselineProducerNegative{baselineProducerReservedAccount, baselineProducerReservedName} {
				object, err := baselineNegativeProducerProbe(plan, kind, nonce, variant, name)
				if err != nil || object == nil {
					t.Fatal("closed negative variant unavailable")
				}
				want := base.DeepCopy()
				if variant == baselineProducerReservedName {
					want.SetName(name)
				} else {
					_ = unstructured.SetNestedField(want.Object, name, "spec", "template", "spec", "serviceAccountName")
					_ = unstructured.SetNestedField(want.Object, name, "spec", "template", "spec", "serviceAccount")
				}
				if !reflect.DeepEqual(want.Object, object.Object) || object.GetUID() != "" || object.GetResourceVersion() != "" {
					t.Fatal("negative constructor modified another field or manufactured identity")
				}
			}
		}
	}
	for _, variant := range []baselineProducerNegative{0, 3, 255} {
		if object, err := baselineNegativeProducerProbe(plan, "Job", nonce, variant, "arcadectl-api"); err == nil || object != nil {
			t.Fatal("unknown negative opcode acquired request authority")
		}
	}
	for _, name := range []string{"", "default", "foreign", "arcadectl-api/foreign"} {
		if object, err := baselineNegativeProducerProbe(plan, "Job", nonce, baselineProducerReservedAccount, name); err == nil || object != nil {
			t.Fatal("arbitrary account entered closed negative request")
		}
	}
	if object, err := baselineNegativeProducerProbe(nil, "Job", nonce, baselineProducerReservedAccount, "arcadectl-api"); err == nil || object != nil {
		t.Fatal("untrusted plan entered negative request")
	}
}

func TestBaselineBehaviorMetadataUpdatePreservesWholeOriginal(t *testing.T) {
	plan := fixturePlan(t)
	for _, pair := range [][2]string{{"batch/v1", "Job"}, {"apps/v1", "Deployment"}, {"v1", "Pod"}, {"v1", "Service"}} {
		key := installstate.Key{APIVersion: pair[0], Kind: pair[1], Namespace: plan.Namespace(), Name: "arcadectl-api"}
		spec := map[string]any{}
		switch key.Kind {
		case "Job":
			spec = map[string]any{"suspend": true, "parallelism": int64(0), "completions": int64(1), "template": map[string]any{"spec": map[string]any{"restartPolicy": "Never", "containers": []any{map[string]any{"name": "fixture", "image": "example.test/fixture:v1"}}}}}
		case "Deployment":
			spec = map[string]any{"replicas": int64(0), "selector": map[string]any{"matchLabels": map[string]any{"original": "keep"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"original": "keep"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "fixture", "image": "example.test/fixture:v1"}}}}}
		case "Pod":
			spec = map[string]any{"serviceAccountName": "arcadectl-api", "containers": []any{map[string]any{"name": "fixture", "image": "example.test/fixture:v1"}}}
		case "Service":
			spec = map[string]any{"clusterIP": "10.96.0.42", "clusterIPs": []any{"10.96.0.42"}, "ports": []any{map[string]any{"port": int64(8080), "targetPort": int64(8080)}}, "selector": map[string]any{"original": "keep"}}
		}
		original := &unstructured.Unstructured{Object: map[string]any{"apiVersion": key.APIVersion, "kind": key.Kind, "metadata": map[string]any{"name": key.Name, "namespace": key.Namespace, "uid": "original-update-probe", "resourceVersion": "17", "annotations": map[string]any{installstate.MutationAnnotation: strings.Repeat("b", 32), "example.test/original": "keep"}, "managedFields": []any{map[string]any{"manager": "original-fixture", "operation": "Update", "apiVersion": key.APIVersion, "fieldsType": "FieldsV1", "fieldsV1": map[string]any{"f:metadata": map[string]any{"f:annotations": map[string]any{"f:example.test/original": map[string]any{}}}}}}}, "spec": spec, "status": map[string]any{"conditions": []any{map[string]any{"type": "OriginalFixture", "status": "False", "reason": "Retain", "message": "keep-original-status"}}}}}
		before := original.DeepCopy()
		object, err := baselineMetadataUpdateProbe(plan.Namespace(), key, original)
		want := before.DeepCopy()
		annotations := want.GetAnnotations()
		annotations["arcade.gobha.me/identity-probe"] = "dry-run"
		want.SetAnnotations(annotations)
		if err != nil || object == nil || !reflect.DeepEqual(want.Object, object.Object) || !reflect.DeepEqual(before.Object, original.Object) {
			t.Fatal("metadata UPDATE lost original fields or changed source")
		}
		object.SetUID("changed-copy")
		if !reflect.DeepEqual(before.Object, original.Object) {
			t.Fatal("metadata UPDATE shares mutable original")
		}
		for _, mutate := range []func(*unstructured.Unstructured){
			func(o *unstructured.Unstructured) { o.SetUID("") },
			func(o *unstructured.Unstructured) { o.SetResourceVersion("00") },
			func(o *unstructured.Unstructured) { o.SetResourceVersion("+0017") },
			func(o *unstructured.Unstructured) { o.SetKind("Secret") },
			func(o *unstructured.Unstructured) { o.SetNamespace("foreign") },
			func(o *unstructured.Unstructured) { o.Object["unknownField"] = "PRIVATE-CANARY" },
		} {
			changed := before.DeepCopy()
			mutate(changed)
			if object, err := baselineMetadataUpdateProbe(plan.Namespace(), key, changed); err == nil || object != nil {
				t.Fatal("unbound original acquired metadata UPDATE request")
			}
		}
		if object, err := baselineMetadataUpdateProbe(plan.Namespace(), key, nil); err == nil || object != nil {
			t.Fatal("nil original acquired metadata UPDATE request")
		}
		if key.Kind == "Service" {
			unreserved := before.DeepCopy()
			unreserved.SetName("unreserved-service")
			key.Name = unreserved.GetName()
			if object, err := baselineMetadataUpdateProbe(plan.Namespace(), key, unreserved); err == nil || object != nil {
				t.Fatal("unreserved Service entered closed metadata UPDATE request")
			}
		}
	}
	for _, key := range testBaselineMetadataKeys(plan.Namespace()) {
		if key.Kind == "Service" {
			continue
		}
		object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": key.APIVersion, "kind": key.Kind, "metadata": map[string]any{"name": key.Name, "namespace": key.Namespace, "uid": "original", "resourceVersion": "17"}}}
		if probe, err := baselineMetadataUpdateProbe(plan.Namespace(), key, object); err == nil || probe != nil {
			t.Fatal("unsupported metadata UPDATE tuple entered request")
		}
	}
}

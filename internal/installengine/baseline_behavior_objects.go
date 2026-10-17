// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type baselineProducerNegative uint8

const (
	baselineProducerReservedAccount baselineProducerNegative = iota + 1
	baselineProducerReservedName
)

// Closed variants of the reviewed suspended/zero-replica probe. A reserved
// account is set in BOTH native aliases. A reserved top-level name keeps the
// unprivileged default account. No arbitrary caller mutation/spec is accepted.
func baselineNegativeProducerProbe(plan *installrender.Plan, kind, nonce string, variant baselineProducerNegative, reserved string) (*unstructured.Unstructured, error) {
	if !baselineReservedAccount(reserved) || variant != baselineProducerReservedAccount && variant != baselineProducerReservedName {
		return nil, ErrInvalid
	}
	object, err := baselineProducerProbe(plan, kind, nonce)
	if err != nil {
		return nil, ErrInvalid
	}
	if variant == baselineProducerReservedName {
		object.SetName(reserved)
	} else {
		for _, alias := range []string{"serviceAccountName", "serviceAccount"} {
			if unstructured.SetNestedField(object.Object, reserved, "spec", "template", "spec", alias) != nil {
				return nil, ErrInvalid
			}
		}
	}
	return object, nil
}

// A disposable complete original UPDATE with one fixed diagnostic annotation.
// The caller must supply an independently classified original witness and
// bracket its denial with exact whole GETs. This helper grants no authority and
// cannot manufacture a UID/RV or reinterpret an absent/foreign object.
func baselineMetadataUpdateProbe(namespace string, key installstate.Key, original *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	if key.Namespace != namespace || original == nil || !receiptUID.MatchString(string(original.GetUID())) || !baselineParentRV(original.GetResourceVersion()) ||
		original.GetAPIVersion() != key.APIVersion || original.GetKind() != key.Kind || original.GetNamespace() != key.Namespace || original.GetName() != key.Name {
		return nil, ErrInvalid
	}
	if _, _, err := baselineProbePath(key); err != nil {
		return nil, ErrInvalid
	}
	// Only tuples admitted by at least one baseline actor's UPDATE protocol.
	valid := false
	switch key.APIVersion + "/" + key.Kind {
	case "batch/v1/Job":
		var object batchv1.Job
		valid = decodeServing(original, &object) == nil
	case "apps/v1/Deployment":
		var object appsv1.Deployment
		valid = decodeServing(original, &object) == nil
	case "v1/Pod":
		var object corev1.Pod
		valid = decodeServing(original, &object) == nil
	case "v1/Service":
		var object corev1.Service
		valid = baselineReservedAccount(key.Name) && decodeServing(original, &object) == nil
	}
	if !valid {
		return nil, ErrInvalid
	}
	object := original.DeepCopy()
	annotations := object.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[baselineProducerLabel] = "dry-run"
	object.SetAnnotations(annotations)
	return object, nil
}

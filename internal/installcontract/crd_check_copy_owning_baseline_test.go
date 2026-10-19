// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	crdv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	strictjson "sigs.k8s.io/json"
)

// Correctness-repaired owning baseline for paired complete-operation timing.
// Derived from the frozen c632 oracle with ONLY method renames and owning-copy
// repairs at all three memo boundaries and the admission result copy. This is
// not the historical oracle and does not use the read-only borrowing selector.
// Both use the same ownership-repaired copy/seeding primitive; only production
// may borrow private read-only hits instead of making another owning copy.
func (t *Template) owningCRDDecodeObservedMode(object *unstructured.Unstructured, strictAdmission bool) (runtime.Object, error) {
	m := &t.decoded
	m.mu.Lock()
	if m.object != nil && m.raw != nil && (!strictAdmission || m.strictAdmission) && sameObservedJSON(object.Object, m.raw) {
		decoded := copyObservedOwning(m.object)
		m.mu.Unlock()
		return decoded, nil
	}
	m.mu.Unlock()
	// Keep the exact original byte path for misses and custom marshalers,
	// including its position outside the memo mutex. No clone cost on churn.
	body, err := json.Marshal(object.Object)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil || len(body) > maxObjectBytes {
		m.body, m.object, m.raw, m.strictAdmission = nil, nil, nil, false
		m.rawCaptureHits = 0
		return nil, ErrInvalid
	}
	if m.object != nil && bytes.Equal(m.body, body) && (!strictAdmission || m.strictAdmission) {
		// Two successive identical byte conversions make one bounded capture
		// attempt worthwhile. This is not a successful whole-match count or an
		// authority/observation receipt. Unsupported/large graphs stay on the
		// unchanged byte path until the memo is replaced or cleared.
		if m.raw == nil && m.rawCaptureHits < 3 {
			m.rawCaptureHits++
			if m.rawCaptureHits == 2 {
				m.rawCaptureHits = 3
				if raw, eligible := cloneObservedJSON(object.Object); eligible {
					// Bind the private clone to the EXACT bytes being reused,
					// never to a second unchecked view of a caller-owned graph.
					if captured, err := json.Marshal(raw); err == nil && bytes.Equal(captured, body) {
						m.raw = raw
					}
				}
			}
		}
		return copyObservedOwning(m.object), nil
	}
	m.body, m.object, m.raw, m.strictAdmission = nil, nil, nil, false
	m.rawCaptureHits = 0
	var decoded runtime.Object
	if strictAdmission {
		// Same case-sensitive, duplicate/unknown-field refusal used by the
		// admission callers before conversion reuse. Never seed from a signed
		// template: absent live fields must not inherit desired defaults.
		switch t.key.APIVersion + "/" + t.key.Kind {
		case "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy":
			decoded = &admissionv1.ValidatingAdmissionPolicy{}
		case "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicyBinding":
			decoded = &admissionv1.ValidatingAdmissionPolicyBinding{}
		default:
			return nil, ErrInvalid
		}
		strictErrors, decodeErr := strictjson.UnmarshalStrict(body, decoded)
		if decodeErr != nil || len(strictErrors) != 0 {
			return nil, ErrDrift
		}
	} else {
		decoded, err = decodeBody(t.key.APIVersion+"/"+t.key.Kind, body)
	}
	if err != nil {
		return nil, err
	}
	// Match normalizes its return; retain a different unnormalized private graph.
	m.body, m.object, m.strictAdmission = body, copyObservedOwning(decoded), strictAdmission
	return decoded, nil
}

func (t *Template) owningCRDMatchLive(object *unstructured.Unstructured, originalUID types.UID) error {
	if object == nil || originalUID == "" || object.GetUID() != originalUID || !identity(object.GetResourceVersion()) {
		if t != nil {
			t.decoded.clear()
		}
		return ErrIdentity
	}
	return t.owningCRDMatchWithAdmissionResult(object, nil, nil)
}

func (t *Template) owningCRDMatchWithAdmissionResult(object *unstructured.Unstructured, journal *installstate.Snapshot, admissionResult *runtime.Object) (resultErr error) {
	if t == nil || t.expected == nil || object == nil || object.GetAPIVersion() != t.key.APIVersion || object.GetKind() != t.key.Kind || object.GetName() != t.key.Name || object.GetNamespace() != t.key.Namespace {
		if t != nil {
			t.decoded.clear()
		}
		return ErrInvalid
	}
	// A refused whole shape must not retain even its pure successful conversion.
	// Clearing a concurrent newer conversion is harmless: this memo is never
	// evidence or authority, only bounded optional local work reuse.
	defer func() {
		if resultErr != nil {
			t.decoded.clear()
		}
	}()
	if object.GetDeletionTimestamp() != nil || len(object.GetOwnerReferences()) != 0 || len(object.GetFinalizers()) != 0 {
		return ErrDrift
	}
	actual, err := t.owningCRDDecodeObservedMode(object, admissionResult != nil)
	if err != nil {
		return err
	}
	var unnormalized runtime.Object
	if admissionResult != nil {
		unnormalized = copyObservedOwning(actual)
	}
	m, err := meta.Accessor(actual)
	if err != nil {
		return ErrInvalid
	}
	if m.GetUID() != "" && !identity(string(m.GetUID())) || m.GetResourceVersion() != "" && !identity(m.GetResourceVersion()) || m.GetGeneration() < 0 {
		return ErrIdentity
	}
	m.SetUID("")
	m.SetResourceVersion("")
	m.SetGeneration(0)
	m.SetCreationTimestamp(metav1.Time{})
	m.SetManagedFields(nil)
	m.SetOwnerReferences(nil)
	m.SetFinalizers(nil)
	if m.GetSelfLink() != "" || m.GetGenerateName() != "" || m.GetDeletionGracePeriodSeconds() != nil {
		return ErrDrift
	}
	a := m.GetAnnotations()
	if nonce, exists := a[installstate.MutationAnnotation]; exists {
		if !nonceID.MatchString(nonce) {
			return ErrDrift
		}
		delete(a, installstate.MutationAnnotation)
	}
	if t.key.Kind == "Deployment" {
		if revision, exists := a["deployment.kubernetes.io/revision"]; exists {
			v, err := strconv.ParseUint(revision, 10, 64)
			if err != nil || v == 0 || len(revision) > 20 || strconv.FormatUint(v, 10) != revision {
				return ErrDrift
			}
			delete(a, "deployment.kubernetes.io/revision")
		}
	}
	if t.key.Kind == "Namespace" {
		if journal == nil || a[installstate.BootstrapAnnotation] != journal.Anchor().InstallationID || !bytes.Equal([]byte(a[installstate.Annotation]), journal.Bytes()) {
			return ErrIdentity
		}
		delete(a, installstate.BootstrapAnnotation)
		delete(a, installstate.Annotation)
	}
	if len(a) == 0 {
		a = nil
	}
	m.SetAnnotations(a)
	switch o := actual.(type) {
	case *appsv1.Deployment:
		o.Status = appsv1.DeploymentStatus{}
		if o.Spec.Template.Spec.DeprecatedServiceAccount != "" && o.Spec.Template.Spec.DeprecatedServiceAccount != o.Spec.Template.Spec.ServiceAccountName {
			return ErrDrift
		}
		o.Spec.Template.Spec.DeprecatedServiceAccount = ""
	case *corev1.Service:
		if !validAllocation(o) {
			return ErrDrift
		}
		o.Spec.ClusterIP = ""
		o.Spec.ClusterIPs = nil
		o.Spec.IPFamilies = nil
		o.Status = corev1.ServiceStatus{}
	case *corev1.Namespace:
		labels := o.Labels
		if labels["kubernetes.io/metadata.name"] != t.key.Name {
			return ErrDrift
		}
		delete(labels, "kubernetes.io/metadata.name")
		o.Status = corev1.NamespaceStatus{}
	case *crdv1.CustomResourceDefinition:
		// Nested schema unions have custom JSON decoders. Compare their raw
		// signed shape too, so unknown schema fields cannot disappear there.
		if !t.matchCRDSpec(object) {
			return ErrDrift
		}
		o.Status = crdv1.CustomResourceDefinitionStatus{}
	case *admissionv1.ValidatingAdmissionPolicy:
		o.Status = admissionv1.ValidatingAdmissionPolicyStatus{}
	}
	// Strict decoding and the raw CRD comparison have already rejected unknown
	// fields. Kubernetes semantic equality additionally compares quantities by
	// numeric value, including different formats (64Mi == 67108864 bytes).
	// The privately compiled expected graph is immutable, and the pinned
	// semantic comparison reads both operands without mutating them. Only the
	// independently decoded actual graph above is normalized; do not allocate
	// another whole signed object merely to read it during this comparison.
	if !apiequality.Semantic.DeepEqual(t.expected, actual) {
		return ErrDrift
	}
	if admissionResult != nil {
		*admissionResult = unnormalized
	}
	return nil
}

func (t *Template) owningCRDCheck(live *unstructured.Unstructured, originalUID types.UID, target *Template) error {
	if t == nil || target == nil || t.contract == nil || target.contract == nil || t.key.Kind != "CustomResourceDefinition" || t.key != target.key || t.contract.plan.Namespace() != target.contract.plan.Namespace() || t.contract.plan.Profile().ID != target.contract.plan.Profile().ID || !t.sameSignedCRDSpec(target) || t.owningCRDMatchLive(live, originalUID) != nil {
		return ErrCRD
	}
	// Presence matters: zero is stale when explicitly provided for generation
	// one, but absent is valid on older profiles/disabled feature gates. Typed
	// omitempty fields alone cannot distinguish these two observations.
	observed, present, err := unstructured.NestedInt64(live.Object, "status", "observedGeneration")
	if err != nil || present && observed != live.GetGeneration() {
		return ErrCRD
	}
	conditions, _, err := unstructured.NestedSlice(live.Object, "status", "conditions")
	if err != nil {
		return ErrCRD
	}
	for _, value := range conditions {
		condition, ok := value.(map[string]any)
		if !ok {
			return ErrCRD
		}
		if value, present := condition["observedGeneration"]; present {
			generation, ok := value.(int64)
			if !ok || generation != live.GetGeneration() {
				return ErrCRD
			}
		}
	}
	// MatchLive above populated only a strict whole-byte conversion, never a
	// health verdict. All fresh raw generation and typed status checks remain.
	object, err := t.owningCRDDecodeObservedMode(live, false)
	if err != nil {
		return ErrCRD
	}
	o := object.(*crdv1.CustomResourceDefinition)
	if o.Generation < 1 || o.Status.ObservedGeneration != 0 && o.Status.ObservedGeneration != o.Generation || len(o.Spec.Versions) != 1 || o.Spec.Versions[0].Name != "v1alpha1" || !o.Spec.Versions[0].Served || !o.Spec.Versions[0].Storage || o.Spec.Conversion == nil || o.Spec.Conversion.Strategy != crdv1.NoneConverter || o.Spec.Conversion.Webhook != nil || o.Spec.PreserveUnknownFields || !reflect.DeepEqual(o.Status.StoredVersions, []string{"v1alpha1"}) || !reflect.DeepEqual(o.Status.AcceptedNames, o.Spec.Names) {
		return ErrCRD
	}
	seen := map[crdv1.CustomResourceDefinitionConditionType]bool{}
	established, accepted := false, false
	for _, c := range o.Status.Conditions {
		if seen[c.Type] || c.ObservedGeneration != 0 && c.ObservedGeneration != o.Generation {
			return ErrCRD
		}
		seen[c.Type] = true
		switch c.Type {
		case crdv1.Established:
			established = c.Status == crdv1.ConditionTrue
		case crdv1.NamesAccepted:
			accepted = c.Status == crdv1.ConditionTrue
		case crdv1.Terminating, crdv1.NonStructuralSchema, crdv1.StorageMigrating:
			if c.Status != crdv1.ConditionFalse {
				return ErrCRD
			}
		}
	}
	if !established || !accepted {
		return ErrCRD
	}
	return nil
}

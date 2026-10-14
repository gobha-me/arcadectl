// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"sync"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	strictjson "sigs.k8s.io/json"
)

// At most one bounded complete JSON value and one private typed conversion per
// sealed template. This is NOT a match result, original identity, permission,
// health observation, journal witness or durable authority. Misses/refusals
// clear it. Readers never receive the memo's mutable typed graph.
type observedDecodeMemo struct {
	mu     sync.Mutex
	body   []byte
	object runtime.Object
	// A standard decoder hit is never evidence of the stricter admission decode.
	strictAdmission bool
}

func (m *observedDecodeMemo) clear() {
	m.mu.Lock()
	m.body, m.object, m.strictAdmission = nil, nil, false
	m.mu.Unlock()
}

func (t *Template) decodeObserved(object *unstructured.Unstructured) (runtime.Object, error) {
	return t.decodeObservedMode(object, false)
}

func (t *Template) decodeObservedMode(object *unstructured.Unstructured, strictAdmission bool) (runtime.Object, error) {
	// Serialize the ENTIRE fresh input before lookup. A hash, UID/RV, selected
	// spec or normalized shape is insufficient; status and unknown fields must
	// also cause a miss. The same bytes, not a second read of the caller's graph,
	// are strictly converted on that miss.
	body, err := json.Marshal(object.Object)
	m := &t.decoded
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil || len(body) > maxObjectBytes {
		m.body, m.object, m.strictAdmission = nil, nil, false
		return nil, ErrInvalid
	}
	if m.object != nil && bytes.Equal(m.body, body) && (!strictAdmission || m.strictAdmission) {
		return m.object.DeepCopyObject(), nil
	}
	m.body, m.object, m.strictAdmission = nil, nil, false
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
	m.body, m.object, m.strictAdmission = body, decoded.DeepCopyObject(), strictAdmission
	return decoded, nil
}

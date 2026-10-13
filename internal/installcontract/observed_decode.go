// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"bytes"
	"encoding/json"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// At most one bounded complete JSON value and one private typed conversion per
// sealed template. This is NOT a match result, original identity, permission,
// health observation, journal witness or durable authority. Misses/refusals
// clear it. Readers never receive the memo's mutable typed graph.
type observedDecodeMemo struct {
	mu     sync.Mutex
	body   []byte
	object runtime.Object
}

func (m *observedDecodeMemo) clear() {
	m.mu.Lock()
	m.body, m.object = nil, nil
	m.mu.Unlock()
}

func (t *Template) decodeObserved(object *unstructured.Unstructured) (runtime.Object, error) {
	// Serialize the ENTIRE fresh input before lookup. A hash, UID/RV, selected
	// spec or normalized shape is insufficient; status and unknown fields must
	// also cause a miss. The same bytes, not a second read of the caller's graph,
	// are strictly converted on that miss.
	body, err := json.Marshal(object.Object)
	m := &t.decoded
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil || len(body) > maxObjectBytes {
		m.body, m.object = nil, nil
		return nil, ErrInvalid
	}
	if m.object != nil && bytes.Equal(m.body, body) {
		return m.object.DeepCopyObject(), nil
	}
	m.body, m.object = nil, nil
	decoded, err := decodeBody(t.key.APIVersion+"/"+t.key.Kind, body)
	if err != nil {
		return nil, err
	}
	// Match normalizes its return; retain a different unnormalized private graph.
	m.body, m.object = body, decoded.DeepCopyObject()
	return decoded, nil
}

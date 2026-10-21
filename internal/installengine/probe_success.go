// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	strictjson "sigs.k8s.io/json"
)

// Called only below wrappers after the original single-attempt route/body
// guard. Pure native reply capture is NOT a whole shape/phase validator or an
// effect, original-UID acknowledgement, cleanup or completion capability.
// Keep the existing reviewed object variant: DELETE Status is not implicitly
// accepted. A native-certified closed Status branch would be separate work.
func (p *probeCapture) captureSuccess(response *http.Response) {
	if p == nil || p.expected != nil || response == nil || response.Body == nil || p.accepted.Load() {
		return
	}
	expectedCode := http.StatusOK
	switch p.operation {
	case probeCreateOperation:
		expectedCode = http.StatusCreated
	case probeUpdateOperation, probeEphemeralOperation, probeResizeOperation, probeDeletePVCOperation:
	default:
		return
	}
	if response.StatusCode != expectedCode {
		return
	}
	typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || !utf8.Valid(raw) || !boundedJSON(raw) {
		return
	}
	var fields map[string]any
	strictErrors, err := strictjson.UnmarshalStrict(raw, &fields)
	if err != nil || len(strictErrors) != 0 || fields == nil {
		return
	}
	result := &unstructured.Unstructured{Object: fields}
	if result.GetAPIVersion() != p.key.APIVersion || result.GetKind() != p.key.Kind || result.GetNamespace() != p.key.Namespace || result.GetName() != p.key.Name {
		return
	}
	if p.operation != probeCreateOperation && (result.GetUID() != p.originalUID || result.GetResourceVersion() != p.originalResourceVersion) {
		return
	}
	p.reply = result
	p.accepted.Store(true) // publish only a complete bounded native object
}

func (p *probeCapture) positiveResult() *unstructured.Unstructured {
	if p == nil || !p.accepted.Load() || p.reply == nil {
		return nil
	}
	return p.reply.DeepCopy()
}

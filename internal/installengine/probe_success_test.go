// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

// Fake HTTPS transport tests are native-provenance controls only, not native
// admission, whole fixture shape, lifecycle or behavior certification.
func TestProbePositiveCaptureBelowWrappersAndWholeReplyPreserved(t *testing.T) {
	for _, test := range []struct {
		name, kind string
		operation  admissionProbeOperation
	}{
		{"pod-create", "Pod", probeCreateOperation},
		{"claim-create", "PersistentVolumeClaim", probeCreateOperation},
		{"destroy-create", "GameDestroy", probeCreateOperation},
		{"pod-update", "Pod", probeUpdateOperation},
		{"claim-update", "PersistentVolumeClaim", probeUpdateOperation},
		{"destroy-update", "GameDestroy", probeUpdateOperation},
		{"ephemeral", "Pod", probeEphemeralOperation},
		{"resize", "Pod", probeResizeOperation},
		{"claim-delete", "PersistentVolumeClaim", probeDeletePVCOperation},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := namedProbeFixture(test.kind)
			if test.operation == probeCreateOperation {
				original.SetUID("")
				original.SetResourceVersion("")
			}
			native := original.DeepCopy()
			native.SetAnnotations(map[string]string{"native-evidence": "PRIVATE-NATIVE-CANARY"})
			if test.operation == probeCreateOperation {
				native.SetUID("native-original")
				native.SetResourceVersion("19")
			}
			var requests atomic.Int32
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", `application/json; private="PRIVATE-NATIVE-CANARY"`)
				w.Header().Set("Warning", "PRIVATE-NATIVE-CANARY")
				w.Header().Set("Trailer", "X-Private")
				code := http.StatusOK
				if test.operation == probeCreateOperation {
					code = http.StatusCreated
				}
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(native.Object)
				w.Header().Set("X-Private", "PRIVATE-NATIVE-CANARY")
			})
			next := a.client.Transport
			a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := next.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readErr != nil || string(body) != "{}" || response.ContentLength != 2 || response.Header.Get("Content-Type") != "application/json" || len(response.Header) != 1 || len(response.Trailer) != 0 || strings.Contains(response.Status, "PRIVATE") {
					t.Error("native success body or metadata escaped inner guard")
				}
				// A wrapper cannot replace captured native identity or whole body.
				response.Body = io.NopCloser(strings.NewReader(`{"kind":"Secret","data":{"PRIVATE-WRAPPER-CANARY":"foreign"}}`))
				return response, nil
			})
			result, err := a.probeOperation(t.Context(), test.operation, original, "", "", "")
			if err != nil || result == nil || !reflect.DeepEqual(result.Object, native.Object) || requests.Load() != 1 {
				t.Fatal("wrapper selected positive evidence or native whole reply was lost")
			}
		})
	}
}

func TestProbeWrapperCannotFabricateNativeSuccess(t *testing.T) {
	for _, mode := range []string{"no-wire", "native-error", "native-invalid", "native-wrong-uid", "native-status", "replay"} {
		t.Run(mode, func(t *testing.T) {
			original := namedProbeFixture("PersistentVolumeClaim")
			var requests atomic.Int32
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "native-error":
					w.WriteHeader(500)
					_, _ = io.WriteString(w, `{"message":"PRIVATE-ERROR-CANARY"}`)
				case "native-invalid":
					_, _ = io.WriteString(w, `{}{} PRIVATE-CANARY`)
				case "native-wrong-uid":
					foreign := original.DeepCopy()
					foreign.SetUID("foreign")
					_ = json.NewEncoder(w).Encode(foreign.Object)
				case "native-status":
					_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"Status","status":"Success","code":200}`)
				default:
					_ = json.NewEncoder(w).Encode(original.Object)
				}
			})
			next := a.client.Transport
			a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if mode != "no-wire" {
					response, err := next.RoundTrip(r)
					if response != nil && response.Body != nil {
						_ = response.Body.Close()
					}
					if err != nil {
						return nil, err
					}
					if mode == "replay" {
						return next.RoundTrip(r.Clone(r.Context()))
					}
				}
				body, _ := json.Marshal(original.Object)
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
			})
			result, err := a.probeOperation(t.Context(), probeDeletePVCOperation, original, "", "", "")
			wantRequests := int32(1)
			if mode == "no-wire" {
				wantRequests = 0
			}
			if err != ErrAdmission || result != nil || requests.Load() != wantRequests {
				t.Fatal("wrapper-fabricated success became native evidence or replay reached wire")
			}
		})
	}
}

func TestProbePositiveCaptureReturnsIndependentCopies(t *testing.T) {
	original := namedProbeFixture("Pod")
	body, _ := json.Marshal(original.Object)
	p := &probeCapture{operation: probeUpdateOperation, key: installstate.Key{APIVersion: original.GetAPIVersion(), Kind: original.GetKind(), Namespace: original.GetNamespace(), Name: original.GetName()}, originalUID: original.GetUID(), originalResourceVersion: original.GetResourceVersion()}
	p.captureSuccess(&http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))})
	first := p.positiveResult()
	if first == nil || !reflect.DeepEqual(first.Object, original.Object) {
		t.Fatal("strict native capture unavailable")
	}
	first.SetUID("foreign")
	first.SetAnnotations(map[string]string{"foreign": "PRIVATE-CANARY"})
	if second := p.positiveResult(); second == nil || !reflect.DeepEqual(second.Object, original.Object) {
		t.Fatal("returned map aliases native retained reply")
	}
	var missing *probeCapture
	if missing.positiveResult() != nil || (&probeCapture{}).positiveResult() != nil {
		t.Fatal("missing native evidence became a positive")
	}
}

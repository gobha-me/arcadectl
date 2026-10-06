// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func probeFixtureObject() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "arcadectl-probe", "namespace": "isolated-install"}}}
}

func namedProbeFixture(kind string) *unstructured.Unstructured {
	o := probeFixtureObject()
	o.SetKind(kind)
	if kind == "GameDestroy" {
		o.SetAPIVersion("arcade.gobha.me/v1alpha1")
	}
	o.SetUID("original-uid")
	o.SetResourceVersion("17")
	return o
}

func TestProbeNamedOperationRoutesBodiesAndNativeDenial(t *testing.T) {
	for _, test := range []struct {
		name, kind, method, suffix string
		op                         admissionProbeOperation
	}{
		{"pod-update", "Pod", "PUT", "pods/arcadectl-probe", probeUpdateOperation},
		{"claim-update", "PersistentVolumeClaim", "PUT", "persistentvolumeclaims/arcadectl-probe", probeUpdateOperation},
		{"destroy-update", "GameDestroy", "PUT", "gamedestroys/arcadectl-probe", probeUpdateOperation},
		{"ephemeral", "Pod", "PUT", "pods/arcadectl-probe/ephemeralcontainers", probeEphemeralOperation},
		{"resize", "Pod", "PUT", "pods/arcadectl-probe/resize", probeResizeOperation},
		{"claim-delete", "PersistentVolumeClaim", "DELETE", "persistentvolumeclaims/arcadectl-probe", probeDeletePVCOperation},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, negative := range []bool{false, true} {
				o := namedProbeFixture(test.kind)
				var requests atomic.Int32
				a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					prefix := "/api/v1"
					if test.kind == "GameDestroy" {
						prefix = "/apis/arcade.gobha.me/v1alpha1"
					}
					if r.Method != test.method || r.URL.Path != prefix+"/namespaces/isolated-install/"+test.suffix || r.ProtoMajor != 1 {
						t.Error("not exact named operation")
					}
					body, _ := io.ReadAll(r.Body)
					if test.op == probeDeletePVCOperation {
						var opts metav1.DeleteOptions
						if json.Unmarshal(body, &opts) != nil || len(opts.DryRun) != 1 || opts.DryRun[0] != "All" || opts.Preconditions == nil || opts.Preconditions.UID == nil || *opts.Preconditions.UID != o.GetUID() || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion != "17" || r.URL.RawQuery != "dryRun=All" || opts.PropagationPolicy != nil || opts.GracePeriodSeconds != nil || opts.OrphanDependents != nil {
							t.Error("DELETE is not body-dry-run with both exact preconditions")
						}
					} else {
						var sent unstructured.Unstructured
						if json.Unmarshal(body, &sent.Object) != nil || sent.GetUID() != o.GetUID() || sent.GetResourceVersion() != "17" || r.URL.RawQuery != "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict" {
							t.Error("UPDATE lost old-object identity or dry-run")
						}
					}
					w.Header().Set("Content-Type", "application/json")
					if negative {
						key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
						_, plural, _ := probePath(key)
						status, _ := expectedProbeDenial(key, plural, "reviewed-policy", "reviewed-binding", "signed validation")
						w.WriteHeader(422)
						_ = json.NewEncoder(w).Encode(status)
					} else {
						w.WriteHeader(200)
						_ = json.NewEncoder(w).Encode(o.Object)
					}
				})
				policy, binding, message := "", "", ""
				if negative {
					policy, binding, message = "reviewed-policy", "reviewed-binding", "signed validation"
				}
				result, err := a.probeOperation(context.Background(), test.op, o, policy, binding, message)
				if err != nil || (result == nil) != negative || requests.Load() != 1 {
					t.Fatal("native operation result refused or unexpected replay", err)
				}
			}
		})
	}
}

func TestProbeNamedOperationRejectsForeignIdentityAndSuccessShape(t *testing.T) {
	for _, op := range []admissionProbeOperation{probeUpdateOperation, probeEphemeralOperation, probeResizeOperation, probeDeletePVCOperation} {
		kind := "Pod"
		if op == probeDeletePVCOperation {
			kind = "PersistentVolumeClaim"
		}
		for _, change := range []func(*unstructured.Unstructured){
			func(o *unstructured.Unstructured) { o.SetUID("foreign") },
			func(o *unstructured.Unstructured) { o.SetResourceVersion("18") },
			func(o *unstructured.Unstructured) { o.SetName("foreign") },
			func(o *unstructured.Unstructured) { o.SetKind("Status") },
		} {
			o := namedProbeFixture(kind)
			result := o.DeepCopy()
			change(result)
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(result.Object)
			})
			if _, err := a.probeOperation(context.Background(), op, o, "", "", ""); err != ErrAdmission {
				t.Fatal("foreign named-operation result accepted")
			}
		}
	}
	var requests atomic.Int32
	a := proofServer(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
	for _, op := range []admissionProbeOperation{probeUpdateOperation, probeEphemeralOperation, probeResizeOperation, probeDeletePVCOperation} {
		for _, field := range []string{"uid", "resourceVersion"} {
			kind := "Pod"
			if op == probeDeletePVCOperation {
				kind = "PersistentVolumeClaim"
			}
			o := namedProbeFixture(kind)
			unstructured.RemoveNestedField(o.Object, "metadata", field)
			if _, err := a.probeOperation(context.Background(), op, o, "", "", ""); err != ErrInvalid {
				t.Fatal("missing original identity allowed")
			}
		}
	}
	for _, op := range []admissionProbeOperation{probeEphemeralOperation, probeResizeOperation, probeDeletePVCOperation, 255} {
		o := namedProbeFixture("GameDestroy")
		if _, err := a.probeOperation(context.Background(), op, o, "", "", ""); err != ErrInvalid {
			t.Fatal("arbitrary operation allowed")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("invalid operation reached wire")
	}
}

func TestProbeGuardRejectsWrapperMutationBeforeWire(t *testing.T) {
	for _, op := range []admissionProbeOperation{probeCreateOperation, probeUpdateOperation, probeEphemeralOperation, probeResizeOperation, probeDeletePVCOperation} {
		for _, mutate := range []func(*http.Request){
			func(r *http.Request) { r.URL.RawQuery = "" },
			func(r *http.Request) { r.Method = http.MethodGet },
			func(r *http.Request) { r.URL.Path += "/status" },
			func(r *http.Request) { r.Host = "foreign.example" },
			func(r *http.Request) { *r = *r.WithContext(context.Background()); r.Method = http.MethodGet },
			func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{}`)); r.ContentLength = 2 },
			func(r *http.Request) {
				r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(`{}`)), nil }
			},
		} {
			var requests atomic.Int32
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) { requests.Add(1) })
			next := a.client.Transport
			a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { mutate(r); return next.RoundTrip(r) })
			o := namedProbeFixture("Pod")
			if op == probeDeletePVCOperation {
				o.SetKind("PersistentVolumeClaim")
			}
			if op == probeCreateOperation {
				o.SetUID("")
				o.SetResourceVersion("")
			}
			if _, err := a.probeOperation(context.Background(), op, o, "", "", ""); err != ErrAdmission || requests.Load() != 0 {
				t.Fatal("wrapper mutation reached network")
			}
		}
	}
}

func TestProbeNamedOperationUnexpectedStatusNeverEvidence(t *testing.T) {
	for _, op := range []admissionProbeOperation{probeUpdateOperation, probeEphemeralOperation, probeResizeOperation, probeDeletePVCOperation} {
		kind := "Pod"
		if op == probeDeletePVCOperation {
			kind = "PersistentVolumeClaim"
		}
		for _, code := range []int{201, 202, 307, 403, 404, 409, 422, 429, 503} {
			var requests atomic.Int32
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Location", "/foreign")
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(namedProbeFixture(kind).Object)
			})
			if _, err := a.probeOperation(context.Background(), op, namedProbeFixture(kind), "", "", ""); err != ErrAdmission || requests.Load() != 1 {
				t.Fatal("wrong status/redirect/replay accepted")
			}
		}
	}
}

func TestProbeRefusesUnpinnedResourceVersionsBeforeWire(t *testing.T) {
	for _, op := range []admissionProbeOperation{probeUpdateOperation, probeEphemeralOperation, probeResizeOperation, probeDeletePVCOperation} {
		kind := "Pod"
		if op == probeDeletePVCOperation {
			kind = "PersistentVolumeClaim"
		}
		for _, rv := range []string{"0", "00", "000", "01", "-1", "+1", "1e0", "opaque", "18446744073709551616"} {
			var requests atomic.Int32
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				o := namedProbeFixture(kind)
				key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
				_, plural, _ := probePath(key)
				body, _ := expectedProbeDenial(key, plural, "reviewed-policy", "reviewed-binding", "signed validation")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(422)
				_ = json.NewEncoder(w).Encode(body)
			})
			o := namedProbeFixture(kind)
			o.SetResourceVersion(rv)
			_, err := a.probeOperation(context.Background(), op, o, "reviewed-policy", "reviewed-binding", "signed validation")
			if err != ErrInvalid || requests.Load() != 0 {
				t.Errorf("operation %d RV %q was unpinned evidence: %v, %d requests", op, rv, err, requests.Load())
			}
		}
	}
}

func TestProbeNegativeRequiresExactNativePolicyDenial(t *testing.T) {
	const policy, binding, validation = "arcadectl-backup-worker-gate", "arcadectl-backup-worker-gate", "signed validation"
	key := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: "isolated-install", Name: "arcadectl-probe"}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
		valid  bool
	}{
		{"exact", func(map[string]any) {}, true},
		{"wrong-policy", func(m map[string]any) {
			m["message"] = strings.ReplaceAll(m["message"].(string), policy, "foreign-policy")
		}, false},
		{"wrong-name", func(m map[string]any) { m["details"].(map[string]any)["name"] = "foreign" }, false},
		{"wrong-kind", func(m map[string]any) { m["details"].(map[string]any)["kind"] = "Pod" }, false},
		{"wrong-group", func(m map[string]any) { m["details"].(map[string]any)["group"] = "foreign" }, false},
		{"multiple-causes", func(m map[string]any) {
			d := m["details"].(map[string]any)
			d["causes"] = append(d["causes"].([]any), map[string]any{"message": "PRIVATE-CANARY"})
		}, false},
		{"wrong-cause", func(m map[string]any) {
			m["details"].(map[string]any)["causes"].([]any)[0].(map[string]any)["message"] = "PRIVATE-CANARY"
		}, false},
		{"null-metadata", func(m map[string]any) { m["metadata"] = nil }, false},
		{"unknown", func(m map[string]any) { m["unreviewed"] = "PRIVATE-CANARY" }, false},
		{"wrong-code", func(m map[string]any) { m["code"] = float64(403) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, err := expectedProbeDenial(key, "pods", policy, binding, validation)
			if err != nil {
				t.Fatal(err)
			}
			test.change(body)
			var requests atomic.Int32
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "POST" || r.ProtoMajor != 1 || r.URL.Path != "/api/v1/namespaces/isolated-install/pods" || r.URL.RawQuery != "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict" {
					t.Error("not the closed nonpersistent probe route")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(422)
				_ = json.NewEncoder(w).Encode(body)
			})
			result, err := a.probeCreate(context.Background(), probeFixtureObject(), policy, binding, validation)
			if (err == nil) != test.valid || result != nil || requests.Load() != 1 || err != nil && strings.Contains(err.Error(), "CANARY") {
				t.Fatal("foreign denial accepted or raw error/retry escaped")
			}
		})
	}
}

func TestProbeRefusesUnexpectedAcceptanceMalformedWireAndReplay(t *testing.T) {
	for _, test := range []struct {
		code int
		body string
	}{
		{201, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"arcadectl-probe","namespace":"isolated-install"}}`},
		{403, "PRIVATE-CANARY"}, {429, "PRIVATE-CANARY"}, {503, "PRIVATE-CANARY"}, {307, "PRIVATE-CANARY"},
		{422, `{"kind":"Status","kind":"Status"}`}, {422, "{}{}"},
		{422, strings.Repeat(" ", 65537)}, {422, strings.Repeat("[", 65) + strings.Repeat("]", 65)},
	} {
		var requests atomic.Int32
		a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "0")
			w.Header().Set("Location", "/unreviewed")
			w.WriteHeader(test.code)
			_, _ = io.WriteString(w, test.body)
		})
		if _, err := a.probeCreate(context.Background(), probeFixtureObject(), "reviewed-policy", "reviewed-binding", "signed validation"); err != ErrAdmission || requests.Load() != 1 {
			t.Fatal("unexpected acceptance, malformed denial, redirect or replay was evidence")
		}
	}
}

func TestProbeClassificationBelowWrappersAndRawErrorRedacted(t *testing.T) {
	key := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: "isolated-install", Name: "arcadectl-probe"}
	for _, replay := range []bool{false, true} {
		var requests atomic.Int32
		a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			body, _ := expectedProbeDenial(key, "pods", "reviewed-policy", "reviewed-binding", "PRIVATE-CANARY")
			w.Header().Set("Content-Type", `application/json; private="PRIVATE-CANARY"`)
			w.Header().Set("Warning", "PRIVATE-CANARY")
			w.Header().Set("Trailer", "X-Private")
			w.WriteHeader(422)
			_ = json.NewEncoder(w).Encode(body)
			w.Header().Set("X-Private", "PRIVATE-CANARY")
		})
		// This wrapper is outside the constructor's inner guard. It sees no
		// native body, even though the guard can privately classify it.
		next := a.client.Transport
		a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			response, err := next.RoundTrip(r)
			if err != nil {
				return nil, err
			}
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if string(body) != "{}" || response.Header.Get("Content-Type") != "application/json" || len(response.Header) != 1 || len(response.Trailer) != 0 || response.Status != "422 Unprocessable Entity" {
				t.Error("raw admission details escaped inner guard")
			}
			response.Body = io.NopCloser(strings.NewReader(string(body)))
			if replay {
				return next.RoundTrip(r.Clone(r.Context()))
			}
			return response, nil
		})
		_, err := a.probeCreate(context.Background(), probeFixtureObject(), "reviewed-policy", "reviewed-binding", "PRIVATE-CANARY")
		if (err == nil) == replay || requests.Load() != 1 {
			t.Fatal("classification lost or wrapper replay escaped")
		}
	}
}

func TestProbePositiveIsBoundedStrictAndOnlyReviewedKinds(t *testing.T) {
	for index, body := range []string{
		`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"arcadectl-probe","namespace":"isolated-install"}}`,
		`{"apiVersion":"v1","apiVersion":"v1","kind":"Pod","metadata":{"name":"arcadectl-probe","namespace":"isolated-install"}}`,
		`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"foreign","namespace":"isolated-install"}}`,
		"{}{}", strings.Repeat(" ", 1024*1024+1),
	} {
		a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			_, _ = io.WriteString(w, body)
		})
		result, err := a.probeCreate(context.Background(), probeFixtureObject(), "", "", "")
		if (err == nil) != (index == 0) || err == nil && result == nil {
			t.Fatal("positive wire validation failed")
		}
		for _, kind := range []string{"Secret", "ServiceAccount", "GameServer"} {
			object := probeFixtureObject()
			object.SetKind(kind)
			if _, err := a.probeCreate(context.Background(), object, "", "", ""); err != ErrInvalid {
				t.Fatal("arbitrary probe kind allowed")
			}
		}
	}
}

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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func probeFixtureObject() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "arcadectl-probe", "namespace": "isolated-install"}}}
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
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Warning", "PRIVATE-CANARY")
			w.WriteHeader(422)
			_ = json.NewEncoder(w).Encode(body)
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
			if string(body) != "{}" || response.Header.Get("Warning") != "" {
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

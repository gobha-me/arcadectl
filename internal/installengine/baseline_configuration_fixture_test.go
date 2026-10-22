// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Independent literal wire oracle shared by synthetic whole-driver fixtures.
// No production route/selector or signed membership derivation is used here.
func testBaselineConfigurationList[K comparable](t *testing.T, w http.ResponseWriter, r *http.Request, objects map[K]*unstructured.Unstructured) bool {
	if testRuntimeConfigurationRequest(r) {
		return testRuntimeConfigurationList(t, w, r, objects)
	}
	return testConfigurationList(t, w, r, objects, false)
}

func testRuntimeConfigurationRequest(r *http.Request) bool {
	return r.URL.Query().Get("labelSelector") == "app.kubernetes.io/part-of=arcadectl,app.kubernetes.io/name in (arcadectl-controller,arcadectl-destroy-controller)"
}

func testRuntimeConfigurationList[K comparable](t *testing.T, w http.ResponseWriter, r *http.Request, objects map[K]*unstructured.Unstructured) bool {
	if !testRuntimeConfigurationRequest(r) {
		return false
	}
	return testConfigurationList(t, w, r, objects, true)
}

func testConfigurationList[K comparable](t *testing.T, w http.ResponseWriter, r *http.Request, objects map[K]*unstructured.Unstructured, runtime bool) bool {
	t.Helper()
	kind := ""
	switch r.URL.Path {
	case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies":
		kind = "ValidatingAdmissionPolicy"
	case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings":
		kind = "ValidatingAdmissionPolicyBinding"
	default:
		return false
	}
	q := r.URL.Query()
	selector := "app.kubernetes.io/part-of=arcadectl,arcade.gobha.me/security-baseline=privileged-identity-v1"
	if runtime {
		selector = "app.kubernetes.io/part-of=arcadectl,app.kubernetes.io/name in (arcadectl-controller,arcadectl-destroy-controller)"
	}
	if r.Method != http.MethodGet || r.Header.Get("Impersonate-User") != "" || len(q) != 2 || len(q["limit"]) != 1 || q.Get("limit") != "128" || len(q["labelSelector"]) != 1 || q.Get("labelSelector") != selector {
		t.Error("configuration LIST escaped closed most-recent installer query")
		w.WriteHeader(500)
		return true
	}
	selected := []*unstructured.Unstructured{}
	for _, object := range objects {
		if object == nil {
			continue
		}
		labels := object.GetLabels()
		selectedPurpose := labels["arcade.gobha.me/security-baseline"] == "privileged-identity-v1"
		if runtime {
			selectedPurpose = labels["app.kubernetes.io/name"] == "arcadectl-controller" || labels["app.kubernetes.io/name"] == "arcadectl-destroy-controller"
		}
		if object.GetAPIVersion() == "admissionregistration.k8s.io/v1" && object.GetKind() == kind && labels["app.kubernetes.io/part-of"] == "arcadectl" && selectedPurpose {
			selected = append(selected, object)
		}
	}
	slices.SortFunc(selected, func(a, b *unstructured.Unstructured) int {
		if a.GetName() < b.GetName() {
			return -1
		}
		if a.GetName() > b.GetName() {
			return 1
		}
		return 0
	})
	items := []any{}
	for _, object := range selected {
		// Native typed LIST replies omit each item's TypeMeta. The closed
		// production reader must derive it only from the verified envelope.
		copy := object.DeepCopy()
		delete(copy.Object, "apiVersion")
		delete(copy.Object, "kind")
		items = append(items, copy.Object)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": kind + "List", "metadata": map[string]any{"resourceVersion": "configuration-" + kind}, "items": items})
	return true
}

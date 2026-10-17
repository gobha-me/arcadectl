// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	authv1 "k8s.io/api/authorization/v1"
)

func TestBaselineWildcardReviewCatalogExactAndPurposeBound(t *testing.T) {
	const namespace = "isolated-install"
	literal := testBaselineContainmentAttributes(namespace)
	production := baselineAuthorizationContainmentPermissions(namespace)
	if len(production) != len(literal) {
		t.Fatal("wildcard catalog omitted or added an authorization domain")
	}
	for index, permission := range production {
		if permission.NonResourceAttributes != nil || permission.ResourceAttributes == nil || !reflect.DeepEqual(*permission.ResourceAttributes, literal[index]) {
			t.Fatal("wildcard catalog differs from the independent literal oracle")
		}
	}
	for _, actorID := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		var requests atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Method != "POST" || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || r.Header.Get("Impersonate-User") != "system:serviceaccount:"+namespace+":"+actorID.account() || r.Header.Get("Authorization") != "Bearer FAKE-ADMIN-CANARY" {
				t.Error("wildcard review changed original credentials, actor or route")
			}
			var review authv1.SelfSubjectAccessReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.ResourceAttributes == nil {
				t.Error("wildcard review malformed")
				w.WriteHeader(500)
				return
			}
			valid := false
			for _, row := range literal {
				if reflect.DeepEqual(row, *review.Spec.ResourceAttributes) {
					valid = true
					break
				}
			}
			if !valid || review.Spec.NonResourceAttributes != nil {
				t.Error("wire review escaped literal wildcard catalog")
			}
			review.Status.Allowed = false
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(review)
		}))
		t.Cleanup(server.Close)
		config := serverConfig(server)
		config.BearerToken = "FAKE-ADMIN-CANARY"
		admin, err := NewDirectHTTPAccess(config)
		if err != nil {
			t.Fatal("wildcard review administrator fixture unavailable")
		}
		actor, err := admin.actorClientForPurpose(actorID, namespace, baselineAdmissionPurpose)
		if err != nil {
			t.Fatal("wildcard review actor unavailable")
		}
		for _, row := range literal {
			spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: row.DeepCopy()}
			before := requests.Load()
			if actor.authorizationDecision(t.Context(), spec, false) != nil || requests.Load() != before+1 {
				t.Fatal("exact wildcard denial refused or replayed")
			}
			for _, change := range []func(*authv1.ResourceAttributes){
				func(a *authv1.ResourceAttributes) { a.Version = "" },
				func(a *authv1.ResourceAttributes) { a.Version = "v1" },
				func(a *authv1.ResourceAttributes) { a.Version = "v2" },
				func(a *authv1.ResourceAttributes) { a.Group = "authentication.k8s.io" },
				func(a *authv1.ResourceAttributes) { a.Namespace = "foreign" },
				func(a *authv1.ResourceAttributes) { a.Name = "unreviewed-producer" },
				func(a *authv1.ResourceAttributes) { a.Subresource = "status" },
				func(a *authv1.ResourceAttributes) { a.Resource = "groups" },
				func(a *authv1.ResourceAttributes) { a.Resource = "uids" },
				func(a *authv1.ResourceAttributes) { a.Resource = "userextras" },
				func(a *authv1.ResourceAttributes) {
					a.FieldSelector = &authv1.FieldSelectorAttributes{RawSelector: "metadata.name=x"}
				},
				func(a *authv1.ResourceAttributes) {
					a.LabelSelector = &authv1.LabelSelectorAttributes{RawSelector: "foreign=scope"}
				},
			} {
				changed := spec.DeepCopy()
				change(changed.ResourceAttributes)
				before := requests.Load()
				if actor.authorizationDecision(t.Context(), *changed, false) == nil || requests.Load() != before {
					t.Fatal("unclosed wildcard descriptor reached the wire")
				}
			}
			for _, purpose := range []actorWirePurpose{runtimeAdmissionPurpose, 255} {
				other, err := admin.actorClientForPurpose(actorID, namespace, purpose)
				before := requests.Load()
				if err == nil && (other.authorizationDecision(t.Context(), spec, false) == nil || requests.Load() != before) {
					t.Fatal("wildcard review widened historical or unknown purpose")
				}
			}
		}
	}
}

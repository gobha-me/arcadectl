// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func testBaselineListFixture(t *testing.T, kind string, serve func(http.ResponseWriter, *http.Request, map[string]any, int)) (*HTTPAccess, map[installstate.Key]bool, *atomic.Int32) {
	t.Helper()
	f := newBaselineFixture(t)
	completeBaselineFixture(t, f)
	expected := map[installstate.Key]bool{}
	items := []any{}
	for _, resource := range f.snapshot.Document().SecurityBaseline.Resources {
		if resource.Key.Kind != kind {
			continue
		}
		expected[resource.Key] = true
		object := f.access.objects[resource.Key].DeepCopy()
		if kind == "ValidatingAdmissionPolicy" {
			object.SetGeneration(1)
			object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
		}
		items = append(items, object.Object)
	}
	page := map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": kind + "List", "metadata": map[string]any{"resourceVersion": "snapshot"}, "items": items}
	requests := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		plural := "validatingadmissionpolicies"
		if kind == "ValidatingAdmissionPolicyBinding" {
			plural = "validatingadmissionpolicybindings"
		}
		valid := r.Method == http.MethodGet && r.URL.Path == "/apis/admissionregistration.k8s.io/v1/"+plural && r.Header.Get("Impersonate-User") == "" && q.Get("limit") == "128" && q.Get("labelSelector") == "app.kubernetes.io/part-of=arcadectl,arcade.gobha.me/security-baseline=privileged-identity-v1"
		for key, values := range q {
			if len(values) != 1 || key != "limit" && key != "labelSelector" && key != "continue" {
				valid = false
			}
		}
		if !valid {
			t.Error("LIST used arbitrary, cached, actor or unbounded query")
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		serve(w, r, (&unstructured.Unstructured{Object: page}).DeepCopy().Object, int(requests.Add(1)))
	}))
	t.Cleanup(server.Close)
	access, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal("closed LIST fixture unavailable")
	}
	return access, expected, requests
}

func TestBaselineConfigurationListsRequireCompleteStrictBoundedSnapshots(t *testing.T) {
	cases := []string{"healthy", "native-items", "partial-kind", "partial-version", "null-kind", "null-version", "empty-kind", "empty-version", "pages", "drain-after-found", "foreign", "foreign-cannot-fill-missing", "missing", "duplicate-name", "duplicate-uid", "wrong-kind", "wrong-version", "namespace", "missing-uid", "missing-rv", "wrong-list", "unknown-list", "unknown-member", "case-aliased", "null-list", "null-metadata", "null-items", "null-item", "null-rv", "null-continue", "null-remaining", "negative-remaining", "final-remaining", "empty-rv", "large-rv", "rv-change", "repeat", "cycle", "pages-bound", "items-bound", "bytes-bound", "large-continue", "expired", "withdrawn", "oversize", "duplicate-json", "malformed", "trailing", "depth", "tokens"}
	for _, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		for _, mode := range cases {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				access, expected, requests := testBaselineListFixture(t, kind, func(w http.ResponseWriter, r *http.Request, page map[string]any, call int) {
					metadata := page["metadata"].(map[string]any)
					items := page["items"].([]any)
					first := items[0].(map[string]any)
					meta := first["metadata"].(map[string]any)
					foreign := (&unstructured.Unstructured{Object: first}).DeepCopy()
					foreign.SetName("foreign-matching-installation")
					foreign.SetUID("foreign-matching-installation-uid")
					switch mode {
					case "native-items":
						for _, item := range items {
							fields := item.(map[string]any)
							delete(fields, "apiVersion")
							delete(fields, "kind")
						}
					case "partial-kind":
						delete(first, "apiVersion")
					case "partial-version":
						delete(first, "kind")
					case "null-kind":
						first["kind"] = nil
					case "null-version":
						first["apiVersion"] = nil
					case "empty-kind":
						first["kind"] = ""
					case "empty-version":
						first["apiVersion"] = ""
					case "pages":
						if call == 1 {
							page["items"], metadata["continue"] = items[:3], "next"
						} else {
							if r.URL.Query().Get("continue") != "next" {
								t.Error("LIST lost continuation")
							}
							page["items"] = items[3:]
						}
					case "drain-after-found":
						if call == 1 {
							metadata["continue"] = "next"
						} else {
							page["items"] = []any{foreign.Object}
						}
					case "foreign":
						page["items"] = append(items, foreign.Object)
					case "foreign-cannot-fill-missing":
						page["items"] = append(items[1:], foreign.Object)
					case "missing":
						page["items"] = items[1:]
					case "duplicate-name":
						page["items"] = append(items, first)
					case "duplicate-uid":
						foreign.SetUID((&unstructured.Unstructured{Object: first}).GetUID())
						page["items"] = append(items, foreign.Object)
					case "wrong-kind":
						first["kind"] = "Secret"
					case "wrong-version":
						first["apiVersion"] = "v1"
					case "namespace":
						meta["namespace"] = "foreign"
					case "missing-uid":
						delete(meta, "uid")
					case "missing-rv":
						delete(meta, "resourceVersion")
					case "wrong-list":
						page["kind"] = "SecretList"
					case "unknown-list":
						page["private"] = "PRIVATE-CANARY"
					case "unknown-member":
						first["private"] = "PRIVATE-CANARY"
					case "case-aliased":
						delete(metadata, "resourceVersion")
						metadata["ResourceVersion"] = "snapshot"
					case "null-list":
						_, _ = io.WriteString(w, "null")
						return
					case "null-metadata":
						page["metadata"] = nil
					case "null-items":
						page["items"] = nil
					case "null-item":
						items[0] = nil
					case "null-rv":
						metadata["resourceVersion"] = nil
					case "null-continue":
						metadata["continue"] = nil
					case "null-remaining":
						metadata["remainingItemCount"] = nil
					case "negative-remaining":
						metadata["remainingItemCount"] = -1
					case "final-remaining":
						metadata["remainingItemCount"] = 1
					case "empty-rv":
						metadata["resourceVersion"] = ""
					case "large-rv":
						metadata["resourceVersion"] = strings.Repeat("r", 1025)
					case "rv-change":
						if call == 1 {
							metadata["continue"] = "next"
						} else {
							page["items"], metadata["resourceVersion"] = []any{}, "other"
						}
					case "repeat", "cycle", "pages-bound", "bytes-bound":
						page["items"] = []any{}
						metadata["continue"] = "page-" + strconv.Itoa(call)
						if mode == "repeat" {
							metadata["continue"] = "same"
						}
						if mode == "cycle" && call == 3 {
							metadata["continue"] = "page-1"
						}
						if mode == "bytes-bound" {
							_, _ = io.WriteString(w, strings.Repeat(" ", 900000))
						}
					case "items-bound":
						page["items"] = []any{}
						for i := 0; i < 1001; i++ {
							page["items"] = append(page["items"].([]any), map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": kind, "metadata": map[string]any{"name": "foreign-" + strconv.Itoa(i), "uid": "foreign-uid-" + strconv.Itoa(i), "resourceVersion": "1"}})
						}
					case "large-continue":
						metadata["continue"] = strings.Repeat("t", 2049)
					case "expired", "withdrawn":
						if call == 1 {
							metadata["continue"] = "next"
						} else {
							code := 410
							if mode == "withdrawn" {
								code = 403
							}
							w.WriteHeader(code)
							_, _ = io.WriteString(w, "PRIVATE-CANARY")
							return
						}
					case "oversize":
						_, _ = io.WriteString(w, strings.Repeat(" ", 1024*1024+1))
						return
					case "duplicate-json":
						_, _ = io.WriteString(w, `{"apiVersion":"admissionregistration.k8s.io/v1","kind":"`+kind+`List","metadata":{"resourceVersion":"one","resourceVersion":"two"},"items":[]}`)
						return
					case "malformed":
						_, _ = io.WriteString(w, `{"metadata":`)
						return
					case "depth":
						_, _ = io.WriteString(w, strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65))
						return
					case "tokens":
						_, _ = io.WriteString(w, "["+strings.Repeat("0,", 200001)+"0]")
						return
					}
					_ = json.NewEncoder(w).Encode(page)
					if mode == "trailing" {
						_, _ = io.WriteString(w, "{}")
					}
				})
				result, err := access.listBaselineConfiguration(t.Context(), kind, expected)
				healthy := mode == "healthy" || mode == "native-items" || mode == "pages" || mode == "drain-after-found" || mode == "foreign"
				if healthy {
					if err != nil || len(result) != 6 {
						t.Fatal("complete bounded snapshot refused")
					}
					for key := range result {
						if !expected[key] {
							t.Fatal("foreign LIST body retained as membership")
						}
					}
					want := int32(1)
					if mode == "pages" || mode == "drain-after-found" {
						want = 2
					}
					if requests.Load() != want {
						t.Fatal("LIST truncated after finding expected members")
					}
				} else if err != ErrRead || result != nil || strings.Contains(err.Error(), "CANARY") {
					t.Fatal("incomplete or ambiguous snapshot produced evidence")
				}
				if mode == "pages-bound" && requests.Load() != 32 || mode == "repeat" && requests.Load() != 2 || mode == "cycle" && requests.Load() != 3 || mode == "bytes-bound" && requests.Load() != 5 || (mode == "expired" || mode == "withdrawn") && requests.Load() != 2 {
					t.Fatal("LIST changed refusal bound, retried or fell back to GET")
				}
				if len(access.publicReplies.entries) != 0 || access.responseBodies.free != nil {
					t.Fatal("collection response entered named public memo or body pool")
				}
			})
		}
	}
}

func TestBaselineConfigurationListsRejectEveryChangedOriginalMember(t *testing.T) {
	for group, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
		for member := range 6 {
			for _, mode := range []string{"missing", "replacement", "same-uid-rv", "shape", "null-spec", "unknown-spec", "deleting", "misrouted", "foreign-name"} {
				t.Run(kind+"/"+strconv.Itoa(member)+"/"+mode, func(t *testing.T) {
					configuration, snapshot, paths := testConfiguredReadLanes(t)
					next := configuration.access.client.Transport
					var changed atomic.Bool
					configuration.access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
						response, err := next.RoundTrip(r)
						if err != nil || r.URL.Path != paths[group][0] {
							return response, err
						}
						defer response.Body.Close()
						var page map[string]any
						if json.NewDecoder(response.Body).Decode(&page) != nil {
							t.Error("member mutation fixture decode failed")
							return nil, ErrRead
						}
						items := page["items"].([]any)
						object := items[member].(map[string]any)
						metadata := object["metadata"].(map[string]any)
						switch mode {
						case "missing":
							page["items"] = append(items[:member], items[member+1:]...)
						case "replacement":
							metadata["uid"] = "replacement"
						case "same-uid-rv":
							if !changed.Load() {
								break
							}
							metadata["resourceVersion"] = "changed"
						case "shape":
							if group == 0 {
								object["spec"].(map[string]any)["failurePolicy"] = "Ignore"
							} else {
								object["spec"].(map[string]any)["policyName"] = "foreign"
							}
						case "null-spec":
							object["spec"] = nil
						case "unknown-spec":
							object["spec"].(map[string]any)["PRIVATE-CANARY"] = true
						case "deleting":
							metadata["deletionTimestamp"] = "2026-10-20T12:00:00Z"
						case "misrouted":
							object["kind"] = "Secret"
						case "foreign-name":
							metadata["name"] = "foreign-installation"
						}
						changed.Store(true)
						body, err := json.Marshal(page)
						if err != nil {
							return nil, ErrRead
						}
						copy := *response
						copy.Body = io.NopCloser(bytes.NewReader(body))
						copy.ContentLength = int64(len(body))
						return &copy, nil
					})
					if err := configuration.VerifyConfigured(t.Context(), snapshot); err != ErrSecurityBaseline || !changed.Load() {
						t.Fatal("changed original member became configuration authority")
					}
				})
			}
		}
	}
}

func TestBaselineConfigurationListsRefuseUnboundOrActorRoutesWithoutWire(t *testing.T) {
	access, expected, requests := testBaselineListFixture(t, "ValidatingAdmissionPolicy", func(w http.ResponseWriter, _ *http.Request, page map[string]any, _ int) {
		_ = json.NewEncoder(w).Encode(page)
	})
	for _, kind := range []string{"Secret", "Deployment", "", "ValidatingAdmissionPolicyList", "../validatingadmissionpolicies"} {
		if result, err := access.listBaselineConfiguration(t.Context(), kind, expected); err != ErrInvalid || result != nil {
			t.Fatal("arbitrary collection route accepted")
		}
	}
	access.actor = &actorWireIdentity{}
	if result, err := access.listBaselineConfiguration(t.Context(), "ValidatingAdmissionPolicy", expected); err != ErrInvalid || result != nil {
		t.Fatal("actor acquired installer LIST")
	}
	access.actor = nil
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := access.listBaselineConfiguration(ctx, "ValidatingAdmissionPolicy", expected); err != ErrRead || result != nil {
		t.Fatal("cancelled LIST produced evidence")
	}
	if requests.Load() != 0 {
		t.Fatal("refused LIST reached the wire")
	}
}

func TestBaselineConfigurationListsKeepOriginalFencesAcrossPagesAndPasses(t *testing.T) {
	for _, mode := range []string{"healthy", "journal-page", "namespace-page", "file-page", "journal-pass2", "namespace-pass2", "permission-pass2"} {
		t.Run(mode, func(t *testing.T) {
			configuration, snapshot, paths := testConfiguredReadLanes(t)
			next := configuration.access.client.Transport
			var calls [2]atomic.Int32
			var namespaceCalls atomic.Int32
			var drift atomic.Bool
			configuration.access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				group := -1
				for i := range paths {
					if r.URL.Path == paths[i][0] {
						group = i
					}
				}
				if group < 0 {
					namespaceCalls.Add(1)
					response, err := next.RoundTrip(r)
					if err != nil || !drift.Load() || mode == "file-page" || mode == "permission-pass2" {
						return response, err
					}
					defer response.Body.Close()
					var object map[string]any
					if json.NewDecoder(response.Body).Decode(&object) != nil {
						t.Error("Namespace fence fixture unavailable")
						return nil, ErrRead
					}
					metadata := object["metadata"].(map[string]any)
					if strings.HasPrefix(mode, "namespace-") {
						metadata["uid"] = "foreign-namespace"
					} else {
						metadata["resourceVersion"] = "changed-journal"
					}
					body, err := json.Marshal(object)
					if err != nil {
						return nil, ErrRead
					}
					copy := *response
					copy.Body, copy.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
					return &copy, nil
				}
				call := calls[group].Add(1)
				continuation := r.URL.Query().Get("continue")
				if call%2 == 1 && continuation != "" || call%2 == 0 && continuation != "next" {
					t.Error("configured pagination did not restart each complete pass")
					return nil, ErrRead
				}
				if group == 0 && mode == "permission-pass2" && call == 3 {
					drift.Store(true)
					return &http.Response{StatusCode: 403, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader("PRIVATE-CANARY"))}, nil
				}
				// The underlying independent fixture supplies the same six live
				// originals; this wrapper splits them into two fresh native pages.
				request := r.Clone(r.Context())
				copiedURL := *r.URL
				request.URL = &copiedURL
				query := request.URL.Query()
				query.Del("continue")
				request.URL.RawQuery = query.Encode()
				response, err := next.RoundTrip(request)
				if err != nil {
					return response, err
				}
				defer response.Body.Close()
				var page map[string]any
				if json.NewDecoder(response.Body).Decode(&page) != nil {
					t.Error("pagination fixture decode failed")
					return nil, ErrRead
				}
				items := page["items"].([]any)
				if call%2 == 1 {
					page["items"], page["metadata"].(map[string]any)["continue"] = items[:3], "next"
				} else {
					page["items"] = items[3:]
				}
				if group == 0 && (strings.HasSuffix(mode, "-page") && call == 2 || strings.HasSuffix(mode, "-pass2") && call == 3) {
					drift.Store(true)
					if mode == "file-page" {
						if _, err := configuration.engine.files.CreateExclusive(fixtureLedgerName(snapshot), []byte("uncertain fixture")); err != nil {
							t.Error("pagination fence fixture failed")
						}
					}
				}
				body, err := json.Marshal(page)
				if err != nil {
					return nil, ErrRead
				}
				copy := *response
				copy.Body, copy.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
				return &copy, nil
			})
			err := configuration.VerifyConfigured(t.Context(), snapshot)
			if mode == "healthy" {
				if err != nil || calls[0].Load() != 4 || calls[1].Load() != 4 || namespaceCalls.Load() != 8 {
					t.Fatal("paginated passes skipped members or original fences")
				}
			} else if err != ErrSecurityBaseline || !drift.Load() {
				t.Fatal("page or second-pass race escaped original fence")
			}
		})
	}
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// Catalog-only synthetic comparison, NOT full configured or native lifecycle:
// it excludes permissions/original Namespace/journal fences. Both schedules
// fetch fresh HTTPS replies and run the same whole-member/health/relationship
// validation. Named reads retain their existing complete-byte conversion memo;
// LISTs do not gain a memo or cached verdict. Run with finite hosted benchtime.
// Validation is joined/serial for BOTH arms to isolate the catalog comparison;
// this does not reproduce old configured's parallel typed-validation timing.
func BenchmarkAdmissionConfigurationFreshCatalog(b *testing.B) {
	plan := fixturePlan(b)
	for _, mode := range []string{"named-eight", "two-list"} {
		b.Run(mode, func(b *testing.B) {
			contract, err := installcontract.New(plan)
			if err != nil {
				b.Fatal(err)
			}
			var catalog []admissionOriginalRead
			expected := [2]map[installstate.Key]bool{{}, {}}
			named := map[string][]byte{}
			var items [2][]any
			for _, resource := range plan.Resources() {
				object := resource.Object.DeepCopy()
				group := 0
				switch object.GetKind() {
				case "ValidatingAdmissionPolicy":
					object.SetGeneration(1)
					object.Object["status"] = map[string]any{"observedGeneration": int64(1), "typeChecking": map[string]any{}}
				case "ValidatingAdmissionPolicyBinding":
					group = 1
				default:
					continue
				}
				object.SetUID(types.UID("original-" + object.GetName()))
				object.SetResourceVersion("91")
				key := resourceKeyFromObject(object)
				template, err := contract.Template(key, false)
				if err != nil {
					b.Fatal(err)
				}
				catalog = append(catalog, admissionOriginalRead{resource: installstate.Resource{Key: key, UID: object.GetUID()}, template: template})
				expected[group][key] = true
				path, err := resourcePath(key, false)
				if err != nil {
					b.Fatal(err)
				}
				body, err := json.Marshal(object.Object)
				if err != nil {
					b.Fatal(err)
				}
				named[path] = body
				items[group] = append(items[group], object.Object)
			}
			if len(catalog) != 12 || len(expected[0]) != 6 || len(expected[1]) != 6 {
				b.Fatal("incomplete independent catalog")
			}
			lists := map[string][]byte{}
			for group, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
				body, err := json.Marshal(map[string]any{"apiVersion": "admissionregistration.k8s.io/v1", "kind": kind + "List", "metadata": map[string]any{"resourceVersion": "snapshot"}, "items": items[group]})
				if err != nil {
					b.Fatal(err)
				}
				lists[admissionConfigurationTestPaths[group][0]] = body
			}
			var requests atomic.Uint64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodGet || r.Header.Get("Impersonate-User") != "" {
					w.WriteHeader(500)
					return
				}
				if body := lists[r.URL.Path]; body != nil {
					q := r.URL.Query()
					if !testRuntimeConfigurationRequest(r) || len(q) != 2 || q.Get("limit") != "128" {
						w.WriteHeader(500)
						return
					}
					_, _ = w.Write(body)
					return
				}
				if body := named[r.URL.Path]; body != nil && r.URL.RawQuery == "" {
					_, _ = w.Write(body)
					return
				}
				w.WriteHeader(404)
			}))
			b.Cleanup(server.Close)
			access, err := NewHTTPAccess(serverConfig(server))
			if err != nil {
				b.Fatal(err)
			}
			run := func() error {
				ctx, cancel := context.WithCancel(b.Context())
				defer cancel()
				observed := make([]*unstructured.Unstructured, len(catalog))
				var failures [8]error
				var readers sync.WaitGroup
				if mode == "named-eight" {
					for lane := range 8 {
						readers.Go(func() {
							for index := lane; index < len(catalog); index += 8 {
								var err error
								observed[index], err = access.Get(ctx, catalog[index].resource.Key)
								if err != nil {
									failures[lane] = err
									cancel()
									return
								}
							}
						})
					}
				} else {
					var collections [2]map[installstate.Key]*unstructured.Unstructured
					for group, kind := range []string{"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"} {
						readers.Go(func() {
							var err error
							collections[group], err = access.listRuntimeConfiguration(ctx, kind, expected[group])
							if err != nil {
								failures[group] = err
								cancel()
							}
						})
					}
					readers.Wait()
					for index, entry := range catalog {
						group := 0
						if entry.resource.Key.Kind == "ValidatingAdmissionPolicyBinding" {
							group = 1
						}
						observed[index] = collections[group][entry.resource.Key]
					}
				}
				readers.Wait()
				for _, err := range failures {
					if err != nil {
						return err
					}
				}
				policies, bindings := map[string]bool{}, map[string]string{}
				for index, entry := range catalog {
					object, err := entry.template.MatchLiveAdmissionObject(observed[index], entry.resource.UID)
					if err != nil {
						return err
					}
					switch typed := object.(type) {
					case *admissionv1.ValidatingAdmissionPolicy:
						if !healthyAdmissionPolicy(typed) {
							return ErrAdmission
						}
						policies[typed.Name] = true
					case *admissionv1.ValidatingAdmissionPolicyBinding:
						bindings[typed.Name] = typed.Spec.PolicyName
					default:
						return ErrAdmission
					}
				}
				if len(policies) != 6 || len(bindings) != 6 {
					return ErrAdmission
				}
				for _, name := range bindings {
					if !policies[name] {
						return ErrAdmission
					}
				}
				return nil
			}
			if err := run(); err != nil {
				b.Fatal("catalog control refused", err)
			}
			requests.Store(0)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := run(); err != nil {
					b.Fatal("fresh catalog refused", err)
				}
			}
			b.StopTimer()
			want := uint64(12)
			if mode == "two-list" {
				want = 2
			}
			if requests.Load() != want*uint64(b.N) {
				b.Fatal("catalog omitted or replayed HTTP reads")
			}
			b.ReportMetric(float64(requests.Load())/float64(b.N), "requests/op")
		})
	}
}

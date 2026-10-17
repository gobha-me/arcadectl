// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

// Real direct HTTP/1.1 lineage: native Kubernetes absence has a nonempty
// Status body. Empty fixture 404s alone cannot prove connection reuse.
func testDirectReadPoolGetNotFound(t *testing.T) {
	testDirectReadPoolGetNotFoundAtFixture(t, false)
}

// The fixture capture returns before the generic absence sanitizer. Exercise
// that real private transport branch too; this primitive control grants no
// fixture permission and does not substitute for a phase's fresh witnesses.
func testDirectReadPoolGetNotFoundAtFixture(t *testing.T, fixture bool) {
	for _, scenario := range []struct {
		name  string
		reuse bool
	}{{"empty-control", true}, {"native-status", true}, {"native-known-length", true}, {"exact-bound-known", true}, {"exact-bound-chunked", true}, {"oversize-known", false}, {"oversize-chunked", false}, {"truncated", false}, {"compressed", false}} {
		t.Run(scenario.name, func(t *testing.T) {
			key, object := accessObject()
			var requests, got, reused, handshakes, sanitized atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/isolated-install/serviceaccounts/reviewed" || r.URL.RawQuery != "" || r.ProtoMajor != 1 || r.Header.Get("Authorization") != "Bearer TEST-ONLY-404-POOL" || r.Header.Get("Impersonate-User") != "" {
					t.Error("absence read changed frozen identity, route or protocol")
				}
				w.Header().Set("Content-Type", "application/json")
				if requests.Add(1) == 2 {
					w.Header().Set("Warning", "PRIVATE-404-HEADER-CANARY")
					w.Header().Set("Retry-After", "PRIVATE-404-RETRY-CANARY")
					body := []byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"PRIVATE-404-BODY-CANARY"}`)
					switch scenario.name {
					case "empty-control":
						body = nil
						w.Header().Set("Content-Length", "0")
					case "native-known-length":
						w.Header().Set("Content-Length", fmt.Sprint(len(body)))
					case "exact-bound-known", "exact-bound-chunked":
						body = append(body, bytes.Repeat([]byte(" "), 8192-len(body))...)
						if scenario.name == "exact-bound-known" {
							w.Header().Set("Content-Length", "8192")
						} else {
							w.Header().Set("Trailer", "X-Private-Trailer")
						}
					case "oversize-known", "oversize-chunked":
						body = append(body, bytes.Repeat([]byte(" "), 65536-len(body))...)
						if scenario.name == "oversize-known" {
							w.Header().Set("Content-Length", "65536")
						} else {
							w.Header().Set("Trailer", "X-Private-Trailer")
						}
					case "truncated":
						w.Header().Set("Content-Length", "1000")
					case "compressed":
						var encoded bytes.Buffer
						zip := gzip.NewWriter(&encoded)
						_, _ = zip.Write(body)
						_ = zip.Close()
						body = encoded.Bytes()
						w.Header().Set("Content-Encoding", "gzip")
						w.Header().Set("Content-Length", fmt.Sprint(len(body)))
					default:
						w.Header().Set("Trailer", "X-Private-Trailer")
					}
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write(body)
					w.Header().Set("X-Private-Trailer", "PRIVATE-404-TRAILER-CANARY")
					return
				}
				_ = json.NewEncoder(w).Encode(object)
			}))
			t.Cleanup(server.Close)
			config := serverConfig(server)
			config.BearerToken = "TEST-ONLY-404-POOL"
			access, err := NewDirectHTTPAccess(config)
			if err != nil {
				t.Fatal("direct static parent refused")
			}
			t.Cleanup(access.pool.(*http.Transport).CloseIdleConnections)
			fixtureAccess := access
			observedAccesses := []*HTTPAccess{access}
			if fixture {
				fixtureAccess = derivedFixturePoolAccess(t, access, key)
				observedAccesses = append(observedAccesses, fixtureAccess)
			}
			// Observe above the real guard after construction, without altering
			// frozen configuration, pool provenance or native TLS routing.
			for _, observedAccess := range observedAccesses {
				outer := observedAccess.client.Transport
				observedAccess.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
					response, err := outer.RoundTrip(r)
					if err == nil && response != nil && response.StatusCode == http.StatusNotFound {
						body, readErr := io.ReadAll(response.Body)
						_ = response.Body.Close()
						if readErr != nil || string(body) != `{}` || len(response.Header) != 1 || response.Header.Get("Content-Type") != "application/json" || response.Status != "404 Not Found" || response.Trailer != nil || response.ContentLength != 2 {
							t.Error("private absence response escaped below-wrapper sanitizer")
						}
						sanitized.Add(1)
						response.Body = io.NopCloser(bytes.NewReader(body))
					}
					return response, err
				})
			}
			trace := &httptrace.ClientTrace{
				GotConn: func(info httptrace.GotConnInfo) {
					got.Add(1)
					if info.Reused && info.WasIdle {
						reused.Add(1)
					}
				},
				TLSHandshakeStart: func() { handshakes.Add(1) },
			}
			ctx := httptrace.WithClientTrace(t.Context(), trace)
			for i := range 3 {
				if fixture && i == 1 {
					capture, response, err := fixturePoolRead(ctx, fixtureAccess, key, false)
					if response != nil && response.Body != nil {
						_ = response.Body.Close()
					}
					if err != nil || response == nil || capture == nil || response.StatusCode != http.StatusNotFound || !capture.success || !capture.notFound || capture.result != nil || capture.uid != "" || capture.strictNotFound {
						t.Fatal("private absence capture changed its non-strict classification")
					}
					continue
				}
				live, err := access.Get(ctx, key)
				if i == 1 {
					if !apierrors.IsNotFound(err) || live != nil || strings.Contains(err.Error(), "CANARY") {
						t.Fatal("native absence lost fixed public classification")
					}
				} else if err != nil || live == nil || live.GetName() != key.Name {
					t.Fatal("surrounding original read refused")
				}
			}
			wantReuse, wantHandshakes := int32(1), int32(2)
			if scenario.reuse {
				wantReuse, wantHandshakes = 2, 1
			}
			if requests.Load() != 3 || got.Load() != 3 || reused.Load() != wantReuse || handshakes.Load() != wantHandshakes || sanitized.Load() != 1 {
				t.Fatalf("absence pooled requests=%d connections=%d idle-reused=%d TLS-handshakes=%d sanitized=%d", requests.Load(), got.Load(), reused.Load(), handshakes.Load(), sanitized.Load())
			}
			if access.frozen.Transport != nil || access.frozen.WrapTransport != nil || access.frozen.Proxy != nil || !access.actorCompatible() {
				t.Fatal("absence optimization changed canonical direct parent provenance")
			}
		})
	}
}

// Real complete sealed SDK observations and alternating private actor reviews,
// not fabricated evidence or cached proof results. A test-owned mutex joins
// handler observations with caller snapshots, including forbidden requests.
func testDirectReadPool(t *testing.T) {
	plan := fixturePlan(t)
	v, namespace, lists := readyControllerFixture(t, plan)
	objects := maps.Clone(v.f.access.objects)
	for name, secret := range v.secrets.objects {
		objects[secretKey(namespace.Name, name)] = servingObject(t, secret)
	}
	connections := map[string]bool{}
	requests, reviews := 0, 0
	var mu sync.Mutex
	base, _ := controllerProofAccessWithRequests(t, namespace, objects, lists, nil, "", func(w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		defer mu.Unlock()
		connections[r.RemoteAddr] = true
		requests++
		if r.ProtoMajor != 1 || r.Header.Get("Authorization") != "Bearer TEST-ONLY-POOL" {
			t.Error("reader/actor escaped frozen static HTTP1 identity")
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.NonResourceAttributes != nil || review.Spec.ResourceAttributes == nil {
				t.Error("invalid private actor review")
				w.WriteHeader(400)
				return true
			}
			actor := ordinaryControllerActor
			if reviews%2 != 0 {
				actor = destroyControllerActor
			}
			if r.Header.Get("Impersonate-User") != "system:serviceaccount:"+namespace.Name+":"+actor.account() || review.Spec.ResourceAttributes.Resource != "pods" || review.Spec.ResourceAttributes.Verb != "update" || review.Spec.ResourceAttributes.Namespace != namespace.Name {
				t.Error("shared pool crossed fresh actor identity or operation")
			}
			reviews++
			review.Status.Allowed = true
			_ = json.NewEncoder(w).Encode(review)
			return true
		}
		if r.Header.Get("Impersonate-User") != "" || r.Method != http.MethodGet {
			t.Error("SDK read inherited actor impersonation or mutation authority")
		}
		return false
	})
	config := rest.CopyConfig(base.frozen)
	config.BearerToken = "TEST-ONLY-POOL"
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal(err)
	}
	store, err := installstate.New(access.Namespaces(), plan)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		observer, err := installobserve.New(access.readConfig(), store, plan)
		if err != nil {
			t.Fatal("strict SDK observer refused frozen pool", err)
		}
		observation, err := observer.Collect(t.Context(), v.f.snapshot.Anchor())
		if err != nil || observation == nil || len(observation.Runtime().Deployments.Items) != 2 {
			t.Fatal("reconstructed observer did not collect complete live evidence", err)
		}
		for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
			client, err := access.actorClient(actor, namespace.Name)
			if err != nil {
				t.Fatal(err)
			}
			spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "pods", Verb: "update", Namespace: namespace.Name, Name: "arcadectl-probe"}}
			if err := client.authorize(t.Context(), spec); err != nil {
				t.Fatal("fresh private review refused", err)
			}
			mu.Lock()
			before := requests
			mu.Unlock()
			_, getErr := client.Get(t.Context(), installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: namespace.Name, Name: "arcadectl-controller"})
			mu.Lock()
			after := requests
			mu.Unlock()
			if getErr == nil || after != before {
				t.Fatal("pool reuse exposed generic actor access")
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if reviews != 6 {
		t.Fatal("private reviews omitted or replayed")
	}
	if len(connections) != 1 {
		t.Fatal("same frozen direct lineage rebuilt independent TCP/TLS pools", len(connections))
	}
	if requests != 141 {
		t.Fatal("connection reuse changed the complete live request count", requests)
	}
	if access.frozen.Transport != nil || access.frozen.Proxy != nil || len(access.frozen.CAData) == 0 || !access.actorCompatible() || access.native == nil {
		t.Fatal("pool derivation changed canonical actor or native TLS provenance")
	}
	t.Logf("complete SDK observations=3 private actor reviews=%d requests=%d TCP connections=%d", reviews, requests, len(connections))
}

// Independent parent lineages must not share TLS or HTTP identities even at
// the same host. Each parent concurrently reconstructs SDK and actor clients;
// every request is observed at the actual TLS server, not a fake RoundTripper.
func testDirectReadPoolParentIsolation(t *testing.T) {
	for _, separateHosts := range []bool{false, true} {
		name := "same-host-distinct-certificates"
		if separateHosts {
			name = "distinct-hosts"
		}
		t.Run(name, func(t *testing.T) {
			const namespace = "isolated-pool"
			var mu sync.Mutex
			certificates := make(map[string][]byte)
			connections := make(map[string]bool)
			requests, reviews := 0, 0
			pairs := make([]tls.Certificate, 2)
			configs := make([]*rest.Config, 2)
			for i := range 2 {
				opts := fixtureTLS(t, namespace, time.Now())
				certificate, err := os.ReadFile(opts.CertificateFile)
				if err != nil {
					t.Fatal(err)
				}
				key, err := os.ReadFile(opts.KeyFile)
				if err != nil {
					t.Fatal(err)
				}
				pairs[i], err = tls.X509KeyPair(certificate, key)
				if err != nil {
					t.Fatal(err)
				}
				token := fmt.Sprintf("TEST-ONLY-POOL-PARENT-%d", i)
				certificates["Bearer "+token] = pairs[i].Certificate[0]
				configs[i] = &rest.Config{BearerToken: token, TLSClientConfig: rest.TLSClientConfig{CertData: certificate, KeyData: key}}
			}
			newServer := func(owner int) *httptest.Server {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					requests++
					connections[fmt.Sprintf("%d/%s", owner, r.RemoteAddr)] = true
					want := certificates[r.Header.Get("Authorization")]
					if r.ProtoMajor != 1 || len(want) == 0 || r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, want) || separateHosts && r.Header.Get("Authorization") != "Bearer "+configs[owner].BearerToken {
						t.Error("parent pool crossed host, static HTTP identity or client certificate")
						w.WriteHeader(http.StatusForbidden)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					if r.Method == http.MethodGet && r.URL.Path == "/version" && r.Header.Get("Impersonate-User") == "" {
						_, _ = w.Write([]byte(`{"major":"1","minor":"37","gitVersion":"v1.37.0"}`))
						return
					}
					if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
						var review authv1.SelfSubjectAccessReview
						if json.NewDecoder(r.Body).Decode(&review) != nil || review.Spec.NonResourceAttributes != nil || review.Spec.ResourceAttributes == nil || review.Spec.ResourceAttributes.Namespace != namespace || review.Spec.ResourceAttributes.Resource != "pods" || review.Spec.ResourceAttributes.Verb != "update" {
							t.Error("pool accepted an unbound private review")
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						actor := ordinaryControllerActor
						if review.Spec.ResourceAttributes.Name == destroyControllerActor.account() {
							actor = destroyControllerActor
						}
						if review.Spec.ResourceAttributes.Name != actor.account() || r.Header.Get("Impersonate-User") != "system:serviceaccount:"+namespace+":"+actor.account() {
							t.Error("concurrent parent pool crossed fresh actor identity")
							w.WriteHeader(http.StatusForbidden)
							return
						}
						reviews++
						review.Status.Allowed = true
						_ = json.NewEncoder(w).Encode(review)
						return
					}
					w.WriteHeader(http.StatusForbidden)
					t.Error("pool exposed a foreign operation")
				}))
				server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
				server.StartTLS()
				t.Cleanup(server.Close)
				return server
			}
			servers := []*httptest.Server{newServer(0)}
			if separateHosts {
				servers = append(servers, newServer(1))
			}
			parents := make([]*HTTPAccess, 2)
			for i := range 2 {
				server := servers[0]
				if separateHosts {
					server = servers[i]
				}
				configs[i].Host, configs[i].CAData = server.URL, serverConfig(server).CAData
				var err error
				parents[i], err = NewDirectHTTPAccess(configs[i])
				if err != nil {
					t.Fatal("independent frozen parent refused", err)
				}
				pool, ok := parents[i].pool.(*http.Transport)
				if !ok || pool.TLSClientConfig == nil || pool.Proxy == nil || !parents[i].actorCompatible() || len(parents[i].frozen.CertData) == 0 || len(parents[i].frozen.CAData) == 0 {
					t.Fatal("parent lost frozen TLS/direct provenance")
				}
				request, _ := http.NewRequest(http.MethodGet, "https://cluster.example/version", nil)
				if proxy, err := pool.Proxy(request); err != nil || proxy != nil {
					t.Fatal("pool admitted environment proxy routing")
				}
				t.Cleanup(pool.CloseIdleConnections)
			}
			if parents[0].pool == parents[1].pool {
				t.Fatal("independent parent identities inherited one raw pool")
			}
			var workers sync.WaitGroup
			failures := make(chan error, 2)
			for _, parent := range parents {
				workers.Go(func() {
					for range 3 {
						reader, err := discovery.NewDiscoveryClientForConfig(parent.readConfig())
						if err != nil {
							failures <- fmt.Errorf("fresh SDK reader: %w", err)
							return
						}
						if version, err := reader.ServerVersionWithContext(t.Context()); err != nil || version == nil || version.GitVersion != "v1.37.0" {
							failures <- fmt.Errorf("fresh SDK TLS request refused: %v", err)
							return
						}
						for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
							client, err := parent.actorClient(actor, namespace)
							if err != nil {
								failures <- err
								return
							}
							spec := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Version: "v1", Resource: "pods", Verb: "update", Namespace: namespace, Name: actor.account()}}
							if err := client.authorize(t.Context(), spec); err != nil {
								failures <- err
								return
							}
						}
					}
				})
			}
			workers.Wait()
			close(failures)
			for err := range failures {
				t.Error(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if requests != 18 || reviews != 12 || len(connections) != 2 {
				t.Fatal("fresh concurrent SDK/actor requests were skipped, replayed or independently repooled", requests, reviews, len(connections))
			}
		})
	}
}

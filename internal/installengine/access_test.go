// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func serverConfig(server *httptest.Server) *rest.Config {
	return &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
}

func accessObject() (installstate.Key, *unstructured.Unstructured) {
	key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "isolated-install", Name: "reviewed"}
	o := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]any{"name": key.Name, "namespace": key.Namespace}}}
	return key, o
}

func TestHTTPMutationsAndNamespaceCASNeverRetryRetryAfter(t *testing.T) {
	for _, code := range []int{429, 503} {
		for _, method := range []string{"create", "update", "delete", "namespace-create", "namespace-update"} {
			t.Run(method+"/"+http.StatusText(code), func(t *testing.T) {
				var requests atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.ProtoMajor != 1 || r.Header.Get("Idempotency-Key") != "" || r.Header.Get("X-Idempotency-Key") != "" {
						t.Error("replay-capable wire protocol")
					}
					body, _ := io.ReadAll(r.Body)
					if len(body) == 0 {
						t.Error("write must have nonempty non-replayable JSON body")
					}
					if r.Method == http.MethodPost || r.Method == http.MethodPut {
						if r.URL.Query().Get("fieldValidation") != "Strict" {
							t.Error("not strict")
						}
					}
					w.Header().Set("Retry-After", "0")
					w.Header().Set("Warning", "PRIVATE-HEADER-CANARY")
					w.WriteHeader(code)
					_, _ = io.WriteString(w, "PRIVATE-BODY-CANARY")
				}))
				defer server.Close()
				a, err := NewHTTPAccess(serverConfig(server))
				if err != nil {
					t.Fatal(err)
				}
				key, o := accessObject()
				ctx := context.Background()
				switch method {
				case "create":
					_, err = a.Create(ctx, key, o, false)
				case "update":
					o.SetUID("original")
					o.SetResourceVersion("42")
					_, err = a.Update(ctx, key, o, false)
				case "delete":
					err = a.Delete(ctx, key, metav1.DeleteOptions{})
				case "namespace-create":
					_, err = a.Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "isolated-install"}}, metav1.CreateOptions{})
				case "namespace-update":
					_, err = a.Namespaces().Update(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "isolated-install", UID: "original", ResourceVersion: "42"}}, metav1.UpdateOptions{})
				}
				if !errors.Is(err, ErrRead) || strings.Contains(err.Error(), "CANARY") || requests.Load() != 1 {
					t.Fatalf("mutation attempted %d times: %v", requests.Load(), err)
				}
			})
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAttemptGuardIsBelowRetryingWrapperAndSanitizesBeforeWrapper(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "0")
		w.Header().Set("Set-Cookie", "PRIVATE-HEADER-CANARY")
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "PRIVATE-BODY-CANARY")
	}))
	defer server.Close()
	config := serverConfig(server)
	config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			response, err := next.RoundTrip(r)
			if err != nil {
				return nil, err
			}
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.Header.Get("Retry-After") != "" || response.Header.Get("Set-Cookie") != "" || strings.Contains(string(body), "CANARY") {
				t.Error("raw server error leaked before wrappers")
			}
			return next.RoundTrip(r.Clone(r.Context()))
		})
	}
	a, err := NewHTTPAccess(config)
	if err != nil {
		t.Fatal(err)
	}
	key, o := accessObject()
	if _, err := a.Create(context.Background(), key, o, false); !errors.Is(err, ErrRead) || requests.Load() != 1 {
		t.Fatalf("wrapper replay escaped guard: %d %v", requests.Load(), err)
	}
}

func TestHTTPAccessRefusesRedirectsAndMalformedEvidence(t *testing.T) {
	var redirects atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects.Add(1) }))
	defer target.Close()
	key, o := accessObject()
	for _, scenario := range []string{"redirect", "duplicate", "deep", "huge", "wrong-gvk", "wrong-address", "bad-type", "not-found", "conflict"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch scenario {
				case "redirect":
					http.Redirect(w, r, target.URL, 307)
				case "duplicate":
					_, _ = io.WriteString(w, `{"kind":"Secret","kind":"ServiceAccount","apiVersion":"v1","metadata":{"name":"reviewed","namespace":"isolated-install"}}`)
				case "deep":
					_, _ = io.WriteString(w, strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65))
				case "huge":
					_, _ = io.WriteString(w, strings.Repeat(" ", 1024*1024+1))
				case "wrong-gvk":
					changed := o.DeepCopy()
					changed.SetKind("Secret")
					_ = json.NewEncoder(w).Encode(changed)
				case "wrong-address":
					changed := o.DeepCopy()
					changed.SetName("foreign")
					_ = json.NewEncoder(w).Encode(changed)
				case "bad-type":
					w.Header().Set("Content-Type", "text/plain")
					_ = json.NewEncoder(w).Encode(o)
				case "not-found":
					w.WriteHeader(404)
					_, _ = io.WriteString(w, "PRIVATE-CANARY")
				case "conflict":
					w.WriteHeader(409)
					_, _ = io.WriteString(w, "PRIVATE-CANARY")
				}
			}))
			defer server.Close()
			a, err := NewHTTPAccess(serverConfig(server))
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.Get(context.Background(), key)
			if err == nil || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("malformed evidence accepted/reflected")
			}
			if scenario == "not-found" && !apierrors.IsNotFound(err) || scenario == "conflict" && !apierrors.IsConflict(err) {
				t.Fatal("fixed classification lost")
			}
		})
	}
	if redirects.Load() != 0 {
		t.Fatal("redirect target contacted")
	}
}

func TestHTTPAccessPreservesIntegerAndDryRunQuery(t *testing.T) {
	key, o := accessObject()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dryRun") != "All" || r.URL.Query().Get("fieldValidation") != "Strict" || r.URL.Path != "/api/v1/namespaces/isolated-install/serviceaccounts" {
			t.Error("unexpected request")
		}
		o := o.DeepCopy()
		o.SetGeneration(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(o)
	}))
	defer server.Close()
	a, err := NewHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	live, err := a.Create(context.Background(), key, o, true)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok, _ := unstructured.NestedInt64(live.Object, "metadata", "generation"); !ok || value != 1 {
		t.Fatal("integer changed to float64")
	}
}

func TestHTTPAccessRejectsUnsafeConfigAndUnreviewedAddresses(t *testing.T) {
	for _, config := range []*rest.Config{nil, {Host: "http://example.invalid"}, {Host: "https://user@example.invalid"}, {Host: "https://example.invalid?private=1"}, {Host: "https://example.invalid", TLSClientConfig: rest.TLSClientConfig{Insecure: true}}, {Host: "https://example.invalid", ExecProvider: &clientcmdapi.ExecConfig{}}, {Host: "https://example.invalid", AuthProvider: &clientcmdapi.AuthProviderConfig{}}} {
		if _, err := NewHTTPAccess(config); !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe config accepted")
		}
	}
	key, _ := accessObject()
	for _, change := range []func(*installstate.Key){func(k *installstate.Key) { k.Name = "../foreign" }, func(k *installstate.Key) { k.Kind = "Secret" }, func(k *installstate.Key) { k.Namespace = "" }, func(k *installstate.Key) { k.Kind = "Namespace" }} {
		bad := key
		change(&bad)
		if _, err := resourcePath(bad, false); !errors.Is(err, ErrInvalid) {
			t.Fatal("unreviewed address accepted")
		}
	}
}

func TestCredentialsAreProtectedStaticSnapshots(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(base, "token")
	keyPath := filepath.Join(base, "key")
	certPath := filepath.Join(base, "certificate")
	caPath := filepath.Join(base, "ca")
	for path, body := range map[string]string{tokenPath: "fake-test-token\n", keyPath: "fake-test-key", certPath: "fake-test-certificate", caPath: "fake-test-ca"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := &rest.Config{BearerTokenFile: tokenPath, TLSClientConfig: rest.TLSClientConfig{KeyFile: keyPath, CertFile: certPath, CAFile: caPath}}
	if err := freezeCredentials(c); err != nil {
		t.Fatal(err)
	}
	if c.BearerToken != "fake-test-token" || string(c.KeyData) != "fake-test-key" || c.BearerTokenFile != "" || c.KeyFile != "" || c.CertFile != "" || c.CAFile != "" {
		t.Fatal("rotating credential sources retained")
	}
	if err := os.WriteFile(tokenPath, []byte("replacement-test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if c.BearerToken != "fake-test-token" {
		t.Fatal("credential snapshot changed")
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := freezeCredentials(&rest.Config{TLSClientConfig: rest.TLSClientConfig{KeyFile: keyPath}}); !errors.Is(err, ErrInvalid) {
		t.Fatal("unprotected private key accepted")
	}
	if err := freezeCredentials(&rest.Config{BearerTokenFile: filepath.Join(base, "absent-private-file")}); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "absent-private-file") {
		t.Fatal("private file error reflected")
	}
	data := []byte("fake-test-ca")
	c = &rest.Config{TLSClientConfig: rest.TLSClientConfig{CAData: data}}
	if err := freezeCredentials(c); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	if string(c.CAData) != "fake-test-ca" {
		t.Fatal("mutable auth bytes not snapshotted")
	}
}

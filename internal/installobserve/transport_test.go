// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const validMetadata = `{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadata","metadata":{"name":"a","namespace":"isolated-install","uid":"uid-a","resourceVersion":"1"}}`
const validMetadataList = `{"apiVersion":"meta.k8s.io/v1","kind":"PartialObjectMetadataList","metadata":{"resourceVersion":"1"},"items":[` + validMetadata + `]}`

func TestMetadataEnvelopeRejectsFallbackAndAmbiguousJSON(t *testing.T) {
	for _, value := range []string{validMetadata, strings.Replace(validMetadata, `"metadata":{`, `"metadata":{"annotations":{"arbitrary":"secret-canary"},"managedFields":[],"finalizers":["a/b"],`, 1)} {
		if !metadataEnvelope([]byte(value), "PartialObjectMetadata") {
			t.Fatal("valid metadata envelope rejected")
		}
	}
	for _, value := range []string{validMetadataList, strings.Replace(validMetadataList, `"items":[`+validMetadata+`]`, `"items":null`, 1)} {
		if !metadataEnvelope([]byte(value), "PartialObjectMetadataList") {
			t.Fatal("valid metadata list rejected")
		}
	}
	for _, value := range []string{
		`{"apiVersion":"v1","kind":"Secret","metadata":{"name":"a"},"data":{"password":"secret-canary"}}`,
		strings.Replace(validMetadata, `"metadata":`, `"data":{"password":"secret-canary"},"metadata":`, 1),
		strings.Replace(validMetadata, `"metadata":`, `"spec":{},"metadata":`, 1),
		strings.Replace(validMetadata, `"metadata":`, `"status":{},"metadata":`, 1),
		strings.Replace(validMetadata, `"name":"a"`, `"name":"a","name":"b"`, 1),
		strings.Replace(validMetadata, `"kind":"PartialObjectMetadata"`, `"kind":"Secret","kind":"PartialObjectMetadata"`, 1),
		strings.Replace(validMetadata, `"metadata":{`, `"metadata":null,"ignored":{`, 1),
		validMetadata + validMetadata, "", validMetadata + "\xff",
		strings.Replace(validMetadata, `"metadata":{`, `"metadata":{"annotations":{"deep":`+strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65)+`},`, 1),
	} {
		if metadataEnvelope([]byte(value), "PartialObjectMetadata") {
			t.Fatal("unsafe metadata body accepted")
		}
	}
	if metadataEnvelope([]byte(strings.Replace(validMetadataList, validMetadata, strings.Replace(validMetadata, `"kind":"PartialObjectMetadata"`, `"kind":"Secret"`, 1), 1)), "PartialObjectMetadataList") {
		t.Fatal("full object list item accepted")
	}
}

func TestStrictTransportBeforeRealMetadataDecoder(t *testing.T) {
	for _, list := range []bool{false, true} {
		for _, bad := range []bool{false, true} {
			kind, body := "PartialObjectMetadata", validMetadata
			if list {
				kind, body = "PartialObjectMetadataList", validMetadataList
			}
			body = strings.ReplaceAll(body, `"uid":"uid-a"`, `"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"secret-canary"},"labels":{"private":"secret-canary"},"uid":"uid-a"`)
			if bad {
				body = strings.Replace(body, `"metadata":`, `"data":{"token":"secret-canary"},"metadata":`, 1)
			}
			calls := 0
			transport := readTransport{metadata: true, next: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/json;as="+kind+";g=meta.k8s.io;v=v1" {
					t.Fatal("full-object or protobuf fallback negotiated")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}, "Warning": []string{"secret-canary"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			client, err := metadata.NewForConfigAndClient(&rest.Config{Host: "https://cluster.example"}, &http.Client{Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			resource := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).Namespace("isolated-install")
			if list {
				objects, gotErr := resource.List(context.Background(), metav1.ListOptions{Limit: 128})
				err = gotErr
				if !bad && (objects == nil || len(objects.Items) != 1 || objects.Items[0].UID != "uid-a" || objects.Items[0].Annotations != nil || objects.Items[0].Labels != nil) {
					t.Fatal("valid list did not survive the real decoder")
				}
			} else {
				object, gotErr := resource.Get(context.Background(), "a", metav1.GetOptions{})
				err = gotErr
				if !bad && (object == nil || object.UID != "uid-a" || object.Annotations != nil || object.Labels != nil) {
					t.Fatal("valid object did not survive the real decoder")
				}
			}
			if calls < 1 || bad != (err != nil) || err != nil && strings.Contains(err.Error(), "secret-canary") {
				t.Fatal("unsafe response was accepted or reflected")
			}
		}
	}
}

func TestMetadataBodyIsSanitizedBeforeClientLogging(t *testing.T) {
	for _, kind := range []string{"PartialObjectMetadata", "PartialObjectMetadataList"} {
		body := validMetadata
		if kind == "PartialObjectMetadataList" {
			body = validMetadataList
		}
		body = strings.ReplaceAll(body, `"uid":"uid-a"`, `"annotations":{"private":"secret-canary"},"labels":{"private":"secret-canary"},"managedFields":[{"manager":"secret-canary"}],"uid":"uid-a"`)
		tpt := readTransport{metadata: true, next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}, "Warning": []string{"secret-canary"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		r, _ := http.NewRequest(http.MethodGet, "https://cluster.example", nil)
		r.Header.Set("Accept", "application/json;as="+kind+";g=meta.k8s.io;v=v1,application/json")
		response, err := tpt.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		filtered, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || strings.Contains(string(filtered), "secret-canary") || response.Header.Get("Warning") != "" || !metadataEnvelope(filtered, kind) {
			t.Fatal("private metadata can reach response logging")
		}
	}
}

type trackedBody struct {
	io.Reader
	closed bool
}

func TestSuppliedWrapperOnlySeesSanitizedMetadataAndErrors(t *testing.T) {
	for _, scenario := range []string{"metadata", "fallback", "error"} {
		t.Run(scenario, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", `application/json; private="secret-canary"`)
				w.Header().Set("Warning", "secret-canary")
				w.Header().Set("Set-Cookie", "secret-canary")
				w.Header().Set("Trailer", "X-Private")
				defer w.Header().Set("X-Private", "secret-canary")
				if scenario == "error" {
					w.WriteHeader(403)
					_, _ = io.WriteString(w, "secret-canary")
					return
				}
				if scenario == "fallback" {
					_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"a"},"data":{"token":"secret-canary"}}`)
					return
				}
				_, _ = io.WriteString(w, strings.Replace(validMetadata, `"metadata":{`, `"metadata":{"annotations":{"private":"secret-canary"},"labels":{"private":"secret-canary"},`, 1))
			}))
			defer srv.Close()
			config := &rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}}
			calls := 0
			config.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
				return roundTripFunc(func(r *http.Request) (*http.Response, error) {
					calls++
					response, err := next.RoundTrip(r)
					if err != nil {
						if response != nil || strings.Contains(err.Error(), "secret-canary") {
							t.Error("private failure escaped read boundary")
						}
						return response, err
					}
					body, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil || strings.Contains(string(body), "secret-canary") || len(response.Header) != 1 || response.Header.Get("Content-Type") != "application/json" || len(response.Trailer) != 0 || response.Status != "200 OK" {
						t.Error("supplied instrumentation received private body/header")
					}
					response.Body = io.NopCloser(strings.NewReader(string(body)))
					return response, nil
				})
			}
			h, err := strictHTTPClient(config, true)
			if err != nil {
				t.Fatal(err)
			}
			client, err := metadata.NewForConfigAndClient(config, h)
			if err != nil {
				t.Fatal(err)
			}
			object, err := client.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).Namespace("isolated-install").Get(context.Background(), "a", metav1.GetOptions{})
			if calls != 1 || (err == nil) != (scenario == "metadata") || err != nil && strings.Contains(err.Error(), "secret-canary") || err == nil && (object.Annotations != nil || object.Labels != nil) {
				t.Fatal("guard/wrapper order did not establish sanitized one-read result")
			}
		})
	}
}

func TestPublicReadSyntaxIsStrictBeforeSDKDecode(t *testing.T) {
	for _, body := range []string{
		`{"kind":"PodList","kind":"PodList"}`, `{"metadata":{"resourceVersion":"one","resourceVersion":"two"}}`,
		`{"items":[]} {}`, `{"items":[]} ` + "\xff", strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65),
	} {
		tpt := readTransport{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		r, _ := http.NewRequest(http.MethodGet, "https://cluster.example", nil)
		if response, err := tpt.RoundTrip(r); response != nil || err != ErrRead {
			t.Fatal("ambiguous public body reached SDK decoder")
		}
	}
}

func TestMetadataIdentityCannotUseCaseAliasesOrUnknownFields(t *testing.T) {
	for _, body := range []string{
		strings.Replace(validMetadata, `"uid":`, `"UID":`, 1),
		strings.Replace(validMetadata, `"metadata":{`, `"metadata":{"OwnerReferences":[],`, 1),
		strings.Replace(validMetadata, `"metadata":{`, `"metadata":{"unreviewed":"secret-canary",`, 1),
	} {
		if sanitized, err := sanitizedMetadata([]byte(body), "PartialObjectMetadata"); sanitized != nil || err != ErrRead {
			t.Fatal("malformed owner metadata became authoritative sanitized identity")
		}
	}
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestReadTransportBoundsClosesAndRedacts(t *testing.T) {
	for _, tc := range []struct {
		method, contentType, body string
		status                    int
	}{
		{"POST", "application/json", validMetadata, 200},
		{"GET", "application/json", "secret-canary", 403},
		{"GET", "application/json", "secret-canary", 410},
		{"GET", "application/octet-stream", "secret-canary", 200},
		{"GET", "application/json", strings.Repeat("x", maxResponseBytes+1), 200},
		{"GET", "application/json", "", 200},
	} {
		body := &trackedBody{Reader: strings.NewReader(tc.body)}
		calls := 0
		tpt := readTransport{next: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{tc.contentType}}, Body: body}, nil
		})}
		r, _ := http.NewRequest(tc.method, "https://cluster.example", nil)
		response, err := tpt.RoundTrip(r)
		if response != nil || !errors.Is(err, ErrRead) || strings.Contains(err.Error(), "secret-canary") || calls > 0 && !body.closed {
			t.Fatal("invalid response not closed and redacted")
		}
	}
	transport := readTransport{metadata: true, next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unrecognized metadata operation reached transport")
		return nil, nil
	})}
	r, _ := http.NewRequest(http.MethodGet, "https://cluster.example", nil)
	if _, err := transport.RoundTrip(r); !errors.Is(err, ErrRead) {
		t.Fatal("missing metadata operation accepted")
	}
}

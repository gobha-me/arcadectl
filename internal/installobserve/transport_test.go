// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"context"
	"errors"
	"io"
	"net/http"
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

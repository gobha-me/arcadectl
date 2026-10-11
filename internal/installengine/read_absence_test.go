// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

type absentReadTestBody struct {
	reader                  io.Reader
	reads, consumed, closes int
}

func (b *absentReadTestBody) Read(p []byte) (int, error) {
	b.reads++
	n, err := b.reader.Read(p)
	b.consumed += n
	return n, err
}

func (b *absentReadTestBody) Close() error { b.closes++; return nil }

type absentReadTestError struct{}

func (absentReadTestError) Read([]byte) (int, error) {
	return 0, errors.New("PRIVATE-DISCARD-ERROR-CANARY")
}

type absentReadTestSignalBody struct {
	io.ReadCloser
	started chan struct{}
	once    atomic.Bool
}

func (b *absentReadTestSignalBody) Read(p []byte) (int, error) {
	if b.once.CompareAndSwap(false, true) {
		close(b.started)
	}
	return b.ReadCloser.Read(p)
}

// Literal byte counts independently check the wire guard's consumption and
// closure; no result or native diagnostic becomes proof/caller authority.
func testDirectReadPoolAbsentDrainBounds(t *testing.T) {
	for _, c := range []struct {
		name, method string
		status       int
		length       int64
		uncompressed bool
		size, want   int
		readError    bool
	}{
		{"small", "GET", 404, 16, false, 16, 16, false},
		{"exact-bound", "GET", 404, 8192, false, 8192, 8192, false},
		{"unknown-exact-bound", "GET", 404, -1, false, 8192, 8192, false},
		{"known-oversize", "GET", 404, 8193, false, 16384, 0, false},
		{"unknown-oversize", "GET", 404, -1, false, 16384, 8193, false},
		{"decompressed", "GET", 404, -1, true, 16384, 0, false},
		{"post-not-found", "POST", 404, 16, false, 16, 0, false},
		{"put-not-found", "PUT", 404, 16, false, 16, 0, false},
		{"delete-not-found", "DELETE", 404, 16, false, 16, 0, false},
		{"forbidden-read", "GET", 403, 16, false, 16, 0, false},
		{"retry-after-read", "GET", 429, 16, false, 16, 0, false},
		{"server-error-read", "GET", 503, 16, false, 16, 0, false},
		{"native-read-error", "GET", 404, 16, false, 0, 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := &absentReadTestBody{reader: bytes.NewReader(bytes.Repeat([]byte("x"), c.size))}
			if c.readError {
				body.reader = absentReadTestError{}
			}
			attempt := &requestAttempt{method: c.method}
			ctx := context.WithValue(t.Context(), attemptKey{}, attempt)
			request, err := http.NewRequestWithContext(ctx, c.method, "https://cluster.example/api/v1/namespaces/test/serviceaccounts/original", nil)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			guard := attemptTransport{roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: c.status, Status: "PRIVATE-STATUS-CANARY", Header: http.Header{"Content-Type": {"application/json"}, "Warning": {"PRIVATE-HEADER-CANARY"}, "Retry-After": {"PRIVATE-RETRY-CANARY"}}, Trailer: http.Header{"Private": {"PRIVATE-TRAILER-CANARY"}}, Body: body, ContentLength: c.length, Uncompressed: c.uncompressed}, nil
			})}
			response, err := guard.RoundTrip(request)
			if err != nil || response == nil {
				t.Fatal("original guarded request refused")
			}
			public, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || string(public) != `{}` || len(response.Header) != 1 || response.Header.Get("Content-Type") != "application/json" || response.Trailer != nil || response.ContentLength != 2 || strings.Contains(response.Status, "CANARY") {
				t.Fatal("native error diagnostics escaped sanitizer")
			}
			if body.consumed != c.want || body.closes != 1 || calls != 1 || c.want == 0 && !c.readError && body.reads != 0 || c.readError && body.reads != 1 {
				t.Fatalf("discard bound/closure changed: read=%d consumed=%d closes=%d attempts=%d", body.reads, body.consumed, body.closes, calls)
			}
			if _, err := guard.RoundTrip(request.Clone(ctx)); !errors.Is(err, ErrOutcomeUnknown) || calls != 1 {
				t.Fatal("discard introduced request replay")
			}
		})
	}
}

// No sleep or new production timer: server headers/body readiness triggers
// caller cancellation, and both operation and native handler are joined.
func testDirectReadPoolAbsentDrainCancellation(t *testing.T) {
	testDirectReadPoolAbsentDrainCancellationAtFixture(t, false)
}

func testDirectReadPoolAbsentDrainCancellationAtFixture(t *testing.T, fixture bool) {
	key, object := accessObject()
	ready, draining, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var requests, got, reused, handshakes atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/isolated-install/serviceaccounts/reviewed" || r.ProtoMajor != 1 || r.Header.Get("Authorization") != "Bearer TEST-ONLY-CANCEL-DRAIN" {
			t.Error("cancelled read changed original wire identity")
		}
		w.Header().Set("Content-Type", "application/json")
		if requests.Add(1) == 1 {
			w.Header().Set("Warning", "PRIVATE-CANCEL-HEADER-CANARY")
			w.Header().Set("Retry-After", "PRIVATE-CANCEL-RETRY-CANARY")
			w.Header().Set("Trailer", "X-Private-Trailer")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("{"))
			w.(http.Flusher).Flush()
			close(ready)
			<-r.Context().Done()
			close(handlerDone)
			return
		}
		_, _ = io.WriteString(w, `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"reviewed","namespace":"isolated-install"}}`)
	}))
	config := serverConfig(server)
	config.BearerToken = "TEST-ONLY-CANCEL-DRAIN"
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		server.Close()
		t.Fatal("direct static parent refused")
	}
	t.Cleanup(server.Close)
	t.Cleanup(access.pool.(*http.Transport).CloseIdleConnections)
	// Test-only body observer below the original attempt guard, still over
	// the actual frozen raw TLS pool. Static auth is independently wrapped
	// from the unchanged canonical config. No constructor routing callback
	// or fabricated body replaces the native incomplete response.
	observed := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := access.pool.RoundTrip(r)
		if err == nil && response != nil && response.StatusCode == http.StatusNotFound {
			response.Body = &absentReadTestSignalBody{ReadCloser: response.Body, started: draining}
		}
		return response, err
	})
	// Keep the actual derived pool/identity lineage. Only this test's body
	// observer sits below capture, signalling entry into native Body.Read.
	var guarded http.RoundTripper = attemptTransport{observed}
	if fixture {
		access = derivedFixturePoolAccess(t, access, key)
		guarded = fixtureIdentityTransport{next: guarded, identity: fixturePoolIdentity(access, key)}
	}
	access.client.Transport, err = rest.HTTPWrappersForConfig(config, guarded)
	if err != nil {
		t.Fatal("unchanged frozen auth wrapper refused")
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		got.Add(1)
		if info.Reused {
			reused.Add(1)
		}
	}, TLSHandshakeStart: func() { handshakes.Add(1) }}
	ctx = httptrace.WithClientTrace(ctx, trace)
	type cancellationResult struct {
		err     error
		private bool
	}
	result := make(chan cancellationResult, 1)
	go func() {
		if fixture {
			capture, response, err := fixturePoolRead(ctx, access, key, false)
			// Inspect actual native-returned error and above-wrapper bytes
			// BEFORE replacing errors with the fixed test result category.
			private := !fixturePoolCancellationPublicSafe(response, err)
			if err != nil || capture == nil || response == nil || !capture.notFound {
				result <- cancellationResult{err: ErrRead, private: private}
			} else {
				// A non-strict native 404 remains its old classification; only
				// the enclosing phase may certify complete live evidence.
				result <- cancellationResult{err: apierrors.NewNotFound(schema.GroupResource{Resource: "serviceaccounts"}, key.Name), private: private}
			}
			return
		}
		_, err := access.Get(ctx, key)
		result <- cancellationResult{err: err}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("native body did not open")
	}
	select {
	case <-draining:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("native discard never entered Body.Read")
	}
	// Cancellation is issued while the original context is active and the
	// client is inside the incomplete native Body.Read, not just after the
	// server flushed headers or after an arbitrary sleep.
	if ctx.Err() != nil {
		t.Fatal("original request already expired")
	}
	cancel()
	select {
	case outcome := <-result:
		err := outcome.err
		if outcome.private || err == nil || !apierrors.IsNotFound(err) && !errors.Is(err, ErrRead) || strings.Contains(err.Error(), "CANARY") {
			t.Fatal("cancelled absence lost sanitized error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("discard ignored caller cancellation")
	}
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("native handler not joined")
	}
	// A fixture derivative cannot make a generic request. Recreate a normal
	// direct parent over the same raw pool for the independent post-cancel read.
	if fixture {
		access, err = newHTTPAccessWithPool(config, true, access.pool)
		if err != nil {
			t.Fatal("independent post-cancel parent refused")
		}
	}
	if live, err := access.Get(httptrace.WithClientTrace(t.Context(), trace), key); err != nil || live == nil || live.GetName() != object.GetName() {
		t.Fatal("next independent request refused")
	}
	if requests.Load() != 2 || got.Load() != 2 || reused.Load() != 0 || handshakes.Load() != 2 || access.client.Timeout != 30*time.Second || ctx.Err() != context.Canceled {
		t.Fatal("cancelled body replayed, reused an incomplete connection or changed finite client budget")
	}
}

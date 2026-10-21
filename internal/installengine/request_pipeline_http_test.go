// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pipelineCloseBody struct {
	io.Reader
	closed atomic.Int32
}

type pipelineGateBody struct {
	io.Reader
	ctx      context.Context
	entered  chan struct{}
	release  <-chan struct{}
	once     sync.Once
	closed   atomic.Int32
	failRead bool
}

func (b *pipelineGateBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-b.release:
	}
	if b.failRead {
		return 0, errors.New("PRIVATE-CANARY")
	}
	return b.Reader.Read(p)
}

func (b *pipelineGateBody) Close() error { b.closed.Add(1); return nil }

// Channel barriers distinguish headers, native guarded capture and the outer
// body reader without attributing wall-time subtraction to local CPU/network.
// This is a private in-memory transport fixture, not native cluster evidence.
func TestRequestPipelineHeadersBodyAndNativeCaptureBoundaries(t *testing.T) {
	for _, mode := range []string{"headers", "headers-cancel", "outer-body", "body-error", "body-cancel", "native-capture", "native-body-error", "native-body-cancel"} {
		t.Run(mode, func(t *testing.T) {
			native := strings.HasPrefix(mode, "native-")
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx, costs := WithLifecycleCosts(ctx)
			ctx, endPhase := baselineProbePhaseContext(ctx, baselineProbeOpening)
			defer endPhase()
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseBody := func() { releaseOnce.Do(func() { close(release) }) }
			key, object := accessObject()
			probe := namedProbeFixture("Pod")
			if native {
				object = probe
			}
			encoded, err := json.Marshal(object.Object)
			if err != nil {
				t.Fatal("fixed response unavailable")
			}
			body := &pipelineGateBody{Reader: bytes.NewReader(encoded), ctx: ctx, entered: make(chan struct{}), release: release, failRead: mode == "body-error" || mode == "native-body-error"}
			headersEntered := make(chan struct{})
			underlying := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if strings.HasPrefix(mode, "headers") {
					close(headersEntered)
					select {
					case <-request.Context().Done():
						return nil, request.Context().Err()
					case <-release:
					}
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: body}, nil
			})
			base, _ := url.Parse("https://owned-fixture.invalid")
			access := &HTTPAccess{base: base, client: &http.Client{Transport: attemptTransport{next: underlying}}}
			result, joined := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(joined)
				if native {
					_, err := access.probeOperation(ctx, probeUpdateOperation, probe, "", "", "")
					result <- err
				} else {
					_, err := access.Get(ctx, key)
					result <- err
				}
			}()
			t.Cleanup(func() {
				cancel()
				releaseBody()
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("inert request goroutine did not join")
				}
			})
			entered := body.entered
			if strings.HasPrefix(mode, "headers") {
				entered = headersEntered
			}
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("inert request boundary was not reached")
			}
			// Only atomic counters are inspected while a call is held. This is
			// not the after-join snapshot or a cross-counter proof snapshot.
			metric := func(kind requestPipelineKind) *requestPipelineMetric {
				return &costs.pipeline.metrics[pipelineBaselineOpening][kind]
			}
			if strings.HasPrefix(mode, "headers") {
				if metric(pipelineClientDo).returned.Load() != 0 || metric(pipelineHeaders).calls.Load() != 1 || metric(pipelineHeaders).returned.Load() != 0 || metric(pipelinePostHeaders).calls.Load() != 0 || metric(pipelineBodyRead).calls.Load() != 0 {
					t.Fatal("headers were mislabeled as completed body work")
				}
			} else if native {
				if metric(pipelineHeaders).returned.Load() != 1 || metric(pipelinePostHeaders).calls.Load() != 1 || metric(pipelinePostHeaders).returned.Load() != 0 || metric(pipelineClientDo).returned.Load() != 0 || metric(pipelineBodyRead).calls.Load() != 0 {
					t.Fatal("native capture was mislabeled as outer body or header-only time")
				}
			} else if metric(pipelineClientDo).returned.Load() != 1 || metric(pipelineHeaders).returned.Load() != 1 || metric(pipelinePostHeaders).returned.Load() != 1 || metric(pipelineBodyRead).calls.Load() != 1 || metric(pipelineBodyRead).returned.Load() != 0 || metric(pipelineValidation).calls.Load() != 0 {
				t.Fatal("outer body read was included in Do or post-body validation")
			}
			if strings.Contains(mode, "cancel") {
				cancel()
			} else {
				releaseBody()
			}
			var commandErr error
			select {
			case commandErr = <-result:
			case <-ctx.Done():
				// Cancellation is intentional in these cases; wait for the same
				// goroutine's terminal result instead of accepting ctx as proof.
				select {
				case commandErr = <-result:
				case <-time.After(time.Second):
					t.Fatal("canceled inert request did not return")
				}
			}
			wantErr := error(nil)
			if strings.Contains(mode, "cancel") || mode == "body-error" {
				wantErr = ErrRead
			}
			if native && (mode == "native-body-error" || mode == "native-body-cancel") {
				wantErr = ErrAdmission
			}
			if commandErr != wantErr {
				t.Fatal("measurement changed bounded body or cancellation refusal")
			}
			<-joined
			wantCloses := int32(1)
			if mode == "headers-cancel" {
				wantCloses = 0 // No response body was transferred to the caller.
			}
			if body.closed.Load() != wantCloses {
				t.Fatal("measurement changed native/outer response body ownership")
			}
			for _, row := range requestPipelineTestRows(t, costs.pipeline) {
				if row.Calls != row.Returned {
					t.Fatal("joined request left an unclosed measurement span")
				}
			}
		})
	}
}

func (b *pipelineCloseBody) Close() error { b.closed.Add(1); return nil }

func TestRequestPipelineDoPreservesDelegationAndBodyOwnership(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, mode := range []string{"success", "error", "canceled"} {
			t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled]+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				var costs *LifecycleCosts
				if enabled {
					ctx, costs = WithLifecycleCosts(ctx)
				}
				private := errors.New("PRIVATE-CANARY")
				if mode == "canceled" {
					cancel(private)
				}
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fixture.invalid/reviewed", strings.NewReader("PRIVATE-CANARY"))
				if err != nil {
					t.Fatal("inert request unavailable")
				}
				request.Header.Set("Authorization", "PRIVATE-CANARY")
				body := &pipelineCloseBody{Reader: strings.NewReader("PRIVATE-CANARY")}
				response := &http.Response{StatusCode: 200, Header: http.Header{}, Body: body}
				calls := 0
				client := &http.Client{Transport: roundTripFunc(func(got *http.Request) (*http.Response, error) {
					calls++
					data, readErr := io.ReadAll(got.Body)
					got.Body.Close()
					if got != request || got.Context() != ctx || got.Header.Get("Authorization") != "PRIVATE-CANARY" || readErr != nil || string(data) != "PRIVATE-CANARY" {
						t.Error("observer replaced request, context, headers or bytes")
					}
					if mode == "error" {
						return nil, private
					}
					if mode == "canceled" {
						if context.Cause(got.Context()) != private {
							t.Error("observer replaced cancellation cause")
						}
						return nil, got.Context().Err()
					}
					return response, nil
				})}
				got, commandErr := requestPipelineDo(client, request)
				wantCalls := 1
				if calls != wantCalls || body.closed.Load() != 0 || mode == "success" && (got != response || commandErr != nil) || mode == "error" && !errors.Is(commandErr, private) || mode == "canceled" && !errors.Is(commandErr, context.Canceled) {
					t.Fatal("observer changed delegation, result, cancellation or body ownership")
				}
				if got != nil {
					data, readErr := io.ReadAll(got.Body)
					got.Body.Close()
					if readErr != nil || string(data) != "PRIVATE-CANARY" || body.closed.Load() != 1 {
						t.Fatal("caller lost original response body")
					}
				}
				if enabled {
					metric := &costs.pipeline.metrics[pipelineOther][pipelineClientDo]
					if metric.calls.Load() != uint64(wantCalls) || metric.returned.Load() != uint64(wantCalls) || strings.Contains(costs.RequestPipelineSnapshot(), "PRIVATE-CANARY") {
						t.Fatal("observer lost joined command counts or retained private data")
					}
				}
			})
		}
	}
}

func TestRequestPipelineNilRequestMatchesClientBehavior(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("nil request reached a transport")
		return nil, ErrRead
	})}
	type outcome struct{ panic, error, response bool }
	observe := func(call func() (*http.Response, error)) (result outcome) {
		defer func() { result.panic = recover() != nil }()
		response, err := call()
		result.error, result.response = err != nil, response != nil
		return
	}
	original := observe(func() (*http.Response, error) { return client.Do(nil) })
	wrapped := observe(func() (*http.Response, error) { return requestPipelineDo(client, nil) })
	if original != wrapped {
		t.Fatal("observer changed invalid request behavior")
	}
}

// Static coverage is a guard against newly bypassing the ONE shared wrapper,
// not dynamic request/authorization proof. Behavioral controls follow below.
func TestRequestPipelineAllSevenDirectCallSitesAreCovered(t *testing.T) {
	want := map[string]int{"access.go": 1, "proof_access.go": 1, "probe_access.go": 1, "fixture_wire.go": 1, "fixture_admission_counterpart.go": 1, "fixture_retained_marker_wire.go": 1, "fixture_marked_cleanup.go": 1}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal("tracked source census unavailable")
	}
	got := map[string]int{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal("production request source unavailable")
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "requestPipelineDo" {
				got[entry.Name()]++
			}
			if method, ok := call.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Do" {
				if receiver, ok := method.X.(*ast.SelectorExpr); ok && receiver.Sel.Name == "client" {
					t.Error("direct HTTP access bypassed complete-command observation")
				}
			}
			return true
		})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("direct request hook census changed without reviewed coverage")
	}
}

func TestRequestPipelineActualReadProofAndProbeWireTraceParity(t *testing.T) {
	type wireRow struct {
		Method, Host, URI, Body string
		Header                  http.Header
		ContentLength           int64
		TransferEncoding        []string
	}
	var rows []wireRow
	var mu sync.Mutex
	key, object := accessObject()
	object.SetUID("original-uid")
	object.SetResourceVersion("17")
	probe := namedProbeFixture("Pod")
	fault := false
	a := proofServer(t, func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		rows = append(rows, wireRow{Method: request.Method, Host: request.Host, URI: request.URL.RequestURI(), Body: string(body), Header: request.Header.Clone(), ContentLength: request.ContentLength, TransferEncoding: append([]string(nil), request.TransferEncoding...)})
		failed := fault
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if failed {
			w.WriteHeader(503)
			io.WriteString(w, "PRIVATE-CANARY")
			return
		}
		switch request.URL.Path {
		case "/version":
			io.WriteString(w, `{"kind":"Proof","value":7}`)
		case "/api/v1/namespaces/isolated-install/serviceaccounts/reviewed":
			json.NewEncoder(w).Encode(object.Object)
		default:
			json.NewEncoder(w).Encode(probe.Object)
		}
	})
	var lastRows []wireRow
	for _, failed := range []bool{false, true} {
		mu.Lock()
		fault = failed
		mu.Unlock()
		var original []wireRow
		for _, enabled := range []bool{false, true} {
			mu.Lock()
			rows = nil
			mu.Unlock()
			ctx := t.Context()
			var costs *LifecycleCosts
			if enabled {
				ctx, costs = WithLifecycleCosts(ctx)
			}
			ctx, endPhase := baselineProbePhaseContext(ctx, baselineProbeClosing)
			read, readErr := a.Get(ctx, key)
			var proof map[string]any
			_, proofErr := a.proofRequest(ctx, http.MethodGet, "/version", nil, &proof)
			observed, probeErr := a.probeOperation(ctx, probeUpdateOperation, probe, "", "", "")
			endPhase()
			mu.Lock()
			trace := append([]wireRow(nil), rows...)
			mu.Unlock()
			lastRows = trace
			if len(trace) != 3 || !failed && (readErr != nil || proofErr != nil || probeErr != nil || read.GetUID() != "original-uid" || observed.GetUID() != probe.GetUID()) || failed && (readErr == nil || proofErr != ErrRead || probeErr != ErrAdmission) {
				t.Fatal("actual request paths changed fixed outcomes or attempted a replay")
			}
			if !enabled {
				original = trace
			} else {
				if !reflect.DeepEqual(original, trace) {
					t.Fatal("enabled observer changed exact wire headers, order or body bytes")
				}
				wantBodyReads := uint64(2)
				if failed {
					wantBodyReads = 0
				}
				for _, kind := range []requestPipelineKind{pipelineBodyRead, pipelineValidation} {
					metric := &costs.pipeline.metrics[pipelineBaselineClosing][kind]
					if metric.calls.Load() != wantBodyReads || metric.returned.Load() != wantBodyReads {
						t.Fatal("outer body/validation accounting included guarded native capture")
					}
				}
				for _, kind := range []requestPipelineKind{pipelineClientDo, pipelineHeaders, pipelinePostHeaders} {
					metric := &costs.pipeline.metrics[pipelineBaselineClosing][kind]
					if metric.calls.Load() != 3 || metric.returned.Load() != 3 {
						t.Fatal("actual direct paths lost joined phase attribution")
					}
				}
				if strings.Contains(costs.RequestPipelineSnapshot(), "PRIVATE-CANARY") {
					t.Fatal("native response text entered scalar metrics")
				}
			}
		}
	}
	// Preserve canonical outgoing probe bytes, not merely decoded equality.
	wantBody, err := json.Marshal(probe.Object)
	if err != nil || len(lastRows) != 3 || !bytes.Equal([]byte(lastRows[2].Body), wantBody) {
		t.Fatal("probe request bytes lost their original constructor")
	}
}

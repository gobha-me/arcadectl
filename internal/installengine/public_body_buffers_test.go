// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

const publicBodyTestLimit int64 = 1024*1024 + 1

var publicBodyTestPartial = errors.New("bounded body read refused")

// This independent reader exercises data+EOF, partial errors and zero progress;
// both the frozen io.ReadAll oracle and the loan receive fresh reader instances.
type publicBodyTestReader struct {
	body         []byte
	chunk, zeros int
	dataEOF      bool
	final        error
}

func (r *publicBodyTestReader) Read(p []byte) (int, error) {
	if r.zeros > 0 {
		r.zeros--
		return 0, nil
	}
	if len(r.body) == 0 {
		if r.final != nil {
			err := r.final
			r.final = nil
			return 0, err
		}
		return 0, io.EOF
	}
	if r.chunk > 0 && len(p) > r.chunk {
		p = p[:r.chunk]
	}
	n := copy(p, r.body)
	r.body = r.body[n:]
	if len(r.body) == 0 {
		if r.final != nil {
			err := r.final
			r.final = nil
			return n, err
		}
		if r.dataEOF {
			return n, io.EOF
		}
	}
	return n, nil
}

func publicBodyTestAllZero(body []byte) bool {
	for _, b := range body {
		if b != 0 {
			return false
		}
	}
	return true
}

// A Reader may use all of p as scratch even when n is smaller. Force a grown
// final buffer with a dirty unused tail; release must clear its full capacity.
type publicBodyTestTailReader struct {
	reads     int
	tailBytes int
}

func (r *publicBodyTestTailReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 't'
	}
	r.reads++
	if r.reads == 1 {
		return len(p), nil
	}
	r.tailBytes = len(p)
	return 1, publicBodyTestPartial
}

func publicBodyTestPoolZero(t *testing.T, pool *publicBodyBuffers) {
	t.Helper()
	if pool == nil || pool.free == nil || len(pool.free) == 0 {
		t.Fatal("eligible read did not return scratch")
	}
	select {
	case scratch := <-pool.free:
		if len(scratch) != publicBodyBufferBytes || !publicBodyTestAllZero(scratch) {
			t.Fatal("retained scratch was not completely zeroed")
		}
		select {
		case pool.free <- scratch:
		default:
			t.Fatal("isolated scratch return unexpectedly blocked")
		}
	default:
		t.Fatal("isolated scratch unavailable")
	}
}

func TestPublicBodyBuffersReadAllOracle(t *testing.T) {
	for _, size := range []int{0, 1, 511, 512, 513, 65535, 65536, 65537, 1048576, 1048577, 1048593} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			body := bytes.Repeat([]byte("x"), size)
			wantReader, gotReader := bytes.NewReader(body), bytes.NewReader(body)
			want, wantErr := io.ReadAll(io.LimitReader(wantReader, publicBodyTestLimit))
			var pool publicBodyBuffers
			loan, gotErr := pool.read(io.LimitReader(gotReader, publicBodyTestLimit))
			defer loan.release()
			if !errors.Is(gotErr, wantErr) || !bytes.Equal(loan.body, want) || gotReader.Len() != wantReader.Len() {
				t.Fatal("limited complete read diverged from io.ReadAll")
			}
			if size > int(publicBodyTestLimit) && (len(loan.body) != int(publicBodyTestLimit) || gotReader.Len() != size-int(publicBodyTestLimit)) {
				t.Fatal("max-plus-one sentinel consumed excess input")
			}
		})
	}
	for _, row := range []struct {
		name         string
		chunk, zeros int
		dataEOF      bool
		final        error
	}{
		{"chunked", 7, 0, false, nil},
		{"data-and-eof", 7, 0, true, nil},
		{"partial-error", 7, 0, false, publicBodyTestPartial},
		{"101-zero-reads", 7, 101, false, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			makeReader := func() io.Reader {
				return &publicBodyTestReader{body: bytes.Repeat([]byte("value"), 211), chunk: row.chunk, zeros: row.zeros, dataEOF: row.dataEOF, final: row.final}
			}
			want, wantErr := io.ReadAll(io.LimitReader(makeReader(), publicBodyTestLimit))
			var pool publicBodyBuffers
			loan, gotErr := pool.read(io.LimitReader(makeReader(), publicBodyTestLimit))
			if !errors.Is(gotErr, wantErr) || !bytes.Equal(loan.body, want) {
				t.Fatal("reader edge diverged from independent io.ReadAll")
			}
			loan.release()
			publicBodyTestPoolZero(t, &pool)
		})
	}
}

func TestPublicBodyBuffersOwnershipZeroingAndCap(t *testing.T) {
	var zero publicBodyLoan
	zero.release()
	var absent *publicBodyLoan
	absent.release()
	t.Run("grown-reader-scratch-tail", func(t *testing.T) {
		var pool publicBodyBuffers
		reader := &publicBodyTestTailReader{}
		loan, err := pool.read(io.LimitReader(reader, publicBodyTestLimit))
		if err != publicBodyTestPartial || len(loan.body) != publicBodyBufferBytes+1 || reader.tailBytes <= 1 || publicBodyTestAllZero(loan.body[len(loan.body):cap(loan.body)]) {
			t.Fatal("grown dirty-tail control did not reach the partial read")
		}
		whole, scratch := loan.body[:cap(loan.body)], loan.scratch
		loan.release()
		if !publicBodyTestAllZero(whole) || !publicBodyTestAllZero(scratch) {
			t.Fatal("release left data beyond the returned body length")
		}
		publicBodyTestPoolZero(t, &pool)
	})
	for _, size := range []int{1, publicBodyBufferBytes - 1, publicBodyBufferBytes, publicBodyBufferBytes + 1, 2*publicBodyBufferBytes + 3} {
		t.Run(fmt.Sprintf("owned-%d", size), func(t *testing.T) {
			var pool publicBodyBuffers
			want := bytes.Repeat([]byte("a"), size)
			first, err := pool.read(bytes.NewReader(want))
			if err != nil || !bytes.Equal(first.body, want) {
				t.Fatal("first loan failed")
			}
			defer first.release()
			second, err := pool.read(strings.NewReader("independent"))
			if err != nil {
				t.Fatal("second loan failed")
			}
			defer second.release()
			if &first.scratch[0] == &second.scratch[0] {
				t.Fatal("simultaneously held loans alias scratch")
			}
			second.body[0] = 'z'
			second.release()
			if !bytes.Equal(first.body, want) {
				t.Fatal("another loan/release modified a held body")
			}
			bodyAlias, scratchAlias := first.body, first.scratch
			// Unwritten scratch is also private storage and must be scrubbed.
			for i := range scratchAlias {
				scratchAlias[i] = 's'
			}
			first.release()
			if !publicBodyTestAllZero(bodyAlias) || !publicBodyTestAllZero(scratchAlias) || first.body != nil || first.scratch != nil || first.pool != nil {
				t.Fatal("release left bytes or ownership references")
			}
			retained := len(pool.free)
			first.release()
			if len(pool.free) != retained {
				t.Fatal("idempotent release returned scratch twice")
			}
			publicBodyTestPoolZero(t, &pool)
		})
	}
	var pool publicBodyBuffers
	loans := make([]publicBodyLoan, publicBodyBufferSlots+4)
	for i := range loans {
		var err error
		loans[i], err = pool.read(strings.NewReader("held"))
		if err != nil {
			t.Fatal("held loan failed")
		}
		for j := 0; j < i; j++ {
			if &loans[i].scratch[0] == &loans[j].scratch[0] {
				t.Fatal("held loans share mutable backing")
			}
		}
	}
	if len(pool.free) != 0 {
		t.Fatal("held scratch remained available")
	}
	for i := range loans {
		loans[i].release()
	}
	if cap(pool.free) != publicBodyBufferSlots || len(pool.free) != publicBodyBufferSlots {
		t.Fatal("retained scratch exceeded or lost its fixed capacity")
	}
	for i := 0; i < publicBodyBufferSlots; i++ {
		select {
		case scratch := <-pool.free:
			if len(scratch) != publicBodyBufferBytes || !publicBodyTestAllZero(scratch) {
				t.Fatal("capacity-limited return retained nonzero storage")
			}
		default:
			t.Fatal("capacity-limited return lost scratch")
		}
	}
	var reuse publicBodyBuffers
	first, err := reuse.read(strings.NewReader("first"))
	if err != nil {
		t.Fatal("reuse fill failed")
	}
	backing := &first.scratch[0]
	first.release()
	next, err := reuse.read(strings.NewReader("next"))
	defer next.release()
	if err != nil || &next.scratch[0] != backing || string(next.body) != "next" {
		t.Fatal("released zeroed scratch was not reused independently")
	}
}

func TestPublicBodyBuffersConcurrentIsolation(t *testing.T) {
	const workers, repetitions = 12, 24
	var pool publicBodyBuffers
	var group sync.WaitGroup
	start, done := make(chan struct{}), make(chan struct{})
	failures := make(chan string, workers)
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			<-start
			want := bytes.Repeat([]byte{byte(worker + 1)}, publicBodyBufferBytes+worker+1)
			for i := 0; i < repetitions; i++ {
				loan, err := pool.read(io.LimitReader(bytes.NewReader(want), publicBodyTestLimit))
				if err != nil || !bytes.Equal(loan.body, want) {
					loan.release()
					failures <- "concurrent read isolation failed"
					return
				}
				loan.body[0] = 0
				loan.release()
			}
		}(worker)
	}
	go func() { group.Wait(); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("bounded workers did not join cleanup")
		}
	})
	close(start)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("bounded workers failed to join")
	}
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	if len(pool.free) > publicBodyBufferSlots {
		t.Fatal("concurrent release exceeded retention bound")
	}
	publicBodyTestPoolZero(t, &pool)
}

func TestHTTPPublicBodyBuffersOwnResultsAndRefetch(t *testing.T) {
	key, _ := accessObject()
	type response struct {
		body, mime string
		status     int
	}
	valid := func(extra string) response {
		return response{string(publicReplyBody(key, extra)), "application/json", 200}
	}
	var current atomic.Value
	current.Store(valid("before"))
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		reply := current.Load().(response)
		w.Header().Set("Content-Type", reply.mime)
		w.WriteHeader(reply.status)
		_, _ = io.WriteString(w, reply.body)
	}))
	defer server.Close()
	a, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil || a.responseBodies == nil || a.responseBodies.free != nil {
		t.Fatal("fresh constructor buffer state")
	}
	first, err := a.Get(t.Context(), key)
	if err != nil || first.Object["extra"] != "before" {
		t.Fatal("eligible read failed")
	}
	publicBodyTestPoolZero(t, a.responseBodies)
	first.SetUID("caller-only")
	second, err := a.Get(t.Context(), key)
	if err != nil || second.GetUID() != "original" || second.Object["extra"] != "before" || !bytes.Equal(a.publicReplies.entries[0].body, publicReplyBody(key, "before")) {
		t.Fatal("zeroed/reused loan aliased object or memo")
	}
	current.Store(valid("after")) // unchanged UID/RV, different complete bytes
	third, err := a.Get(t.Context(), key)
	if err != nil || third.Object["extra"] != "after" || second.Object["extra"] != "before" || requests.Load() != 3 {
		t.Fatal("changed complete body reused stale bytes")
	}
	publicBodyTestPoolZero(t, a.responseBodies)
	large := strings.Repeat("g", publicBodyBufferBytes+17)
	current.Store(valid(large))
	grown, err := a.Get(t.Context(), key)
	if err != nil || grown.Object["extra"] != large || len(a.publicReplies.entries) != 0 {
		t.Fatal("grown valid reply was rejected, retained or aliased")
	}
	publicBodyTestPoolZero(t, a.responseBodies)
	current.Store(valid("after-growth"))
	if _, err := a.Get(t.Context(), key); err != nil || grown.Object["extra"] != large {
		t.Fatal("scratch reuse modified an owning grown result")
	}
	for _, row := range []struct {
		name      string
		reply     response
		readError bool
	}{
		{"invalid", response{"{", "application/json", 200}, true},
		{"duplicate", response{`{"apiVersion":"v1","apiVersion":"v1"}`, "application/json", 200}, true},
		{"oversize", valid(strings.Repeat("x", int(publicBodyTestLimit))), true},
		{"mime", response{valid("fresh").body, "text/plain", 200}, true},
		{"identity", response{string(publicReplyBody(installstate.Key{APIVersion: key.APIVersion, Kind: key.Kind, Namespace: key.Namespace, Name: "different"}, "fresh")), "application/json", 200}, true},
		{"fresh-denial", response{"{}", "application/json", 403}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			current.Store(valid("warm"))
			if _, err := a.Get(t.Context(), key); err != nil {
				t.Fatal("warm read failed")
			}
			before := requests.Load()
			current.Store(row.reply)
			if object, err := a.Get(t.Context(), key); object != nil || err == nil || row.readError && err != ErrRead || requests.Load() != before+1 || len(a.publicReplies.entries) != 0 {
				t.Fatal("fresh refusal was not freshly read and refused")
			}
			publicBodyTestPoolZero(t, a.responseBodies)
			current.Store(valid("recovered"))
			object, err := a.Get(t.Context(), key)
			if err != nil || object.Object["extra"] != "recovered" || requests.Load() != before+2 {
				t.Fatal("fresh read after refusal failed")
			}
		})
	}
}

type publicBodyTestCancelReader struct {
	ctx     context.Context
	started chan struct{}
	once    sync.Once
	closed  atomic.Bool
}

func (r *publicBodyTestCancelReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

func (r *publicBodyTestCancelReader) Close() error { r.closed.Store(true); return nil }

func TestHTTPPublicBodyBuffersPartialAndCancellation(t *testing.T) {
	key, _ := accessObject()
	a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(publicReplyBody(key, "wire"))
	})
	if _, err := a.Get(t.Context(), key); err != nil {
		t.Fatal("warm control failed")
	}
	partial := &publicReplyFailingBody{body: publicReplyBody(key, "partial")}
	var attempts atomic.Int32
	a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: partial, Request: r}, nil
	})
	if object, err := a.Get(t.Context(), key); object != nil || err != ErrRead || !partial.closed.Load() || attempts.Load() != 1 || len(a.publicReplies.entries) != 0 {
		t.Fatal("partial read was accepted, replayed or left open")
	}
	publicBodyTestPoolZero(t, a.responseBodies)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reader := &publicBodyTestCancelReader{ctx: ctx, started: make(chan struct{})}
	a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: reader, Request: r}, nil
	})
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); _, err := a.Get(ctx, key); result <- err }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("cancelled request did not join cleanup")
		}
	})
	bounded, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	select {
	case <-reader.started:
	case <-bounded.Done():
		cancel()
		t.Fatal("cancelled reader never entered")
	}
	cancel()
	select {
	case err := <-result:
		if err != ErrRead || !reader.closed.Load() || attempts.Load() != 2 || len(a.publicReplies.entries) != 0 {
			t.Fatal("cancelled read was accepted, replayed or left open")
		}
	case <-bounded.Done():
		t.Fatal("cancelled read failed to join")
	}
	publicBodyTestPoolZero(t, a.responseBodies)
	a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(publicReplyBody(key, "after-cancel"))), Request: r}, nil
	})
	object, err := a.Get(t.Context(), key)
	if err != nil || object.Object["extra"] != "after-cancel" || attempts.Load() != 3 {
		t.Fatal("cancelled scratch poisoned a later fresh read")
	}
}

func TestHTTPPublicBodyBuffersExcludePrivateAndNonGET(t *testing.T) {
	key, _ := accessObject()
	path, err := resourcePath(key, false)
	if err != nil {
		t.Fatal("fixed path unavailable")
	}
	collection, err := resourcePath(key, true)
	if err != nil {
		t.Fatal("collection path unavailable")
	}
	for _, row := range []struct {
		name, method, path string
		dry                bool
		body               any
		extra              url.Values
	}{
		{"post", http.MethodPost, path, false, map[string]any{}, nil},
		{"put", http.MethodPut, path, false, map[string]any{}, nil},
		{"delete", http.MethodDelete, path, false, nil, nil},
		{"dry-get", http.MethodGet, path, true, nil, nil},
		{"body-get", http.MethodGet, path, false, map[string]any{}, nil},
		{"query", http.MethodGet, path, false, nil, url.Values{"limit": {"1"}}},
		{"subresource", http.MethodGet, path + "/status", false, nil, nil},
		{"collection", http.MethodGet, collection, false, nil, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			var requests atomic.Int32
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(publicReplyBody(key, "public"))
			})
			_, _ = a.requestAt(t.Context(), row.method, key, row.body, row.dry, row.path, row.extra)
			if requests.Load() != 1 || a.responseBodies.free != nil || len(a.publicReplies.entries) != 0 {
				t.Fatal("ineligible route borrowed public scratch or skipped wire")
			}
		})
	}
	t.Run("private-secret", func(t *testing.T) {
		secret := installstate.Key{APIVersion: "v1", Kind: "Secret", Namespace: key.Namespace, Name: "arcadectl-api-tls"}
		a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(publicReplyBody(secret, "test-only"))
		})
		privatePath, err := privateSecretPath(secret, false)
		if err != nil {
			t.Fatal("private path unavailable")
		}
		if _, err := a.requestAt(t.Context(), http.MethodGet, secret, nil, false, privatePath, nil); err != nil || a.responseBodies.free != nil || len(a.publicReplies.entries) != 0 {
			t.Fatal("private reply borrowed public scratch")
		}
	})
	t.Run("actor", func(t *testing.T) {
		var requests atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
		defer server.Close()
		a, err := NewDirectHTTPAccess(serverConfig(server))
		if err != nil {
			t.Fatal("direct access unavailable")
		}
		actor, err := a.actorClientForPurpose(ordinaryControllerActor, key.Namespace, baselineAdmissionPurpose)
		if err != nil {
			t.Fatal("closed actor unavailable")
		}
		if _, err := actor.Get(t.Context(), key); err == nil || requests.Load() != 0 || actor.responseBodies.free != nil || a.responseBodies.free != nil {
			t.Fatal("actor inherited ordinary public read scratch")
		}
	})
	for _, disabled := range []string{"memo", "buffers"} {
		t.Run("disabled-"+disabled, func(t *testing.T) {
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(publicReplyBody(key, "fallback"))
			})
			pool := a.responseBodies
			if disabled == "memo" {
				a.publicReplies = nil
			} else {
				a.responseBodies = nil
			}
			object, err := a.Get(t.Context(), key)
			if err != nil || object.Object["extra"] != "fallback" || pool.free != nil {
				t.Fatal("disabled optional buffers changed fallback")
			}
		})
	}
}

// Body-read-only comparison, not whole-command/native timing. The loan side
// includes release/zeroing; cold cases additionally include pool construction.
func BenchmarkPublicBodyBuffersReadAll(b *testing.B) {
	for _, size := range []int{512, 65536, 65537} {
		body := bytes.Repeat([]byte("x"), size)
		for _, mode := range []string{"frozen-io-readall", "warm-loan", "cold-loan"} {
			b.Run(fmt.Sprintf("%d/%s", size, mode), func(b *testing.B) {
				var pool publicBodyBuffers
				if mode == "warm-loan" {
					loan, _ := pool.read(bytes.NewReader(nil))
					loan.release()
				}
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					reader := io.LimitReader(bytes.NewReader(body), publicBodyTestLimit)
					if mode == "frozen-io-readall" {
						got, err := io.ReadAll(reader)
						if err != nil || len(got) != size {
							b.Fatal("oracle read failed")
						}
					} else {
						selected := &pool
						if mode == "cold-loan" {
							selected = &publicBodyBuffers{}
						}
						loan, err := selected.read(reader)
						if err != nil || len(loan.body) != size {
							loan.release()
							b.Fatal("loan read failed")
						}
						loan.release()
					}
				}
			})
		}
	}
}

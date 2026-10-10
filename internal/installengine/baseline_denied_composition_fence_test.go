// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
)

type testDeniedFenceEntry struct{ pass, actor int }
type testDeniedCompositionFence struct {
	namespace           string
	enabled             atomic.Bool
	blocked, violations atomic.Int32
	mu                  sync.Mutex
	seen                [2]int
	entered             chan testDeniedFenceEntry
	release             [4][2]chan struct{}
	once                [4][2]sync.Once
}

// An opt-in server wrapper only, outside the responder's mutex. The literal
// last row gates both actors in all four catalog passes of a COMPLETE guard,
// including the behavior-owned original metadata/parent/family closes.
func (f *testDeniedCompositionFence) wrap(t *testing.T, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !f.enabled.Load() {
			next(w, r)
			return
		}
		user := r.Header.Get("Impersonate-User")
		path := "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
		if f.blocked.Load() != 0 && (user == "" || r.Method != http.MethodPost || r.URL.Path != path) {
			f.violations.Add(1)
			t.Error("closing read, rule review or behavioral probe outran a denied lane")
			w.WriteHeader(500)
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == path {
			body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
			var review authv1.SelfSubjectAccessReview
			if err != nil || len(body) > 65536 || json.Unmarshal(body, &review) != nil {
				t.Error("test fence lost original review bytes")
				w.WriteHeader(500)
				return
			}
			last := authv1.ResourceAttributes{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles", Namespace: f.namespace, Name: "arcadectl-destroy-controller", Verb: "update"}
			actor := -1
			for i, name := range []string{"arcadectl-controller", "arcadectl-destroy-controller"} {
				if user == "system:serviceaccount:"+f.namespace+":"+name {
					actor = i
				}
			}
			if actor >= 0 && review.Spec.ResourceAttributes != nil && reflect.DeepEqual(*review.Spec.ResourceAttributes, last) {
				f.mu.Lock()
				pass := f.seen[actor]
				f.seen[actor]++
				f.mu.Unlock()
				if pass >= 4 {
					t.Error("guard repeated a literal last catalog row")
					w.WriteHeader(500)
					return
				}
				f.blocked.Add(1)
				f.entered <- testDeniedFenceEntry{pass, actor}
				select {
				case <-f.release[pass][actor]:
				case <-r.Context().Done():
					f.blocked.Add(-1)
					return
				}
				f.blocked.Add(-1)
			}
		}
		next(w, r)
	}
}

func TestBaselineDeniedCompositionJoinsBothLanesBeforeEveryClosingBundle(t *testing.T) {
	f := &testDeniedCompositionFence{entered: make(chan testDeniedFenceEntry, 8)}
	for pass := range f.release {
		for actor := range f.release[pass] {
			f.release[pass][actor] = make(chan struct{})
		}
	}
	testBaselineBehaviorWholeProviderComposition(t, "healthy", func(_ *Engine, snapshot *installstate.Snapshot, provider *ClusterSecurityBaseline, _ func() int) error {
		f.namespace = snapshot.Anchor().Namespace
		f.enabled.Store(true)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		done := make(chan error, 1)
		go func() { done <- provider.Verify(ctx, snapshot) }()
		joined := false
		defer func() {
			cancel()
			for pass := range f.release {
				for actor := range f.release[pass] {
					f.once[pass][actor].Do(func() { close(f.release[pass][actor]) })
				}
			}
			if !joined {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Error("composition outlived canceled fixture")
				}
			}
			f.enabled.Store(false)
		}()
		for pass := range 4 {
			seen := [2]bool{}
			for range 2 {
				select {
				case entry := <-f.entered:
					if entry.pass != pass || seen[entry.actor] {
						t.Fatal("catalog passes overlapped or one lane failed to reach its literal last row")
					}
					seen[entry.actor] = true
				case <-done:
					joined = true
					t.Fatal("complete guard returned before both catalog lanes joined")
				case <-ctx.Done():
					t.Fatal("complete guard did not reach paired literal rows")
				}
			}
			// Let ordinary finish while destroy remains in flight. ALL closing
			// reads and the next pass must still be held behind the sibling join.
			f.once[pass][0].Do(func() { close(f.release[pass][0]) })
			select {
			case <-done:
				joined = true
				t.Fatal("guard returned with a catalog sibling still blocked")
			case <-time.After(200 * time.Millisecond):
			}
			if f.violations.Load() != 0 {
				t.Fatal("closing bundle outran joined catalogs")
			}
			f.once[pass][1].Do(func() { close(f.release[pass][1]) })
		}
		select {
		case err := <-done:
			joined = true
			if err != nil {
				t.Fatal("healthy complete proof refused after joined catalogs")
			}
		case <-ctx.Done():
			t.Fatal("complete joined proof did not finish")
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.seen != [2]int{4, 4} || f.blocked.Load() != 0 || f.violations.Load() != 0 {
			t.Fatal("complete guard omitted a pass or leaked a lane")
		}
		return nil
	}, nil, nil, f)
}

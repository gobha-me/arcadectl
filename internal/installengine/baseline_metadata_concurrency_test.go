// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type metadataConcurrencyFixture struct {
	reader         *ClusterSecurityBaseline
	snapshot       *installstate.Snapshot
	paths          [8][2]string // literal eight-lane oracle, independent of production bound
	keys           []installstate.Key
	receipt        string
	mu             sync.Mutex
	reads, reviews map[installstate.Key]int
	namespaceReads int
}

type metadataReadExitBody struct {
	io.ReadCloser
	exited chan struct{}
	once   sync.Once
}

func (b *metadataReadExitBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { close(b.exited) })
	return err
}

// Real transport, sealed original journal and owned pending-CREATE receipt;
// synthetic rows do not certify native admission or the complete runtime guard.
func testMetadataConcurrencyFixture(t *testing.T) *metadataConcurrencyFixture {
	t.Helper()
	f, d, pending, service := testBaselinePendingReceipt(t, false)
	h := &metadataConcurrencyFixture{keys: testBaselineMetadataKeys(d.Namespace), receipt: "create-" + d.Pending.CreateNonce + ".json", reads: map[installstate.Key]int{}, reviews: map[installstate.Key]int{}}
	objects := map[installstate.Key]*unstructured.Unstructured{}
	for key, object := range f.access.objects {
		objects[key] = object.DeepCopy()
	}
	objects[pending] = service.DeepCopy()
	paths := map[string]installstate.Key{}
	plurals := map[string]string{"ServiceAccount": "serviceaccounts", "Service": "services", "Role": "roles", "RoleBinding": "rolebindings"}
	for index, key := range h.keys {
		prefix := "/api/v1"
		if key.APIVersion != "v1" {
			prefix = "/apis/rbac.authorization.k8s.io/v1"
		}
		path := prefix + "/namespaces/" + d.Namespace + "/" + plurals[key.Kind] + "/" + key.Name
		h.paths[index%8][index/8] = path
		paths[path] = key
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer FAKE-METADATA-LANES" || r.Header.Get("Impersonate-User") != "" {
			t.Error("metadata identity changed")
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			var review authv1.SelfSubjectAccessReview
			if r.URL.RawQuery != "fieldManager=arcadectl-installer&fieldValidation=Strict" || json.NewDecoder(r.Body).Decode(&review) != nil {
				t.Error("metadata review malformed")
				w.WriteHeader(500)
				return
			}
			var selected installstate.Key
			for _, key := range h.keys {
				group := ""
				if key.APIVersion != "v1" {
					group = "rbac.authorization.k8s.io"
				}
				want := authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: group, Version: "v1", Resource: plurals[key.Kind], Namespace: d.Namespace, Name: key.Name, Verb: "get"}}
				if reflect.DeepEqual(review.Spec, want) {
					selected = key
				}
			}
			if selected == (installstate.Key{}) {
				t.Error("metadata review escaped literal domain")
				w.WriteHeader(500)
				return
			}
			h.reviews[selected]++
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview", "spec": review.Spec, "status": map[string]any{"allowed": true}})
			return
		}
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			t.Error("metadata attempted effect or cached GET")
			w.WriteHeader(500)
			return
		}
		switch r.URL.Path {
		case "/version":
			_ = json.NewEncoder(w).Encode(map[string]any{"major": "1", "minor": "35", "gitVersion": "v" + f.plan.Profile().KubernetesVersion})
			return
		case "/api/v1/namespaces/" + d.Namespace:
			h.namespaceReads++
			ns, err := f.access.client.CoreV1().Namespaces().Get(r.Context(), d.Namespace, metav1.GetOptions{})
			if err != nil {
				t.Error("original namespace unavailable")
				w.WriteHeader(500)
				return
			}
			ns.APIVersion, ns.Kind = "v1", "Namespace"
			_ = json.NewEncoder(w).Encode(ns)
			return
		case "/api/v1", "/apis/rbac.authorization.k8s.io/v1":
			gv := "v1"
			if strings.HasPrefix(r.URL.Path, "/apis/") {
				gv = "rbac.authorization.k8s.io/v1"
			}
			resources := []metav1.APIResource{}
			for _, pair := range [][2]string{{"ServiceAccount", "serviceaccounts"}, {"Service", "services"}, {"Role", "roles"}, {"RoleBinding", "rolebindings"}} {
				if (gv == "v1") == (pair[0] == "Service" || pair[0] == "ServiceAccount") {
					resources = append(resources, metav1.APIResource{Name: pair[1], Kind: pair[0], Namespaced: true, Verbs: metav1.Verbs{"get"}})
				}
			}
			_ = json.NewEncoder(w).Encode(metav1.APIResourceList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"}, GroupVersion: gv, APIResources: resources})
			return
		}
		key, exists := paths[r.URL.Path]
		if !exists {
			t.Error("metadata GET escaped literal domain")
			w.WriteHeader(500)
			return
		}
		if h.reviews[key] != h.reads[key]+1 {
			t.Error("metadata GET lacked fresh preceding authorization")
		}
		h.reads[key]++
		if object := objects[key]; object != nil {
			_ = json.NewEncoder(w).Encode(object.Object)
		} else {
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	config := serverConfig(server)
	config.BearerToken, config.QPS, config.Burst = "FAKE-METADATA-LANES", 1000, 2000
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		t.Fatal("metadata transport unavailable")
	}
	store, err := installstate.NewWithBaseline(access.Namespaces(), f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewWithBaselineAccess(access, store, f.engine.files, f.engine.baselinePlan(), f.plan)
	if err != nil {
		t.Fatal(err)
	}
	h.snapshot, err = store.Load(t.Context(), f.snapshot.Anchor())
	if err != nil {
		t.Fatal(err)
	}
	h.reader, err = NewClusterSecurityBaseline(engine, access)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.namespaceReads = 0
	h.mu.Unlock()
	return h
}

func TestBaselineMetadataEightLanesKeepBothCompletePasses(t *testing.T) {
	h := testMetadataConcurrencyFixture(t)
	access := h.reader.access
	next := access.client.Transport
	var entered, release, exited [2][8]chan struct{}
	var once [2][8]sync.Once
	for pass := range 2 {
		for lane := range 8 {
			entered[pass][lane], release[pass][lane] = make(chan struct{}), make(chan struct{})
			exited[pass][lane] = make(chan struct{})
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		for pass := range 2 {
			for lane := range 8 {
				once[pass][lane].Do(func() { close(release[pass][lane]) })
			}
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("metadata invocation leaked")
			}
		}
	}()
	var active, maximum atomic.Int32
	var calls, starts [8]atomic.Int32
	access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		lane := -1
		final := false
		for i, paths := range h.paths {
			if r.URL.Path == paths[0] || r.URL.Path == paths[1] {
				lane = i
				final = r.URL.Path == paths[1]
			}
		}
		if lane < 0 {
			if r.URL.Path == "/api/v1/namespaces/"+h.snapshot.Anchor().Namespace && active.Load() != 0 {
				t.Error("metadata closing fence escaped a reader")
			}
			return next.RoundTrip(r)
		}
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		if !final {
			starts[lane].Add(1)
			return next.RoundTrip(r)
		}
		pass := int(calls[lane].Add(1)) - 1
		if pass > 1 {
			t.Error("metadata repeated an address")
			return nil, ErrRead
		}
		response, err := next.RoundTrip(r)
		if response != nil && response.Body != nil {
			response.Body = &metadataReadExitBody{ReadCloser: response.Body, exited: exited[pass][lane]}
		}
		close(entered[pass][lane])
		select {
		case <-release[pass][lane]:
		case <-r.Context().Done():
		}
		return response, err
	})
	go func() {
		observed, err := h.reader.originalMetadata(ctx, h.snapshot)
		if err == nil {
			if observed == nil || len(observed.objects) != 16 || h.reader.engine.confirmBaselineMetadataReceipts(observed) != nil {
				t.Error("metadata lost original membership or receipt")
			}
		}
		observed.release()
		done <- err
	}()
	for pass := range 2 {
		for lane := range 8 {
			select {
			case <-entered[pass][lane]:
			case <-done:
				joined = true
				t.Fatal("metadata returned before complete overlap")
			case <-ctx.Done():
				t.Fatal("eight metadata lanes did not overlap")
			}
		}
		if active.Load() != 8 || testBaselineReceiptDescriptors(t, h.receipt) != pass+1 {
			t.Fatal("metadata bound or receipt lifetime changed")
		}
		// Seven completed bodies must not let this pass's final lane, its
		// receipt owners, or either remote boundary be bypassed.
		for lane := range 7 {
			once[pass][lane].Do(func() { close(release[pass][lane]) })
		}
		for lane := range 7 {
			select {
			case <-exited[pass][lane]:
			case <-done:
				joined = true
				t.Fatal("metadata returned with its eighth reader blocked")
			case <-ctx.Done():
				t.Fatal("released metadata body did not exit")
			}
		}
		window := time.NewTimer(150 * time.Millisecond)
		select {
		case <-done:
			window.Stop()
			joined = true
			t.Fatal("metadata returned before its final reader joined")
		case <-exited[pass][7]:
			window.Stop()
			t.Fatal("held metadata body exited without release")
		case <-window.C:
		}
		h.mu.Lock()
		namespaceReads := h.namespaceReads
		h.mu.Unlock()
		if active.Load() != 1 || namespaceReads != 4*pass+2 || testBaselineReceiptDescriptors(t, h.receipt) != pass+1 {
			t.Fatal("metadata advanced its fence or released receipts with a reader held")
		}
		for lane := range 8 {
			if starts[lane].Load() != int32(pass+1) || calls[lane].Load() != int32(pass+1) {
				t.Fatal("metadata pipelined a second pass past its held reader")
			}
		}
		once[pass][7].Do(func() { close(release[pass][7]) })
		select {
		case <-exited[pass][7]:
		case <-ctx.Done():
			t.Fatal("final released metadata body did not exit")
		}
	}
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal("joined metadata refused", err)
		}
	case <-ctx.Done():
		t.Fatal("metadata failed to join")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if maximum.Load() != 8 || active.Load() != 0 || h.namespaceReads != 8 || testBaselineReceiptDescriptors(t, h.receipt) != 0 {
		t.Fatal("metadata changed concurrency, original fences or receipt cleanup")
	}
	for _, key := range h.keys {
		if h.reads[key] != 2 || h.reviews[key] != 2 {
			t.Fatal("metadata omitted an explicit address or fresh review")
		}
	}
}

func TestBaselineMetadataEightLanesRefusalAndCancellationJoinBeforeRelease(t *testing.T) {
	for scenario := range 9 {
		mode, refused, delayed := "refusal", scenario, (scenario+1)%8
		if scenario == 8 {
			mode, refused, delayed = "caller", 0, 7
		}
		t.Run(mode+"/"+strconv.Itoa(refused), func(t *testing.T) {
			h := testMetadataConcurrencyFixture(t)
			access := h.reader.access
			next := access.client.Transport
			var entered, canceled, exited [8]chan struct{}
			for lane := range 8 {
				entered[lane], canceled[lane], exited[lane] = make(chan struct{}), make(chan struct{}), make(chan struct{})
			}
			release := make(chan struct{})
			var once sync.Once
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			done := make(chan error, 1)
			joined := false
			defer func() {
				cancel()
				once.Do(func() { close(release) })
				if !joined {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("metadata refusal leaked")
					}
				}
			}()
			var blocked atomic.Int32
			access.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/v1/namespaces/"+h.snapshot.Anchor().Namespace && blocked.Load() != 0 {
					t.Error("metadata refusal reached closing fence")
				}
				if r.Method != http.MethodPost || r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
					return next.RoundTrip(r)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				r.Body = io.NopCloser(strings.NewReader(string(body)))
				var review authv1.SelfSubjectAccessReview
				if json.Unmarshal(body, &review) != nil {
					t.Error("review fixture malformed")
					return nil, ErrRead
				}
				lane := -1
				for i := range 8 {
					key := h.keys[i+8]
					a := review.Spec.ResourceAttributes
					plural := map[string]string{"ServiceAccount": "serviceaccounts", "Service": "services", "Role": "roles", "RoleBinding": "rolebindings"}[key.Kind]
					if a != nil && a.Name == key.Name && a.Resource == plural {
						lane = i
					}
				}
				if lane < 0 {
					return next.RoundTrip(r)
				}
				response, err := next.RoundTrip(r)
				if err != nil || response == nil || response.Body == nil {
					t.Error("review response unavailable")
					return response, err
				}
				original := response.Body
				response.Body = &baselineEightLaneRefusalBody{read: func() (int, error) {
					blocked.Add(1)
					close(entered[lane])
					if mode == "refusal" && lane == refused {
						for _, ready := range entered {
							select {
							case <-ready:
							case <-r.Context().Done():
								return 0, ErrRead
							}
						}
						return 0, ErrRead
					}
					<-r.Context().Done()
					close(canceled[lane])
					if lane == delayed {
						<-release
					}
					return 0, ErrRead
				}, close: func() error { blocked.Add(-1); close(exited[lane]); return original.Close() }}
				return response, nil
			})
			go func() {
				observed, err := h.reader.originalMetadata(ctx, h.snapshot)
				if observed != nil {
					observed.release()
					t.Error("metadata refusal returned partial success")
				}
				done <- err
			}()
			for _, ready := range entered {
				select {
				case <-ready:
				case <-done:
					joined = true
					t.Fatal("metadata refused before pending pin and every sibling entered")
				case <-ctx.Done():
					t.Fatal("metadata cancellation controls did not enter")
				}
			}
			if mode == "caller" {
				cancel()
			}
			for lane, ack := range canceled {
				if mode == "refusal" && lane == refused {
					continue
				}
				select {
				case <-ack:
				case <-done:
					joined = true
					t.Fatal("metadata refused before sibling cancellation")
				case <-time.After(2 * time.Second):
					t.Fatal("metadata sibling did not cancel")
				}
			}
			if testBaselineReceiptDescriptors(t, h.receipt) != 1 {
				t.Fatal("metadata released partial receipt before delayed reader joined")
			}
			window := time.NewTimer(150 * time.Millisecond)
			select {
			case <-done:
				window.Stop()
				joined = true
				t.Fatal("metadata escaped canceled delayed reader")
			case <-exited[delayed]:
				window.Stop()
				t.Fatal("delayed metadata body exited before release")
			case <-window.C:
			}
			h.mu.Lock()
			namespaceReads := h.namespaceReads
			h.mu.Unlock()
			if namespaceReads != 2 || testBaselineReceiptDescriptors(t, h.receipt) != 1 {
				t.Fatal("metadata refusal crossed its fence or released receipt during delayed join")
			}
			once.Do(func() { close(release) })
			select {
			case err := <-done:
				joined = true
				if err != ErrSecurityBaseline {
					t.Fatal("metadata changed refusal error")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("released metadata readers did not join")
			}
			for _, closed := range exited {
				select {
				case <-closed:
				default:
					t.Fatal("metadata escaped live body")
				}
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if blocked.Load() != 0 || h.namespaceReads != 2 || testBaselineReceiptDescriptors(t, h.receipt) != 0 {
				t.Fatal("metadata refusal leaked receipt or crossed remote fence")
			}
		})
	}
}

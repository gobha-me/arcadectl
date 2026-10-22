// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func discoveryMemoBody(tb testing.TB, gv string, resources int) []byte {
	tb.Helper()
	list := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: gv}
	for i := 0; i < resources; i++ {
		list.APIResources = append(list.APIResources, metav1.APIResource{
			Name: "resource" + strings.Repeat("x", i), SingularName: "resource", Namespaced: true, Kind: "Resource",
			Verbs: metav1.Verbs{"get", "list"}, ShortNames: []string{"r"}, Categories: []string{"all"}, StorageVersionHash: "hash",
		})
	}
	body, err := json.Marshal(list)
	if err != nil {
		tb.Fatal(err)
	}
	return body
}

func TestDiscoveryReplyMemoOwnsRawTypedAndFieldGraphs(t *testing.T) {
	body := discoveryMemoBody(t, "v1", 2)
	want, fields, err := strictDiscoveryReply(body)
	if err != nil {
		t.Fatal(err)
	}
	var memo discoveryReplyMemo
	for i := 0; i < 3; i++ { // fill and subsequent hits must all be private
		raw := bytes.Clone(body)
		got, gotFields, err := memo.decode("v1", raw)
		if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotFields, fields) {
			t.Fatal("changed conversion", err)
		}
		raw[0] = '!'
		got.APIResources[0].Verbs[0] = "delete"
		got.APIResources[0].ShortNames[0] = "changed"
		got.APIResources[0].Categories[0] = "changed"
		gotFields["resources"].([]any)[0].(map[string]any)["verbs"].([]any)[0] = "delete"
		gotFields["resources"].([]any)[0].(map[string]any)["name"] = "changed"
	}
	changed := bytes.Replace(body, []byte(`"namespaced":true`), []byte(`"namespaced":false`), 1)
	got, _, err := memo.decode("v1", changed)
	if err != nil || got.APIResources[0].Namespaced || len(memo.entries) != 1 || !bytes.Equal(memo.entries[0].body, changed) {
		t.Fatal("changed bytes reused old conversion", err)
	}
	for _, bad := range [][]byte{
		[]byte(`{"kind":"APIResourceList","kind":"APIResourceList"}`), []byte(`{"unexpected":"CANARY"}`),
		[]byte(`{"resources":"bad"}`), []byte(`null`), append(bytes.Clone(body), []byte(` {}`)...),
	} {
		if _, _, err := memo.decode("v1", body); err != nil {
			t.Fatal(err)
		}
		if _, _, err := memo.decode("v1", bad); err != ErrRead || len(memo.entries) != 0 || memo.bytes != 0 {
			t.Fatal("malformed bytes retained prior conversion", err)
		}
	}
	if _, _, err := memo.decode("foreign/v1", body); err != ErrInvalid || len(memo.entries) != 0 {
		t.Fatal("unknown group acquired slot", err)
	}
}

func TestDiscoveryReplyMemoBoundsAndStrictFallback(t *testing.T) {
	pad := func(body []byte, size int) []byte { return append(body, bytes.Repeat([]byte(" "), size-len(body))...) }
	var memo discoveryReplyMemo
	for _, gv := range proofGroups {
		if _, _, err := memo.decode(gv, discoveryMemoBody(t, gv, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if len(memo.entries) != len(proofGroups) || len(memo.entries) > discoveryReplyEntries {
		t.Fatal("fixed groups lost or bound exceeded")
	}
	memo = discoveryReplyMemo{}
	for _, gv := range proofGroups {
		if _, _, err := memo.decode(gv, pad(discoveryMemoBody(t, gv, 1), discoveryReplySize)); err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, entry := range memo.entries {
			total += len(entry.body)
		}
		if total != memo.bytes || total > discoveryReplyBytes || len(memo.entries) > discoveryReplyEntries {
			t.Fatal("incorrect raw byte accounting or bounds")
		}
	}
	if len(memo.entries) != discoveryReplyBytes/discoveryReplySize || memo.entries[0].group != proofGroups[3] {
		t.Fatal("byte-bound FIFO failed")
	}
	gv := proofGroups[len(proofGroups)-1]
	large := pad(discoveryMemoBody(t, gv, 1), discoveryReplySize+1)
	want, wantFields, err := strictDiscoveryReply(large)
	if err != nil {
		t.Fatal(err)
	}
	got, fields, err := memo.decode(gv, large)
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(fields, wantFields) || len(memo.entries) != 7 {
		t.Fatal("oversized valid reply must decode uncached and invalidate old slot", err)
	}
	var absent *discoveryReplyMemo
	got, fields, err = absent.decode(gv, large)
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(fields, wantFields) {
		t.Fatal("nil fallback changed conversion", err)
	}
	absent.clear(gv)
}

func TestDiscoveryReplyMemoConcurrentPrivateReaders(t *testing.T) {
	var memo discoveryReplyMemo
	var group sync.WaitGroup
	var failed atomic.Bool
	for i := 0; i < 16; i++ {
		gv, body := proofGroups[i%len(proofGroups)], discoveryMemoBody(t, proofGroups[i%len(proofGroups)], 2)
		group.Go(func() {
			for j := 0; j < 32; j++ {
				list, fields, err := memo.decode(gv, body)
				if err != nil || list.APIResources[0].Verbs[0] != "get" || fields["resources"].([]any)[0].(map[string]any)["name"] != "resource" {
					failed.Store(true)
					return
				}
				list.APIResources[0].Verbs[0] = "delete"
				fields["resources"].([]any)[0].(map[string]any)["name"] = "changed"
				if j%4 == 0 {
					memo.clear(gv)
				}
			}
		})
	}
	group.Wait()
	if failed.Load() {
		t.Fatal("concurrent conversion shared mutable output")
	}
}

func TestDiscoveryReplyMemoFreshHTTPAndFailClosed(t *testing.T) {
	body := string(discoveryMemoBody(t, "v1", 1))
	for _, test := range []struct {
		name, body  string
		status      int
		contentType string
	}{
		{"forbidden", body, http.StatusForbidden, "application/json"},
		{"unavailable", body, http.StatusServiceUnavailable, "application/json"},
		{"content-type", body, http.StatusOK, "text/plain"},
		{"duplicate", strings.Replace(body, `"kind":"APIResourceList"`, `"kind":"APIResourceList","kind":"APIResourceList"`, 1), http.StatusOK, "application/json"},
		{"scope-null", strings.Replace(body, `"namespaced":true`, `"namespaced":null`, 1), http.StatusOK, "application/json"},
		{"wrong-group", strings.Replace(body, `"groupVersion":"v1"`, `"groupVersion":"apps/v1"`, 1), http.StatusOK, "application/json"},
		{"wrong-kind", strings.Replace(body, `"kind":"APIResourceList"`, `"kind":"Foreign"`, 1), http.StatusOK, "application/json"},
		{"wrong-api-version", strings.Replace(body, `"apiVersion":"v1"`, `"apiVersion":null`, 1), http.StatusOK, "application/json"},
		{"empty-resources", `{"kind":"APIResourceList","groupVersion":"v1","resources":[]}`, http.StatusOK, "application/json"},
		{"wildcard-verb", strings.Replace(body, `"get"`, `"*"`, 1), http.StatusOK, "application/json"},
		{"invalid-utf8", body + string([]byte{255}), http.StatusOK, "application/json"},
		{"oversized", body + strings.Repeat(" ", 1024*1024), http.StatusOK, "application/json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			var failing atomic.Bool
			a := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1" || r.URL.RawQuery != "" {
					t.Error("route changed")
				}
				if failing.Load() {
					w.Header().Set("Content-Type", test.contentType)
					w.WriteHeader(test.status)
					_, _ = io.WriteString(w, test.body)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			})
			for i := 0; i < 2; i++ {
				list, err := a.discover(t.Context(), "v1")
				if err != nil || list.APIResources[0].Name != "resource" {
					t.Fatal(err)
				}
				list.APIResources[0].Name = "private-change"
			}
			if requests.Load() != 2 || len(a.discoveryReplies.entries) != 1 {
				t.Fatal("skipped fresh HTTP or failed to warm")
			}
			failing.Store(true)
			if _, err := a.discover(t.Context(), "v1"); err != ErrRead || requests.Load() != 3 || len(a.discoveryReplies.entries) != 0 {
				t.Fatal("warm memo concealed current failure", err)
			}
			failing.Store(false)
			if _, err := a.discover(t.Context(), "v1"); err != nil || requests.Load() != 4 || len(a.discoveryReplies.entries) != 1 {
				t.Fatal("fresh recovery failed", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := a.discover(ctx, "v1"); err == nil || requests.Load() != 4 || len(a.discoveryReplies.entries) != 0 {
				t.Fatal("warm memo bypassed cancellation", err)
			}
		})
	}
}

func TestDiscoveryReplyMemoEligibilityAndConstructorIsolation(t *testing.T) {
	var reply atomic.Value
	reply.Store(string(discoveryMemoBody(t, "v1", 1)))
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply.Load().(string))
	}))
	t.Cleanup(server.Close)
	a, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.discover(t.Context(), "v1"); err != nil {
		t.Fatal(err)
	}
	other, err := NewHTTPAccess(serverConfig(server))
	if err != nil || other.discoveryReplies == a.discoveryReplies || len(other.discoveryReplies.entries) != 0 {
		t.Fatal("constructors share conversion state", err)
	}
	actor, err := a.actorClientForPurpose(ordinaryControllerActor, "isolated-install", baselineAdmissionPurpose)
	if err != nil || actor.discoveryReplies == a.discoveryReplies || len(actor.discoveryReplies.entries) != 0 {
		t.Fatal("actor inherited memo", err)
	}
	before := requests.Load()
	if _, err := actor.discover(t.Context(), "v1"); err == nil || requests.Load() != before || len(actor.discoveryReplies.entries) != 0 || len(a.discoveryReplies.entries) != 1 {
		t.Fatal("memo granted actor discovery capability", err)
	}
	for _, path := range []string{"/version", "/apis/unknown/v1", "/apis/v1", "/api/v1/"} {
		var result metav1.APIResourceList
		if _, err := other.proofRequest(t.Context(), http.MethodGet, path, nil, &result); err != nil || len(other.discoveryReplies.entries) != 0 {
			t.Fatal("non-fixed path changed fallback or used memo", err)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		var result metav1.APIResourceList
		if _, err := other.proofRequest(t.Context(), method, "/api/v1", map[string]any{}, &result); err != nil || len(other.discoveryReplies.entries) != 0 {
			t.Fatal("body-bearing request used memo or changed fallback", err)
		}
	}
	reply.Store(`{"groupVersion":"v1","resources":[]}`)
	prefilled := metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "RetainOmittedKind"}}
	if _, err := other.proofRequest(t.Context(), http.MethodGet, "/api/v1", nil, &prefilled); err != nil || prefilled.Kind != "RetainOmittedKind" || len(other.discoveryReplies.entries) != 0 {
		t.Fatal("prefilled output lost merge semantics", err)
	}
	var fields map[string]any
	if _, err := other.proofRequest(t.Context(), http.MethodGet, "/api/v1", nil, &fields); err != nil || len(other.discoveryReplies.entries) != 0 {
		t.Fatal("other output type used memo or changed fallback", err)
	}
	var typedNil *metav1.APIResourceList
	if _, err := other.proofRequest(t.Context(), http.MethodGet, "/api/v1", nil, typedNil); err != ErrRead || len(other.discoveryReplies.entries) != 0 {
		t.Fatal("typed nil changed strict refusal", err)
	}
	other.discoveryReplies = nil
	if _, err := other.discover(t.Context(), "v1"); err != ErrRead {
		t.Fatal("nil memo skipped semantic refusal", err)
	}
	reply.Store(string(discoveryMemoBody(t, "v1", 1)))
	if _, err := other.discover(t.Context(), "v1"); err != nil {
		t.Fatal("nil memo changed valid discovery", err)
	}
}

func BenchmarkDiscoveryReplyConversion(b *testing.B) {
	for _, count := range []struct {
		name      string
		resources int
	}{{"small", 8}, {"native-sized", 64}} {
		body := discoveryMemoBody(b, "v1", count.resources)
		b.Run(count.name+"/strict", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, err := strictDiscoveryReply(bytes.Clone(body)); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(count.name+"/identical-fresh-bytes", func(b *testing.B) {
			var memo discoveryReplyMemo
			if _, _, err := memo.decode("v1", body); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := memo.decode("v1", bytes.Clone(body)); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(count.name+"/parallel-strict", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, _, err := strictDiscoveryReply(bytes.Clone(body)); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
		b.Run(count.name+"/parallel-identical-fresh-bytes", func(b *testing.B) {
			var memo discoveryReplyMemo
			if _, _, err := memo.decode("v1", body); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, _, err := memo.decode("v1", bytes.Clone(body)); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

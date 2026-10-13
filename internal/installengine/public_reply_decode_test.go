// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
)

func publicReplyBody(key installstate.Key, extra string) []byte {
	return []byte(fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"metadata":{"name":%q,"namespace":%q,"uid":"original","resourceVersion":"7"},"extra":%q}`, key.APIVersion, key.Kind, key.Name, key.Namespace, extra))
}

func TestPublicReplyMemoCompleteBytesAndDefensiveGraphs(t *testing.T) {
	key, _ := accessObject()
	var memo publicReplyMemo
	body := publicReplyBody(key, "before")
	first, err := memo.decode(key, body)
	if err != nil {
		t.Fatal(err)
	}
	first.Object["extra"] = "caller-mutated"
	first.SetUID("caller-replacement")
	second, err := memo.decode(key, body)
	if err != nil || second.Object["extra"] != "before" || second.GetUID() != "original" {
		t.Fatal("fill graph aliased")
	}
	second.SetResourceVersion("caller-change")
	third, err := memo.decode(key, body)
	if err != nil || third.GetResourceVersion() != "7" {
		t.Fatal("hit graph aliased")
	}
	changed := publicReplyBody(key, "after") // same original UID/RV, changed WHOLE body
	after, err := memo.decode(key, changed)
	if err != nil || after.Object["extra"] != "after" {
		t.Fatal("same UID/RV reused stale conversion")
	}
	changed[0] = '[' // input bytes must not alias the memo
	if len(memo.entries) != 1 || !bytes.Equal(memo.entries[0].body, publicReplyBody(key, "after")) {
		t.Fatal("raw bytes aliased")
	}
	for _, invalid := range [][]byte{
		[]byte(`{"apiVersion":"v1","apiVersion":"v1"}`),
		append(publicReplyBody(key, "after"), []byte(` {}`)...),
		[]byte(`{"apiVersion":`),
		publicReplyBody(installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: key.Namespace, Name: "replacement"}, "after"),
	} {
		if _, err := memo.decode(key, invalid); err != ErrRead || len(memo.entries) != 0 {
			t.Fatal("refusal retained conversion", err)
		}
		if _, err := memo.decode(key, body); err != nil {
			t.Fatal("refusal poisoned next valid reply", err)
		}
	}
}

func TestPublicReplyMemoBoundedRetentionAndLargeValidReplies(t *testing.T) {
	for _, size := range []int{10, publicReplySize / 2} {
		var memo publicReplyMemo
		for i := 0; i < publicReplyEntries+5; i++ {
			key := installstate.Key{APIVersion: "v1", Kind: "ServiceAccount", Namespace: "isolated-install", Name: fmt.Sprintf("row-%d", i)}
			if _, err := memo.decode(key, publicReplyBody(key, strings.Repeat("x", size))); err != nil {
				t.Fatal(err)
			}
			if len(memo.entries) > publicReplyEntries || memo.bytes > publicReplyBytes {
				t.Fatal("retention budget exceeded")
			}
		}
		if memo.entries[0].key.Name == "row-0" {
			t.Fatal("oldest entry not evicted")
		}
		counted := 0
		for _, entry := range memo.entries {
			counted += len(entry.body)
		}
		if counted != memo.bytes {
			t.Fatal("raw-byte accounting drift")
		}
	}
	key, _ := accessObject()
	var memo publicReplyMemo
	if _, err := memo.decode(key, publicReplyBody(key, strings.Repeat("x", publicReplySize))); err != nil || len(memo.entries) != 0 {
		t.Fatal("large valid reply rejected or retained", err)
	}
	for _, size := range []int{publicReplySize, publicReplySize + 1} {
		raw := publicReplyBody(key, strings.Repeat("x", size-len(publicReplyBody(key, ""))))
		if len(raw) != size {
			t.Fatal("exact size control drift")
		}
		if _, err := memo.decode(key, raw); err != nil {
			t.Fatal("valid boundary reply refused", err)
		}
		if (size == publicReplySize) != (len(memo.entries) == 1) {
			t.Fatal("inclusive retention boundary changed")
		}
	}
}

func TestHTTPPublicReplyMemoAlwaysFetchesAndRefusesFreshErrors(t *testing.T) {
	key, _ := accessObject()
	var reply atomic.Value
	reply.Store(string(publicReplyBody(key, "original")))
	var requests atomic.Int32
	var status atomic.Int32
	status.Store(200)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, reply.Load().(string))
	}))
	defer server.Close()
	a, err := NewHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		object, err := a.Get(t.Context(), key)
		if err != nil || object.Object["extra"] != "original" {
			t.Fatal(err)
		}
		object.SetUID("caller-change")
	}
	if requests.Load() != 2 || len(a.publicReplies.entries) != 1 {
		t.Fatal("GET skipped fresh wire or did not retain conversion")
	}
	status.Store(403)
	if _, err := a.Get(t.Context(), key); err == nil || requests.Load() != 3 || len(a.publicReplies.entries) != 0 {
		t.Fatal("fresh denial substituted old reply")
	}
	status.Store(200)
	for _, raw := range []string{
		string(publicReplyBody(key, "changed-same-uid-rv")),
		`{"apiVersion":"v1","apiVersion":"v1","kind":"ServiceAccount"}`,
		string(publicReplyBody(key, "restored")),
	} {
		reply.Store(raw)
		object, err := a.Get(t.Context(), key)
		if strings.Contains(raw, `"apiVersion":"v1","apiVersion"`) {
			if err != ErrRead || len(a.publicReplies.entries) != 0 {
				t.Fatal("duplicate field reused old decode")
			}
		} else if err != nil || object.GetUID() != "original" {
			t.Fatal("fresh conversion failed", err)
		}
	}
	if requests.Load() != 6 {
		t.Fatal("memo changed wire attempts")
	}
	other, err := NewHTTPAccess(serverConfig(server))
	if err != nil || other.publicReplies == a.publicReplies || len(other.publicReplies.entries) != 0 {
		t.Fatal("access constructors share decoding state")
	}
	parent, err := NewDirectHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parent.Get(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	actor, err := parent.actorClientForPurpose(ordinaryControllerActor, key.Namespace, baselineAdmissionPurpose)
	if err != nil || actor.publicReplies == parent.publicReplies || len(actor.publicReplies.entries) != 0 {
		t.Fatal("derived actor shares parent decode state", err)
	}
	before := requests.Load()
	if _, err := actor.Get(t.Context(), key); err == nil || requests.Load() != before || len(actor.publicReplies.entries) != 0 || len(parent.publicReplies.entries) != 1 {
		t.Fatal("actor GET inherited parent capability or changed parent")
	}
}

func TestPublicReplyMemoConcurrentReadersStayPrivate(t *testing.T) {
	key, _ := accessObject()
	var memo publicReplyMemo
	var group sync.WaitGroup
	var failed atomic.Bool
	for i := 0; i < 16; i++ {
		group.Go(func() {
			for j := 0; j < 20; j++ {
				object, err := memo.decode(key, publicReplyBody(key, "unchanged"))
				if err != nil || object.GetUID() != "original" || object.Object["extra"] != "unchanged" {
					failed.Store(true)
					return
				}
				object.SetUID("caller-change")
			}
		})
	}
	group.Wait()
	if failed.Load() || len(memo.entries) != 1 {
		t.Fatal("concurrent conversion aliased")
	}
}

func TestHTTPPublicReplyMemoExcludesPrivateAndNonGETRoutes(t *testing.T) {
	key, _ := accessObject()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/secrets/") {
			secret := key
			secret.Kind, secret.Name = "Secret", "arcadectl-api-tls"
			_, _ = w.Write(publicReplyBody(secret, "PRIVATE-REPLY-CANARY"))
			return
		}
		_, _ = w.Write(publicReplyBody(key, "reply"))
	}))
	defer server.Close()
	a, err := NewHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	path, err := resourcePath(key, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		method, path string
		dry          bool
		body         any
	}{
		{http.MethodPost, path, false, map[string]any{}},
		{http.MethodPut, path, false, map[string]any{}},
		{http.MethodDelete, path, false, map[string]any{}},
		{http.MethodGet, path, true, nil},
		{http.MethodGet, path + "/status", false, nil},
		{http.MethodGet, path, false, map[string]any{}},
	} {
		_, _ = a.requestAt(context.Background(), row.method, key, row.body, row.dry, row.path, nil)
		if len(a.publicReplies.entries) != 0 {
			t.Fatal("non-public GET route retained reply")
		}
	}
	_, _ = a.requestAt(t.Context(), http.MethodGet, key, nil, false, path, url.Values{"limit": {"1"}})
	if len(a.publicReplies.entries) != 0 {
		t.Fatal("query-selected route retained reply")
	}
	collectionPath, err := resourcePath(key, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.requestAt(t.Context(), http.MethodGet, key, nil, false, collectionPath, nil)
	if len(a.publicReplies.entries) != 0 {
		t.Fatal("collection route retained reply")
	}
	// Secret data can never enter the memo, even through the private named GET.
	secret := key
	secret.Kind, secret.Name = "Secret", "arcadectl-api-tls"
	privatePath, err := privateSecretPath(secret, false)
	if err != nil {
		t.Fatal(err)
	}
	private, err := a.requestAt(t.Context(), http.MethodGet, secret, nil, false, privatePath, nil)
	if err != nil || private.Object["extra"] != "PRIVATE-REPLY-CANARY" || len(a.publicReplies.entries) != 0 {
		t.Fatal("private reply retained")
	}
	// The retained graph carries unknown members unchanged for mandatory later
	// typed schema checks; this memo is not whole-object acceptance.
	body := publicReplyBody(key, "unknown-member")
	var expected map[string]any
	if json.Unmarshal(body, &expected) != nil {
		t.Fatal("control encoding")
	}
	result, err := a.publicReplies.decode(key, body)
	if err != nil || result.Object["extra"] != expected["extra"] {
		t.Fatal("decode projected unknown members")
	}
}

func TestHTTPPublicReplyMemoFreshBoundsAndEnvelopeRefusals(t *testing.T) {
	key, _ := accessObject()
	type response struct{ body, mime string }
	var reply atomic.Value
	warm := response{string(publicReplyBody(key, "unchanged")), "application/json"}
	reply.Store(warm)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		current := reply.Load().(response)
		w.Header().Set("Content-Type", current.mime)
		_, _ = io.WriteString(w, current.body)
	}))
	defer server.Close()
	a, err := NewHTTPAccess(serverConfig(server))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []response{
		{warm.body, "text/plain"},
		{warm.body + ` {}`, warm.mime},
		{`null`, warm.mime},
		{strings.Repeat("x", 1024*1024+1), warm.mime},
		{strings.Repeat("[", 65) + strings.Repeat("]", 65), warm.mime},
		{strings.Replace(warm.body, `"namespace":"isolated-install"`, `"namespace":"foreign"`, 1), warm.mime},
		{strings.Replace(warm.body, `"name":"reviewed"`, `"name":null`, 1), warm.mime},
	} {
		reply.Store(warm)
		if _, err := a.Get(t.Context(), key); err != nil || len(a.publicReplies.entries) != 1 {
			t.Fatal("warm control failed", err)
		}
		reply.Store(bad)
		if _, err := a.Get(t.Context(), key); err != ErrRead || len(a.publicReplies.entries) != 0 {
			t.Fatal("fresh refusal inherited conversion", err)
		}
	}
	if requests.Load() != 14 {
		t.Fatal("refusal changed fresh wire census")
	}
	reply.Store(warm)
	if _, err := a.Get(t.Context(), key); err != nil {
		t.Fatal("read-error warm control", err)
	}
	failed := &publicReplyFailingBody{body: []byte(warm.body)}
	a.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: failed, Request: r}, nil
	})
	if _, err := a.Get(t.Context(), key); err != ErrRead || len(a.publicReplies.entries) != 0 || !failed.closed.Load() {
		t.Fatal("incomplete read used memo or leaked body", err)
	}
}

type publicReplyFailingBody struct {
	body   []byte
	closed atomic.Bool
}

func (r *publicReplyFailingBody) Read(p []byte) (int, error) {
	return copy(p, r.body), io.ErrUnexpectedEOF
}
func (r *publicReplyFailingBody) Close() error { r.closed.Store(true); return nil }

func TestPublicReplyMemoReducesStrictConversionAllocations(t *testing.T) {
	key, _ := accessObject()
	raw := publicReplyBody(key, strings.Repeat("value", 100))
	var memo publicReplyMemo
	if _, err := memo.decode(key, raw); err != nil {
		t.Fatal(err)
	}
	original := testing.AllocsPerRun(30, func() {
		if _, err := strictPublicReply(raw); err != nil {
			panic("strict control refused")
		}
	})
	warm := testing.AllocsPerRun(30, func() {
		if _, err := memo.decode(key, raw); err != nil {
			panic("memo control refused")
		}
	})
	if warm >= original {
		t.Fatalf("defensive conversion reuse did not reduce allocations: warm=%g strict=%g", warm, original)
	}
	t.Logf("decode-only allocation control warm=%g strict=%g; not native timing or RSS", warm, original)
}

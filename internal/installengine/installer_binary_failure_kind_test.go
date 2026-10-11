//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	strictjson "sigs.k8s.io/json"
)

// Failure-only test observation after the authentic historical child exits.
// This cannot repair its result, adopt a UID, send an effect, or certify the
// earlier response. Only fixed categories/booleans leave this private observer.
type historicalInstallerFailureObservation struct {
	status, slotState                                                             string
	uidKnown, originalGET, podDecoded, managedTimesPresent, managedBeforeCreation bool
	initialStatusMatch, singleInstallerMainRecord                                 bool
	listComplete, listOriginal, listGETSameUIDRV, listGETWhole                    bool
	trailingOriginal, getUnchanged, journalUnchanged, walUnchanged                bool
}

func (o historicalInstallerFailureObservation) String() string {
	return fmt.Sprintf("status=%s slot=6 state=%s uid-known=%t original-get=%t pod-decoded=%t managed-times-present=%t managed-before-creation=%t initial-status-match=%t single-installer-main-record=%t list-complete=%t list-original=%t list-get-same-uid-rv=%t list-get-whole=%t trailing-original=%t get-unchanged=%t journal-unchanged=%t wal-unchanged=%t", o.status, o.slotState, o.uidKnown, o.originalGET, o.podDecoded, o.managedTimesPresent, o.managedBeforeCreation, o.initialStatusMatch, o.singleInstallerMainRecord, o.listComplete, o.listOriginal, o.listGETSameUIDRV, o.listGETWhole, o.trailingOriginal, o.getUnchanged, o.journalUnchanged, o.walUnchanged)
}

func observeHistoricalInstallerFailure(ctx context.Context, config *rest.Config, state string, original *installrender.Plan) historicalInstallerFailureObservation {
	o := historicalInstallerFailureObservation{status: "unavailable", slotState: "unknown"}
	if ctx == nil || ctx.Err() != nil || config == nil || !original.IsTrusted() {
		return o
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	access, err := NewDirectHTTPAccess(config)
	if err != nil {
		return o
	}
	files, err := privatefs.Open(state, false)
	if err != nil {
		return o
	}
	defer files.Close()
	receipt, err := installstate.LoadBootstrap(files, "bootstrap.json", original)
	if err != nil {
		return o
	}
	anchor, err := receipt.PinnedAnchor(ctx)
	if err != nil {
		return o
	}
	store, err := installstate.New(access.Namespaces(), original)
	if err != nil {
		return o
	}
	snapshot, err := store.Load(ctx, anchor)
	if err != nil {
		return o
	}
	engine, err := NewWithAccess(access, store, files, original)
	if err != nil {
		return o
	}
	return collectHistoricalInstallerFailure(ctx, engine, snapshot, func(ctx context.Context, key installstate.Key) (*unstructured.Unstructured, error) {
		return historicalFailurePodGet(ctx, access, key)
	}, func(ctx context.Context, namespace string) (*unstructured.Unstructured, error) {
		return historicalFailurePodList(ctx, access, namespace)
	})
}

// The generic installation accessor deliberately has no Pod mapping. This
// failure-only observer reads the original WAL-bound Pod using its separate,
// fixed fixture route; it does not widen ordinary installation read authority.
func historicalFailurePodGet(ctx context.Context, access *HTTPAccess, key installstate.Key) (*unstructured.Unstructured, error) {
	if key.APIVersion != "v1" || key.Kind != "Pod" {
		return nil, ErrRead
	}
	path, _, err := fixturePath(key, false)
	if err != nil {
		return nil, ErrRead
	}
	return access.requestAt(ctx, http.MethodGet, key, nil, false, path, nil)
}

// Fixed one-attempt route under HTTPAccess's original response/privacy bounds;
// no SDK retry, continuation, arbitrary URL, or permissive list decoding.
func historicalFailurePodList(ctx context.Context, access *HTTPAccess, namespace string) (*unstructured.Unstructured, error) {
	if !installrender.ValidNamespace(namespace) {
		return nil, ErrRead
	}
	key := installstate.Key{APIVersion: "v1", Kind: "PodList"}
	return access.requestAt(ctx, http.MethodGet, key, nil, false, "/api/v1/namespaces/"+namespace+"/pods", url.Values{"limit": []string{"64"}})
}

func decodeHistoricalFailurePodList(raw *unstructured.Unstructured, namespace string) (*corev1.PodList, error) {
	var list corev1.PodList
	if raw == nil || raw.GetAPIVersion() != "v1" || raw.GetKind() != "PodList" || decodeServing(raw, &list) != nil || !fixtureRV(list.ResourceVersion) || list.Continue != "" || list.RemainingItemCount != nil && *list.RemainingItemCount != 0 || len(list.Items) > 64 {
		return nil, ErrRead
	}
	items, present := raw.Object["items"]
	objects, ok := items.([]any)
	if !present || !ok && items != nil || len(objects) != len(list.Items) {
		return nil, ErrRead
	}
	for i, value := range objects {
		object, ok := value.(map[string]any)
		if !ok {
			return nil, ErrRead
		}
		version, hasVersion := object["apiVersion"]
		kind, hasKind := object["kind"]
		if hasVersion != hasKind || hasVersion && (version != "v1" || kind != "Pod") {
			return nil, ErrRead
		}
		pod := &list.Items[i]
		if pod.Namespace != namespace || !addressPart(pod.Name) || !nativeFixtureUID(string(pod.UID)) || !fixtureRV(pod.ResourceVersion) {
			return nil, ErrRead
		}
		if !hasVersion {
			// Only literal omission of BOTH fields, as in native typed LISTs.
			// Explicit null/empty/partial/wrong envelopes were refused above.
			pod.APIVersion, pod.Kind = "v1", "Pod"
		}
	}
	return &list, nil
}

func collectHistoricalInstallerFailure(ctx context.Context, engine *Engine, snapshot *installstate.Snapshot, get func(context.Context, installstate.Key) (*unstructured.Unstructured, error), list func(context.Context, string) (*unstructured.Unstructured, error)) historicalInstallerFailureObservation {
	o := historicalInstallerFailureObservation{status: "unavailable", slotState: "unknown"}
	if ctx == nil || ctx.Err() != nil || engine == nil || engine.files == nil || snapshot == nil || get == nil || list == nil {
		return o
	}
	name := fixtureLedgerName(snapshot)
	body, identity, err := engine.files.Read(name, fixtureLedgerMaxBytes)
	if err != nil {
		return o
	}
	document, err := engine.decodeFixtureLedger(body)
	if err != nil || document.Recipe != fixtureRecipeV2 || !bytes.Equal(document.Journal, snapshot.Bytes()) || document.JournalResourceVersion != snapshot.ResourceVersion() {
		return o
	}
	entry := document.Entries[fixturePlainPod]
	// A validated protected original recipe supplies the sole address. Never
	// learn an original UID from a name lookup after an unknown CREATE.
	switch entry.State {
	case fixturePlanned, fixtureCreateAttempted, fixtureOriginal, fixtureDeleteAttempted, fixtureAbsent:
		o.slotState = string(entry.State)
	default:
		return o
	}
	o.uidKnown = nativeFixtureUID(string(entry.OriginalUID))
	o.status = "observed"
	if entry.State == fixtureOriginal && o.uidKnown {
		before, getErr := get(ctx, entry.Key)
		o.originalGET = getErr == nil && historicalFailureOriginalPod(before, entry)
		if o.originalGET {
			var typed corev1.Pod
			o.podDecoded = decodeServing(before, &typed) == nil
			if o.podDecoded {
				// Pure post-exit shape facets, not a complete whole-object proof
				// or evidence that the earlier native CREATE response passed.
				status, statusErr := fixtureResultStatus(before, fixtureAcknowledgedResult, typed.CreationTimestamp.Time, time.Now().UTC().Add(time.Second))
				o.initialStatusMatch = statusErr == nil && reflect.DeepEqual(before.Object["status"], status)
				if len(typed.ManagedFields) == 1 {
					field := typed.ManagedFields[0]
					o.singleInstallerMainRecord = field.Manager == "arcadectl-installer" && field.Operation == metav1.ManagedFieldsOperationUpdate && field.APIVersion == "v1" && field.FieldsType == "FieldsV1" && field.Subresource == ""
				}
				o.managedTimesPresent = !typed.CreationTimestamp.IsZero() && len(typed.ManagedFields) != 0
				for _, field := range typed.ManagedFields {
					if field.Time == nil || field.Time.IsZero() {
						o.managedTimesPresent = false
						continue
					}
					o.managedBeforeCreation = o.managedBeforeCreation || field.Time.Before(&typed.CreationTimestamp)
				}
				raw, listErr := list(ctx, entry.Key.Namespace)
				pods, decodeErr := decodeHistoricalFailurePodList(raw, entry.Key.Namespace)
				o.listComplete = listErr == nil && decodeErr == nil
				if o.listComplete {
					matches := 0
					for _, pod := range pods.Items {
						if pod.UID == entry.OriginalUID || pod.Namespace == entry.Key.Namespace && pod.Name == entry.Key.Name {
							matches++
							if pod.UID == entry.OriginalUID && pod.Namespace == entry.Key.Namespace && pod.Name == entry.Key.Name {
								o.listOriginal = true
								o.listGETSameUIDRV = typed.UID == pod.UID && typed.ResourceVersion == pod.ResourceVersion
								o.listGETWhole = reflect.DeepEqual(&typed, &pod)
							}
						}
					}
					if matches != 1 {
						o.listOriginal, o.listGETSameUIDRV, o.listGETWhole = false, false, false
					}
				}
			}
			after, trailingErr := get(ctx, entry.Key)
			o.trailingOriginal = trailingErr == nil && historicalFailureOriginalPod(after, entry)
			o.getUnchanged = o.trailingOriginal && reflect.DeepEqual(before, after)
		}
	}
	fresh, journalErr := engine.journal.Load(ctx, snapshot.Anchor())
	o.journalUnchanged = journalErr == nil && bytes.Equal(fresh.Bytes(), snapshot.Bytes()) && fresh.ResourceVersion() == snapshot.ResourceVersion()
	closing, closingIdentity, closingErr := engine.files.Read(name, fixtureLedgerMaxBytes)
	o.walUnchanged = closingErr == nil && closingIdentity == identity && bytes.Equal(closing, body)
	if ctx.Err() != nil {
		o.status = "context-ended"
	}
	return o
}

func historicalFailureOriginalPod(pod *unstructured.Unstructured, entry fixtureEntry) bool {
	return pod != nil && pod.GetAPIVersion() == "v1" && pod.GetKind() == "Pod" && pod.GetNamespace() == entry.Key.Namespace && pod.GetName() == entry.Key.Name && pod.GetUID() == entry.OriginalUID && fixtureRV(pod.GetResourceVersion())
}

func testHistoricalInstallerFailureObservation(t *testing.T) {
	t.Helper()
	testHistoricalFailurePodGetWire(t)
	testHistoricalFailurePodListWire(t)
	testHistoricalFailureObserverPodWire(t)
	for _, scenario := range []string{"earlier-managed-time", "same-managed-time", "status-change", "manager-change", "omitted-list-type", "partial-list-type", "wrong-list-type", "replaced-get", "replaced-list", "list-rv-change", "list-whole-change", "incomplete-list", "duplicate-list", "unknown-create", "malformed-wal", "journal-change", "wal-change", "trailing-replacement", "unknown-pod-field"} {
		t.Run("historical-failure-"+scenario, func(t *testing.T) {
			f := newFixture(t, false)
			ledger, err := f.engine.prepareFixtureLedgerV2(t.Context(), f.snapshot)
			if err != nil {
				t.Fatal("failure diagnostic WAL fixture unavailable")
			}
			for slot := 0; slot <= fixturePlainPod; slot++ {
				if scenario == "unknown-create" && slot == fixturePlainPod {
					next, _ := ledger.nextDocument()
					next.Entries[slot].State = fixtureCreateAttempted
					if ledger.advance(next) != nil {
						t.Fatal("unknown original fixture unavailable")
					}
					break
				}
				acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
			}
			entry := ledger.document.Entries[fixturePlainPod]
			created := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
			var object *unstructured.Unstructured
			if scenario != "unknown-create" {
				object = fixtureResultExample(t, ledger, fixturePlainPod, fixtureAcknowledgedResult, created)
				fields := object.GetManagedFields()
				stamp := metav1.NewTime(created)
				if scenario == "earlier-managed-time" {
					stamp = metav1.NewTime(created.Add(-time.Second))
				}
				fields[0].Time = &stamp
				if scenario == "manager-change" {
					fields[0].Manager = "PRIVATE-CANARY"
				}
				object.SetManagedFields(fields)
				if scenario == "status-change" {
					object.Object["status"].(map[string]any)["phase"] = "Running"
				}
				object.SetAnnotations(map[string]string{"PRIVATE-CANARY": "PRIVATE-CANARY"})
				f.access.objects[entry.Key] = object
			}
			if ledger.close() != nil {
				t.Fatal("failure fixture close refused")
			}
			body, identity, err := f.engine.files.Read(fixtureLedgerName(f.snapshot), fixtureLedgerMaxBytes)
			if err != nil {
				t.Fatal("failure fixture WAL unavailable")
			}
			if scenario == "malformed-wal" {
				if _, err := f.engine.files.AtomicWrite(fixtureLedgerName(f.snapshot), []byte("PRIVATE-CANARY"), &identity); err != nil {
					t.Fatal("malformed fixture unavailable")
				}
			}
			gets, lists := 0, 0
			f.access.get = func(key installstate.Key) error {
				gets++
				if key != entry.Key {
					t.Fatal("diagnostic escaped original Pod address")
				}
				if scenario == "replaced-get" || scenario == "trailing-replacement" && gets == 2 {
					f.access.objects[key].SetUID("b0000000-0000-4000-8000-000000000001")
				}
				if scenario == "unknown-pod-field" {
					f.access.objects[key].Object["PRIVATE-CANARY"] = "PRIVATE-CANARY"
				}
				return nil
			}
			list := func(ctx context.Context, namespace string) (*unstructured.Unstructured, error) {
				lists++
				if namespace != entry.Key.Namespace {
					t.Fatal("diagnostic listed another namespace")
				}
				var pod corev1.Pod
				if decodeServing(object, &pod) != nil {
					t.Fatal("fixture Pod decode unavailable")
				}
				pods := &corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: metav1.ListMeta{ResourceVersion: "101"}, Items: []corev1.Pod{pod}}
				switch scenario {
				case "omitted-list-type":
					pods.Items[0].TypeMeta = metav1.TypeMeta{}
				case "partial-list-type":
					pods.Items[0].Kind = ""
				case "wrong-list-type":
					pods.Items[0].Kind = "Service"
				case "replaced-list":
					pods.Items[0].UID = "b0000000-0000-4000-8000-000000000001"
				case "list-rv-change":
					pods.Items[0].ResourceVersion = "102"
				case "list-whole-change":
					pods.Items[0].Annotations = map[string]string{"PRIVATE-CANARY": "changed"}
				case "incomplete-list":
					pods.Continue = "PRIVATE-CANARY"
				case "duplicate-list":
					pods.Items = append(pods.Items, pod)
				case "journal-change":
					ns, _ := f.access.client.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
					ns.ResourceVersion = "2"
					if f.access.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), ns, "") != nil {
						t.Fatal("changed journal fixture unavailable")
					}
				case "wal-change":
					if _, err := f.engine.files.AtomicWrite(fixtureLedgerName(f.snapshot), []byte("PRIVATE-CANARY"), &identity); err != nil {
						t.Fatal("changed WAL fixture unavailable")
					}
				}
				body, err := json.Marshal(pods)
				result := &unstructured.Unstructured{}
				strictErrors, decodeErr := strictjson.UnmarshalStrict(body, &result.Object)
				if err != nil || decodeErr != nil || len(strictErrors) != 0 {
					t.Fatal("private LIST fixture unavailable")
				}
				return result, nil
			}
			report := collectHistoricalInstallerFailure(t.Context(), f.engine, f.snapshot, f.access.Get, list)
			if strings.Contains(report.String(), "PRIVATE-CANARY") || entry.OriginalUID != "" && strings.Contains(report.String(), string(entry.OriginalUID)) || strings.Contains(report.String(), entry.Key.Name) || f.access.writes != 0 || f.access.dryRuns != 0 || f.nsUpdates != 0 {
				t.Fatal("failure observation leaked private values or issued an effect")
			}
			if scenario == "malformed-wal" {
				if report.status != "unavailable" || gets != 0 || lists != 0 {
					t.Fatal("malformed evidence acquired diagnostic read authority")
				}
				return
			}
			if scenario == "unknown-create" {
				if report.slotState != "create-attempted" || report.uidKnown || gets != 0 || lists != 0 || !report.walUnchanged || !report.journalUnchanged {
					t.Fatal("unknown CREATE inferred identity or looked up an original")
				}
				return
			}
			if scenario == "replaced-get" {
				if report.originalGET || gets != 1 || lists != 0 {
					t.Fatal("replacement acquired original diagnostic shape evidence")
				}
			} else if scenario == "unknown-pod-field" {
				if report.podDecoded || lists != 0 {
					t.Fatal("unknown Pod field accepted as typed evidence")
				}
			} else {
				if gets != 2 || lists != 1 || !report.originalGET || !report.podDecoded || !report.managedTimesPresent || report.managedBeforeCreation != (scenario == "earlier-managed-time") {
					t.Fatal("bounded original/timestamp failure facets incorrect")
				}
				if report.initialStatusMatch != (scenario != "status-change") || report.singleInstallerMainRecord != (scenario != "manager-change") {
					t.Fatal("post-exit status or manager shape facet incorrect")
				}
				switch scenario {
				case "earlier-managed-time", "same-managed-time", "status-change", "manager-change", "omitted-list-type", "journal-change", "wal-change", "trailing-replacement":
					if !report.listComplete || !report.listOriginal || !report.listGETSameUIDRV || !report.listGETWhole {
						t.Fatal("original whole LIST/GET correlation lost")
					}
				case "partial-list-type", "wrong-list-type", "replaced-list", "duplicate-list", "incomplete-list":
					if report.listOriginal || report.listGETWhole {
						t.Fatal("incomplete or replacement LIST became original evidence")
					}
				case "list-rv-change":
					if report.listGETSameUIDRV || report.listGETWhole {
						t.Fatal("LIST RV drift accepted")
					}
				case "list-whole-change":
					if !report.listGETSameUIDRV || report.listGETWhole {
						t.Fatal("whole-object change collapsed to UID/RV match")
					}
				}
			}
			if report.journalUnchanged != (scenario != "journal-change") || report.walUnchanged != (scenario != "wal-change") || report.trailingOriginal == (scenario == "trailing-replacement" || scenario == "replaced-get") || report.getUnchanged == (scenario == "trailing-replacement" || scenario == "replaced-get") {
				t.Fatal("closing failure observation lost original drift")
			}
			if scenario != "wal-change" {
				closing, closingIdentity, _ := f.engine.files.Read(fixtureLedgerName(f.snapshot), fixtureLedgerMaxBytes)
				if !bytes.Equal(body, closing) || identity != closingIdentity {
					t.Fatal("failure observation changed original WAL")
				}
			}
		})
	}
}

func testHistoricalFailurePodGetWire(t *testing.T) {
	t.Helper()
	key := installstate.Key{APIVersion: "v1", Kind: "Pod", Namespace: "isolated-install", Name: "reviewed"}
	const original = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"reviewed","namespace":"isolated-install","uid":"a0000000-0000-4000-8000-000000000007","resourceVersion":"101"},"spec":{},"status":{}}`
	for _, scenario := range []string{"canonical", "wrong-kind", "wrong-version", "wrong-name", "wrong-namespace", "duplicate-field", "exact-byte-limit", "oversized", "not-found", "forbidden", "retry-429", "retry-503", "redirect", "invalid-key-kind", "invalid-key-version", "invalid-key-name", "invalid-key-namespace", "cancelled"} {
		t.Run("historical-get-wire-"+scenario, func(t *testing.T) {
			body := original
			switch scenario {
			case "wrong-kind":
				body = strings.Replace(body, `"kind":"Pod"`, `"kind":"Service"`, 1)
			case "wrong-version":
				body = strings.Replace(body, `"apiVersion":"v1"`, `"apiVersion":"apps/v1"`, 1)
			case "wrong-name":
				body = strings.Replace(body, `"name":"reviewed"`, `"name":"PRIVATE-CANARY"`, 1)
			case "wrong-namespace":
				body = strings.Replace(body, `"namespace":"isolated-install"`, `"namespace":"other-install"`, 1)
			case "duplicate-field":
				body = strings.Replace(body, `"kind":"Pod"`, `"kind":"Pod","kind":"Pod"`, 1)
			case "exact-byte-limit":
				body += strings.Repeat(" ", 1024*1024-len(body))
			case "oversized":
				body += strings.Repeat(" ", 1024*1024+1-len(body))
			}
			var requests atomic.Int32
			var wrongRoute atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/isolated-install/pods/reviewed" || r.URL.RawQuery != "" || r.ProtoMajor != 1 || r.Header.Get("Accept") != "application/json" {
					wrongRoute.Store(true)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Warning", "PRIVATE-CANARY")
				code := http.StatusOK
				switch scenario {
				case "not-found":
					code = http.StatusNotFound
				case "forbidden":
					code = http.StatusForbidden
				case "retry-429":
					code = http.StatusTooManyRequests
				case "retry-503":
					code = http.StatusServiceUnavailable
				case "redirect":
					w.Header().Set("Location", "/PRIVATE-CANARY")
					code = http.StatusTemporaryRedirect
				}
				if code != http.StatusOK {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(code)
					_, _ = io.WriteString(w, "PRIVATE-CANARY")
					return
				}
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			access, err := NewDirectHTTPAccess(serverConfig(server))
			if err != nil {
				t.Fatal("closed TLS diagnostic GET fixture unavailable")
			}
			// This is the regression: ordinary installer resource mappings must
			// still reject Pods without a request; only the private route reads it.
			if _, err := access.Get(t.Context(), key); !errors.Is(err, ErrInvalid) || requests.Load() != 0 {
				t.Fatal("ordinary installation accessor unexpectedly gained Pod authority")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			selected := key
			switch scenario {
			case "invalid-key-kind":
				selected.Kind = "Service"
			case "invalid-key-version":
				selected.APIVersion = "apps/v1"
			case "invalid-key-name":
				selected.Name = "../PRIVATE-CANARY"
			case "invalid-key-namespace":
				selected.Namespace = "../PRIVATE-CANARY"
			case "cancelled":
				cancel()
			}
			raw, readErr := historicalFailurePodGet(ctx, access, selected)
			accepted := readErr == nil
			want := scenario == "canonical" || scenario == "exact-byte-limit"
			if accepted != want || wrongRoute.Load() || readErr != nil && strings.Contains(readErr.Error(), "PRIVATE-CANARY") {
				t.Fatal("private diagnostic GET violated its exact route or response privacy")
			}
			expectedRequests := int32(1)
			if strings.HasPrefix(scenario, "invalid-key-") || scenario == "cancelled" {
				expectedRequests = 0
			}
			if requests.Load() != expectedRequests {
				t.Fatal("private diagnostic GET retried, redirected or escaped its context")
			}
			if accepted && !historicalFailureOriginalPod(raw, fixtureEntry{Key: key, OriginalUID: "a0000000-0000-4000-8000-000000000007"}) {
				t.Fatal("native original Pod response was not observable")
			}
		})
	}
}

func testHistoricalFailureObserverPodWire(t *testing.T) {
	t.Helper()
	t.Run("historical-observer-real-pod-route", func(t *testing.T) {
		f := newFixture(t, false)
		ledger, err := f.engine.prepareFixtureLedgerV2(t.Context(), f.snapshot)
		if err != nil {
			t.Fatal("observer WAL fixture unavailable")
		}
		for slot := 0; slot <= fixturePlainPod; slot++ {
			acknowledgeRecipeFixture(t, ledger, slot, types.UID(fmt.Sprintf("a0000000-0000-4000-8000-%012x", slot+1)))
		}
		entry := ledger.document.Entries[fixturePlainPod]
		object := fixtureResultExample(t, ledger, fixturePlainPod, fixtureAcknowledgedResult, time.Now().UTC().Truncate(time.Second).Add(-time.Minute))
		body, err := json.Marshal(object.Object)
		if err != nil || ledger.close() != nil {
			t.Fatal("observer original fixture unavailable")
		}
		var pod corev1.Pod
		if decodeServing(object, &pod) != nil {
			t.Fatal("observer typed Pod unavailable")
		}
		listBody, err := json.Marshal(&corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: metav1.ListMeta{ResourceVersion: "101"}, Items: []corev1.Pod{pod}})
		if err != nil {
			t.Fatal("observer typed list unavailable")
		}
		var gets, lists atomic.Int32
		var wrongRoute atomic.Bool
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method != http.MethodGet {
				wrongRoute.Store(true)
			}
			switch {
			case r.URL.Path == "/api/v1/namespaces/"+entry.Key.Namespace+"/pods/"+entry.Key.Name && r.URL.RawQuery == "":
				gets.Add(1)
				_, _ = w.Write(body)
			case r.URL.Path == "/api/v1/namespaces/"+entry.Key.Namespace+"/pods" && r.URL.RawQuery == "limit=64":
				lists.Add(1)
				_, _ = w.Write(listBody)
			default:
				wrongRoute.Store(true)
				w.WriteHeader(http.StatusForbidden)
			}
		}))
		defer server.Close()
		access, err := NewDirectHTTPAccess(serverConfig(server))
		if err != nil {
			t.Fatal("observer TLS accessor unavailable")
		}
		report := collectHistoricalInstallerFailure(t.Context(), f.engine, f.snapshot, func(ctx context.Context, key installstate.Key) (*unstructured.Unstructured, error) {
			return historicalFailurePodGet(ctx, access, key)
		}, func(ctx context.Context, ns string) (*unstructured.Unstructured, error) {
			return historicalFailurePodList(ctx, access, ns)
		})
		if wrongRoute.Load() || gets.Load() != 2 || lists.Load() != 1 || !report.originalGET || !report.podDecoded || !report.listComplete || !report.listOriginal || !report.listGETSameUIDRV || !report.listGETWhole || !report.trailingOriginal || !report.getUnchanged || !report.journalUnchanged || !report.walUnchanged || f.access.writes != 0 || f.access.dryRuns != 0 || f.nsUpdates != 0 {
			t.Fatal("complete failure observer lost actual native Pod route or original evidence")
		}
	})
}

func testHistoricalFailurePodListWire(t *testing.T) {
	t.Helper()
	const namespace = "isolated-install"
	const original = `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"101"},"items":[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"reviewed","namespace":"isolated-install","uid":"a0000000-0000-4000-8000-000000000007","resourceVersion":"101"},"spec":{},"status":{}}]}`
	for _, scenario := range []string{"canonical", "omitted-type", "partial-type", "empty-type", "null-type", "wrong-type", "unknown-field", "duplicate-field", "incomplete-page", "remaining-items", "wrong-namespace", "exact-byte-limit", "oversized", "retry-429", "retry-503", "redirect", "invalid-namespace", "cancelled"} {
		t.Run("historical-list-wire-"+scenario, func(t *testing.T) {
			body := original
			switch scenario {
			case "omitted-type":
				body = strings.Replace(body, `"apiVersion":"v1","kind":"Pod",`, "", 1)
			case "partial-type":
				body = strings.Replace(body, `"kind":"Pod",`, "", 1)
			case "empty-type":
				body = strings.Replace(body, `"apiVersion":"v1","kind":"Pod",`, `"apiVersion":"","kind":"",`, 1)
			case "null-type":
				body = strings.Replace(body, `"apiVersion":"v1","kind":"Pod",`, `"apiVersion":null,"kind":null,`, 1)
			case "wrong-type":
				body = strings.Replace(body, `"kind":"Pod",`, `"kind":"Service",`, 1)
			case "unknown-field":
				body = strings.Replace(body, `"spec":{}`, `"spec":{},"PRIVATE-CANARY":true`, 1)
			case "duplicate-field":
				body = strings.Replace(body, `"kind":"PodList"`, `"kind":"PodList","kind":"PodList"`, 1)
			case "incomplete-page":
				body = strings.Replace(body, `"resourceVersion":"101"`, `"resourceVersion":"101","continue":"PRIVATE-CANARY"`, 1)
			case "remaining-items":
				body = strings.Replace(body, `"resourceVersion":"101"`, `"resourceVersion":"101","remainingItemCount":1`, 1)
			case "wrong-namespace":
				body = strings.Replace(body, `"namespace":"isolated-install"`, `"namespace":"other-install"`, 1)
			case "exact-byte-limit":
				body += strings.Repeat(" ", 1024*1024-len(body))
			case "oversized":
				body += strings.Repeat(" ", 1024*1024+1-len(body))
			}
			var requests atomic.Int32
			var wrongRoute atomic.Bool
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/"+namespace+"/pods" || r.URL.RawQuery != "limit=64" || r.ProtoMajor != 1 || r.Header.Get("Accept") != "application/json" {
					wrongRoute.Store(true)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Warning", "PRIVATE-CANARY")
				switch scenario {
				case "retry-429", "retry-503":
					w.Header().Set("Retry-After", "0")
					code := http.StatusTooManyRequests
					if scenario == "retry-503" {
						code = http.StatusServiceUnavailable
					}
					w.WriteHeader(code)
					_, _ = io.WriteString(w, "PRIVATE-CANARY")
				case "redirect":
					w.Header().Set("Location", "/PRIVATE-CANARY")
					w.WriteHeader(http.StatusTemporaryRedirect)
					_, _ = io.WriteString(w, "PRIVATE-CANARY")
				default:
					_, _ = io.WriteString(w, body)
				}
			}))
			defer server.Close()
			access, err := NewDirectHTTPAccess(serverConfig(server))
			if err != nil {
				t.Fatal("closed TLS diagnostic fixture unavailable")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			selectedNamespace := namespace
			if scenario == "invalid-namespace" {
				selectedNamespace = "../PRIVATE-CANARY"
			}
			if scenario == "cancelled" {
				cancel()
			}
			raw, readErr := historicalFailurePodList(ctx, access, selectedNamespace)
			pods, decodeErr := decodeHistoricalFailurePodList(raw, selectedNamespace)
			accepted := readErr == nil && decodeErr == nil
			want := scenario == "canonical" || scenario == "omitted-type" || scenario == "exact-byte-limit"
			if accepted != want || wrongRoute.Load() || readErr != nil && strings.Contains(readErr.Error(), "PRIVATE-CANARY") || decodeErr != nil && (!errors.Is(decodeErr, ErrRead) || strings.Contains(decodeErr.Error(), "PRIVATE-CANARY")) {
				t.Fatal("native diagnostic list violated closed response/privacy contract")
			}
			expectedRequests := int32(1)
			if scenario == "invalid-namespace" || scenario == "cancelled" {
				expectedRequests = 0
			}
			if requests.Load() != expectedRequests {
				t.Fatal("native diagnostic list retried, redirected or escaped its original context")
			}
			if accepted && (len(pods.Items) != 1 || pods.Items[0].APIVersion != "v1" || pods.Items[0].Kind != "Pod") {
				t.Fatal("native literal omission was not canonically normalized")
			}
		})
	}
}

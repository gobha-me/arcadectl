// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/google/uuid"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	strictjson "sigs.k8s.io/json"
)

// Private transport primitive, NOT fixture permission or a complete provider.
// The closed provider must separately prove cold/runtime absence, dry-run whole
// shapes BEFORE CREATE, whole original live shapes/descendant absence BEFORE
// DELETE, all behavioral probes, and cleanup/retirement. No public caller uses
// this primitive yet. There is no callback/object/path/actor selection API.
type fixtureWire struct {
	ledger       *fixtureLedger
	actors       *admissionActors
	clients      map[admissionActor]*HTTPAccess
	previewStage fixturePreviewStage // diagnostics only, protected by ledger.wireMu
}

type fixtureRequest uint8

const (
	fixtureGetRequest fixtureRequest = iota + 1
	fixtureCreateRequest
	fixtureDeleteRequest
	fixtureDryRunRequest
	fixtureSeedStatusRequest
	fixtureWarmSeedStatusRequest
)

func (actors *admissionActors) fixtures(ctx context.Context, ledger *fixtureLedger) (*fixtureWire, error) {
	if actors == nil || actors.admission == nil || actors.admission.prerequisites == nil || ledger == nil || ledger.engine == nil || ledger.engine != actors.admission.prerequisites.engine {
		return nil, ErrFixtures
	}
	ledger.wireMu.Lock()
	defer ledger.wireMu.Unlock()
	w := &fixtureWire{ledger: ledger, actors: actors, clients: map[admissionActor]*HTTPAccess{}}
	if w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	parent := actors.admission.prerequisites.access
	if !parent.actorCompatible() {
		return nil, ErrFixtures
	}
	for _, actor := range []admissionActor{0, destroyAdministratorActor, destroyControllerActor} {
		config := rest.CopyConfig(parent.frozen)
		identity := fixtureWireIdentity{actor: actor, namespace: actors.request.Snapshot.Anchor().Namespace}
		if actor != 0 {
			identity.username = "system:serviceaccount:" + identity.namespace + ":" + actor.account()
			config.Impersonate = rest.ImpersonationConfig{UserName: identity.username}
		}
		if config.BearerToken != "" {
			identity.authorization = "Bearer " + config.BearerToken
		} else if config.Username != "" || config.Password != "" {
			identity.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(config.Username+":"+config.Password))
		}
		config.WrapTransport = func(next http.RoundTripper) http.RoundTripper { return fixtureIdentityTransport{next, identity} }
		client, err := NewDirectHTTPAccess(config)
		if err != nil {
			return nil, ErrFixtures
		}
		w.clients[actor] = client // never returned as general Access
	}
	return w, nil
}

func (w *fixtureWire) current(ctx context.Context) error {
	if ctx == nil || w.localCurrent() != nil || w.actors.verify(ctx) != nil {
		return ErrFixtures
	}
	return nil
}

// Exact protected local evidence, never a substitute for live authorization,
// actor/policy/journal guards or a complete phase. The read-only named scan
// retains these checks at EACH old boundary, even when remote guards bracket
// the whole closed scan. Local inode+hash identity is not a monotonic version.
func (w *fixtureWire) localCurrent() error {
	if w == nil || w.ledger == nil || w.ledger.engine == nil || w.ledger.engine.files == nil || w.actors == nil || w.ledger.lock == nil {
		return ErrFixtures
	}
	f, s := w.ledger, w.actors.request.Snapshot
	if s == nil || !bytes.Equal(f.document.Journal, s.Bytes()) || f.document.JournalResourceVersion != s.ResourceVersion() {
		return ErrFixtures
	}
	if f.document.OriginalWorldsSHA256 != "" && f.originalWorldsCurrent() != nil {
		return ErrFixtures
	}
	body, identity, err := f.engine.files.Read(f.name, fixtureLedgerMaxBytes)
	if err != nil || identity != f.identity || !bytes.Equal(body, f.body) || f.engine.files.ConfirmDurable(f.name, identity) != nil {
		return ErrFixtures
	}
	d, err := f.decodeCurrentWAL(body)
	if err != nil || !reflect.DeepEqual(d, f.document) {
		return ErrFixtures
	}
	return nil
}

func fixturePath(key installstate.Key, collection bool) (string, string, error) {
	if !installrender.ValidNamespace(key.Namespace) || !addressPart(key.Name) {
		return "", "", ErrFixtures
	}
	prefix, plural := "/api/v1", ""
	switch key.APIVersion + "/" + key.Kind {
	case "v1/Pod":
		plural = "pods"
	case "v1/ServiceAccount":
		plural = "serviceaccounts"
	case "v1/PersistentVolumeClaim":
		plural = "persistentvolumeclaims"
	case "batch/v1/Job":
		prefix, plural = "/apis/batch/v1", "jobs"
	case "arcade.gobha.me/v1alpha1/GameDestroy":
		prefix, plural = "/apis/arcade.gobha.me/v1alpha1", "gamedestroys"
	default:
		return "", "", ErrFixtures
	}
	path := prefix + "/namespaces/" + key.Namespace + "/" + plural
	if !collection {
		path += "/" + key.Name
	}
	return path, plural, nil
}

func fixturePermission(key installstate.Key, verb string) (proofPermission, error) {
	_, plural, err := fixturePath(key, verb == "create")
	if err != nil || verb != "get" && verb != "create" && verb != "delete" {
		return proofPermission{}, ErrFixtures
	}
	group, version, _ := strings.Cut(key.APIVersion, "/")
	if version == "" {
		group, version = "", key.APIVersion
	}
	name := key.Name
	if verb == "create" {
		name = ""
	}
	return proofPermission{spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Group: group, Version: version, Resource: plural, Namespace: key.Namespace, Name: name, Verb: verb}}, kind: key.Kind}, nil
}

func fixtureActor(slot int, verb string) admissionActor {
	if slot == fixtureCancelledDestroy && verb == "create" {
		return destroyAdministratorActor
	}
	if slot == fixtureRetainedPVC && verb == "delete" {
		return destroyControllerActor
	}
	return 0 // original administrator; never another runtime/human identity
}

func (w *fixtureWire) prepare(ctx context.Context, slot int, verb string) (installstate.Key, admissionActor, error) {
	if w == nil || w.ledger == nil || slot < 0 || slot >= len(fixtureCatalogFor(w.ledger.document)) || verb != "get" && (w.ledger.markerUnresolved() || w.ledger.retirementArchive) || w.current(ctx) != nil {
		return installstate.Key{}, 0, ErrFixtures
	}
	key := w.ledger.document.Entries[slot].Key
	actor := fixtureActor(slot, verb)
	permission, err := fixturePermission(key, verb)
	if err != nil {
		return installstate.Key{}, 0, ErrFixtures
	}
	parent := w.actors.admission.prerequisites.access
	discovery, err := parent.discover(ctx, key.APIVersion)
	if err != nil || !discoveredPermission(discovery, permission) {
		return installstate.Key{}, 0, ErrFixtures
	}
	authorizer := parent
	if actor != 0 {
		authorizer = w.actors.clients[actor]
	}
	if authorizer == nil || authorizer.authorize(ctx, permission.spec) != nil || w.current(ctx) != nil {
		return installstate.Key{}, 0, ErrFixtures
	}
	return key, actor, nil
}

// GET never pins/adopts a UID or resets an attempt. The provider must validate
// the whole returned object; NotFound is only exact-address observation, not
// original-UID ownership or permission to replay a prior CREATE/DELETE.
func (w *fixtureWire) get(ctx context.Context, slot int) (*unstructured.Unstructured, bool, error) {
	if w == nil || w.ledger == nil {
		return nil, false, ErrFixtures
	}
	w.ledger.wireMu.Lock()
	defer w.ledger.wireMu.Unlock()
	return w.getLocked(ctx, slot)
}

// Caller holds this ledger's wireMu, including composed read-only observations.
func (w *fixtureWire) getLocked(ctx context.Context, slot int) (*unstructured.Unstructured, bool, error) {
	_, _, err := w.prepare(ctx, slot, "get")
	if err != nil {
		return nil, false, err
	}
	capture, err := w.request(ctx, slot, fixtureGetRequest)
	if err != nil || w.current(ctx) != nil {
		return nil, false, ErrFixtures
	}
	if capture.notFound {
		return nil, true, nil
	}
	if capture.result == nil {
		return nil, false, ErrFixtures
	}
	uid := w.ledger.document.Entries[slot].OriginalUID
	if uid != "" && capture.result.GetUID() != uid {
		return nil, false, ErrFixtures
	}
	return capture.result.DeepCopy(), false, nil
}

// Preview only the next original Planned recipe, never a pending/cleanup slot.
// Whole-shape validation and unchanged original witnesses precede acceptance.
// This sends once, never records the preview UID or changes the WAL/capability,
// and does not authorize the separate durable CREATE intent or any cleanup.
func (w *fixtureWire) dryRun(ctx context.Context, slot int) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	w.ledger.wireMu.Lock()
	defer w.ledger.wireMu.Unlock()
	return w.dryRunLocked(ctx, slot)
}

// The closed admission driver holds wireMu across both complete phase
// observations and this one send. Keep the lock-owning wrapper for other paths.
func (w *fixtureWire) dryRunLocked(ctx context.Context, slot int) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewReadiness
	if !w.ledger.dryRunReady(slot) {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewPrepare
	if _, _, err := w.prepare(ctx, slot, "create"); err != nil {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewPreparedReadiness
	if !w.ledger.dryRunReady(slot) {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewRequest
	capture, err := w.request(ctx, slot, fixtureDryRunRequest)
	if err != nil {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewReply
	if capture == nil || capture.result == nil || capture.uid != "" {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewPostWitness
	if w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewPostReadiness
	if !w.ledger.dryRunReady(slot) {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewWholeShape
	if w.ledger.validateResult(slot, fixtureDryRunResult, capture.result, time.Now().UTC()) != nil {
		return nil, ErrFixtures
	}
	w.previewStage = fixturePreviewAccepted
	return capture.result.DeepCopy(), nil
}

func (f *fixtureLedger) dryRunReady(slot int) bool {
	if f.markerUnresolved() || slot < 0 || slot >= len(fixtureCatalogFor(f.document)) || f.ackSlot != -1 || f.effectSlot != -1 || f.document.Entries[slot].State != fixturePlanned {
		return false
	}
	next, err := f.nextDocument()
	if err != nil {
		return false
	}
	next.Entries[slot].State = fixtureCreateAttempted
	return validFixtureTransition(f.document, next)
}

// Only the SAME instance's newly durable intent may send ONCE. Rebuilding this
// wire client cannot restore its shared ledger capability. Reliable ACK UID is
// pinned/fsynced BEFORE returning a body for the separate whole-shape validator,
// or checking post-request witnesses. Unknown outcomes revoke ACK capability.
func (w *fixtureWire) create(ctx context.Context, slot int) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil || slot < 0 || slot >= fixtureMaxSlots {
		return nil, ErrFixtures
	}
	w.ledger.wireMu.Lock()
	defer w.ledger.wireMu.Unlock()
	return w.createLocked(ctx, slot)
}

// Caller holds wireMu for the complete original-creation witness interval.
func (w *fixtureWire) createLocked(ctx context.Context, slot int) (*unstructured.Unstructured, error) {
	if w == nil || w.ledger == nil || slot < 0 || slot >= fixtureMaxSlots {
		return nil, ErrFixtures
	}
	if slot >= len(fixtureCatalogFor(w.ledger.document)) {
		return nil, ErrFixtures
	}
	if w.ledger.document.Entries[slot].State != fixtureCreateAttempted || w.ledger.ackSlot != slot || w.ledger.effectSlot != slot {
		return nil, ErrFixtures
	}
	_, _, err := w.prepare(ctx, slot, "create")
	if err != nil {
		return nil, err
	}
	f := w.ledger
	entry := f.document.Entries[slot]
	if entry.State != fixtureCreateAttempted || f.ackSlot != slot || f.effectSlot != slot {
		return nil, ErrFixtures
	}
	if _, err := f.object(slot); err != nil {
		return nil, err
	}
	defer func() { f.ackSlot = -1 }()
	capture, requestErr := w.request(ctx, slot, fixtureCreateRequest)
	if capture == nil || capture.uid == "" {
		return nil, ErrOutcomeUnknown
	}
	next, err := f.nextDocument()
	if err != nil {
		return nil, ErrFixtures
	}
	next.Entries[slot].State, next.Entries[slot].OriginalUID = fixtureOriginal, capture.uid
	if f.advance(next) != nil || requestErr != nil || w.current(ctx) != nil {
		return nil, ErrFixtures
	}
	return capture.result.DeepCopy(), nil // not whole-shape acceptance or effect authorization
}

func (w *fixtureWire) delete(ctx context.Context, slot int) error {
	if w == nil || w.ledger == nil || slot < 0 || slot >= fixtureMaxSlots {
		return ErrFixtures
	}
	w.ledger.wireMu.Lock()
	defer w.ledger.wireMu.Unlock()
	if slot >= len(fixtureCatalogFor(w.ledger.document)) {
		return ErrFixtures
	}
	if w.ledger.document.Entries[slot].State != fixtureDeleteAttempted || w.ledger.effectSlot != slot {
		return ErrFixtures
	}
	_, _, err := w.prepare(ctx, slot, "delete")
	if err != nil {
		return err
	}
	f := w.ledger
	entry := f.document.Entries[slot]
	if entry.State != fixtureDeleteAttempted || f.effectSlot != slot || entry.OriginalUID == "" || !fixtureRV(entry.DeleteResourceVersion) {
		return ErrFixtures
	}
	_, err = w.request(ctx, slot, fixtureDeleteRequest)
	if err != nil || w.current(ctx) != nil {
		return ErrOutcomeUnknown
	}
	return nil // state remains delete-attempted; independent actual absence required
}

func fixtureDeleteOptions(entry fixtureEntry) (metav1.DeleteOptions, error) {
	if entry.State != fixtureDeleteAttempted || entry.OriginalUID == "" || !fixtureRV(entry.DeleteResourceVersion) {
		return metav1.DeleteOptions{}, ErrFixtures
	}
	uid, rv := entry.OriginalUID, entry.DeleteResourceVersion
	propagation := metav1.DeletePropagationBackground
	if entry.Key.Kind == "Job" {
		propagation = metav1.DeletePropagationForeground
	}
	opts := metav1.DeleteOptions{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "DeleteOptions"}, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}, PropagationPolicy: &propagation}
	if entry.Key.Kind == "Pod" {
		zero := int64(0)
		opts.GracePeriodSeconds = &zero
	}
	return opts, nil
}

type fixtureWireIdentity struct {
	actor                              admissionActor
	namespace, username, authorization string
}
type fixtureIdentityTransport struct {
	next     http.RoundTripper
	identity fixtureWireIdentity
}

func (t fixtureIdentityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil {
		return nil, ErrFixtures
	}
	attempt, ok := r.Context().Value(attemptKey{}).(*requestAttempt)
	if !ok || attempt == nil || attempt.fixture == nil || attempt.fixture.identity != t.identity || !attempt.fixture.guard(r) {
		return nil, ErrFixtures
	}
	return t.next.RoundTrip(r)
}

type fixtureCapture struct {
	identity           fixtureWireIdentity
	method, url        string
	body               []byte
	key                installstate.Key
	result             *unstructured.Unstructured
	uid                types.UID
	notFound, success  bool
	strictNotFound     bool // closed CREATE-counterpart reads need exact native Status
	dryRun             bool
	seedUID            types.UID
	seedBeforeRV       string
	seedAcknowledgedRV string
}

func (c *fixtureCapture) guard(r *http.Request) bool {
	if c == nil || !(&probeCapture{method: c.method, url: c.url, body: c.body}).guard(r) {
		return false
	}
	userSeen, authSeen := false, false
	for key, values := range r.Header {
		switch {
		case strings.EqualFold(key, "Accept"), strings.EqualFold(key, "Content-Type"):
			if key != "Accept" && key != "Content-Type" || len(values) != 1 || values[0] != "application/json" {
				return false
			}
		case strings.EqualFold(key, "Idempotency-Key"), strings.EqualFold(key, "X-Idempotency-Key"):
			return false // even empty/aliased keys make GET/POST replayable in net/http
		case strings.EqualFold(key, "Impersonate-User"):
			if userSeen || c.identity.username == "" || key != "Impersonate-User" || len(values) != 1 || values[0] != c.identity.username {
				return false
			}
			userSeen = true
		case strings.HasPrefix(strings.ToLower(key), "impersonate-"):
			return false
		case strings.EqualFold(key, "Authorization"):
			if authSeen || c.identity.authorization == "" || key != "Authorization" || len(values) != 1 || values[0] != c.identity.authorization {
				return false
			}
			authSeen = true
		}
	}
	return userSeen == (c.identity.username != "") && authSeen == (c.identity.authorization != "")
}

func nativeFixtureUID(value string) bool {
	u, err := uuid.Parse(value)
	return err == nil && value == u.String() && u != uuid.Nil
}

// Parse the reply below wrappers and strip ALL response bodies at the caller.
// Only complete bounded unambiguous JSON with the exact original route identity
// yields a reliable CREATE UID or original status-seed UID/distinct RV;
// spec/status/remaining metadata are NOT trusted until whole validation.
func (c *fixtureCapture) capture(response *http.Response) {
	if response == nil {
		return
	}
	if response.Body != nil {
		defer response.Body.Close()
	}
	if c.method == http.MethodGet && response.StatusCode == http.StatusNotFound {
		if c.strictNotFound && !fixtureCounterpartNotFound(response, c.key) {
			return
		}
		c.notFound, c.success = true, true
		return
	}
	if c.method == http.MethodDelete {
		c.success = response.StatusCode == http.StatusOK || response.StatusCode == http.StatusAccepted
		return
	}
	want := http.StatusOK
	if c.method == http.MethodPost {
		want = http.StatusCreated
	}
	if response.StatusCode != want || response.Body == nil {
		return
	}
	typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || !utf8.Valid(raw) || !boundedJSON(raw) {
		return
	}
	var fields map[string]any
	if strictErrors, err := strictjson.UnmarshalStrict(raw, &fields); err != nil || len(strictErrors) != 0 || fields == nil {
		return
	}
	o := &unstructured.Unstructured{Object: fields}
	key := installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
	if key != c.key || !nativeFixtureUID(string(o.GetUID())) {
		return
	}
	if c.method == http.MethodPut {
		if !nativeFixtureUID(string(c.seedUID)) || o.GetUID() != c.seedUID || !fixtureRV(c.seedBeforeRV) || !fixtureRV(o.GetResourceVersion()) || o.GetResourceVersion() == c.seedBeforeRV {
			return
		}
		c.seedAcknowledgedRV = o.GetResourceVersion()
	}
	c.result, c.success = o, true
	if c.method == http.MethodPost && !c.dryRun {
		c.uid = o.GetUID()
	}
}

// Called only with ledger.wireMu held by the closed operations above. It has no
// caller-selected key, actor or payload. Persistent effects consume the shared
// send capability immediately before Do; preview never consumes or grants one.
// Even an accidental new caller cannot select generic PUT/PATCH or a non-dry
// preview. Both closed status routes derive from the fixed original intent.
func (w *fixtureWire) request(ctx context.Context, slot int, operation fixtureRequest) (*fixtureCapture, error) {
	if ctx == nil || w == nil || w.ledger == nil || w.actors == nil || w.actors.admission == nil || w.actors.admission.prerequisites == nil || w.actors.admission.prerequisites.access == nil || w.actors.admission.prerequisites.access.frozen == nil || slot < 0 || slot >= len(fixtureCatalogFor(w.ledger.document)) {
		return nil, ErrFixtures
	}
	f := w.ledger
	if f.document.OriginalWorldsSHA256 != "" && f.originalWorldsCurrent() != nil {
		return nil, ErrFixtures
	}
	if operation != fixtureGetRequest && f.markerUnresolved() {
		return nil, ErrFixtures // no old effect route accepts a marked/unknown PVC
	}
	seedRequest := operation == fixtureSeedStatusRequest || operation == fixtureWarmSeedStatusRequest
	entry := f.document.Entries[slot]
	key := entry.Key
	var payload any
	verb, method := "", ""
	switch operation {
	case fixtureGetRequest:
		verb, method = "get", http.MethodGet
	case fixtureCreateRequest, fixtureDryRunRequest:
		verb, method = "create", http.MethodPost
		if operation == fixtureDryRunRequest {
			if !f.dryRunReady(slot) {
				return nil, ErrFixtures
			}
		} else if entry.State != fixtureCreateAttempted || f.ackSlot != slot || f.effectSlot != slot {
			return nil, ErrFixtures
		}
		o, err := f.object(slot)
		if err != nil {
			return nil, ErrFixtures
		}
		payload = o.Object
	case fixtureDeleteRequest:
		verb, method = "delete", http.MethodDelete
		if f.effectSlot != slot {
			return nil, ErrFixtures
		}
		opts, err := fixtureDeleteOptions(entry)
		if err != nil {
			return nil, ErrFixtures
		}
		payload = opts
	case fixtureSeedStatusRequest:
		if slot != fixtureCancelledDestroy {
			return nil, ErrFixtures
		}
		verb, method = "seed-status", http.MethodPut
		o, err := w.destroySeedPayload(ctx)
		if err != nil {
			return nil, ErrFixtures
		}
		payload = o.Object
	case fixtureWarmSeedStatusRequest:
		if slot != fixtureCancelledDestroy {
			return nil, ErrFixtures
		}
		verb, method = "seed-status", http.MethodPut
		o, err := w.warmDestroySeedPayload(ctx)
		if err != nil {
			return nil, ErrFixtures
		}
		payload = o.Object
	default:
		return nil, ErrFixtures
	}
	actor := fixtureActor(slot, verb)
	a := w.clients[actor]
	if a == nil || a.base == nil || a.client == nil {
		return nil, ErrFixtures
	}
	path, _, err := fixturePath(key, method == http.MethodPost)
	if err != nil {
		return nil, ErrFixtures
	}
	if seedRequest {
		path += "/status"
	}
	identity := fixtureWireIdentity{actor: actor, namespace: key.Namespace}
	parent := w.actors.admission.prerequisites.access.frozen
	if actor != 0 {
		identity.username = "system:serviceaccount:" + key.Namespace + ":" + actor.account()
	}
	if parent.BearerToken != "" {
		identity.authorization = "Bearer " + parent.BearerToken
	} else if parent.Username != "" || parent.Password != "" {
		identity.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(parent.Username+":"+parent.Password))
	}
	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil || len(body) > 65536 {
			return nil, ErrFixtures
		}
	}
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = ""
	if method == http.MethodPost || seedRequest {
		u.RawQuery = "fieldManager=arcadectl-installer&fieldValidation=Strict"
		if operation == fixtureDryRunRequest {
			u.RawQuery = "dryRun=All&" + u.RawQuery
		}
	}
	capture := &fixtureCapture{identity: identity, method: method, url: u.String(), body: body, key: key, dryRun: operation == fixtureDryRunRequest}
	if seedRequest {
		if operation == fixtureSeedStatusRequest && !f.destroySeedReady() || operation == fixtureWarmSeedStatusRequest && !f.destroyWarmSeedReady() {
			return nil, ErrFixtures
		}
		capture.seedUID, capture.seedBeforeRV = entry.OriginalUID, f.document.DestroySeed.BeforeResourceVersion
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	ctx = context.WithValue(ctx, attemptKey{}, &requestAttempt{method: method, fixture: capture})
	r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrFixtures
	}
	r.GetBody = nil
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Content-Type", "application/json")
	if f.document.OriginalWorldsSHA256 != "" && f.originalWorldsCurrent() != nil {
		return nil, ErrFixtures
	}
	if operation == fixtureCreateRequest || operation == fixtureDeleteRequest {
		f.effectSlot = -1
	} // consumed before any possible wire attempt
	if seedRequest {
		f.seedEffect = false
	}
	response, err := a.client.Do(r)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil || !capture.success {
		if seedRequest && capture.seedAcknowledgedRV == "" {
			f.seedAck = false // even a direct private enum caller cannot ACK uncertainty
		}
		return capture, ErrFixtures
	}
	return capture, nil
}

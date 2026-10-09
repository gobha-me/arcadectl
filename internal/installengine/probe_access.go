// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	strictjson "sigs.k8s.io/json"
)

type probeCapture struct {
	method                  string
	url                     string
	body                    []byte
	expected                map[string]any
	denied                  atomic.Bool
	operation               admissionProbeOperation
	key                     installstate.Key
	originalUID             types.UID
	originalResourceVersion string
	reply                   *unstructured.Unstructured
	accepted                atomic.Bool
}

// guard runs BELOW wrappers and BEFORE the wire. A wrapper cannot turn a
// nonpersistent probe into a real write, a different route or a different
// operation. In particular DELETE needs dryRun in its BODY, not just its URL.
func (p *probeCapture) guard(r *http.Request) bool {
	if p == nil || r == nil || r.URL == nil || r.Host != r.URL.Host || r.RequestURI != "" || r.Method != p.method || r.URL.String() != p.url || r.GetBody != nil || r.Body == nil || r.ContentLength != int64(len(p.body)) || len(r.TransferEncoding) != 0 || !exactProbeHeader(r.Header, "Accept", "application/json") || !exactProbeHeader(r.Header, "Content-Type", probeContentType(p.operation)) {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	_ = r.Body.Close()
	if err != nil || !bytes.Equal(body, p.body) {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return true
}

func exactProbeHeader(header http.Header, name, value string) bool {
	seen := false
	for key, values := range header {
		if !strings.EqualFold(key, name) {
			continue
		}
		if seen || key != name || len(values) != 1 || values[0] != value {
			return false
		}
		seen = true
	}
	return seen
}

func probeContentType(operation admissionProbeOperation) string {
	if operation == probePatchMetadataOperation {
		return "application/merge-patch+json"
	}
	return "application/json"
}

// classify runs inside the inner transport, before SDK wrappers can see any
// native error body. Only a fixed single-attempt dry-run operation's exact native
// policy/binding/validation Status is evidence; raw errors never escape.
func (p *probeCapture) classify(request *http.Request, response *http.Response) {
	if p == nil || p.expected == nil || request.Method != p.method || request.URL.String() != p.url || response.StatusCode != http.StatusUnprocessableEntity || response.Body == nil {
		return
	}
	typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) == 0 || len(body) > 65536 || !utf8.Valid(body) || !boundedJSON(body) {
		return
	}
	var status metav1.Status
	strictErrors, err := strictjson.UnmarshalStrict(body, &status)
	if err != nil || len(strictErrors) != 0 {
		return
	}
	var fields map[string]any
	strictErrors, err = strictjson.UnmarshalStrict(body, &fields)
	if err == nil && len(strictErrors) == 0 && reflect.DeepEqual(fields, p.expected) {
		p.denied.Store(true)
	}
}

func probePath(key installstate.Key) (string, string, error) {
	if !installrender.ValidNamespace(key.Namespace) || !addressPart(key.Name) {
		return "", "", ErrInvalid
	}
	plural, prefix := "", "/api/v1"
	switch key.APIVersion + "/" + key.Kind {
	case "v1/Pod":
		plural = "pods"
	case "v1/PersistentVolumeClaim":
		plural = "persistentvolumeclaims"
	case "arcade.gobha.me/v1alpha1/GameDestroy":
		plural, prefix = "gamedestroys", "/apis/arcade.gobha.me/v1alpha1"
	default:
		return "", "", ErrInvalid
	}
	return prefix + "/namespaces/" + key.Namespace + "/" + plural, plural, nil
}

func expectedProbeDenial(key installstate.Key, plural, policy, binding, validation string) (map[string]any, error) {
	group := ""
	if key.Kind == "GameDestroy" {
		group = "arcade.gobha.me"
	}
	return expectedProbeDenialGroup(key, plural, group, policy, binding, validation)
}

func expectedProbeDenialGroup(key installstate.Key, plural, group, policy, binding, validation string) (map[string]any, error) {
	if !addressPart(policy) || !addressPart(binding) || validation == "" || len(validation) > 2048 {
		return nil, ErrInvalid
	}
	cause := fmt.Sprintf("ValidatingAdmissionPolicy '%s' with binding '%s' denied request: %s", policy, binding, validation)
	resource := plural
	if group != "" {
		resource += "." + group
	}
	status := metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Code: http.StatusUnprocessableEntity, Reason: metav1.StatusReasonInvalid, Message: fmt.Sprintf("%s %q is forbidden: %s", resource, key.Name, cause), Details: &metav1.StatusDetails{Group: group, Kind: plural, Name: key.Name, Causes: []metav1.StatusCause{{Message: cause}}}}
	body, err := json.Marshal(status)
	if err != nil {
		return nil, ErrInvalid
	}
	var fields map[string]any
	if strictErrors, err := strictjson.UnmarshalStrict(body, &fields); err != nil || len(strictErrors) != 0 {
		return nil, ErrInvalid
	}
	return fields, nil
}

func (a *HTTPAccess) probeCreate(ctx context.Context, object *unstructured.Unstructured, policy, binding, validation string) (*unstructured.Unstructured, error) {
	return a.probeOperation(ctx, probeCreateOperation, object, policy, binding, validation)
}

type admissionProbeOperation uint8

const (
	probeCreateOperation admissionProbeOperation = iota
	probeUpdateOperation
	probeEphemeralOperation
	probeResizeOperation
	probeDeletePVCOperation
	probeDeleteAccountOperation    // baseline-only, never a PVC-delete route
	probeDeleteExecutableOperation // baseline-only exact denial; no accepted DELETE
	probeDeleteIdentityOperation   // baseline-only Role/RoleBinding/Service denial
	probePatchMetadataOperation    // baseline-only internally built metadata denial
)

// This seam is private and dry-run ONLY. It does not authorize persistent
// fixture creation, PVC deletion, impersonation or additional installer RBAC.
// Named operations require the actual old object's UID/RV, not fictitious
// CREATE metadata. Callers must independently verify the whole returned shape
// and reread the unchanged original object across the operation.
func (a *HTTPAccess) probeOperation(ctx context.Context, operation admissionProbeOperation, object *unstructured.Unstructured, policy, binding, validation string) (*unstructured.Unstructured, error) {
	if a == nil || a.client == nil || a.base == nil || ctx == nil || object == nil {
		return nil, ErrInvalid
	}
	key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
	path, plural, err := probePath(key)
	if a.actor != nil && a.actor.purpose == baselineAdmissionPurpose {
		path, plural, err = baselineProbePath(key)
	}
	if err != nil {
		return nil, err
	}
	if a.actor != nil && !a.actor.allows(key, operation) {
		return nil, ErrInvalid
	}
	method, successCode := http.MethodPost, http.StatusCreated
	query := "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict"
	var payload any = object.Object
	switch operation {
	case probeCreateOperation:
		if object.GetUID() != "" || object.GetResourceVersion() != "" {
			return nil, ErrInvalid
		}
	case probeUpdateOperation, probeEphemeralOperation, probeResizeOperation, probeDeletePVCOperation, probeDeleteAccountOperation, probeDeleteExecutableOperation, probeDeleteIdentityOperation, probePatchMetadataOperation:
		// The two declared native storage profiles encode RV as uint64.
		// Zero (including zero-padded spellings) selects unconditional UPDATE,
		// so it must never count as a pinned oldObject, even on a VAP denial.
		rv, err := strconv.ParseUint(object.GetResourceVersion(), 10, 64)
		if !receiptUID.MatchString(string(object.GetUID())) || err != nil || rv == 0 || strconv.FormatUint(rv, 10) != object.GetResourceVersion() {
			return nil, ErrInvalid
		}
		path += "/" + key.Name
		method, successCode = http.MethodPut, http.StatusOK
		switch operation {
		case probePatchMetadataOperation:
			if a.actor == nil || a.actor.purpose != baselineAdmissionPurpose || key.Kind != "Deployment" && key.Kind != "Service" {
				return nil, ErrInvalid
			}
			method = http.MethodPatch
			// No caller-supplied patch or object/spec fields are forwarded.
			// Whole original witnesses still bracket this dry-run denial.
			payload = map[string]any{"metadata": map[string]any{"uid": string(object.GetUID()), "resourceVersion": object.GetResourceVersion(), "annotations": map[string]any{"arcade.gobha.me/identity-probe": "dry-run"}}}
		case probeEphemeralOperation, probeResizeOperation:
			if key.Kind != "Pod" {
				return nil, ErrInvalid
			}
			if operation == probeEphemeralOperation {
				path += "/ephemeralcontainers"
			} else {
				path += "/resize"
			}
		case probeDeletePVCOperation, probeDeleteAccountOperation, probeDeleteExecutableOperation, probeDeleteIdentityOperation:
			if operation == probeDeletePVCOperation && key.Kind != "PersistentVolumeClaim" ||
				operation == probeDeleteAccountOperation && (key.Kind != "ServiceAccount" || a.actor == nil || a.actor.purpose != baselineAdmissionPurpose) ||
				operation == probeDeleteExecutableOperation && (a.actor == nil || a.actor.purpose != baselineAdmissionPurpose || key.Kind != "Job" && key.Kind != "Deployment") ||
				operation == probeDeleteIdentityOperation && (a.actor == nil || a.actor.purpose != baselineAdmissionPurpose || key.Kind != "Role" && key.Kind != "RoleBinding" && key.Kind != "Service") {
				return nil, ErrInvalid
			}
			method, query = http.MethodDelete, "dryRun=All"
			uid, rv := object.GetUID(), object.GetResourceVersion()
			payload = metav1.DeleteOptions{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "DeleteOptions"}, DryRun: []string{metav1.DryRunAll}, Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}
		}
	default:
		return nil, ErrInvalid
	}
	negative := policy != "" || binding != "" || validation != ""
	if (operation == probeDeleteAccountOperation || operation == probeDeleteExecutableOperation || operation == probeDeleteIdentityOperation || operation == probePatchMetadataOperation || a.actor != nil && a.actor.purpose == baselineAdmissionPurpose && baselineIdentityKey(key)) && !negative {
		return nil, ErrInvalid // identity/PATCH/DELETE never yields accepted authority
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = query
	body, err := json.Marshal(payload)
	if err != nil || len(body) > 65536 {
		return nil, ErrInvalid
	}
	capture := &probeCapture{method: method, url: u.String(), body: body, operation: operation, key: key, originalUID: object.GetUID(), originalResourceVersion: object.GetResourceVersion()}
	if negative {
		expected, err := expectedProbeDenial(key, plural, policy, binding, validation)
		if err != nil {
			return nil, err
		}
		capture.expected = expected
		if a.actor != nil && a.actor.purpose == baselineAdmissionPurpose {
			capture.expected, err = expectedBaselineProbeDenial(key, plural, policy, binding, validation)
			if err != nil {
				return nil, err
			}
		}
	}
	attempt := &requestAttempt{method: method, probe: capture}
	if a.actor != nil {
		attempt.actor = &actorRequestCapture{identity: *a.actor, method: method, url: u.String(), body: body, contentType: probeContentType(operation)}
	}
	ctx = context.WithValue(ctx, attemptKey{}, attempt)
	request, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalid
	}
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", probeContentType(operation))
	response, err := a.client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrAdmission
	}
	defer response.Body.Close()
	if negative {
		if response.StatusCode == http.StatusUnprocessableEntity && capture.denied.Load() {
			return nil, nil
		}
		return nil, ErrAdmission
	}
	if response.StatusCode != successCode {
		return nil, ErrAdmission
	}
	typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return nil, ErrAdmission
	}
	// The inner single-attempt guard captured and bounded the native reply
	// BEFORE client-go/debug/identity wrappers. Their body cannot substitute
	// evidence or fabricate a success without the exact underlying request.
	result := capture.positiveResult()
	if result == nil {
		return nil, ErrAdmission
	}
	if result.GetAPIVersion() != key.APIVersion || result.GetKind() != key.Kind || result.GetNamespace() != key.Namespace || result.GetName() != key.Name {
		return nil, ErrAdmission
	}
	if operation != probeCreateOperation && (result.GetUID() != object.GetUID() || result.GetResourceVersion() != object.GetResourceVersion()) {
		return nil, ErrAdmission
	}
	return result, nil // caller must additionally verify the whole defaulted shape
}

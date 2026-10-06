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
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	strictjson "sigs.k8s.io/json"
)

type probeCaptureKey struct{}
type probeCapture struct {
	path     string
	expected map[string]any
	denied   atomic.Bool
}

// classify runs inside the inner transport, before SDK wrappers can see any
// native error body. Only a fixed single-attempt dry-run CREATE's exact native
// policy/binding/validation Status is evidence; raw errors never escape.
func (p *probeCapture) classify(request *http.Request, response *http.Response) {
	if p == nil || request.Method != http.MethodPost || request.URL.Path != p.path || response.StatusCode != http.StatusUnprocessableEntity || response.Body == nil {
		return
	}
	q := request.URL.Query()
	if len(q) != 3 || len(q["dryRun"]) != 1 || len(q["fieldValidation"]) != 1 || len(q["fieldManager"]) != 1 || q.Get("dryRun") != "All" || q.Get("fieldValidation") != "Strict" || q.Get("fieldManager") != "arcadectl-installer" {
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
	if !addressPart(policy) || !addressPart(binding) || validation == "" || len(validation) > 2048 {
		return nil, ErrInvalid
	}
	group := ""
	if key.Kind == "GameDestroy" {
		group = "arcade.gobha.me"
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
	if a == nil || a.client == nil || a.base == nil || ctx == nil || object == nil {
		return nil, ErrInvalid
	}
	key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
	path, plural, err := probePath(key)
	if err != nil {
		return nil, err
	}
	negative := policy != "" || binding != "" || validation != ""
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	ctx = context.WithValue(ctx, attemptKey{}, &atomic.Bool{})
	var capture *probeCapture
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = "dryRun=All&fieldManager=arcadectl-installer&fieldValidation=Strict"
	if negative {
		expected, err := expectedProbeDenial(key, plural, policy, binding, validation)
		if err != nil {
			return nil, err
		}
		capture = &probeCapture{path: u.Path, expected: expected}
		ctx = context.WithValue(ctx, probeCaptureKey{}, capture)
	}
	body, err := json.Marshal(object.Object)
	if err != nil || len(body) > 65536 {
		return nil, ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrInvalid
	}
	request.GetBody = nil
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
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
	if response.StatusCode != http.StatusCreated {
		return nil, ErrAdmission
	}
	typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return nil, ErrAdmission
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || !utf8.Valid(raw) || !boundedJSON(raw) {
		return nil, ErrAdmission
	}
	var fields map[string]any
	strictErrors, err := strictjson.UnmarshalStrict(raw, &fields)
	if err != nil || len(strictErrors) != 0 || fields == nil {
		return nil, ErrAdmission
	}
	result := &unstructured.Unstructured{Object: fields}
	if result.GetAPIVersion() != key.APIVersion || result.GetKind() != key.Kind || result.GetNamespace() != key.Namespace || result.GetName() != key.Name {
		return nil, ErrAdmission
	}
	return result, nil // caller must additionally verify the whole defaulted shape
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/gobha-me/arcadectl/internal/installpackage"
	"github.com/gobha-me/arcadectl/internal/installrender"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	strictjson "sigs.k8s.io/json"
)

// proofRequest is private and used only by fixed version, discovery, named PV and
// authorization methods below. It exposes neither arbitrary routes nor retrying
// SDK clients. Authorization POSTs are nonpersistent evaluations, not effects.
func (a *HTTPAccess) proofRequest(ctx context.Context, method, path string, body any, out any) (map[string]any, error) {
	if a == nil || a.client == nil || a.base == nil || ctx == nil || out == nil || method != http.MethodGet && method != http.MethodPost || method == http.MethodPost && body == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	ctx = context.WithValue(ctx, attemptKey{}, &atomic.Bool{})
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil || len(encoded) > 65536 {
			return nil, ErrInvalid
		}
	}
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = ""
	if method == http.MethodPost {
		u.RawQuery = "fieldManager=arcadectl-installer&fieldValidation=Strict"
	}
	r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(encoded))
	if err != nil {
		return nil, ErrInvalid
	}
	r.GetBody = nil
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := a.client.Do(r)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrRead
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && !(method == http.MethodPost && response.StatusCode == http.StatusCreated) {
		return nil, ErrRead // ordinary error bodies remain stripped by inner guard
	}
	typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return nil, ErrRead
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || !utf8.Valid(raw) || !boundedJSON(raw) {
		return nil, ErrRead
	}
	strictErrors, err := strictjson.UnmarshalStrict(raw, out)
	if err != nil || len(strictErrors) != 0 {
		return nil, ErrRead
	}
	var fields map[string]any
	strictErrors, err = strictjson.UnmarshalStrict(raw, &fields)
	if err != nil || len(strictErrors) != 0 || fields == nil {
		return nil, ErrRead
	}
	return fields, nil
}

func (a *HTTPAccess) checkVersion(ctx context.Context, profile installpackage.Profile) error {
	if profile.ID != installrender.Profile135 && profile.ID != installrender.Profile137 {
		return ErrInvalid
	}
	expected := "1.35.8"
	if profile.ID == installrender.Profile137 {
		expected = "1.37.0"
	}
	if profile.KubernetesVersion != expected {
		return ErrInvalid
	}
	var info version.Info
	fields, err := a.proofRequest(ctx, http.MethodGet, "/version", nil, &info)
	if err != nil {
		return err
	}
	// Null strings must not be silently accepted as Go's zero value.
	for _, value := range fields {
		v, ok := value.(string)
		if !ok || len(v) > 1024 {
			return ErrRead
		}
	}
	parts := strings.Split(expected, ".")
	if info.Major != parts[0] || info.Minor != parts[1] || info.GitVersion != "v"+expected {
		return ErrRead
	}
	for _, pair := range [][2]string{{"emulationMajor", "emulationMinor"}, {"minCompatibilityMajor", "minCompatibilityMinor"}} {
		major, hasMajor := fields[pair[0]]
		minor, hasMinor := fields[pair[1]]
		if hasMajor != hasMinor {
			return ErrRead
		}
		if !hasMajor { // reviewed profiles may omit both optional fields
			continue
		}
		m, parseErr := strconv.ParseUint(minor.(string), 10, 32)
		want, _ := strconv.ParseUint(parts[1], 10, 32)
		if major != parts[0] || parseErr != nil || strconv.FormatUint(m, 10) != minor || m > want || pair[0] == "emulationMajor" && m != want {
			return ErrRead
		}
	}
	return nil
}

var proofGroups = []string{"v1", "apps/v1", "batch/v1", "coordination.k8s.io/v1", "discovery.k8s.io/v1", "storage.k8s.io/v1", "rbac.authorization.k8s.io/v1", "apiextensions.k8s.io/v1", "admissionregistration.k8s.io/v1", "authorization.k8s.io/v1", "arcade.gobha.me/v1alpha1"}

func discoveryPath(gv string) (string, error) {
	for _, known := range proofGroups {
		if known == gv {
			if gv == "v1" {
				return "/api/v1", nil
			}
			return "/apis/" + gv, nil
		}
	}
	return "", ErrInvalid
}

func (a *HTTPAccess) discover(ctx context.Context, gv string) (*metav1.APIResourceList, error) {
	path, err := discoveryPath(gv)
	if err != nil {
		return nil, err
	}
	var result metav1.APIResourceList
	fields, err := a.proofRequest(ctx, http.MethodGet, path, nil, &result)
	if err != nil || result.Kind != "APIResourceList" || result.GroupVersion != gv || len(result.APIResources) == 0 || len(result.APIResources) > 2048 {
		return nil, ErrRead
	}
	// Native discovery can omit apiVersion (unlike persisted object envelopes).
	// Its fixed route, exact groupVersion and APIResourceList kind identify the
	// response. A present version must be literal v1, never null/empty/foreign.
	if v, present := fields["apiVersion"]; present && v != "v1" {
		return nil, ErrRead
	}
	resources, ok := fields["resources"].([]any)
	if !ok || len(resources) != len(result.APIResources) {
		return nil, ErrRead
	}
	seen := map[string]bool{}
	for i, r := range result.APIResources {
		raw, ok := resources[i].(map[string]any)
		if !ok {
			return nil, ErrRead
		}
		if _, ok := raw["namespaced"].(bool); !ok {
			return nil, ErrRead
		}
		for _, key := range []string{"group", "version"} {
			if value, present := raw[key]; present {
				if _, ok := value.(string); !ok {
					return nil, ErrRead
				}
			}
		}
		if r.Name == "" || len(r.Name) > 253 || r.Kind == "" || len(r.Kind) > 128 || seen[r.Name] || len(r.Verbs) == 0 || len(r.Verbs) > 16 {
			return nil, ErrRead
		}
		seen[r.Name] = true
		verbs := map[string]bool{}
		for _, verb := range r.Verbs {
			if verb == "" || verb == "*" || len(verb) > 32 || verbs[verb] {
				return nil, ErrRead
			}
			verbs[verb] = true
		}
	}
	return result.DeepCopy(), nil
}

// authorize accepts only specs constructed by the sealed operation permission
// derivation, never a user/group/selector supplied by a configuration file.
func (a *HTTPAccess) authorize(ctx context.Context, spec authv1.SelfSubjectAccessReviewSpec) error {
	if (spec.ResourceAttributes == nil) == (spec.NonResourceAttributes == nil) {
		return ErrInvalid
	}
	request := authv1.SelfSubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: spec}
	var reply authv1.SelfSubjectAccessReview
	fields, err := a.proofRequest(ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", &request, &reply)
	meta := reply.ObjectMeta.DeepCopy()
	meta.ManagedFields = nil
	if err != nil || reply.APIVersion != request.APIVersion || reply.Kind != request.Kind || !reflect.DeepEqual(*meta, metav1.ObjectMeta{}) {
		return ErrRead
	}
	want, _ := json.Marshal(spec)
	var expectedSpec map[string]any
	strictErrors, err := strictjson.UnmarshalStrict(want, &expectedSpec)
	if err != nil || len(strictErrors) != 0 || !reflect.DeepEqual(expectedSpec, fields["spec"]) {
		return ErrRead
	}
	status, ok := fields["status"].(map[string]any)
	if !ok || status["allowed"] != true {
		return ErrRead
	}
	if denied, present := status["denied"]; present && denied != false {
		return ErrRead
	}
	if failure, present := status["evaluationError"]; present && failure != "" {
		return ErrRead
	}
	if reason, present := status["reason"]; present {
		if _, ok := reason.(string); !ok {
			return ErrRead
		}
	}
	if meta, present := fields["metadata"]; present {
		m, ok := meta.(map[string]any)
		if !ok || len(m) > 2 {
			return ErrRead
		}
		for key, value := range m {
			switch key {
			case "creationTimestamp":
				if value != nil {
					return ErrRead
				}
			case "managedFields":
				if !authorizationManagedFields(value, reply.ManagedFields, expectedSpec) {
					return ErrRead
				}
			default:
				return ErrRead
			}
		}
	}
	return nil
}

// Native create handlers can attach nonpersistent managed-field bookkeeping to
// a SSAR. It is not permission evidence. Admit only the one fixed manager's
// current-version Update and the exact fieldset of the already echoed spec;
// no identity, labels, annotations, owners or foreign field authority follows.
func authorizationManagedFields(raw any, entries []metav1.ManagedFieldsEntry, spec map[string]any) bool {
	values, ok := raw.([]any)
	if !ok || len(values) != 1 || len(entries) != 1 {
		return false
	}
	entry := entries[0]
	fields, ok := values[0].(map[string]any)
	if !ok || len(fields) != 6 || entry.Manager != "arcadectl-installer" || entry.Operation != metav1.ManagedFieldsOperationUpdate || entry.APIVersion != "authorization.k8s.io/v1" || entry.FieldsType != "FieldsV1" || entry.Subresource != "" || entry.Time == nil || entry.Time.IsZero() || entry.FieldsV1 == nil {
		return false
	}
	for _, key := range []string{"manager", "operation", "apiVersion", "fieldsType", "time"} {
		if _, ok := fields[key].(string); !ok {
			return false
		}
	}
	if fields["time"] != entry.Time.UTC().Format(time.RFC3339) {
		return false
	}
	wantSpec := map[string]any{}
	for kind, value := range spec {
		attributes, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fieldSet := map[string]any{".": map[string]any{}}
		for key := range attributes {
			fieldSet["f:"+key] = map[string]any{}
		}
		wantSpec["f:"+kind] = fieldSet
	}
	return reflect.DeepEqual(fields["fieldsV1"], map[string]any{"f:spec": wantSpec})
}

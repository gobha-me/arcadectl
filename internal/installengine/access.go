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
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	strictjson "sigs.k8s.io/json"
)

// Access is a trusted test/instrumentation seam, not caller-supplied evidence.
// Every method must be uncached and send AT MOST ONE mutation HTTP attempt.
// Namespace writes belong to NamespaceAccess, never Apply/Delete.
type Access interface {
	Get(context.Context, installstate.Key) (*unstructured.Unstructured, error)
	Create(context.Context, installstate.Key, *unstructured.Unstructured, bool) (*unstructured.Unstructured, error)
	Update(context.Context, installstate.Key, *unstructured.Unstructured, bool) (*unstructured.Unstructured, error)
	Delete(context.Context, installstate.Key, metav1.DeleteOptions) error
}

// HTTPAccess uses client-go's TLS/authentication configuration, but deliberately
// not rest.Request/dynamic/typed mutation methods (which can retry internally).
// Responses never pass through SDK body logging or permissive error decoders.
type HTTPAccess struct {
	client *http.Client
	base   *url.URL
}

type attemptKey struct{}
type attemptTransport struct{ next http.RoundTripper }

func (t attemptTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		attempt, ok := r.Context().Value(attemptKey{}).(*atomic.Bool)
		if !ok || !attempt.CompareAndSwap(false, true) {
			return nil, ErrOutcomeUnknown
		}
	}
	response, err := t.next.RoundTrip(r)
	if err != nil || response == nil {
		return response, err
	}
	// Sanitize before client-go's outer debug/auth wrappers can observe headers.
	copyResponse := *response
	copyResponse.Header = http.Header{}
	copyResponse.Header.Set("Content-Type", response.Header.Get("Content-Type"))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		copyResponse.Body = io.NopCloser(strings.NewReader(`{}`))
		copyResponse.ContentLength = 2
	}
	return &copyResponse, nil
}

func NewHTTPAccess(config *rest.Config) (*HTTPAccess, error) {
	// External credential plugins may print secrets or log raw refresh errors;
	// v1 deliberately supports static client certificates/bearer credentials.
	if config == nil || config.ExecProvider != nil || config.AuthProvider != nil || config.Transport != nil {
		return nil, ErrInvalid
	}
	u, err := url.Parse(config.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || config.Insecure {
		return nil, ErrInvalid
	}
	c := rest.CopyConfig(config)
	if freezeCredentials(c) != nil {
		return nil, ErrInvalid
	}
	c.Timeout = 30 * time.Second
	// HTTP/2 can retry REFUSED_STREAM/GOAWAY within one RoundTrip, beyond the
	// guard below. Non-replayable nonempty writes use HTTP/1.1 exclusively.
	c.TLSClientConfig.NextProtos = []string{"http/1.1"}
	previous := c.WrapTransport
	c.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		// Place the guard below any supplied wrapper or auth-refresh transport.
		var guarded http.RoundTripper = attemptTransport{base}
		if previous != nil {
			guarded = previous(guarded)
		}
		return guarded
	}
	h, err := rest.HTTPClientFor(c)
	if err != nil {
		return nil, ErrInvalid
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRead }
	return &HTTPAccess{client: h, base: u}, nil
}

// File-backed credentials are protected, bounded snapshots, never background
// rotating sources (their global reload logs can reflect private file errors).
// External credential plugins remain unsupported; no kubeconfig is modified.
func freezeCredentials(c *rest.Config) error {
	for _, entry := range []struct {
		path       *string
		data       *[]byte
		protection privatefs.Protection
	}{
		{&c.CAFile, &c.CAData, privatefs.TrustedPublic},
		{&c.CertFile, &c.CertData, privatefs.TrustedPublic},
		{&c.KeyFile, &c.KeyData, privatefs.Private},
	} {
		if len(*entry.data) == 0 && *entry.path != "" {
			data, _, err := privatefs.ReadAbsolute(*entry.path, 1024*1024, entry.protection)
			if err != nil || len(data) == 0 {
				return ErrInvalid
			}
			*entry.data = data
		} else {
			*entry.data = bytes.Clone(*entry.data)
		}
		*entry.path = ""
	}
	if c.BearerTokenFile != "" {
		token, _, err := privatefs.ReadAbsolute(c.BearerTokenFile, 65536, privatefs.Private)
		if err != nil {
			return ErrInvalid
		}
		c.BearerToken = strings.TrimSpace(string(token))
		if c.BearerToken == "" || strings.ContainsAny(c.BearerToken, "\r\n\t ") {
			return ErrInvalid
		}
		c.BearerTokenFile = ""
	}
	return nil
}

// These are fixed reviewed resource mappings, not guessed plurals/discovery or
// URLs supplied by journal bytes. Exact object names are validated separately.
func resourcePath(key installstate.Key, collection bool) (string, error) {
	resources := map[string]string{
		"v1/Namespace": "namespaces", "v1/ServiceAccount": "serviceaccounts", "v1/Service": "services",
		"apps/v1/Deployment": "deployments", "rbac.authorization.k8s.io/v1/Role": "roles",
		"rbac.authorization.k8s.io/v1/RoleBinding": "rolebindings", "rbac.authorization.k8s.io/v1/ClusterRole": "clusterroles",
		"rbac.authorization.k8s.io/v1/ClusterRoleBinding":                  "clusterrolebindings",
		"apiextensions.k8s.io/v1/CustomResourceDefinition":                 "customresourcedefinitions",
		"admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy":        "validatingadmissionpolicies",
		"admissionregistration.k8s.io/v1/ValidatingAdmissionPolicyBinding": "validatingadmissionpolicybindings",
	}
	plural, ok := resources[key.APIVersion+"/"+key.Kind]
	if !ok || !addressPart(key.Name) || key.Namespace != "" && !addressPart(key.Namespace) {
		return "", ErrInvalid
	}
	cluster := key.Kind == "Namespace" || strings.HasPrefix(key.Kind, "Cluster") || key.Kind == "CustomResourceDefinition" || strings.HasPrefix(key.Kind, "ValidatingAdmissionPolicy")
	if cluster != (key.Namespace == "") {
		return "", ErrInvalid
	}
	prefix := "/apis/" + key.APIVersion
	if key.APIVersion == "v1" {
		prefix = "/api/v1"
	}
	if key.Namespace != "" {
		prefix += "/namespaces/" + key.Namespace
	}
	prefix += "/" + plural
	if !collection {
		prefix += "/" + key.Name
	}
	return prefix, nil
}

func addressPart(s string) bool {
	if len(s) == 0 || len(s) > 253 || s == "." || s == ".." {
		return false
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.') {
			return false
		}
	}
	return true
}

func (a *HTTPAccess) request(ctx context.Context, method string, key installstate.Key, body any, dry bool) (*unstructured.Unstructured, error) {
	return a.requestBound(ctx, method, key, body, dry, false)
}

func (a *HTTPAccess) privateRequest(ctx context.Context, method string, key installstate.Key, body any, dry bool) (*unstructured.Unstructured, error) {
	if method != http.MethodGet && method != http.MethodPost {
		return nil, ErrInvalid
	}
	return a.requestBound(ctx, method, key, body, dry, true)
}

func (a *HTTPAccess) requestBound(ctx context.Context, method string, key installstate.Key, body any, dry, private bool) (*unstructured.Unstructured, error) {
	if a == nil || a.client == nil || a.base == nil || ctx == nil {
		return nil, ErrInvalid
	}
	path, err := resourcePath(key, method == http.MethodPost)
	if private {
		path, err = privateSecretPath(key, method == http.MethodPost)
	}
	if err != nil {
		return nil, err
	}
	return a.requestAt(ctx, method, key, body, dry, path, nil)
}

// requestAt is private: every caller derives a fixed reviewed route, never a
// path supplied by a journal/object. Serving routes expose read-only mappings.
func (a *HTTPAccess) requestAt(ctx context.Context, method string, key installstate.Key, body any, dry bool, path string, extra url.Values) (*unstructured.Unstructured, error) {
	if a == nil || a.client == nil || a.base == nil || ctx == nil {
		return nil, ErrInvalid
	}
	var err error
	var encoded []byte
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil || len(encoded) > 1024*1024 {
			return nil, ErrInvalid
		}
	}
	u := *a.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	query := url.Values{}
	for name, values := range extra {
		query[name] = append([]string(nil), values...)
	}
	if dry {
		query.Set("dryRun", "All")
	}
	if method == http.MethodPost || method == http.MethodPut {
		query.Set("fieldValidation", "Strict")
	}
	u.RawQuery = query.Encode()
	ctx = logr.NewContext(ctx, logr.Discard())
	ctx = context.WithValue(ctx, attemptKey{}, &atomic.Bool{})
	r, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(encoded))
	if err != nil {
		return nil, ErrInvalid
	}
	// Disable replayable bodies even for transports which infer idempotency.
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
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Never read, log or reflect an error body/Warning/Retry-After header.
		gr := schema.GroupResource{Resource: key.Kind}
		switch response.StatusCode {
		case 404:
			return nil, apierrors.NewNotFound(gr, key.Name)
		case 409:
			return nil, apierrors.NewConflict(gr, key.Name, ErrConcurrent)
		case 400:
			return nil, apierrors.NewBadRequest("installation API request rejected")
		case 401:
			return nil, apierrors.NewUnauthorized("installation API request rejected")
		case 403:
			return nil, apierrors.NewForbidden(gr, key.Name, ErrOwnership)
		case 405:
			return nil, apierrors.NewMethodNotSupported(gr, method)
		case 413:
			return nil, apierrors.NewRequestEntityTooLargeError("installation API request rejected")
		case 415:
			return nil, &apierrors.StatusError{ErrStatus: metav1.Status{Status: metav1.StatusFailure, Code: 415, Reason: metav1.StatusReasonUnsupportedMediaType, Message: "installation API request rejected"}}
		case 422:
			return nil, apierrors.NewInvalid(schema.GroupKind{Kind: key.Kind}, key.Name, nil)
		case 429:
			return nil, apierrors.NewTooManyRequests("installation API request rejected", 0)
		default:
			return nil, ErrRead
		}
	}
	typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return nil, ErrRead
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || !boundedJSON(raw) {
		return nil, ErrRead
	}
	result := &unstructured.Unstructured{}
	strictErrors, err := strictjson.UnmarshalStrict(raw, &result.Object)
	if err != nil || len(strictErrors) != 0 {
		return nil, ErrRead
	}
	if method != http.MethodDelete && (result.GetAPIVersion() != key.APIVersion || result.GetKind() != key.Kind || result.GetName() != key.Name || result.GetNamespace() != key.Namespace) {
		return nil, ErrRead
	}
	return result, nil
}

func boundedJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	depth, nodes := 0, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			return depth == 0
		}
		if err != nil {
			return false
		}
		nodes++
		if nodes > 200000 {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
			if depth > 64 || depth < 0 {
				return false
			}
		}
	}
}

func (a *HTTPAccess) Get(ctx context.Context, key installstate.Key) (*unstructured.Unstructured, error) {
	return a.request(ctx, http.MethodGet, key, nil, false)
}
func (a *HTTPAccess) Create(ctx context.Context, key installstate.Key, o *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	return a.request(ctx, http.MethodPost, key, o, dry)
}
func (a *HTTPAccess) Update(ctx context.Context, key installstate.Key, o *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	return a.request(ctx, http.MethodPut, key, o, dry)
}
func (a *HTTPAccess) Delete(ctx context.Context, key installstate.Key, opts metav1.DeleteOptions) error {
	_, err := a.request(ctx, http.MethodDelete, key, opts, false)
	return err
}

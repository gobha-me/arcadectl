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
	"strconv"
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
	"k8s.io/client-go/util/flowcontrol"
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

// One aggregate SDK-only budget: full installation proofs perform complete
// typed and metadata inventories repeatedly. Keep a small burst and preserve
// every explicit caller limit; do not mint independent observer buckets.
const installerReadQPS float32 = 100
const installerReadBurst = 20

// HTTPAccess uses client-go's TLS/authentication configuration, but deliberately
// not rest.Request/dynamic/typed mutation methods (which can retry internally).
// Responses never pass through SDK body logging or permissive error decoders.
type HTTPAccess struct {
	client *http.Client
	base   *url.URL
	native *nativeTLS
	// Private frozen read-client configuration shares this access's exact
	// cluster/static identity, never the caller's rotating files or plugins.
	frozen *rest.Config
	// One aggregate budget for SDK observers only when the caller supplies
	// NO rate settings. Effect HTTP clients never use this limiter, and all
	// explicit caller settings remain unchanged in the frozen configuration.
	readLimiter flowcontrol.RateLimiter
	// direct records explicitly selected no-environment-proxy routing. The
	// caller's configuration has no callbacks; only our constructor adds one.
	direct bool
	// Raw connection infrastructure only, captured below all purpose, attempt,
	// instrumentation and auth wrappers. Never share a wrapped actor client or
	// authority result; direct descendants keep fresh independent wire guards.
	pool http.RoundTripper
	// actor is set only by the closed admission factory. Its wire guard rejects
	// ordinary Access methods; only bound dry-run probes and actor SSARs pass.
	actor *actorWireIdentity
	// Pure decoding of complete fresh named public GET replies only. Never a
	// cached observation, permission, identity, health or mutation result.
	publicReplies *publicReplyMemo
}

type attemptKey struct{}
type requestAttempt struct {
	used    atomic.Bool
	method  string
	probe   *probeCapture
	actor   *actorRequestCapture
	fixture *fixtureCapture
}
type attemptTransport struct{ next http.RoundTripper }

func (t attemptTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// All requests carry their original operation witness, including GET.
	// Losing context or replacing a probe PUT with GET is not a read fallback.
	attempt, ok := r.Context().Value(attemptKey{}).(*requestAttempt)
	if !ok || attempt == nil || r.Method != attempt.method || !attempt.used.CompareAndSwap(false, true) {
		return nil, ErrOutcomeUnknown
	}
	if attempt.probe != nil && !attempt.probe.guard(r) {
		return nil, ErrAdmission
	}
	if attempt.fixture != nil && !attempt.fixture.guard(r) {
		return nil, ErrFixtures
	}
	finishDiagnostic := beginBaselineProbeRoundTrip(r.Context())
	response, err := t.next.RoundTrip(r)
	finishDiagnostic()
	if err != nil || response == nil {
		return response, err
	}
	// Sanitize before client-go's outer debug/auth wrappers can observe headers.
	copyResponse := *response
	copyResponse.Header = http.Header{}
	if typ, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err == nil && typ == "application/json" {
		copyResponse.Header.Set("Content-Type", "application/json")
	}
	copyResponse.Status = strconv.Itoa(response.StatusCode) + " " + http.StatusText(response.StatusCode)
	copyResponse.Trailer = nil
	if attempt.fixture != nil {
		// Fixture replies are captured below wrappers, then replaced by fixed
		// public bytes. No native status, body, header or trailer can become a
		// debug/error leak or a wrapper-selected acknowledgement identity.
		attempt.fixture.capture(response)
		copyResponse.Body = io.NopCloser(strings.NewReader(`{}`))
		copyResponse.ContentLength = 2
		return &copyResponse, nil
	}
	if attempt.probe != nil && response.StatusCode >= 200 && response.StatusCode < 300 {
		// Success is native evidence too. Capture beneath wrappers and replace
		// the body before debug/auth code can observe it; no wrapper-selected
		// positive object can certify an admission endpoint.
		attempt.probe.captureSuccess(response)
		if response.Body != nil {
			_ = response.Body.Close()
		}
		copyResponse.Body = io.NopCloser(strings.NewReader(`{}`))
		copyResponse.ContentLength = 2
		return &copyResponse, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if attempt.probe != nil {
			attempt.probe.classify(r, response)
		} else if r.Method == http.MethodGet && response.StatusCode == http.StatusNotFound {
			// Native absence is frequent in complete live proofs. Discard a
			// small uncompressed Status beneath wrappers so HTTP/1.1 can reuse
			// the original frozen TLS connection. This is not evidence: never
			// parse, retain, expose, log or retry these bytes. The earlier
			// request context/frozen client timeout still bounds a slow body.
			discardSmallAbsentRead(response)
		}
		if response.Body != nil {
			_ = response.Body.Close()
		}
		copyResponse.Body = io.NopCloser(strings.NewReader(`{}`))
		copyResponse.ContentLength = 2
	}
	return &copyResponse, nil
}

const absentReadDiscardLimit int64 = 8 * 1024

func discardSmallAbsentRead(response *http.Response) {
	if response.Body == nil || response.Uncompressed || response.ContentLength > absentReadDiscardLimit {
		return
	}
	// One extra byte distinguishes the real underlying EOF from a limited
	// reader's synthetic EOF at the accepted bound. Known oversize skips all
	// reads; unknown/chunked bodies consume at most the limit plus sentinel.
	// Completion or any native read error is immaterial to public status.
	_, _ = io.CopyN(io.Discard, response.Body, absentReadDiscardLimit+1)
}

func NewHTTPAccess(config *rest.Config) (*HTTPAccess, error) {
	return newHTTPAccess(config, false)
}

// NewDirectHTTPAccess explicitly selects direct cluster routing without an
// environment proxy. It rejects caller routing callbacks rather than replacing
// them. Admission actor derivation requires this same original routing mode.
func NewDirectHTTPAccess(config *rest.Config) (*HTTPAccess, error) {
	if config == nil || config.Proxy != nil || config.Dial != nil {
		return nil, ErrInvalid
	}
	return newHTTPAccess(config, true)
}

func newHTTPAccess(config *rest.Config, direct bool) (*HTTPAccess, error) {
	return newHTTPAccessWithPool(config, direct, nil)
}

// Only private derivation below may inherit a pool. Public constructors still
// reject caller transports, and inherited configuration cannot select a host,
// certificate or static identity independently from its frozen parent.
func newHTTPAccessWithPool(config *rest.Config, direct bool, inherited http.RoundTripper) (*HTTPAccess, error) {
	// External credential plugins may print secrets or log raw refresh errors;
	// v1 deliberately supports static client certificates/bearer credentials.
	if config == nil || config.ExecProvider != nil || config.AuthProvider != nil || config.Transport != nil || inherited != nil && !direct {
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
	c.Impersonate.Groups = append([]string(nil), c.Impersonate.Groups...)
	if c.Impersonate.Extra != nil {
		c.Impersonate.Extra = make(map[string][]string, len(config.Impersonate.Extra))
		for key, values := range config.Impersonate.Extra {
			c.Impersonate.Extra[key] = append([]string(nil), values...)
		}
	}
	frozen := rest.CopyConfig(c)
	native := nativeTransport(c)
	if direct {
		c.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	}
	previous := c.WrapTransport
	pool := inherited
	c.WrapTransport = func(base http.RoundTripper) http.RoundTripper {
		pool = base // raw TLS transport, before any client-specific wrapper
		// Place the guard below any supplied wrapper or auth-refresh transport.
		var guarded http.RoundTripper = attemptTransport{base}
		if previous != nil {
			guarded = previous(guarded)
		}
		return guarded
	}
	var h *http.Client
	if inherited == nil {
		h, err = rest.HTTPClientFor(c)
	} else {
		var wrapped http.RoundTripper
		wrapped, err = rest.HTTPWrappersForConfig(c, inherited)
		h = &http.Client{Transport: wrapped, Timeout: c.Timeout}
	}
	if err != nil || pool == nil {
		return nil, ErrInvalid
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRead }
	a := &HTTPAccess{client: h, base: u, native: native, frozen: frozen, direct: direct, pool: pool, publicReplies: &publicReplyMemo{}}
	if frozen.RateLimiter == nil && frozen.QPS == 0 && frozen.Burst == 0 {
		a.readLimiter = &sdkWaitDiagnosticLimiter{RateLimiter: flowcontrol.NewTokenBucketRateLimiter(installerReadQPS, installerReadBurst)}
	}
	return a, nil
}

// Closed callers supply only already-validated request identity/purpose, not
// transport routing or TLS credentials. Canonical frozen provenance remains
// callback-free and complete for later actor compatibility and native TLS.
func (a *HTTPAccess) derivedDirectAccess(identity rest.ImpersonationConfig, wrapper func(http.RoundTripper) http.RoundTripper) (*HTTPAccess, error) {
	if !a.actorCompatible() || a.pool == nil || wrapper == nil {
		return nil, ErrInvalid
	}
	c := rest.CopyConfig(a.frozen)
	c.Impersonate, c.WrapTransport = identity, wrapper
	derived, err := newHTTPAccessWithPool(c, true, a.pool)
	if err != nil {
		return nil, err
	}
	derived.readLimiter = a.readLimiter
	return derived, nil
}

// Observer clients must inherit explicit direct routing too. Keep the source
// snapshot callback-free for actor provenance; derive only our fixed no-proxy
// callback for trusted read clients, never a credential or identity fallback.
func (a *HTTPAccess) readConfig() *rest.Config {
	if a == nil || a.frozen == nil {
		return nil
	}
	c := rest.CopyConfig(a.frozen)
	if a.readLimiter != nil {
		c.QPS, c.Burst, c.RateLimiter = installerReadQPS, installerReadBurst, a.readLimiter
	}
	if a.direct {
		if a.pool == nil {
			return nil
		}
		// The private raw pool already owns this parent's frozen TLS and
		// fixed direct routing. client-go rejects custom Transport plus TLS
		// options, so clear them ONLY in this trusted SDK derivative. Static
		// HTTP auth/read wrappers and the aggregate limiter remain separate.
		c.Transport = a.pool
		c.TLSClientConfig = rest.TLSClientConfig{}
		c.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	}
	return c
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
	publicPath, publicErr := resourcePath(key, false)
	memo := a.publicReplies
	if method != http.MethodGet || body != nil || dry || len(extra) != 0 || a.actor != nil || key.Kind == "Secret" || publicErr != nil || publicPath != path {
		memo = nil
	}
	accepted := false
	defer func() {
		if !accepted && memo != nil {
			memo.clear(key)
		}
	}()
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
	ctx = context.WithValue(ctx, attemptKey{}, &requestAttempt{method: method})
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
		// The guarded transport has replaced the native error body and
		// headers. Never decode, log or reflect private rejection diagnostics.
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
	if err != nil || len(raw) == 0 || len(raw) > 1024*1024 || !boundedJSONLimits(raw) {
		return nil, ErrRead
	}
	// A memo can reuse ONLY the strict conversion of identical complete fresh
	// bytes. All transport/size/limits checks above still run, and original
	// envelope and every downstream typed/identity/health check remain fresh.
	result, err := memo.decode(key, raw)
	if err != nil {
		return nil, ErrRead
	}
	if method != http.MethodDelete && (result.GetAPIVersion() != key.APIVersion || result.GetKind() != key.Kind || result.GetName() != key.Name || result.GetNamespace() != key.Namespace) {
		return nil, ErrRead
	}
	accepted = true
	return result, nil
}

func boundedJSON(raw []byte) bool {
	return boundedJSONLimits(raw) && json.Valid(raw)
}

// Limits only, NOT JSON acceptance. Follow with strict single-value decoding,
// or a closed memo's identical complete bytes previously strictly decoded.
// Other callers retain boundedJSON's grammar contract; invalid inputs can never
// become objects based on this scan alone.
func boundedJSONLimits(raw []byte) bool {
	depth, nodes := 0, 0
	// Count the same tokens as Decoder.Token without materializing strings or
	// numbers. Reject limits BEFORE standard grammar validation, so an invalid
	// deeply nested response cannot grow the standard scanner's depth stack.
	// This is only prevalidation: acceptance still requires ONE strictly decoded
	// value (or its identical complete-byte conversion), duplicate rejection and
	// the original envelope/identity checks.
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case ' ', '\t', '\r', '\n', ',', ':':
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case '"':
			i++
			for ; i < len(raw) && raw[i] != '"'; i++ {
				if raw[i] == '\\' {
					i++ // Escaped quotes and structural bytes are not tokens.
				}
			}
			if i >= len(raw) {
				return false
			}
		default:
			// A primitive is one token, irrespective of numeric length. The
			// standard parser below, not this scan, validates its grammar.
			for i+1 < len(raw) && !jsonTokenBoundary(raw[i+1]) {
				i++
			}
		}
		nodes++
		if nodes > 200000 || depth > 64 || depth < 0 {
			return false
		}
	}
	return depth == 0
}

func jsonTokenBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', ',', ':', '{', '}', '[', ']', '"':
		return true
	default:
		return false
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

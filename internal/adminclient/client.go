// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package adminclient implements the bounded ordinary HTTPS client without a
// Kubernetes client, bearer writer, or unsafe-destruction capability.
package adminclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	"github.com/gobha-me/arcadectl/internal/receiptid"
)

type ContextConfig struct {
	Version        string `json:"version"`
	Name           string `json:"name"`
	APIOrigin      string `json:"apiOrigin"`
	TLSServerName  string `json:"tlsServerName"`
	CAFile         string `json:"caFile"`
	CredentialFile string `json:"credentialFile"`
}
type Identity struct {
	Origin      string `json:"origin"`
	CAHash      string `json:"caHash"`
	PrincipalID string `json:"principalId"`
	Namespace   string `json:"namespace"`
}
type SavedContext struct {
	Config   ContextConfig `json:"config"`
	Identity Identity      `json:"identity"`
}
type Error struct {
	Code, OperationID string
	HTTPStatus        int
	Ambiguous         bool
}

func (e *Error) Error() string {
	switch e.Code {
	case "credential_expired":
		return "administrator credential expired; admitted work was not cancelled"
	case "credential_unavailable":
		return "private administrator credential is unavailable or invalid"
	case "context_unavailable":
		return "administrator context is unavailable or unsafe"
	case "context_changed":
		return "administrator context identity changed; explicitly verify the context again"
	case "tls_unavailable":
		return "verified HTTPS connection is unavailable"
	case "request_timeout":
		return "bounded administrator request timed out; admitted work was not cancelled"
	case "interrupted":
		return "administrator request was interrupted; admitted work was not cancelled"
	case "response_too_large":
		return "API response exceeds the bounded client budget"
	case "invalid_response":
		return "API response does not satisfy the versioned contract"
	case "ambiguous_submission", "commit_unknown":
		return "submission is unconfirmed; retry only the exact durable attempt"
	case "unauthenticated":
		return "API denied the administrator credential"
	case "forbidden":
		return "API denied the requested action"
	case "not_found":
		return "requested resource was not found"
	case "idempotency_conflict":
		return "idempotency key belongs to a different intent"
	case "precondition_failed":
		return "exact target precondition no longer matches"
	default:
		return "administrator request failed safely"
	}
}
func problem(code string) *Error { return &Error{Code: code} }

type Conditional struct {
	IfMatch     string `json:"ifMatch,omitempty"`
	IfNoneMatch bool   `json:"ifNoneMatch,omitempty"`
}
type Client struct {
	mu               sync.Mutex
	config           ContextConfig
	credential       adminauth.ClientCredential
	roots            *x509.CertPool
	identity         Identity
	expectedIdentity *Identity
	verified, closed bool
	now              func() time.Time
}

var labelPattern = regexp.MustCompile("^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
var dnsPattern = regexp.MustCompile("^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
var uidPattern = regexp.MustCompile("^[A-Za-z0-9_.-]{1,128}$")
var digestPattern = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
var keyPattern = regexp.MustCompile("^[A-Za-z0-9._:-]{1,128}$")
var receiptPattern = regexp.MustCompile("^ao-[a-z2-7]{52}$")

func NormalizeContext(config ContextConfig) (ContextConfig, error) {
	if config.Version != "v1" || !labelPattern.MatchString(config.Name) || !utf8.ValidString(config.APIOrigin) || len(config.APIOrigin) > 512 {
		return ContextConfig{}, problem("context_unavailable")
	}
	p, e := url.Parse(config.APIOrigin)
	if e != nil || p.Scheme != "https" || p.Host == "" || p.User != nil || p.Opaque != "" || p.RawQuery != "" || p.ForceQuery || p.Fragment != "" || p.RawFragment != "" || p.RawPath != "" || (p.Path != "" && p.Path != "/") {
		return ContextConfig{}, problem("context_unavailable")
	}
	host := strings.ToLower(p.Hostname())
	if net.ParseIP(host) == nil && (len(host) > 253 || !dnsPattern.MatchString(host) || strings.Contains(host, "..")) {
		return ContextConfig{}, problem("context_unavailable")
	}
	port := p.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return ContextConfig{}, problem("context_unavailable")
		}
	}
	if port == "443" {
		port = ""
	}
	if port != "" {
		p.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		p.Host = "[" + host + "]"
	} else {
		p.Host = host
	}
	p.Path = ""
	config.APIOrigin = p.String()
	if config.TLSServerName == "" {
		config.TLSServerName = host
	}
	if net.ParseIP(config.TLSServerName) == nil && (len(config.TLSServerName) > 253 || !dnsPattern.MatchString(config.TLSServerName) || strings.Contains(config.TLSServerName, "..")) {
		return ContextConfig{}, problem("context_unavailable")
	}
	for _, path := range []string{config.CAFile, config.CredentialFile} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
			return ContextConfig{}, problem("context_unavailable")
		}
	}
	return config, nil
}
func Load(config ContextConfig) (*Client, error) {
	config, e := NormalizeContext(config)
	if e != nil {
		return nil, e
	}
	raw, _, e := privatefs.ReadAbsolute(config.CredentialFile, adminauth.MaxClientCredentialBytes, privatefs.Private)
	if e != nil || !utf8.Valid(raw) {
		return nil, problem("credential_unavailable")
	}
	credential, e := adminauth.ParseClientCredential(raw)
	if e != nil {
		return nil, problem("credential_unavailable")
	}
	if !time.Now().Before(credential.ExpiresAt) {
		return nil, problem("credential_expired")
	}
	ca, _, e := privatefs.ReadAbsolute(config.CAFile, 1024*1024, privatefs.TrustedPublic)
	if e != nil {
		return nil, problem("context_unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, problem("context_unavailable")
	}
	hash := sha256.Sum256(ca)
	return &Client{config: config, credential: credential, roots: roots, identity: Identity{Origin: config.APIOrigin, CAHash: "sha256:" + hex.EncodeToString(hash[:])}, now: time.Now}, nil
}
func (c *Client) Identity() Identity {
	if c == nil {
		return Identity{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.identity
}
func (c *Client) Close() {
	if c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = true
		c.credential = adminauth.ClientCredential{}
		c.roots = nil
	}
}
func (c *Client) Verify(ctx context.Context) (Identity, error) {
	var self adminv1.Self
	if _, e := c.Read(ctx, "/v1/auth/self", &self); e != nil {
		return Identity{}, e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || self.PrincipalID != adminauth.AdminPrincipalID || !labelPattern.MatchString(self.Namespace) || self.CredentialID != c.credential.CredentialID || self.ExpiresAt != c.credential.ExpiresAt.UTC().Format(time.RFC3339Nano) {
		return Identity{}, problem("context_changed")
	}
	if c.expectedIdentity != nil && (self.PrincipalID != c.expectedIdentity.PrincipalID || self.Namespace != c.expectedIdentity.Namespace) {
		return Identity{}, problem("context_changed")
	}
	c.identity.PrincipalID, c.identity.Namespace, c.verified = self.PrincipalID, self.Namespace, true
	return c.identity, nil
}
func fixedRoute(method, path string) (adminv1.Route, bool) {
	if len(path) > 512 || strings.ContainsAny(path, "%?#\r\n\x00") || !strings.HasPrefix(path, "/v1/") {
		return adminv1.Route{}, false
	}
	parts := strings.Split(path, "/")
	for _, route := range adminv1.Routes() {
		want := strings.Split(route.Path, "/")
		if route.Method != method || len(want) != len(parts) {
			continue
		}
		match := true
		for i, piece := range want {
			if strings.HasPrefix(piece, "{") {
				if piece == "{operationID}" {
					match = match && receiptPattern.MatchString(parts[i])
				} else if strings.HasPrefix(route.Path, "/v1/servers/") {
					match = match && labelPattern.MatchString(parts[i])
				} else {
					match = match && len(parts[i]) <= 253 && dnsPattern.MatchString(parts[i]) && !strings.Contains(parts[i], "..")
				}
			} else {
				match = match && piece == parts[i]
			}
		}
		if match {
			return route, true
		}
	}
	return adminv1.Route{}, false
}
func responseLimit(schema string) int64 {
	switch schema {
	case "Self":
		return 2048
	case "Server":
		return 128 * 1024
	case "ServerList":
		return 8 * 1024 * 1024
	case "OperationList":
		return 1024 * 1024
	default:
		return 64 * 1024
	}
}
func (c *Client) Read(ctx context.Context, path string, out any) (string, error) {
	route, ok := fixedRoute("GET", path)
	if !ok || !destinationMatches(route.ResponseSchema, out) {
		return "", problem("invalid_request")
	}
	status, header, body, e := c.request(ctx, "GET", path, nil, "", Conditional{}, responseLimit(route.ResponseSchema), false)
	if e != nil {
		return "", e
	}
	if status != 200 {
		return "", responseError(status, body, "", false)
	}
	if e := decodeResponse(body, out); e != nil {
		return "", e
	}
	if e := validateResponse(out); e != nil {
		return "", e
	}
	if !responseMatchesPath(path, out) {
		return "", problem("invalid_response")
	}
	return checkedETag(header, out)
}
func responseMatchesPath(path string, out any) bool {
	name := path[strings.LastIndex(path, "/")+1:]
	switch value := out.(type) {
	case *adminv1.Server:
		return value.Name == name
	case *adminv1.Operation:
		return value.OperationID == name
	case *adminv1.RetainedWorld:
		return value.OperationID == name
	case *adminv1.NativeOperation:
		kind := "GameDestroy"
		if strings.HasPrefix(path, "/v1/backups/") {
			kind = "GameBackup"
		}
		if strings.HasPrefix(path, "/v1/restores/") {
			kind = "GameRestore"
		}
		return value.Name == name && value.Kind == kind
	}
	return true
}
func (c *Client) Submit(ctx context.Context, method, path string, body []byte, key string, condition Conditional) (adminv1.Operation, error) {
	route, ok := fixedRoute(method, path)
	if !ok || route.RequestSchema == "" || !keyPattern.MatchString(key) {
		return adminv1.Operation{}, problem("invalid_request")
	}
	canonical, e := canonicaljson.CanonicalJSON(body)
	if e != nil || !bytes.Equal(canonical, body) || !validRequestBody(route.RequestSchema, body) {
		return adminv1.Operation{}, problem("invalid_request")
	}
	if route.Action == "server.create" {
		if !condition.IfNoneMatch || condition.IfMatch != "" {
			return adminv1.Operation{}, problem("invalid_precondition")
		}
	} else if condition.IfNoneMatch || !validConditional(route.Path, condition.IfMatch) {
		return adminv1.Operation{}, problem("invalid_precondition")
	}
	if c == nil {
		return adminv1.Operation{}, problem("context_unavailable")
	}
	c.mu.Lock()
	identity, verified := c.identity, c.verified && !c.closed
	c.mu.Unlock()
	if !verified {
		return adminv1.Operation{}, problem("context_changed")
	}
	expected, e := receiptid.ReceiptName(identity.Namespace, identity.PrincipalID, key)
	if e != nil {
		return adminv1.Operation{}, problem("invalid_request")
	}
	status, header, contents, e := c.request(ctx, method, path, body, key, condition, 64*1024, true)
	if e != nil {
		if failure, ok := e.(*Error); ok && failure.Ambiguous {
			failure.OperationID = expected
		}
		return adminv1.Operation{}, e
	}
	if status != 200 && status != 202 {
		return adminv1.Operation{}, responseError(status, contents, expected, true)
	}
	var operation adminv1.Operation
	if decodeResponse(contents, &operation) != nil || validateResponse(&operation) != nil || operation.OperationID != expected || operation.Action != route.Action {
		return adminv1.Operation{}, &Error{Code: "ambiguous_submission", OperationID: expected, HTTPStatus: status, Ambiguous: true}
	}
	if _, e := checkedETag(header, &operation); e != nil {
		return adminv1.Operation{}, &Error{Code: "ambiguous_submission", OperationID: expected, HTTPStatus: status, Ambiguous: true}
	}
	return operation, nil
}
func (c *Client) request(ctx context.Context, method, path string, body []byte, key string, condition Conditional, max int64, mutation bool) (int, http.Header, []byte, error) {
	if c == nil || ctx == nil {
		return 0, nil, nil, problem("invalid_request")
	}
	if e := ctx.Err(); e != nil {
		// No transport was started, so even a mutation is known not submitted.
		return 0, nil, nil, requestFailure(e, false)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, nil, nil, problem("context_unavailable")
	}
	if !c.now().Before(c.credential.ExpiresAt) {
		c.mu.Unlock()
		return 0, nil, nil, problem("credential_expired")
	}
	token, config, roots := c.credential.Token, c.config, c.roots
	c.mu.Unlock()
	// Fresh HTTP/1 connection and a non-replayable body prevent implicit Go
	// transport retries of mutations carrying Idempotency-Key.
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: config.TLSServerName, NextProtos: []string{"http/1.1"}}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, ForceAttemptHTTP2: false, DisableKeepAlives: true, DisableCompression: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 8192}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var reader io.Reader
	if body != nil {
		reader = io.NopCloser(bytes.NewReader(body))
	}
	request, e := http.NewRequestWithContext(ctx, method, config.APIOrigin+path, reader)
	if e != nil {
		return 0, nil, nil, problem("invalid_request")
	}
	request.GetBody = nil
	request.Close = true
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len(body))
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if condition.IfNoneMatch {
		request.Header.Set("If-None-Match", "*")
	} else if condition.IfMatch != "" {
		request.Header.Set("If-Match", condition.IfMatch)
	}
	response, e := httpClient.Do(request)
	if e != nil {
		return 0, nil, nil, requestFailure(e, mutation)
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Encoding") != "" {
		return response.StatusCode, nil, nil, &Error{Code: "invalid_response", Ambiguous: mutation}
	}
	media, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		return response.StatusCode, nil, nil, &Error{Code: "invalid_response", Ambiguous: mutation}
	}
	contents, e := io.ReadAll(io.LimitReader(response.Body, max+1))
	if e != nil && requestInterrupted(e) {
		return response.StatusCode, nil, nil, requestFailure(e, mutation)
	}
	if e != nil || int64(len(contents)) > max {
		code := "invalid_response"
		if int64(len(contents)) > max {
			code = "response_too_large"
		}
		return response.StatusCode, nil, nil, &Error{Code: code, Ambiguous: mutation}
	}
	if credentialReflection(contents, token) {
		return response.StatusCode, nil, nil, &Error{Code: "invalid_response", Ambiguous: mutation}
	}
	return response.StatusCode, response.Header, contents, nil
}

func requestInterrupted(err error) bool {
	var networkError net.Error
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &networkError) && networkError.Timeout()
}

// All post-send mutation failures remain ambiguous regardless of the local
// deadline/cancellation cause. Reads expose only fixed bounded classifications.
func requestFailure(err error, mutation bool) *Error {
	if mutation {
		return &Error{Code: "ambiguous_submission", Ambiguous: true}
	}
	if errors.Is(err, context.Canceled) {
		return problem("interrupted")
	}
	if requestInterrupted(err) {
		return problem("request_timeout")
	}
	return problem("tls_unavailable")
}

func credentialReflection(contents []byte, token string) bool {
	digest := adminauth.TokenDigest(token)
	if bytes.Contains(contents, []byte(token)) || bytes.Contains(contents, []byte(digest)) {
		return true
	}
	// Also catch JSON-escaped echoes, including escaped fields inside settings.
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	for {
		value, err := decoder.Token()
		if err != nil {
			return false
		}
		if text, ok := value.(string); ok && (strings.Contains(text, token) || strings.Contains(text, digest)) {
			return true
		}
	}
}
func validConditional(route, value string) bool {
	if len(value) > 512 || len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	parts := strings.Split(value[1:len(value)-1], ":")
	if strings.Contains(route, "retained-worlds") {
		return len(parts) == 4 && parts[0] == "retained" && uidPattern.MatchString(parts[1]) && digestPattern.MatchString(parts[2]+":"+parts[3])
	}
	kind := "server"
	if strings.Contains(route, "destroy-operations") {
		kind = "operation"
	}
	if len(parts) != 3 || parts[0] != kind || !uidPattern.MatchString(parts[1]) {
		return false
	}
	n, e := strconv.ParseInt(parts[2], 10, 64)
	return e == nil && n > 0 && strconv.FormatInt(n, 10) == parts[2]
}
func checkedETag(header http.Header, out any) (string, error) {
	values := header.Values("ETag")
	want := ""
	switch v := out.(type) {
	case *adminv1.Server:
		want = fmt.Sprintf("\"server:%s:%d\"", v.UID, v.Generation)
	case *adminv1.Operation:
		want = fmt.Sprintf("\"operation:%s:%d\"", v.UID, v.Generation)
	case *adminv1.RetainedWorld:
		want = fmt.Sprintf("\"retained:%s:%s\"", v.OperationUID, v.SnapshotDigest)
	default:
		if len(values) != 0 {
			return "", problem("invalid_response")
		}
		return "", nil
	}
	if len(values) != 1 || values[0] != want || len(want) > 512 {
		return "", problem("invalid_response")
	}
	return want, nil
}

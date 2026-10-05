// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package apiserver provides the single authenticated API boundary. It owns no
// game-specific state and has no unguarded route registration escape hatch.
package apiserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
)

type Config struct {
	Authenticator adminauth.Authenticator
	Authorizer    Authorizer
	Audit         AuditSink
	Namespace     string
	Clock         func() time.Time
	AuditTimeout  time.Duration
}

type Server struct {
	authenticator adminauth.Authenticator
	authorizer    Authorizer
	audit         AuditSink
	namespace     string
	clock         func() time.Time
	mux           *http.ServeMux
	auditMu       sync.Mutex
	auditHealthy  atomic.Bool
	auditTimeout  time.Duration
}

var opaqueID = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
var bearerSyntax = regexp.MustCompile(`^[a-zA-Z0-9._~+/-]+=*$`)
var namespaceID = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var routePattern = regexp.MustCompile(`^/v1(/[a-zA-Z0-9_.-]+|/\{[a-zA-Z][a-zA-Z0-9_]*\})+$`)

func New(config Config) (*Server, error) {
	if config.Authenticator == nil || config.Authorizer == nil || config.Audit == nil || !namespaceID.MatchString(config.Namespace) {
		return nil, errors.New("invalid API boundary configuration")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.AuditTimeout == 0 {
		config.AuditTimeout = time.Second
	}
	if config.AuditTimeout <= 0 || config.AuditTimeout > 5*time.Second {
		return nil, errors.New("invalid audit acknowledgment timeout")
	}
	server := &Server{
		authenticator: config.Authenticator, authorizer: config.Authorizer,
		audit: config.Audit, namespace: config.Namespace, clock: config.Clock,
		mux: http.NewServeMux(), auditTimeout: config.AuditTimeout,
	}
	server.auditHealthy.Store(true)
	if err := server.HandleAuthenticatedRead(http.MethodGet, "/v1/auth/self", ActionAuthSelf, http.HandlerFunc(server.self)); err != nil {
		return nil, err
	}
	return server, nil
}

// Register routes before serving requests. Only typed read/mutation registration
// is exposed; a caller cannot install middleware-bypassing mutation handlers.
func (server *Server) HandleAuthenticatedRead(method, pattern string, action Action, handler http.Handler) error {
	if (method != http.MethodGet && method != http.MethodHead) || !isReadAction(action) || handler == nil {
		return errors.New("invalid authenticated read route")
	}
	return server.register(method, pattern, action, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handler.ServeHTTP(writer, request)
	}))
}

func (server *Server) HandleMutation(method, pattern string, action Action, handler MutationHandler) error {
	if (method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete) || !isMutationAction(action) || handler == nil {
		return errors.New("invalid protected mutation route")
	}
	return server.register(method, pattern, action, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state := request.Context().Value(requestStateKey{}).(*requestState)
		if !server.record(state, request.Method, "intent", "authorized", 0) {
			state.outcome = "unavailable"
			writeError(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		capability := &mutationCapability{principal: state.principal, requestID: state.requestID, action: action, owner: server, context: request.Context(), active: true}
		defer capability.deactivate()
		handler(writer, request, capability)
	}))
}

func (server *Server) register(method, pattern string, action Action, handler http.Handler) (err error) {
	if len(pattern) > 160 || !routePattern.MatchString(pattern) {
		return errors.New("invalid API route pattern")
	}
	// ServeMux reports duplicate/ambiguous registrations by panic. Do not expose
	// its input-bearing panic text, even to a future configuration caller.
	defer func() {
		if recover() != nil {
			err = errors.New("conflicting API route")
		}
	}()
	server.mux.Handle(method+" "+pattern, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state := request.Context().Value(requestStateKey{}).(*requestState)
		state.route, state.action = pattern, action
		if !server.auditHealthy.Load() {
			state.outcome = "unavailable"
			writeError(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		if err := server.authorizer.Authorize(request.Context(), state.principal, action); err != nil {
			state.outcome = "forbidden"
			writeError(writer, http.StatusForbidden, "forbidden")
			return
		}
		handler.ServeHTTP(writer, request)
	}))
	return nil
}

type requestStateKey struct{}
type requestState struct {
	requestID string
	started   time.Time
	principal adminauth.Principal
	route     string
	action    Action
	outcome   string
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	state := &requestState{started: server.clock(), route: "unmatched", action: "unmatched"}
	identity := make([]byte, 16)
	if _, err := rand.Read(identity); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	state.requestID = hex.EncodeToString(identity)
	writer.Header().Set("X-Request-ID", state.requestID)
	tracked := &statusWriter{ResponseWriter: writer}
	defer func() {
		if recover() != nil {
			state.outcome = "internal"
			if tracked.status == 0 {
				writeError(tracked, http.StatusInternalServerError, "internal")
			}
		}
		status := tracked.status
		if status == 0 {
			status = http.StatusOK
		}
		if state.outcome == "" {
			if status < 400 {
				state.outcome = "succeeded"
			} else {
				state.outcome = "rejected"
			}
		}
		// Never turn an already-applied mutation into a fictional error response
		// when its outcome audit fails. Latch unhealthy and fence later requests.
		_ = server.record(state, request.Method, "outcome", state.outcome, status)
	}()
	if !server.auditHealthy.Load() {
		state.outcome = "unavailable"
		writeError(tracked, http.StatusServiceUnavailable, "unavailable")
		return
	}
	token, ok := bearerToken(request.Header)
	if !ok {
		state.outcome = "unauthenticated"
		writeError(tracked, http.StatusUnauthorized, "unauthenticated")
		return
	}
	principal, err := server.authenticator.Authenticate(request.Context(), token)
	if errors.Is(err, adminauth.ErrUnavailable) {
		state.outcome = "unavailable"
		writeError(tracked, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if err != nil || !validPrincipal(principal, server.clock()) {
		state.outcome = "unauthenticated"
		writeError(tracked, http.StatusUnauthorized, "unauthenticated")
		return
	}
	state.principal = principal
	server.mux.ServeHTTP(tracked, request.WithContext(context.WithValue(request.Context(), requestStateKey{}, state)))
}

func bearerToken(header http.Header) (string, bool) {
	var values []string
	for key, candidates := range header {
		if strings.EqualFold(key, "Authorization") {
			values = append(values, candidates...)
		}
	}
	if len(values) != 1 || len(values[0]) <= len("Bearer ") || len(values[0]) > len("Bearer ")+4096 || !strings.EqualFold(values[0][:7], "Bearer ") {
		return "", false
	}
	token := values[0][7:]
	// RFC 6750 transport syntax is independent of the authenticator's token
	// format. FileVerifier enforces the generated opaque credential; a future
	// OIDC implementation can accept a JWT without changing this router.
	if !bearerSyntax.MatchString(token) {
		return "", false
	}
	return token, true
}

func validPrincipal(principal adminauth.Principal, now time.Time) bool {
	return opaqueID.MatchString(principal.ID) && opaqueID.MatchString(principal.CredentialID) && now.Before(principal.ExpiresAt)
}

func (server *Server) record(state *requestState, method, phase, outcome string, status int) bool {
	server.auditMu.Lock()
	defer server.auditMu.Unlock()
	if !server.auditHealthy.Load() {
		return false
	}
	now := server.clock()
	duration := now.Sub(state.started).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	event := AuditEvent{
		Version: "v1", Timestamp: now.UTC().Format(time.RFC3339Nano), RequestID: state.requestID,
		PrincipalID: state.principal.ID, CredentialID: state.principal.CredentialID,
		Action: state.action, Method: auditMethod(method), Route: state.route,
		Namespace: server.namespace, Phase: phase, Outcome: outcome, Status: status, DurationMS: duration,
	}
	// Only one sink call can be outstanding. A timeout latches unhealthy before
	// releasing auditMu, so no subsequent call starts. A stalled external writer
	// occupies at most this one goroutine, not an unbounded retry queue.
	acknowledged := make(chan error, 1)
	go func() {
		defer func() {
			if recover() != nil {
				acknowledged <- errors.New("audit output unavailable")
			}
		}()
		acknowledged <- server.audit.Record(event)
	}()
	timer := time.NewTimer(server.auditTimeout)
	defer timer.Stop()
	var err error
	select {
	case err = <-acknowledged:
	case <-timer.C:
		err = errors.New("audit acknowledgment unavailable")
	}
	if err != nil {
		server.auditHealthy.Store(false)
		return false
	}
	return true
}

func auditMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func (server *Server) Ready() bool {
	if !server.auditHealthy.Load() {
		return false
	}
	if readiness, ok := server.authenticator.(adminauth.Readiness); ok {
		return readiness.Ready()
	}
	return true
}

// HealthHandler is served on a separate, non-Service port. It has no mutation
// handlers and never exposes credential state beyond readiness availability.
func (server *Server) HealthHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		switch request.URL.Path {
		case "/livez":
			writer.WriteHeader(http.StatusOK)
		case "/readyz":
			if !server.Ready() {
				writeError(writer, http.StatusServiceUnavailable, "unavailable")
				return
			}
			writer.WriteHeader(http.StatusOK)
		default:
			writeError(writer, http.StatusNotFound, "not_found")
		}
	})
}

func (server *Server) self(writer http.ResponseWriter, request *http.Request) {
	principal := request.Context().Value(requestStateKey{}).(*requestState).principal
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(adminv1.Self{Version: "v1", PrincipalID: principal.ID, CredentialID: principal.CredentialID, ExpiresAt: principal.ExpiresAt.UTC().Format(time.RFC3339Nano), Namespace: server.namespace})
}

func writeError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/json")
	if status == http.StatusUnauthorized {
		writer.Header().Set("WWW-Authenticate", "Bearer")
	}
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		Version string `json:"version"`
		Code    string `json:"code"`
	}{"v1", code})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusWriter) Write(contents []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(contents)
}

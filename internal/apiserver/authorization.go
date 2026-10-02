// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/gobha-me/arcadectl/internal/adminauth"
)

// Actions are domain intent, not Kubernetes verbs. UnsafeNoBackup deliberately
// has no API action: it requires the separate Kubernetes administrator boundary.
type Action string

const (
	ActionAuthSelf            Action = "auth.self"
	ActionServerRead          Action = "server.read"
	ActionOperationRead       Action = "operation.read"
	ActionServerCreate        Action = "server.create"
	ActionServerConfigure     Action = "server.configure"
	ActionServerStart         Action = "server.start"
	ActionServerStop          Action = "server.stop"
	ActionServerRestart       Action = "server.restart"
	ActionServerUpdate        Action = "server.update"
	ActionWorldBackup         Action = "world.backup"
	ActionWorldRestore        Action = "world.restore"
	ActionServerDecommission  Action = "server.decommission"
	ActionWorldDestroyPreview Action = "world.destroy.preview"
	ActionWorldDestroyConfirm Action = "world.destroy.confirm"
	ActionWorldDestroyCancel  Action = "world.destroy.cancel"
)

var ErrForbidden = errors.New("authorization denied")

type Authorizer interface {
	Authorize(context.Context, adminauth.Principal, Action) error
}

// AdministratorAuthorizer recognizes only the enumerated normal-admin actions.
// Replacing authentication does not require changing adapters or reconcilers.
type AdministratorAuthorizer struct{}

func (AdministratorAuthorizer) Authorize(_ context.Context, principal adminauth.Principal, action Action) error {
	if !isReadAction(action) && !isMutationAction(action) {
		return ErrForbidden
	}
	for _, role := range principal.Roles {
		if role == adminauth.RoleAdministrator {
			return nil
		}
	}
	return ErrForbidden
}

func isReadAction(action Action) bool {
	return action == ActionAuthSelf || action == ActionServerRead || action == ActionOperationRead
}

func isMutationAction(action Action) bool {
	switch action {
	case ActionServerCreate, ActionServerConfigure, ActionServerStart, ActionServerStop,
		ActionServerRestart, ActionServerUpdate, ActionWorldBackup, ActionWorldRestore,
		ActionServerDecommission, ActionWorldDestroyPreview, ActionWorldDestroyConfirm,
		ActionWorldDestroyCancel:
		return true
	default:
		return false
	}
}

// AuthorizedMutation is sealed: consumers cannot construct an authorization
// capability without passing the server's authentication, authorization, and
// synchronous audit-intent guards. It is scoped to one handler invocation.
type AuthorizedMutation interface {
	Principal() adminauth.Principal
	RequestID() string
	Action() Action
	authorizedMutation()
}

type mutationCapability struct {
	principal adminauth.Principal
	requestID string
	action    Action
	owner     *Server
	context   context.Context
	mu        sync.Mutex
	active    bool
}

func (capability *mutationCapability) Principal() adminauth.Principal {
	principal := capability.principal
	principal.Roles = append([]adminauth.Role(nil), principal.Roles...)
	return principal
}
func (capability *mutationCapability) RequestID() string { return capability.requestID }
func (capability *mutationCapability) Action() Action    { return capability.action }
func (*mutationCapability) authorizedMutation()          {}

func (capability *mutationCapability) deactivate() {
	capability.mu.Lock()
	defer capability.mu.Unlock()
	capability.active = false
}

// ExecuteMutation is the boundary for the API-owned Kubernetes mutation client.
// Keep that client private to guarded handlers; read handlers receive no such
// client. Like any Go API, this cannot sandbox trusted code that independently
// constructs another client. Multiple steps can execute while a handler is live,
// but a captured capability is rejected after it returns or its context ends.
func (server *Server) ExecuteMutation(capability AuthorizedMutation, execute func(context.Context) error) error {
	live, ok := capability.(*mutationCapability)
	if !ok || live == nil || execute == nil {
		return ErrForbidden
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	if live.owner != server || !live.active || live.context.Err() != nil || !server.auditHealthy.Load() {
		return ErrForbidden
	}
	return execute(live.context)
}

type MutationHandler func(http.ResponseWriter, *http.Request, AuthorizedMutation)

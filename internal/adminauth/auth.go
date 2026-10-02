// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package adminauth implements the single-administrator credential boundary.
// Authentication is independent of game adapters and Kubernetes reconciliation.
package adminauth

import (
	"context"
	"errors"
	"time"
)

const (
	AdminPrincipalID     = "admin"
	CredentialNamespace  = "arcadectl-system"
	CredentialSecretName = "arcadectl-admin-credential"
	CredentialSecretType = "arcade.gobha.me/admin-credential"
	VerifierSecretKey    = "auth.json"
	TokenSecretKey       = "token"
)

type Role string

const RoleAdministrator Role = "administrator"

// Principal contains only non-secret, server-authenticated identity evidence.
// ID remains stable across credential rotation; CredentialID is not the token
// or its verifier. Future authenticators must translate provider identities to
// bounded opaque IDs rather than returning authorization headers or claims.
type Principal struct {
	ID           string
	CredentialID string
	Roles        []Role
	ExpiresAt    time.Time
}

var (
	ErrUnauthorized = errors.New("authentication denied")
	ErrUnavailable  = errors.New("credential verifier unavailable")
)

// Authenticator can be replaced by OIDC without adapter/controller changes.
// The API parses the one allowed Authorization header before calling it.
type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

// Readiness is separate from liveness and from individual request denial.
// In particular, expired credentials are denied with 401, not recovered by
// restarting the process or accepting a stale verifier.
type Readiness interface {
	Ready() bool
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package game defines the constrained contract between the Arcadectl
// platform and a supported game adapter.
package game

import "encoding/json"

// Protocol is a transport protocol exposed by a game server.
type Protocol string

const (
	ProtocolTCP Protocol = "TCP"
	ProtocolUDP Protocol = "UDP"
)

// EndpointScope describes who should be able to reach an endpoint.
type EndpointScope string

const (
	ScopePlayer   EndpointScope = "player"
	ScopeAdmin    EndpointScope = "admin"
	ScopeInternal EndpointScope = "internal"
)

// Endpoint is a named network endpoint supplied by a game adapter.
type Endpoint struct {
	Name          string
	Protocol      Protocol
	ContainerPort uint16
	Scope         EndpointScope
}

// PersistentPath identifies game data included in backup and restore.
type PersistentPath struct {
	Name      string
	MountPath string
}

// ConfigurationTarget declares one non-secret configuration artifact. Its
// mount path is static certified adapter data rather than renderer output.
type ConfigurationTarget struct {
	Name      string
	MountPath string
}

// SettingsRenderer turns already schema-validated administrator settings into
// bytes for the exact declared target keys. Renderers cannot select paths or
// add containers, commands, privileges, or raw objects.
type SettingsRenderer func(json.RawMessage) (map[string][]byte, error)

// ConfigurationFile is validated renderer output paired with its static
// certified target.
type ConfigurationFile struct {
	Name      string
	MountPath string
	Contents  []byte
}

// RuntimeIdentity is the fixed non-root Linux identity certified for a game
// image. The platform applies it at pod scope so persistent volumes are made
// writable through fsGroup without allowing image entrypoints to run as root.
type RuntimeIdentity struct {
	UserID  int64
	GroupID int64
	FSGroup int64
}

// Capabilities declare optional behavior supported by an adapter.
type Capabilities struct {
	ColdBackup       bool
	Restore          bool
	GracefulShutdown bool
}

// Definition is a curated, game-specific input to the game-neutral platform.
// It deliberately cannot express arbitrary Kubernetes objects or commands.
type Definition struct {
	ID                   string
	DisplayName          string
	ImageRepository      string
	Endpoints            []Endpoint
	PersistentPaths      []PersistentPath
	ReadinessEndpoint    string
	SettingsSchema       json.RawMessage
	ConfigurationTargets []ConfigurationTarget
	RenderSettings       SettingsRenderer
	RuntimeIdentity      RuntimeIdentity
	Capabilities         Capabilities
}

// Clone returns a definition whose slices and byte buffers do not alias the
// original. Catalog callers may safely inspect or modify the returned value.
func (d Definition) Clone() Definition {
	clone := d
	clone.Endpoints = append([]Endpoint(nil), d.Endpoints...)
	clone.PersistentPaths = append([]PersistentPath(nil), d.PersistentPaths...)
	clone.ConfigurationTargets = append([]ConfigurationTarget(nil), d.ConfigurationTargets...)
	clone.SettingsSchema = append(json.RawMessage(nil), d.SettingsSchema...)
	return clone
}

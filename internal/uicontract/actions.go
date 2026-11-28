// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package uicontract describes the API routes a future UI may call. It neither
// serves UI controls nor grants authorization; the API remains authoritative.
package uicontract

// Confirmation is the interaction required before submitting an action.
type Confirmation string

const (
	ConfirmNone               Confirmation = "none"
	ConfirmTypedName          Confirmation = "typed-name"
	ConfirmPreviewThenConfirm Confirmation = "preview-then-confirm"
)

// Action is an ordered UI-to-API mapping. SecondStepOnly marks an action that
// must be reached from an existing destroy preview, never a standalone control.
// The API's exact operation identity and challenge remain required.
type Action struct {
	ID, Label, Method, Path, RouteAction string
	Confirm                              Confirmation
	SecondStepOnly                       bool
}

// Actions returns a fresh copy of the allowed UI action map. A mapping is a
// design contract, not an implemented control or a substitute for API checks.
func Actions() []Action {
	return []Action{
		{"create-server", "Create server", "POST", "/v1/servers", "server.create", ConfirmNone, false},
		{"configure-server", "Configure server", "PATCH", "/v1/servers/{name}", "server.configure", ConfirmNone, false},
		{"start-server", "Start server", "POST", "/v1/servers/{name}/start", "server.start", ConfirmNone, false},
		{"stop-server", "Stop server", "POST", "/v1/servers/{name}/stop", "server.stop", ConfirmNone, false},
		{"restart-server", "Restart server", "POST", "/v1/servers/{name}/restart", "server.restart", ConfirmNone, false},
		{"update-server", "Update server", "POST", "/v1/servers/{name}/update", "server.update", ConfirmNone, false},
		{"backup-world", "Back up world", "POST", "/v1/servers/{name}/backup", "world.backup", ConfirmNone, false},
		{"decommission-server", "Decommission server", "POST", "/v1/servers/{name}/decommission", "server.decommission", ConfirmTypedName, false},
		{"preview-server-destroy", "Preview server world destruction", "POST", "/v1/servers/{name}/destroy", "world.destroy.preview", ConfirmPreviewThenConfirm, false},
		{"preview-retained-destroy", "Preview retained world destruction", "POST", "/v1/retained-worlds/{operationID}/destroy", "world.destroy.preview", ConfirmPreviewThenConfirm, false},
		{"confirm-world-destroy", "Confirm previewed world destruction", "POST", "/v1/destroy-operations/{operationID}/confirm", "world.destroy.confirm", ConfirmPreviewThenConfirm, true},
		{"cancel-world-destroy", "Cancel previewed world destruction", "POST", "/v1/destroy-operations/{operationID}/cancel", "world.destroy.cancel", ConfirmNone, true},
	}
}

// UnmappedRoute records a mutating API action with no planned UI control yet.
// RouteAction intentionally covers every route for that authenticated action.
type UnmappedRoute struct {
	RouteAction string
	Reason      string
}

// Unmapped returns explicit exclusions from the UI action map.
func Unmapped() []UnmappedRoute {
	return []UnmappedRoute{
		{"world.restore", "Needs exact backup selection and candidate recovery UX"},
	}
}

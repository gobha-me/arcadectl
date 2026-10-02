// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1

// Route is the single registration/OpenAPI source. Schema names are typed DTOs;
// Action maps directly to the sealed authenticated server boundary.
type Route struct{ Method, Path, Action, RequestSchema, ResponseSchema string }

func Routes() []Route {
	return []Route{
		{"GET", "/v1/auth/self", "auth.self", "", "Self"},
		{"GET", "/v1/servers", "server.read", "", "ServerList"},
		{"POST", "/v1/servers", "server.create", "CreateRequest", "Operation"},
		{"GET", "/v1/servers/{name}", "server.read", "", "Server"},
		{"PATCH", "/v1/servers/{name}", "server.configure", "ConfigureRequest", "Operation"},
		{"POST", "/v1/servers/{name}/start", "server.start", "EmptyRequest", "Operation"},
		{"POST", "/v1/servers/{name}/stop", "server.stop", "EmptyRequest", "Operation"},
		{"POST", "/v1/servers/{name}/restart", "server.restart", "EmptyRequest", "Operation"},
		{"POST", "/v1/servers/{name}/update", "server.update", "UpdateRequest", "Operation"},
		{"POST", "/v1/servers/{name}/backup", "world.backup", "BackupRequest", "Operation"},
		{"POST", "/v1/servers/{name}/restore", "world.restore", "RestoreRequest", "Operation"},
		{"POST", "/v1/servers/{name}/decommission", "server.decommission", "EmptyRequest", "Operation"},
		{"POST", "/v1/servers/{name}/destroy", "world.destroy.preview", "DestroyRequest", "Operation"},
		{"GET", "/v1/operations", "operation.read", "", "OperationList"},
		{"GET", "/v1/operations/{operationID}", "operation.read", "", "Operation"},
		{"GET", "/v1/retained-worlds/{operationID}", "operation.read", "", "RetainedWorld"},
		{"POST", "/v1/retained-worlds/{operationID}/destroy", "world.destroy.preview", "DestroyRequest", "Operation"},
		{"POST", "/v1/destroy-operations/{operationID}/confirm", "world.destroy.confirm", "ConfirmRequest", "Operation"},
		{"POST", "/v1/destroy-operations/{operationID}/cancel", "world.destroy.cancel", "CancelRequest", "Operation"},
		{"GET", "/v1/backups/{name}", "operation.read", "", "NativeOperation"},
		{"GET", "/v1/restores/{name}", "operation.read", "", "NativeOperation"},
		{"GET", "/v1/destroys/{name}", "operation.read", "", "NativeOperation"},
	}
}

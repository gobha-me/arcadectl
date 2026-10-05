// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/gobha-me/arcadectl/internal/catalog"
)

// OpenAPI is generated from the DTOs and the exact guarded route table. Adapter
// settings schemas come from the curated catalog, never caller input.
func OpenAPI() ([]byte, error) {
	components := map[string]any{}
	types := []any{Self{}, Compute{}, Storage{}, Image{}, ExactReference{}, RetainedSelector{}, CreateRequest{}, ConfigureRequest{}, EmptyRequest{}, UpdateRequest{}, BackupRequest{}, RestoreRequest{}, DestroyRequest{}, ConfirmRequest{}, CancelRequest{}, Error{}, Condition{}, Endpoint{}, Server{}, ServerList{}, OperationChild{}, Failure{}, DestroyTarget{}, DestroyPreview{}, Operation{}, OperationList{}, RetainedClaim{}, RetainedWorld{}, NativeOperation{}}
	for _, value := range types {
		typ := reflect.TypeOf(value)
		components[typ.Name()] = schema(typ, "")
	}
	gameCatalog, err := catalog.Builtins()
	if err != nil {
		return nil, err
	}
	settings := make([]any, 0)
	for _, definition := range gameCatalog.List() {
		var value any
		if err := json.Unmarshal(definition.SettingsSchema, &value); err != nil {
			return nil, err
		}
		settings = append(settings, value)
	}
	components["Settings"] = map[string]any{"oneOf": settings}
	paths := map[string]any{}
	for _, route := range Routes() {
		path, ok := paths[route.Path].(map[string]any)
		if !ok {
			path = map[string]any{}
			paths[route.Path] = path
		}
		parameters := make([]any, 0)
		for _, segment := range strings.Split(route.Path, "/") {
			if strings.HasPrefix(segment, "{") {
				name := strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
				pathSchema := map[string]any{"type": "string", "minLength": 1, "maxLength": 63, "pattern": "^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$"}
				if strings.HasPrefix(route.Path, "/v1/backups/") || strings.HasPrefix(route.Path, "/v1/restores/") || strings.HasPrefix(route.Path, "/v1/destroys/") {
					pathSchema["maxLength"] = 253
					pathSchema["pattern"] = "^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$"
				}
				parameters = append(parameters, map[string]any{"name": name, "in": "path", "required": true, "schema": pathSchema})
			}
		}
		responses := map[string]any{"200": response(route.ResponseSchema)}
		for _, status := range []string{"400", "401", "403", "404", "409", "412", "413", "415", "422", "428", "500", "503"} {
			responses[status] = response("Error")
		}
		operation := map[string]any{"operationId": strings.ReplaceAll(route.Action, ".", "_") + "_" + strings.ReplaceAll(strings.NewReplacer("/", "_", "{", "", "}", "").Replace(route.Path), "-", "_"), "x-arcadectl-action": route.Action, "security": []any{map[string]any{"bearerAuth": []string{}}}, "responses": responses}
		if route.RequestSchema != "" {
			parameters = append(parameters, map[string]any{"name": "Idempotency-Key", "in": "header", "required": true, "schema": map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9._:-]+$"}})
			header := "If-Match"
			headerSchema := map[string]any{"type": "string", "minLength": 1, "maxLength": 512, "description": "One strong exact ETag from the corresponding current resource GET. Weak tags, wildcard tags and lists are rejected."}
			if route.Action == "server.create" {
				header = "If-None-Match"
				headerSchema = map[string]any{"type": "string", "enum": []string{"*"}}
			}
			parameters = append(parameters, map[string]any{"name": header, "in": "header", "required": true, "schema": headerSchema})
			operation["requestBody"] = map[string]any{"required": true, "description": "Strict JSON, at most 65536 bytes; duplicate keys, unknown fields, trailing values and unsafe fields are rejected.", "content": map[string]any{"application/json": map[string]any{"schema": reference(route.RequestSchema)}}}
			responses["202"] = response("Operation")
		}
		if len(parameters) > 0 {
			operation["parameters"] = parameters
		}
		path[strings.ToLower(route.Method)] = operation
	}
	document := map[string]any{"openapi": "3.0.3", "info": map[string]any{"title": "Arcadectl ordinary administrator API", "version": "v1"}, "paths": paths, "components": map[string]any{"schemas": components, "securitySchemes": map[string]any{"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "description": "Projected opaque administrator credential; authenticated before all validation, reads and mutation effects."}}}}
	contents, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(contents, '\n'), nil
}
func reference(name string) map[string]any {
	return map[string]any{"$ref": "#/components/schemas/" + name}
}
func response(name string) map[string]any {
	return map[string]any{"description": "Versioned bounded response; no raw worker, credential or Kubernetes error output.", "content": map[string]any{"application/json": map[string]any{"schema": reference(name)}}}
}
func schema(typ reflect.Type, field string) map[string]any {
	if typ.Kind() == reflect.Pointer {
		return schema(typ.Elem(), field)
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return reference("Settings")
	}
	if typ.Kind() == reflect.Struct {
		properties := map[string]any{}
		required := make([]string, 0)
		for index := 0; index < typ.NumField(); index++ {
			entry := typ.Field(index)
			tag := strings.Split(entry.Tag.Get("json"), ",")
			if tag[0] == "" || tag[0] == "-" {
				continue
			}
			properties[tag[0]] = schema(entry.Type, tag[0])
			if len(tag) == 1 {
				required = append(required, tag[0])
			}
		}
		result := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
		if len(required) > 0 {
			result["required"] = required
		}
		if typ.Name() == "Image" {
			properties["version"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 64}
			result["oneOf"] = []any{map[string]any{"required": []string{"digest"}}, map[string]any{"required": []string{"version"}}}
		}
		if typ.Name() == "Error" {
			properties["code"] = map[string]any{"type": "string", "enum": []string{"unauthenticated", "forbidden", "unavailable", "internal", "not_found", "method_not_allowed", "invalid_content_type", "invalid_body", "invalid_request", "invalid_idempotency_key", "precondition_required", "invalid_precondition", "precondition_failed", "idempotency_conflict", "invalid_reference", "unsupported", "validation_failed", "image_unavailable", "api_unavailable", "commit_unknown"}}
		}
		if typ.Name() == "ExactReference" || typ.Name() == "NativeOperation" || typ.Name() == "OperationChild" {
			properties["name"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 253, "pattern": "^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$"}
		}
		return result
	}
	if typ.Kind() == reflect.Slice {
		limit := 16
		if field == "items" {
			limit = 100
		}
		return map[string]any{"type": "array", "maxItems": limit, "items": schema(typ.Elem(), "")}
	}
	switch typ.Kind() {
	case reflect.Int, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer", "format": "int64"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	}
	result := map[string]any{"type": "string", "maxLength": 512}
	switch field {
	case "version":
		if typ == reflect.TypeOf("") {
			result["enum"] = []string{"v1"}
		}
	case "name", "game", "operationID", "path", "dataIdentity", "namespace":
		result["maxLength"] = 63
		result["minLength"] = 1
		result["pattern"] = "^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$"
	case "principalId", "credentialId":
		result["maxLength"] = 64
		result["minLength"] = 1
		result["pattern"] = "^[A-Za-z0-9_.-]+$"
	case "uid", "operationUID":
		result["maxLength"] = 128
		result["minLength"] = 1
		result["pattern"] = "^[A-Za-z0-9_.-]+$"
	case "cpuRequest", "cpuLimit", "memoryRequest", "memoryLimit", "size":
		result["minLength"] = 1
		result["maxLength"] = 64
	case "digest", "imageDigest", "snapshotDigest":
		result["pattern"] = "^sha256:[0-9a-f]{64}$"
		result["maxLength"] = 71
	case "storageClassName", "repositorySecretName":
		result["maxLength"] = 253
		result["pattern"] = "^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$"
		if field == "storageClassName" {
			result["pattern"] = "^(?:[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?)?$"
		}
	case "desiredState":
		result["enum"] = []string{"Running", "Stopped"}
	case "restartPolicy":
		result["enum"] = []string{"LeaveStopped", "RestorePreviousState"}
	case "challenge":
		result["minLength"] = 16
		result["maxLength"] = 128
		result["pattern"] = "^[A-Za-z0-9_-]+$"
	case "expiresAt", "startedAt", "completedAt":
		result["format"] = "date-time"
	}
	// Image.version is a curated adapter version, not the API version marker.
	return result
}

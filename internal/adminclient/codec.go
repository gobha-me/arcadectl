// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0
package adminclient

import (
	"bytes"
	"encoding/json"
	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var rawJSONType = reflect.TypeOf(json.RawMessage{})

func pointed(typ reflect.Type) reflect.Type {
	for typ != nil && typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	return typ
}

// Scan tokens before typed decoding. No numeric normalization or exponent
// expansion is performed, even for the 8MiB list budget.
func scanJSON(d *json.Decoder, typ reflect.Type, depth int, count *int) error {
	if depth > 32 || *count > 2000000 {
		return problem("invalid_response")
	}
	*count++
	token, e := d.Token()
	if e != nil {
		return problem("invalid_response")
	}
	typ = pointed(typ)
	if typ == rawJSONType {
		typ = nil
	}
	switch v := token.(type) {
	case json.Delim:
		if v == '{' {
			seen := map[string]bool{}
			fields := map[string]reflect.Type{}
			if typ != nil && typ.Kind() == reflect.Struct {
				for i := 0; i < typ.NumField(); i++ {
					f := typ.Field(i)
					name := strings.Split(f.Tag.Get("json"), ",")[0]
					if name != "" && name != "-" {
						fields[name] = f.Type
					}
				}
			}
			for d.More() {
				key, e := d.Token()
				name, ok := key.(string)
				if e != nil || !ok || len(name) > 128 || seen[name] {
					return problem("invalid_response")
				}
				seen[name] = true
				var child reflect.Type
				if typ != nil && typ.Kind() == reflect.Struct {
					child = fields[name]
					if child == nil {
						return problem("invalid_response")
					}
				}
				if e := scanJSON(d, child, depth+1, count); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return problem("invalid_response")
			}
		} else if v == '[' {
			var elem reflect.Type
			if typ != nil && typ.Kind() == reflect.Slice {
				elem = typ.Elem()
			}
			for d.More() {
				if e := scanJSON(d, elem, depth+1, count); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return problem("invalid_response")
			}
		} else {
			return problem("invalid_response")
		}
	case string:
		if len(v) > 65536 {
			return problem("invalid_response")
		}
	case json.Number:
		if len(v) > 128 {
			return problem("invalid_response")
		}
	}
	return nil
}
func decodeResponse(body []byte, out any) error {
	typ := reflect.TypeOf(out)
	if typ == nil || typ.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() || !utf8.Valid(body) {
		return problem("invalid_response")
	}
	scan := json.NewDecoder(bytes.NewReader(body))
	scan.UseNumber()
	count := 0
	if scanJSON(scan, typ.Elem(), 0, &count) != nil {
		return problem("invalid_response")
	}
	if _, e := scan.Token(); e != io.EOF {
		return problem("invalid_response")
	}
	decode := json.NewDecoder(bytes.NewReader(body))
	decode.UseNumber()
	decode.DisallowUnknownFields()
	if decode.Decode(out) != nil {
		return problem("invalid_response")
	}
	if decode.Decode(new(any)) != io.EOF {
		return problem("invalid_response")
	}
	return nil
}
func destinationMatches(schema string, out any) bool {
	switch schema {
	case "Self":
		_, ok := out.(*adminv1.Self)
		return ok
	case "Server":
		_, ok := out.(*adminv1.Server)
		return ok
	case "ServerList":
		_, ok := out.(*adminv1.ServerList)
		return ok
	case "Operation":
		_, ok := out.(*adminv1.Operation)
		return ok
	case "OperationList":
		_, ok := out.(*adminv1.OperationList)
		return ok
	case "RetainedWorld":
		_, ok := out.(*adminv1.RetainedWorld)
		return ok
	case "NativeOperation":
		_, ok := out.(*adminv1.NativeOperation)
		return ok
	}
	return false
}
func validRequestBody(schema string, body []byte) bool {
	var out any
	switch schema {
	case "CreateRequest":
		out = &adminv1.CreateRequest{}
	case "ConfigureRequest":
		out = &adminv1.ConfigureRequest{}
	case "EmptyRequest":
		out = &adminv1.EmptyRequest{}
	case "UpdateRequest":
		out = &adminv1.UpdateRequest{}
	case "BackupRequest":
		out = &adminv1.BackupRequest{}
	case "RestoreRequest":
		out = &adminv1.RestoreRequest{}
	case "DestroyRequest":
		out = &adminv1.DestroyRequest{}
	case "ConfirmRequest":
		out = &adminv1.ConfirmRequest{}
	case "CancelRequest":
		out = &adminv1.CancelRequest{}
	default:
		return false
	}
	if decodeResponse(body, out) != nil {
		return false
	}
	return reflect.ValueOf(out).Elem().FieldByName("Version").String() == "v1"
}
func validTime(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	t, e := time.Parse(time.RFC3339Nano, value)
	return e == nil && t.Location() == time.UTC && t.Format(time.RFC3339Nano) == value
}
func validName(value string) bool {
	return len(value) <= 253 && dnsPattern.MatchString(value) && !strings.Contains(value, "..")
}
func validReference(ref adminv1.ExactReference) bool {
	return validName(ref.Name) && uidPattern.MatchString(ref.UID)
}
func validPhase(value string) bool {
	switch value {
	case "Accepted", "Planning", "Pending", "Blocked", "Preparing", "Starting", "Ready", "Stopping", "Stopped", "Running", "Activating", "RollingBack", "Cancelling", "Preview", "AwaitingConfirmation", "Verifying", "Deleting", "Succeeded", "Failed", "Cancelled":
		return true
	}
	return false
}
func validConditions(values []adminv1.Condition) bool {
	if len(values) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v.Type] || len(v.Type) > 64 || len(v.Reason) > 64 || !uidPattern.MatchString(v.Type) || !uidPattern.MatchString(v.Reason) || v.ObservedGeneration < 0 {
			return false
		}
		seen[v.Type] = true
		switch v.Status {
		case "True", "False", "Unknown":
		default:
			return false
		}
	}
	return true
}
func validPreview(v *adminv1.DestroyPreview) bool {
	if v == nil {
		return true
	}
	if !regexp.MustCompile("^[A-Za-z0-9_-]{16,128}$").MatchString(v.Challenge) || !validTime(v.ExpiresAt, false) || len(v.RestoreGuidance) > 1024 {
		return false
	}
	if !validReference(v.BackupRef) {
		return false
	}
	{
		if !labelPattern.MatchString(v.Target.Namespace) || !validReference(v.Target.OriginalServer) || !labelPattern.MatchString(v.Target.Game) || !labelPattern.MatchString(v.Target.DataIdentity) || len(v.Target.Claims) < 1 || len(v.Target.Claims) > 16 {
			return false
		}
		for _, claim := range v.Target.Claims {
			if !labelPattern.MatchString(claim.Path) || !validReference(claim.ClaimRef) {
				return false
			}
		}
	}
	v.RestoreGuidance = "Preserve the verified backup and repository credentials; prove an isolated restore before further deletion."
	return true
}
func validateResponse(out any) error {
	valid := false
	switch v := out.(type) {
	case *adminv1.Self:
		valid = v.Version == "v1" && v.PrincipalID == "admin" && uidPattern.MatchString(v.CredentialID) && labelPattern.MatchString(v.Namespace) && validTime(v.ExpiresAt, false)
	case *adminv1.Server:
		valid = v.Version == "v1" && labelPattern.MatchString(v.Name) && uidPattern.MatchString(v.UID) && v.Generation > 0 && v.ObservedGeneration >= 0 && v.ObservedGeneration <= v.Generation && labelPattern.MatchString(v.Game) && digestPattern.MatchString(v.ImageDigest) && (v.DesiredState == "Running" || v.DesiredState == "Stopped") && len(v.Settings) <= 65536 && validPhase(v.Phase) && validConditions(v.Conditions) && len(v.Endpoints) <= 16
		for _, endpoint := range v.Endpoints {
			valid = valid && labelPattern.MatchString(endpoint.Name) && len(endpoint.Address) <= 253 && regexp.MustCompile("^[a-z0-9:][a-z0-9.:-]*$").MatchString(endpoint.Address) && (endpoint.Protocol == "TCP" || endpoint.Protocol == "UDP") && endpoint.Port > 0 && endpoint.Port <= 65535
		}
	case *adminv1.ServerList:
		valid = v.Version == "v1" && len(v.Items) <= 100
		seen := map[string]bool{}
		for i := range v.Items {
			valid = valid && !seen[v.Items[i].Name] && validateResponse(&v.Items[i]) == nil
			seen[v.Items[i].Name] = true
		}
	case *adminv1.Operation:
		valid = v.Version == "v1" && receiptPattern.MatchString(v.OperationID) && uidPattern.MatchString(v.UID) && v.Generation > 0 && v.ObservedGeneration >= 0 && v.ObservedGeneration <= v.Generation && validPhase(v.Phase) && validTime(v.StartedAt, true) && validTime(v.CompletedAt, true) && v.PollURL == "/v1/operations/"+v.OperationID && validPreview(v.DestroyPreview)
		action := false
		for _, route := range adminv1.Routes() {
			if route.RequestSchema != "" && route.Action == v.Action {
				action = true
			}
		}
		valid = valid && action
		if v.Child != nil {
			valid = valid && validReference(adminv1.ExactReference{Name: v.Child.Name, UID: v.Child.UID}) && v.Child.Generation > 0
			switch v.Child.Kind {
			case "GameServer", "GameBackup", "GameRestore", "GameDestroy":
			default:
				valid = false
			}
		}
		if v.Failure != nil {
			valid = valid && safeFailureCode(v.Failure.Code)
			v.Failure.Message = "The operation reports " + v.Failure.Code + "."
			v.Failure.SuggestedAction = "Inspect this exact receipt and native child before another intent."
			if v.Failure.Retryable {
				v.Failure.Message = "The admitted operation is waiting to make progress."
				v.Failure.SuggestedAction = "Continue polling this exact receipt; do not submit a replacement key."
			}
		}
	case *adminv1.OperationList:
		valid = v.Version == "v1" && len(v.Items) <= 100
		seen := map[string]bool{}
		for i := range v.Items {
			valid = valid && !seen[v.Items[i].OperationID] && validateResponse(&v.Items[i]) == nil
			seen[v.Items[i].OperationID] = true
		}
	case *adminv1.RetainedWorld:
		valid = v.Version == "v1" && receiptPattern.MatchString(v.OperationID) && uidPattern.MatchString(v.OperationUID) && validReference(v.OriginalServer) && labelPattern.MatchString(v.Game) && labelPattern.MatchString(v.DataIdentity) && digestPattern.MatchString(v.SnapshotDigest) && len(v.Claims) > 0 && len(v.Claims) <= 16
		for _, claim := range v.Claims {
			valid = valid && labelPattern.MatchString(claim.Path) && validReference(claim.ClaimRef)
		}
	case *adminv1.NativeOperation:
		valid = v.Version == "v1" && validName(v.Name) && uidPattern.MatchString(v.UID) && v.Generation > 0 && v.ObservedGeneration >= 0 && v.ObservedGeneration <= v.Generation && validPhase(v.Phase) && validTime(v.CompletedAt, true) && validConditions(v.Conditions) && validPreview(v.DestroyPreview)
		switch v.Kind {
		case "GameBackup", "GameRestore", "GameDestroy":
		default:
			valid = false
		}
	}
	if !valid {
		return problem("invalid_response")
	}
	return nil
}
func safeFailureCode(code string) bool {
	switch code {
	case "invalid_request", "target_changed", "operation_conflict", "invalid_reference", "secret_unavailable", "unsupported", "image_unavailable", "validation_failed", "worker_failed", "verification_failed", "too_late", "confirmation_expired", "child_changed", "api_unavailable", "receipt_invalid":
		return true
	}
	return false
}
func safeErrorCode(code string) bool {
	if safeFailureCode(code) {
		return true
	}
	switch code {
	case "unauthenticated", "forbidden", "unavailable", "internal", "not_found", "method_not_allowed", "invalid_content_type", "invalid_body", "invalid_idempotency_key", "precondition_required", "invalid_precondition", "precondition_failed", "idempotency_conflict", "commit_unknown":
		return true
	}
	return false
}
func responseError(status int, body []byte, expected string, mutation bool) error {
	if mutation && !supportedErrorStatus(status) {
		// An unsupported post-send status is not authoritative rejection evidence,
		// even when its body resembles the Error DTO. Preserve the exact attempt.
		return &Error{Code: "invalid_response", HTTPStatus: status, OperationID: expected, Ambiguous: true}
	}
	var wire adminv1.Error
	if decodeResponse(body, &wire) != nil || wire.Version != "v1" || !safeErrorCode(wire.Code) || (wire.OperationID != "" && (!receiptPattern.MatchString(wire.OperationID) || expected != "" && wire.OperationID != expected)) {
		return &Error{Code: "invalid_response", HTTPStatus: status, OperationID: expected, Ambiguous: mutation}
	}
	ambiguous := mutation && (status >= 500 || wire.Code == "commit_unknown")
	id := wire.OperationID
	if ambiguous {
		id = expected
	}
	return &Error{Code: wire.Code, HTTPStatus: status, OperationID: id, Ambiguous: ambiguous}
}

func supportedErrorStatus(status int) bool {
	switch status {
	case 400, 401, 403, 404, 409, 412, 413, 415, 422, 428, 500, 503:
		return true
	}
	return false
}

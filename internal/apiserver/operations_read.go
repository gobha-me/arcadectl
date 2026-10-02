// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func jsonSettings(settings string) runtime.RawExtension {
	return runtime.RawExtension{Raw: json.RawMessage(settings)}
}
func timeOutput(value *metav1.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
func phaseOutput(value string) string {
	switch value {
	case "Accepted", "Planning", "Pending", "Blocked", "Preparing", "Starting", "Ready", "Stopping", "Stopped", "Running", "Activating", "RollingBack", "Cancelling", "Preview", "AwaitingConfirmation", "Verifying", "Deleting", "Succeeded", "Failed", "Cancelled":
		return value
	default:
		return "Pending"
	}
}
func conditionOutput(input []metav1.Condition) []adminv1.Condition {
	output := make([]adminv1.Condition, 0, len(input))
	for _, condition := range input {
		if len(output) == 16 {
			break
		}
		switch condition.Type {
		case "SpecValid", "StorageReady", "ConfigurationReady", "WorkloadReady", "NetworkReady", "Ready", "Complete":
		default:
			continue
		}
		if condition.Status != metav1.ConditionTrue && condition.Status != metav1.ConditionFalse && condition.Status != metav1.ConditionUnknown {
			continue
		}
		reason := "Unknown"
		switch condition.Reason {
		case "Ready", "RuntimeStopped", "InvalidSpec", "Valid", "ClaimsReady", "ClaimsProvisioning", "StoragePending", "Succeeded", "Cancelled", "VerificationFailed", "WorkerFailed", "Blocked", "DataOperationActive", "PreflightVerified", "CandidatesReady", "OperationComplete":
			reason = condition.Reason
		}
		output = append(output, adminv1.Condition{Type: condition.Type, Status: string(condition.Status), Reason: reason, ObservedGeneration: condition.ObservedGeneration})
	}
	return output
}
func computeOutput(input arcadev1.ComputeSpec) adminv1.Compute {
	return adminv1.Compute{CPURequest: input.CPURequest.String(), CPULimit: input.CPULimit.String(), MemoryRequest: input.MemoryRequest.String(), MemoryLimit: input.MemoryLimit.String()}
}
func storageOutput(input arcadev1.StorageSpec) adminv1.Storage {
	return adminv1.Storage{Size: input.Size.String(), StorageClassName: input.StorageClassName}
}
func serverOutput(input *arcadev1.GameServer) adminv1.Server {
	endpoints := make([]adminv1.Endpoint, 0, len(input.Status.Endpoints))
	for _, endpoint := range input.Status.Endpoints {
		if len(endpoints) == 16 {
			break
		}
		endpoints = append(endpoints, adminv1.Endpoint{Name: endpoint.Name, Protocol: endpoint.Protocol, Address: endpoint.Address, Port: endpoint.Port})
	}
	return adminv1.Server{Version: "v1", Name: input.Name, UID: string(input.UID), Generation: input.Generation, Game: input.Spec.Game, ImageDigest: input.Spec.ImageDigest, DesiredState: string(input.Spec.DesiredState), Compute: computeOutput(input.Spec.Compute), Storage: storageOutput(input.Spec.Storage), Settings: input.Spec.Settings.Raw, Phase: phaseOutput(string(input.Status.Phase)), ObservedGeneration: input.Status.ObservedGeneration, Conditions: conditionOutput(input.Status.Conditions), Endpoints: endpoints}
}
func previewOutput(input *arcadev1.GameDestroyPreview) *adminv1.DestroyPreview {
	if input == nil || !challengeSyntax.MatchString(input.Challenge) {
		return nil
	}
	return &adminv1.DestroyPreview{Challenge: input.Challenge, ExpiresAt: input.ExpiresAt.UTC().Format(time.RFC3339Nano), RestoreGuidance: "Retain the verified backup and repository credentials; restore into isolated candidate storage before deleting any other world."}
}
func failureOutput(input *arcadev1.OperationFailure) *adminv1.Failure {
	if input == nil {
		return nil
	}
	code := input.Code
	switch code {
	case "invalid_request", "target_changed", "operation_conflict", "invalid_reference", "secret_unavailable", "unsupported", "image_unavailable", "validation_failed", "worker_failed", "verification_failed", "too_late", "confirmation_expired", "child_changed", "api_unavailable", "receipt_invalid":
	default:
		code = "receipt_invalid"
	}
	// No underlying controller/Kubernetes/worker error text crosses HTTP.
	message := "The admitted operation could not complete (" + code + ")."
	guidance := "Inspect this receipt and its exact native child before deciding on another intent."
	switch code {
	case "verification_failed", "worker_failed":
		guidance = "Preserve the original world and inspect this receipt and its exact native child; do not delete retained storage."
	case "target_changed", "child_changed", "invalid_reference":
		guidance = "Read the exact target and native child identities before deciding on another intent."
	case "secret_unavailable":
		guidance = "Have the cluster administrator check the referenced repository credential; never put credentials in a request or diagnostic."
	case "confirmation_expired", "too_late":
		guidance = "Read the parent destroy receipt and its exact native child before taking another destructive action."
	}
	if input.Retryable {
		message = "The admitted operation is waiting to make progress (" + code + ")."
		guidance = "Continue polling this exact receipt and its native child; the admitted intent remains active. Do not submit a replacement key."
	}
	return &adminv1.Failure{Code: code, Retryable: input.Retryable, Message: message, SuggestedAction: guidance}
}
func operationOutput(input *arcadev1.ArcadeOperation) adminv1.Operation {
	output := adminv1.Operation{Version: "v1", OperationID: input.Name, UID: string(input.UID), Generation: input.Generation, Action: string(input.Spec.Action), Phase: phaseOutput(string(input.Status.Phase)), ObservedGeneration: input.Status.ObservedGeneration, StartedAt: timeOutput(input.Status.StartedAt), CompletedAt: timeOutput(input.Status.CompletedAt), Failure: failureOutput(input.Status.Failure), DestroyPreview: previewOutput(input.Status.DestroyPreview), PollURL: "/v1/operations/" + input.Name}
	if input.Status.Phase == "" {
		output.Phase = "Accepted"
	}
	if input.Status.Child != nil {
		child := input.Status.Child
		switch child.Kind {
		case "GameServer", "GameBackup", "GameRestore", "GameDestroy":
			output.Child = &adminv1.OperationChild{Kind: child.Kind, Name: child.Name, UID: child.UID, Generation: child.Generation}
		}
	}
	return output
}
func (api *operationAPI) read(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		operationError(w, 400, "invalid_request", "")
		return
	}
	ctx := r.Context()
	key := types.NamespacedName{Namespace: api.server.namespace, Name: r.PathValue("name")}
	state := ctx.Value(requestStateKey{}).(*requestState)
	switch state.route {
	case "/v1/servers":
		list := &arcadev1.GameServerList{}
		if err := api.store.List(ctx, list, client.InNamespace(api.server.namespace), client.Limit(100)); err != nil {
			api.readError(w, err)
			return
		}
		sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
		output := adminv1.ServerList{Version: "v1", Items: make([]adminv1.Server, 0)}
		for index := range list.Items {
			if len(output.Items) == 100 {
				break
			}
			output.Items = append(output.Items, serverOutput(&list.Items[index]))
		}
		operationJSON(w, 200, output)
	case "/v1/servers/{name}":
		if !operationName.MatchString(key.Name) {
			operationError(w, 400, "invalid_request", "")
			return
		}
		server := &arcadev1.GameServer{}
		if err := api.store.Get(ctx, key, server); err != nil {
			api.readError(w, err)
			return
		}
		w.Header().Set("ETag", serverETag(server))
		operationJSON(w, 200, serverOutput(server))
	case "/v1/operations":
		list := &arcadev1.ArcadeOperationList{}
		if err := api.store.List(ctx, list, client.InNamespace(api.server.namespace), client.Limit(100)); err != nil {
			api.readError(w, err)
			return
		}
		sort.Slice(list.Items, func(i, j int) bool { return list.Items[i].Name < list.Items[j].Name })
		output := adminv1.OperationList{Version: "v1", Items: make([]adminv1.Operation, 0)}
		for index := range list.Items {
			if len(output.Items) == 100 {
				break
			}
			output.Items = append(output.Items, operationOutput(&list.Items[index]))
		}
		operationJSON(w, 200, output)
	case "/v1/operations/{operationID}", "/v1/retained-worlds/{operationID}":
		id := r.PathValue("operationID")
		if !operationName.MatchString(id) {
			operationError(w, 400, "invalid_request", "")
			return
		}
		receipt, err := api.lookup(ctx, id)
		if err != nil {
			api.readError(w, err)
			return
		}
		if strings.Contains(state.route, "retained-worlds") {
			if receipt.Status.RetainedWorld == nil {
				operationError(w, 404, "not_found", "")
				return
			}
			retained := receipt.Status.RetainedWorld
			selector := &arcadev1.OperationRetainedWorldSelector{DecommissionOperationRef: arcadev1.ExactLocalReference{Name: receipt.Name, UID: string(receipt.UID)}, SnapshotDigest: retained.SnapshotDigest}
			if err := api.checkRetained(ctx, selector); err != nil {
				var problem *operationProblem
				if errors.As(err, &problem) {
					operationError(w, problem.status, problem.code, "")
				} else {
					operationError(w, 503, "api_unavailable", "")
				}
				return
			}
			output := adminv1.RetainedWorld{Version: "v1", OperationID: receipt.Name, OperationUID: string(receipt.UID), OriginalServer: adminv1.ExactReference{Name: retained.Target.GameServer.Name, UID: retained.Target.GameServer.UID}, Game: retained.Target.Game, DataIdentity: retained.Target.Data.Identity, Claims: make([]adminv1.RetainedClaim, 0), SnapshotDigest: retained.SnapshotDigest}
			for _, claim := range retained.Target.Data.Claims {
				output.Claims = append(output.Claims, adminv1.RetainedClaim{Path: claim.Path, ClaimRef: adminv1.ExactReference{Name: claim.ClaimRef.Name, UID: claim.ClaimRef.UID}})
			}
			w.Header().Set("ETag", retainedETag(receipt))
			operationJSON(w, 200, output)
		} else {
			w.Header().Set("ETag", operationETag(receipt))
			operationJSON(w, 200, operationOutput(receipt))
		}
	case "/v1/backups/{name}", "/v1/restores/{name}", "/v1/destroys/{name}":
		if key.Name == "" || len(validation.IsDNS1123Subdomain(key.Name)) != 0 {
			operationError(w, 400, "invalid_request", "")
			return
		}
		var object client.Object
		var output adminv1.NativeOperation
		switch state.route {
		case "/v1/backups/{name}":
			value := &arcadev1.GameBackup{}
			object = value
			if err := api.store.Get(ctx, key, value); err != nil {
				api.readError(w, err)
				return
			}
			output = adminv1.NativeOperation{Kind: "GameBackup", Phase: phaseOutput(string(value.Status.Phase)), ObservedGeneration: value.Status.ObservedGeneration, CompletedAt: timeOutput(value.Status.CompletedAt), Conditions: conditionOutput(value.Status.Conditions)}
		case "/v1/restores/{name}":
			value := &arcadev1.GameRestore{}
			object = value
			if err := api.store.Get(ctx, key, value); err != nil {
				api.readError(w, err)
				return
			}
			output = adminv1.NativeOperation{Kind: "GameRestore", Phase: phaseOutput(string(value.Status.Phase)), ObservedGeneration: value.Status.ObservedGeneration, CompletedAt: timeOutput(value.Status.CompletedAt), Conditions: conditionOutput(value.Status.Conditions)}
		default:
			value := &arcadev1.GameDestroy{}
			object = value
			if err := api.store.Get(ctx, key, value); err != nil {
				api.readError(w, err)
				return
			}
			output = adminv1.NativeOperation{Kind: "GameDestroy", Phase: phaseOutput(string(value.Status.Phase)), ObservedGeneration: value.Status.ObservedGeneration, CompletedAt: timeOutput(value.Status.CompletedAt), Conditions: conditionOutput(value.Status.Conditions), DestroyPreview: previewOutput(value.Status.Preview)}
		}
		output.Version = "v1"
		output.Name = object.GetName()
		output.UID = string(object.GetUID())
		output.Generation = object.GetGeneration()
		operationJSON(w, 200, output)
	default:
		operationError(w, 404, "not_found", "")
	}
}
func (api *operationAPI) readError(w http.ResponseWriter, err error) {
	if apierrors.IsNotFound(err) {
		operationError(w, 404, "not_found", "")
	} else {
		operationError(w, 503, "api_unavailable", "")
	}
}

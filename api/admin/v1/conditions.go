// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package v1

// ConditionGuidance projects only repository-owned reason codes and fixed prose.
// Controller messages, events, annotations and provider errors are not inputs.
// A newer or untrusted reason must not become an arbitrary HTTP output channel.
func ConditionGuidance(input string) (reason, action string) {
	switch input {
	case "InvalidSpec":
		action = "Review the adapter settings, immutable image digest, resource bounds, ports, and storage request before submitting corrected configuration."
	case "ControllerMisconfigured":
		action = "Ask the cluster administrator to check controller configuration and its scoped permissions; preserve retained storage."
	case "ClaimsProvisioning", "StoragePending":
		action = "Ask the cluster administrator to check the selected storage class, available capacity, and claim binding; do not delete retained claims."
	case "ClaimExpansionPending":
		action = "Wait for storage expansion and ask the cluster administrator to check the provisioner's expansion support; do not replace retained claims."
	case "StorageOperationFailed":
		action = "Ask the cluster administrator to check storage availability and scoped permissions; preserve the exact retained claims."
	case "RetainedDataReferenceRequired":
		action = "Inspect the successful decommission receipt and deliberately select its exact retained world; do not relabel or adopt claims automatically."
	case "RetainedDataMissing":
		action = "Recover the exact missing retained claim or restore a verified backup into new storage; do not create an empty replacement under the old identity."
	case "RetainedDataConflict":
		action = "Preserve retained storage and ask the cluster administrator to compare exact claim UIDs, data identity, paths, class, and ownership."
	case "ConfigurationOperationFailed":
		action = "Ask the cluster administrator to check configuration ownership and scoped permissions; never include credentials in diagnostics."
	case "WorkloadProgressing", "WorkloadPending":
		action = "Wait for the current workload and ask the cluster administrator to check scheduling, capacity, and image availability; do not start another workload."
	case "WorkloadUnavailable", "WorkloadOperationFailed":
		action = "Ask the cluster administrator to check workload availability, image access, and scoped permissions; preserve the world and avoid overlapping workloads."
	case "PlayerEndpointPending", "NetworkOperationFailed":
		action = "Ask the cluster administrator to check Service provisioning, LoadBalancer support, and player-port routing; keep administrative ports private."
	case "ResourceCollision":
		action = "Inspect existing object ownership before choosing another server name or deliberately resolving the collision; do not adopt or delete foreign resources."
	case "DataOperationActive":
		action = "Inspect and wait on the exact active backup, restore, or destroy receipt before submitting another lifecycle intent."
	case "RuntimeStopping":
		action = "Wait for the existing workload to stop; retained storage remains intact."
	case "Blocked", "ReconcileFailed":
		action = "Inspect the other conditions and exact active operation; ask the cluster administrator to investigate while preserving retained storage."
	case "VerificationFailed", "WorkerFailed":
		action = "Preserve the original world and inspect the exact operation and native child; never include repository credentials or save contents in diagnostics."
	case "Valid", "ClaimsReady", "ConfigurationReady",
		"WorkloadAvailable", "PlayerEndpointReady", "RuntimeStopped",
		"Ready", "Succeeded", "Cancelled", "PreflightVerified", "CandidatesReady", "OperationComplete":
		// These codes describe progress or successful completion, not a failure.
	default:
		return "Unknown", "Ask the cluster administrator to inspect this exact server or native operation; redact credentials and preserve retained storage."
	}
	return input, action
}

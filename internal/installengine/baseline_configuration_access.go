// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	baselineConfigurationPageLimit   = 128
	baselineConfigurationMaxPages    = 32
	baselineConfigurationMaxItems    = 1000
	baselineConfigurationMaxBytes    = 4 * 1024 * 1024
	baselineConfigurationMaxContinue = 2048
	baselineConfigurationSelector    = "app.kubernetes.io/part-of=arcadectl,arcade.gobha.me/security-baseline=" + installbaseline.Version
	runtimeConfigurationSelector     = "app.kubernetes.io/part-of=arcadectl,app.kubernetes.io/name in (arcadectl-controller,arcadectl-destroy-controller)"
)

type configurationListPurpose uint8

const (
	baselineConfigurationList configurationListPurpose = iota + 1
	runtimeConfigurationList
)

// This is NOT a general LIST interface. Only the frozen installer parent may
// read these two public cluster collections. Labels reduce transport volume;
// they confer no namespace, membership, ownership or enforcement authority.
// Every call drains a new most-recent snapshot (RV is absent, never "0"), with
// one stable collection RV per kind. Foreign matching installations are parsed
// transiently but their object bodies are neither retained nor memoized.
func (a *HTTPAccess) listBaselineConfiguration(ctx context.Context, kind string, expected map[installstate.Key]bool) (map[installstate.Key]*unstructured.Unstructured, error) {
	return a.listConfiguration(ctx, kind, expected, baselineConfigurationList)
}

// Runtime configuration remains usable by a non-direct parent observer. Full
// lifecycle/actor construction independently enforces its stronger routing
// contract. Neither wrapper grants actor clients a generic collection route.
func (a *HTTPAccess) listRuntimeConfiguration(ctx context.Context, kind string, expected map[installstate.Key]bool) (map[installstate.Key]*unstructured.Unstructured, error) {
	return a.listConfiguration(ctx, kind, expected, runtimeConfigurationList)
}

func (a *HTTPAccess) listConfiguration(ctx context.Context, kind string, expected map[installstate.Key]bool, purpose configurationListPurpose) (map[installstate.Key]*unstructured.Unstructured, error) {
	if ctx == nil || a == nil || a.actor != nil {
		return nil, ErrInvalid
	}
	selector := ""
	expectedCount := 0
	switch purpose {
	case baselineConfigurationList:
		if !a.actorCompatible() {
			return nil, ErrInvalid
		}
		selector = baselineConfigurationSelector
		expectedCount = installbaseline.ResourceCount / 2
	case runtimeConfigurationList:
		selector = runtimeConfigurationSelector
		expectedCount = 6
	default:
		return nil, ErrInvalid
	}
	if len(expected) != expectedCount {
		return nil, ErrInvalid
	}
	plural := ""
	switch kind {
	case "ValidatingAdmissionPolicy":
		plural = "validatingadmissionpolicies"
	case "ValidatingAdmissionPolicyBinding":
		plural = "validatingadmissionpolicybindings"
	default:
		return nil, ErrInvalid
	}
	const version = "admissionregistration.k8s.io/v1"
	for key, present := range expected {
		if !present || key.APIVersion != version || key.Kind != kind || key.Namespace != "" || !addressPart(key.Name) {
			return nil, ErrInvalid
		}
	}
	key := installstate.Key{APIVersion: version, Kind: kind + "List"}
	path := "/apis/" + version + "/" + plural
	result := make(map[installstate.Key]*unstructured.Unstructured, len(expected))
	seenNames, seenUIDs, seenTokens := map[string]bool{}, map[string]bool{}, map[string]bool{}
	remaining, count, continuation, revision := baselineConfigurationMaxBytes, 0, "", ""
	for range baselineConfigurationMaxPages {
		if ctx.Err() != nil {
			return nil, ErrRead
		}
		query := url.Values{"limit": {strconv.Itoa(baselineConfigurationPageLimit)}, "labelSelector": {selector}}
		if continuation != "" {
			query.Set("continue", continuation)
		}
		page, err := a.requestAtBudget(ctx, http.MethodGet, key, nil, false, path, query, &remaining)
		if err != nil || page == nil || ctx.Err() != nil {
			return nil, ErrRead
		}
		// Typed strict decoding rejects unknown/case-aliased fields throughout
		// the list AND its items, not just the selected original objects.
		if kind == "ValidatingAdmissionPolicy" {
			var typed admissionv1.ValidatingAdmissionPolicyList
			if decodeServing(page, &typed) != nil {
				return nil, ErrRead
			}
		} else {
			var typed admissionv1.ValidatingAdmissionPolicyBindingList
			if decodeServing(page, &typed) != nil {
				return nil, ErrRead
			}
		}
		metadata, ok := page.Object["metadata"].(map[string]any)
		if !ok {
			return nil, ErrRead
		}
		for field, value := range metadata {
			switch field {
			case "resourceVersion", "continue", "selfLink":
				text, valid := value.(string)
				if !valid || field == "selfLink" && text != "" {
					return nil, ErrRead
				}
			case "remainingItemCount":
				if n, valid := value.(int64); !valid || n < 0 {
					return nil, ErrRead
				}
			default:
				return nil, ErrRead
			}
		}
		rv, ok := metadata["resourceVersion"].(string)
		if !ok || rv == "" || len(rv) > 1024 || revision != "" && rv != revision {
			return nil, ErrRead
		}
		revision = rv
		items, ok := page.Object["items"].([]any)
		if !ok || count+len(items) > baselineConfigurationMaxItems {
			return nil, ErrRead
		}
		count += len(items)
		for _, item := range items {
			fields, ok := item.(map[string]any)
			if !ok || fields == nil {
				return nil, ErrRead
			}
			object := &unstructured.Unstructured{Object: fields}
			// Native typed LIST items may omit BOTH TypeMeta fields. Only the
			// verified fixed collection envelope can supply them; partial,
			// explicit null, empty or different item identities are refused.
			versionValue, versionPresent := fields["apiVersion"]
			kindValue, kindPresent := fields["kind"]
			if versionPresent != kindPresent || versionPresent && (versionValue != version || kindValue != kind) {
				return nil, ErrRead
			}
			name, uid := object.GetName(), string(object.GetUID())
			if object.GetNamespace() != "" || !addressPart(name) || !receiptUID.MatchString(uid) || !receiptUID.MatchString(object.GetResourceVersion()) || seenNames[name] || seenUIDs[uid] {
				return nil, ErrRead
			}
			seenNames[name], seenUIDs[uid] = true, true
			member := installstate.Key{APIVersion: version, Kind: kind, Name: name}
			if expected[member] {
				selected := object.DeepCopy()
				if !versionPresent {
					selected.SetAPIVersion(version)
					selected.SetKind(kind)
				}
				result[member] = selected
			}
		}
		continuation, _ = metadata["continue"].(string)
		if continuation == "" {
			if n, present := metadata["remainingItemCount"]; present && n != int64(0) || len(result) != len(expected) || ctx.Err() != nil {
				return nil, ErrRead
			}
			return result, nil
		}
		if len(continuation) > baselineConfigurationMaxContinue || seenTokens[continuation] {
			return nil, ErrRead
		}
		seenTokens[continuation] = true
	}
	return nil, ErrRead
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installrender"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Effective native-RBAC rules complement original signed object witnesses;
// they do NOT establish ownership or support arbitrary external authorizers.
// The sorted raw rule multisets retain duplicate grants and every raw name.
type baselineRulesEvidence struct {
	resources, nonresources []string
	rules                   []authv1.ResourceRule
}

func (identity actorWireIdentity) allowsRulesReview(review *authv1.SelfSubjectRulesReview) bool {
	return identity.purpose == baselineRulesReviewPurpose && identity.deniedScope == nil &&
		(identity.actor == ordinaryControllerActor || identity.actor == destroyControllerActor) &&
		installrender.ValidNamespace(identity.namespace) && identity.username == "system:serviceaccount:"+identity.namespace+":"+identity.actor.account() &&
		review != nil && review.APIVersion == "authorization.k8s.io/v1" && review.Kind == "SelfSubjectRulesReview" &&
		reflect.DeepEqual(review.ObjectMeta, metav1.ObjectMeta{}) && review.Spec.Namespace == identity.namespace &&
		reflect.DeepEqual(review.Status, authv1.SubjectRulesReviewStatus{})
}

func (a *HTTPAccess) baselineRulesClient(actor admissionActor, namespace string) (*HTTPAccess, error) {
	return a.frozenActorClient(actor, namespace, baselineRulesReviewPurpose, nil)
}

// Internally constructed namespace-only review; no caller-selected route,
// user/groups, review descriptor, effect, TokenRequest or generic actor read.
func (a *HTTPAccess) baselineRules(ctx context.Context) (*baselineRulesEvidence, error) {
	if a == nil || a.actor == nil || a.actor.purpose != baselineRulesReviewPurpose || ctx == nil {
		return nil, ErrSecurityBaseline
	}
	request := &authv1.SelfSubjectRulesReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectRulesReview"}, Spec: authv1.SelfSubjectRulesReviewSpec{Namespace: a.actor.namespace}}
	var reply authv1.SelfSubjectRulesReview
	fields, err := a.proofRequest(ctx, http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", request, &reply)
	if err != nil || reply.APIVersion != request.APIVersion || reply.Kind != request.Kind || !reflect.DeepEqual(reply.ObjectMeta, metav1.ObjectMeta{}) || reply.Spec != (authv1.SelfSubjectRulesReviewSpec{}) {
		return nil, ErrSecurityBaseline
	}
	// Both exact native handlers return a fresh status-only object, not an
	// echoed namespace spec or persisted metadata. Its scope comes from the
	// exact captured request. Missing/null/present-foreign envelopes refuse.
	if spec, ok := fields["spec"].(map[string]any); !ok || len(spec) != 0 {
		return nil, ErrSecurityBaseline
	}
	if raw, present := fields["metadata"]; present {
		meta, ok := raw.(map[string]any)
		if !ok || len(meta) > 1 {
			return nil, ErrSecurityBaseline
		}
		for key, value := range meta {
			if key != "creationTimestamp" || value != nil {
				return nil, ErrSecurityBaseline
			}
		}
	}
	status, ok := fields["status"].(map[string]any)
	if !ok || status["incomplete"] != false || reply.Status.Incomplete || reply.Status.EvaluationError != "" {
		return nil, ErrSecurityBaseline
	}
	if failure, present := status["evaluationError"]; present && failure != "" {
		return nil, ErrSecurityBaseline
	}
	evidence := &baselineRulesEvidence{rules: reply.Status.ResourceRules}
	for _, family := range []struct {
		name string
		out  *[]string
	}{{"resourceRules", &evidence.resources}, {"nonResourceRules", &evidence.nonresources}} {
		rows, ok := status[family.name].([]any)
		if !ok || len(rows) > 4096 {
			return nil, ErrSecurityBaseline
		}
		*family.out = []string{}
		for _, row := range rows {
			fields, ok := row.(map[string]any)
			if !ok {
				return nil, ErrSecurityBaseline
			}
			allowed := map[string]bool{"verbs": true, "nonResourceURLs": true}
			if family.name == "resourceRules" {
				allowed = map[string]bool{"verbs": true, "apiGroups": true, "resources": true, "resourceNames": true}
			}
			copy := map[string]any{}
			for field, raw := range fields {
				values, ok := raw.([]any)
				if !allowed[field] || !ok || len(values) > 4096 || field != "resourceNames" && len(values) == 0 {
					return nil, ErrSecurityBaseline
				}
				strings := []string{}
				for _, raw := range values {
					value, ok := raw.(string)
					if !ok || len(value) > 4096 || field != "apiGroups" && value == "" {
						return nil, ErrSecurityBaseline
					}
					strings = append(strings, value)
				}
				slices.Sort(strings)
				copy[field] = strings
			}
			if copy["verbs"] == nil || family.name == "resourceRules" && (copy["apiGroups"] == nil || copy["resources"] == nil) || family.name == "nonResourceRules" && copy["nonResourceURLs"] == nil {
				return nil, ErrSecurityBaseline
			}
			body, err := json.Marshal(copy)
			if err != nil {
				return nil, ErrSecurityBaseline
			}
			*family.out = append(*family.out, string(body))
		}
		slices.Sort(*family.out)
	}
	return evidence, nil
}

func sameBaselineRules(before, after *baselineRulesEvidence) bool {
	return before != nil && after != nil && reflect.DeepEqual(before.resources, after.resources) && reflect.DeepEqual(before.nonresources, after.nonresources)
}

// Native RBAC matches resourceNames literally, not by '*' or normalized URL
// aliases. Examine every actual finite name instead of inventing a bounded
// list of spellings. Any native-parser-valid address selecting a protected
// target refuses, regardless of port spelling or current backend readiness.
func baselineProxyRulesContained(evidence *baselineRulesEvidence, executables *baselineExecutables) bool {
	if evidence == nil || executables == nil || executables.guarded == nil {
		return false
	}
	pods, services := map[string]bool{}, map[string]bool{}
	for _, name := range []string{"arcadectl-controller", "arcadectl-api", "arcadectl-destroy-controller", "arcadectl-destroy-admin"} {
		pods[name], services[name] = true, true
	}
	for key := range executables.guarded {
		if key.Kind == "Pod" && key.APIVersion == "v1" {
			pods[key.Name] = true
		}
	}
	for _, rule := range evidence.rules {
		if !slices.Contains(rule.APIGroups, "") && !slices.Contains(rule.APIGroups, "*") || !baselineProxyRuleVerb(rule.Verbs) {
			continue
		}
		for resource, names := range map[string]map[string]bool{"pods/proxy": pods, "services/proxy": services} {
			if !slices.Contains(rule.Resources, resource) && !slices.Contains(rule.Resources, "*") && !slices.Contains(rule.Resources, "*/proxy") {
				continue
			}
			if len(rule.ResourceNames) == 0 {
				return false
			}
			for _, raw := range rule.ResourceNames {
				parts := strings.Split(raw, ":")
				name := ""
				switch len(parts) {
				case 1, 2:
					name = parts[0]
				case 3:
					if parts[0] == "" || parts[0] == "http" || parts[0] == "https" {
						name = parts[1]
					}
				}
				if name != "" && names[name] {
					return false
				}
			}
		}
	}
	return true
}

func baselineProxyRuleVerb(verbs []string) bool {
	for _, verb := range verbs {
		if verb == "*" || verb == "get" || verb == "create" || verb == "update" || verb == "patch" || verb == "delete" || verb == "" {
			return true
		}
	}
	return false
}

// Only the already-original two software identities have review authority.
// The descriptor proof and complete rule proof remain separate protocols.
func (actors *baselineActors) rulesClients(ctx context.Context, executables *baselineExecutables) (map[admissionActor]*HTTPAccess, map[admissionActor]*baselineRulesEvidence, error) {
	if actors == nil || actors.baseline == nil || baselineDeniedObservation(actors.snapshot, executables) != nil {
		return nil, nil, ErrSecurityBaseline
	}
	clients := map[admissionActor]*HTTPAccess{}
	opening := map[admissionActor]*baselineRulesEvidence{}
	for _, actor := range []admissionActor{ordinaryControllerActor, destroyControllerActor} {
		client, err := actors.baseline.access.baselineRulesClient(actor, actors.snapshot.Document().Namespace)
		if err != nil {
			return nil, nil, ErrSecurityBaseline
		}
		rules, err := client.baselineRules(ctx)
		if err != nil || !baselineProxyRulesContained(rules, executables) {
			return nil, nil, ErrSecurityBaseline
		}
		clients[actor], opening[actor] = client, rules
	}
	return clients, opening, nil
}

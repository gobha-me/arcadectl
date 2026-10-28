// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gobha-me/arcadectl/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"
)

type apiEndpointContract struct {
	namespace            string
	deploymentSelector   metav1.LabelSelector
	serviceSelector      map[string]string
	podTemplateLabels    map[string]string
	httpsPortNumber      int32
	httpsPortName        string
	healthPortNumber     int32
	healthPortName       string
	justifiedIngressPort map[string]bool
}

func loadAPIEndpointContract(t *testing.T) apiEndpointContract {
	t.Helper()
	root := repositoryRoot(t)

	deployRaw, err := os.ReadFile(filepath.Join(root, "config", "api", "deployment.yaml.tmpl"))
	if err != nil {
		t.Fatalf("read api deployment template: %v", err)
	}
	deployRendered := bytes.ReplaceAll(deployRaw, []byte("@@API_IMAGE@@"), []byte(testAPIImage))
	deployObjects := decodeObjects(t, deployRendered)
	if len(deployObjects) != 1 {
		t.Fatalf("expected 1 object in api deployment template, got %d", len(deployObjects))
	}
	deployment := &appsv1.Deployment{}
	convertObject(t, deployObjects[0], deployment)

	serviceRaw, err := os.ReadFile(filepath.Join(root, "config", "api", "service.yaml"))
	if err != nil {
		t.Fatalf("read api service manifest: %v", err)
	}
	serviceObjects := decodeObjects(t, serviceRaw)
	if len(serviceObjects) != 1 {
		t.Fatalf("expected 1 object in api service manifest, got %d", len(serviceObjects))
	}
	service := &corev1.Service{}
	convertObject(t, serviceObjects[0], service)

	if deployment.Namespace == "" || deployment.Namespace != service.Namespace {
		t.Fatalf("api deployment/service namespace mismatch: %q vs %q", deployment.Namespace, service.Namespace)
	}
	if deployment.Spec.Selector == nil || len(deployment.Spec.Selector.MatchLabels) == 0 || len(deployment.Spec.Selector.MatchExpressions) != 0 {
		t.Fatalf("api deployment selector must be non-empty matchLabels only: %#v", deployment.Spec.Selector)
	}
	if !maps.Equal(deployment.Spec.Selector.MatchLabels, service.Spec.Selector) {
		t.Fatalf("api deployment selector %v != service selector %v", deployment.Spec.Selector.MatchLabels, service.Spec.Selector)
	}
	if len(deployment.Spec.Template.Labels) == 0 {
		t.Fatal("api deployment pod template has no labels")
	}
	for k, v := range deployment.Spec.Selector.MatchLabels {
		if deployment.Spec.Template.Labels[k] != v {
			t.Fatalf("api deployment pod template labels %v missing selector %s=%s", deployment.Spec.Template.Labels, k, v)
		}
	}
	if len(deployment.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("expected 1 api container, got %d", len(deployment.Spec.Template.Spec.Containers))
	}

	var httpsPort, healthPort int32
	var httpsName, healthName string
	for _, p := range deployment.Spec.Template.Spec.Containers[0].Ports {
		switch p.Name {
		case "https":
			httpsPort = p.ContainerPort
			httpsName = p.Name
		case "health":
			healthPort = p.ContainerPort
			healthName = p.Name
		}
	}
	if httpsPort != 8443 || httpsName != "https" || healthPort != 8081 || healthName != "health" {
		t.Fatalf("unexpected api container ports: https=%s:%d health=%s:%d", httpsName, httpsPort, healthName, healthPort)
	}

	// Product invariant (see docs/ADMIN_API.md):
	// - No in-cluster admin API client is installed for 8443 (installer & tests use pods/portforward via CRI netns).
	// - Same-node kubelet probes on 8081 are exempt under standard NetworkPolicy.
	// Therefore no ingress rule or port is permitted in the NetworkPolicy (ingress: []).
	return apiEndpointContract{
		namespace:            deployment.Namespace,
		deploymentSelector:   *deployment.Spec.Selector.DeepCopy(),
		serviceSelector:      maps.Clone(service.Spec.Selector),
		podTemplateLabels:    maps.Clone(deployment.Spec.Template.Labels),
		httpsPortNumber:      httpsPort,
		httpsPortName:        httpsName,
		healthPortNumber:     healthPort,
		healthPortName:       healthName,
		justifiedIngressPort: map[string]bool{},
	}
}

func validateAPINetworkPolicyManifest(raw []byte, contract apiEndpointContract) error {
	var problems []string

	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	var objects []*unstructured.Unstructured
	for {
		obj := &unstructured.Unstructured{}
		if err := decoder.Decode(obj); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("decode networkpolicy yaml: %w", err)
		}
		if len(obj.Object) != 0 {
			objects = append(objects, obj)
		}
	}
	if len(objects) != 1 {
		return fmt.Errorf("expected exactly 1 YAML document, got %d", len(objects))
	}

	var strictPolicy networkingv1.NetworkPolicy
	if err := sigsyaml.UnmarshalStrict(raw, &strictPolicy); err != nil {
		problems = append(problems, fmt.Sprintf("strict YAML unmarshal failed: %v", err))
	}

	unstructuredObj := objects[0]
	policy := &networkingv1.NetworkPolicy{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, policy); err != nil {
		return fmt.Errorf("convert unstructured to NetworkPolicy: %w", err)
	}

	if policy.APIVersion != networkingv1.SchemeGroupVersion.String() {
		problems = append(problems, fmt.Sprintf("apiVersion = %q, want %q", policy.APIVersion, networkingv1.SchemeGroupVersion.String()))
	}
	if policy.Kind != "NetworkPolicy" {
		problems = append(problems, fmt.Sprintf("kind = %q, want NetworkPolicy", policy.Kind))
	}
	if policy.Namespace != "arcadectl-system" || policy.Namespace != contract.namespace {
		problems = append(problems, fmt.Sprintf("namespace = %q, want %q", policy.Namespace, contract.namespace))
	}
	if policy.Name == "" {
		problems = append(problems, "metadata.name is empty")
	}

	// PodSelector checks against API Deployment and Service selectors + Pod template labels.
	if len(policy.Spec.PodSelector.MatchExpressions) != 0 {
		problems = append(problems, fmt.Sprintf("podSelector.matchExpressions must be empty, got %#v", policy.Spec.PodSelector.MatchExpressions))
	}
	if len(policy.Spec.PodSelector.MatchLabels) == 0 {
		problems = append(problems, "podSelector.matchLabels is empty (selects all pods in namespace)")
	} else {
		if !maps.Equal(policy.Spec.PodSelector.MatchLabels, contract.deploymentSelector.MatchLabels) {
			problems = append(problems, fmt.Sprintf("podSelector.matchLabels %v does not exactly match API Deployment selector %v", policy.Spec.PodSelector.MatchLabels, contract.deploymentSelector.MatchLabels))
		}
		if !maps.Equal(policy.Spec.PodSelector.MatchLabels, contract.serviceSelector) {
			problems = append(problems, fmt.Sprintf("podSelector.matchLabels %v does not exactly match API Service selector %v", policy.Spec.PodSelector.MatchLabels, contract.serviceSelector))
		}
		for k, v := range policy.Spec.PodSelector.MatchLabels {
			if contract.podTemplateLabels[k] != v {
				problems = append(problems, fmt.Sprintf("podSelector label %s=%s does not match API Deployment pod template labels %v", k, v, contract.podTemplateLabels))
			}
		}
	}

	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	if err != nil {
		problems = append(problems, fmt.Sprintf("invalid podSelector: %v", err))
	} else {
		if selector.Empty() {
			problems = append(problems, "compiled podSelector is empty")
		}
		if !selector.Matches(labels.Set(contract.podTemplateLabels)) {
			problems = append(problems, "podSelector does not match API Deployment template pod labels")
		}
		// Ensure a non-API pod sharing only non-selector template labels (like part-of) is not matched.
		nonAPILabels := maps.Clone(contract.podTemplateLabels)
		for k := range contract.deploymentSelector.MatchLabels {
			nonAPILabels[k] = "arcadectl-controller"
		}
		if selector.Matches(labels.Set(nonAPILabels)) {
			problems = append(problems, "podSelector overly broad: matches non-API controller pod labels")
		}
	}

	// Product invariant (see docs/ADMIN_API.md): policyTypes must be exactly [Ingress].
	// Adding Egress without egress rules would deny all API egress (kube-apiserver, DNS).
	if !slices.Equal(policy.Spec.PolicyTypes, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}) {
		problems = append(problems, fmt.Sprintf("policyTypes must be exactly [Ingress], got %v (see docs/ADMIN_API.md)", policy.Spec.PolicyTypes))
	}

	// Require explicit policyTypes and ingress keys in YAML spec so isolation does not rely on omitted fields.
	specMap, ok := unstructuredObj.Object["spec"].(map[string]any)
	if !ok {
		problems = append(problems, "missing spec object")
	} else {
		if _, hasPolicyTypes := specMap["policyTypes"]; !hasPolicyTypes {
			problems = append(problems, "spec.policyTypes must be explicitly present")
		}
		if _, hasIngress := specMap["ingress"]; !hasIngress {
			problems = append(problems, "spec.ingress must be explicitly present as []")
		}
	}

	// Adversarial rule-by-rule inspection.
	for i, rule := range policy.Spec.Ingress {
		if len(rule.From) == 0 {
			problems = append(problems, fmt.Sprintf("ingress[%d] has empty from (allows ingress from everywhere)", i))
		}
		for j, peer := range rule.From {
			problems = append(problems, validateIngressPeer(i, j, peer)...)
		}

		if len(rule.Ports) == 0 {
			problems = append(problems, fmt.Sprintf("ingress[%d] omits explicit ports (allows all ports including %d/%s)", i, contract.httpsPortNumber, contract.httpsPortName))
		}
		for j, p := range rule.Ports {
			problems = append(problems, validateIngressPort(i, j, p, contract)...)
		}
	}

	if len(policy.Spec.Ingress) != 0 && len(contract.justifiedIngressPort) == 0 {
		problems = append(problems, fmt.Sprintf("no ingress rule is permitted (got %d rule(s); spec.ingress must be []; see docs/ADMIN_API.md)", len(policy.Spec.Ingress)))
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func isEmptyLabelSelector(sel *metav1.LabelSelector) bool {
	return sel != nil && len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}

func validateIngressPeer(ruleIndex, peerIndex int, peer networkingv1.NetworkPolicyPeer) []string {
	var problems []string
	if peer.IPBlock == nil && peer.NamespaceSelector == nil && peer.PodSelector == nil {
		problems = append(problems, fmt.Sprintf("ingress[%d].from[%d] is an empty peer", ruleIndex, peerIndex))
		return problems
	}
	if peer.IPBlock != nil {
		cidr := strings.TrimSpace(peer.IPBlock.CIDR)
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			problems = append(problems, fmt.Sprintf("ingress[%d].from[%d] has invalid ipBlock CIDR %q: %v", ruleIndex, peerIndex, cidr, err))
		} else if prefix.Bits() == 0 || cidr == "0.0.0.0/0" || cidr == "::/0" {
			problems = append(problems, fmt.Sprintf("ingress[%d].from[%d] allows everywhere via wildcard ipBlock %q", ruleIndex, peerIndex, cidr))
		}
	}
	nsEmpty := isEmptyLabelSelector(peer.NamespaceSelector)
	podEmpty := isEmptyLabelSelector(peer.PodSelector)
	if nsEmpty && podEmpty {
		problems = append(problems, fmt.Sprintf("ingress[%d].from[%d] uses empty namespaceSelector {} with empty podSelector {} (allows all pods in all namespaces)", ruleIndex, peerIndex))
	} else if nsEmpty && peer.PodSelector == nil {
		problems = append(problems, fmt.Sprintf("ingress[%d].from[%d] uses empty namespaceSelector {} without podSelector (allows all namespaces)", ruleIndex, peerIndex))
	} else if podEmpty && peer.NamespaceSelector == nil {
		problems = append(problems, fmt.Sprintf("ingress[%d].from[%d] uses empty podSelector {} without namespaceSelector (allows all pods in namespace)", ruleIndex, peerIndex))
	} else if peer.IPBlock == nil && (peer.NamespaceSelector == nil || peer.PodSelector == nil || nsEmpty || podEmpty) {
		problems = append(problems, fmt.Sprintf("ingress[%d].from[%d] must combine non-empty namespaceSelector and non-empty podSelector in the same peer", ruleIndex, peerIndex))
	}
	return problems
}

func validateIngressPort(ruleIndex, portIndex int, p networkingv1.NetworkPolicyPort, contract apiEndpointContract) []string {
	var problems []string
	if p.Protocol == nil || *p.Protocol != corev1.ProtocolTCP {
		problems = append(problems, fmt.Sprintf("ingress[%d].ports[%d] must explicitly set protocol TCP", ruleIndex, portIndex))
	}
	if p.EndPort != nil {
		problems = append(problems, fmt.Sprintf("ingress[%d].ports[%d] uses forbidden endPort range (%d)", ruleIndex, portIndex, *p.EndPort))
	}
	if p.Port == nil {
		problems = append(problems, fmt.Sprintf("ingress[%d].ports[%d] has nil port (allows all ports)", ruleIndex, portIndex))
		return problems
	}

	var portKey string
	switch p.Port.Type {
	case intstr.Int:
		portNum := p.Port.IntVal
		portKey = fmt.Sprintf("%d", portNum)
		switch portNum {
		case contract.httpsPortNumber:
			problems = append(problems, fmt.Sprintf("ingress[%d].ports[%d] allows admin API port %d (%s)", ruleIndex, portIndex, contract.httpsPortNumber, contract.httpsPortName))
		case contract.healthPortNumber:
			problems = append(problems, fmt.Sprintf("ingress[%d].ports[%d] allows probe port %d (%s)", ruleIndex, portIndex, contract.healthPortNumber, contract.healthPortName))
		}
	case intstr.String:
		portName := p.Port.StrVal
		portKey = portName
		switch portName {
		case contract.httpsPortName:
			problems = append(problems, fmt.Sprintf("ingress[%d].ports[%d] allows admin API named port %q (%d)", ruleIndex, portIndex, contract.httpsPortName, contract.httpsPortNumber))
		case contract.healthPortName:
			problems = append(problems, fmt.Sprintf("ingress[%d].ports[%d] allows probe named port %q (%d)", ruleIndex, portIndex, contract.healthPortName, contract.healthPortNumber))
		}
	}

	if !contract.justifiedIngressPort[portKey] {
		problems = append(problems, fmt.Sprintf("ingress[%d].ports[%d] port %q is not permitted (no ingress rule is permitted; see docs/ADMIN_API.md)", ruleIndex, portIndex, portKey))
	}
	return problems
}

func validateNetworkPolicyNotEmbedded(installationFS, legacyFS fs.FS, assetsSource []byte) error {
	var problems []string

	for name, filesystem := range map[string]fs.FS{"Installation": installationFS, "LegacyInstallation": legacyFS} {
		err := fs.WalkDir(filesystem, ".", func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			lower := strings.ToLower(path)
			if strings.Contains(lower, "networkpolicy") || strings.Contains(lower, "arcadectl-api-ingress") {
				problems = append(problems, fmt.Sprintf("%s embeds forbidden networkpolicy path %q", name, path))
			}
			if entry.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yaml.tmpl")) {
				return nil
			}
			contents, err := fs.ReadFile(filesystem, path)
			if err != nil {
				return err
			}
			rendered := bytes.ReplaceAll(contents, []byte("@@CONTROLLER_IMAGE@@"), []byte(testControllerImage))
			rendered = bytes.ReplaceAll(rendered, []byte("@@API_IMAGE@@"), []byte(testAPIImage))
			decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
			for {
				obj := &unstructured.Unstructured{}
				if err := decoder.Decode(obj); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return err
				}
				if obj.GetKind() == "NetworkPolicy" {
					problems = append(problems, fmt.Sprintf("%s embeds NetworkPolicy object in %q", name, path))
				}
			}
			return nil
		})
		if err != nil {
			problems = append(problems, fmt.Sprintf("walk %s: %v", name, err))
		}
	}

	const wantInstallEmbed = "//go:embed install/*.yaml install/deployment.yaml.tmpl rbac/*.yaml api/*.yaml api/deployment.yaml.tmpl"
	const wantLegacyEmbed = "//go:embed legacy7dcbad/install/*.yaml legacy7dcbad/install/deployment.yaml.tmpl legacy7dcbad/rbac/*.yaml legacy7dcbad/api/*.yaml legacy7dcbad/api/deployment.yaml.tmpl"
	sourceText := string(assetsSource)
	if !strings.Contains(sourceText, wantInstallEmbed) || !strings.Contains(sourceText, wantLegacyEmbed) {
		problems = append(problems, "config/assets.go embed directives changed")
	}
	if strings.Contains(strings.ToLower(sourceText), "networkpolicy") {
		problems = append(problems, "config/assets.go references networkpolicy")
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func TestAPINetworkPolicyRestrictsAdminAPIIngress(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	contract := loadAPIEndpointContract(t)

	netpolDir := filepath.Join(root, "config", "networkpolicy")
	entries, err := os.ReadDir(netpolDir)
	if err != nil {
		t.Fatalf("read config/networkpolicy directory: %v", err)
	}
	var yamlFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			yamlFiles = append(yamlFiles, entry.Name())
		}
	}
	if !slices.Equal(yamlFiles, []string{"arcadectl-api-ingress.yaml"}) {
		t.Fatalf("config/networkpolicy YAML files = %v, want [arcadectl-api-ingress.yaml]", yamlFiles)
	}

	manifestPath := filepath.Join(netpolDir, "arcadectl-api-ingress.yaml")
	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read NetworkPolicy manifest: %v", err)
	}

	if err := validateAPINetworkPolicyManifest(rawManifest, contract); err != nil {
		t.Fatalf("valid NetworkPolicy manifest failed validation: %v", err)
	}

	assetsSource, err := os.ReadFile(filepath.Join(root, "config", "assets.go"))
	if err != nil {
		t.Fatalf("read config/assets.go: %v", err)
	}
	if err := validateNetworkPolicyNotEmbedded(config.Installation, config.LegacyInstallation, assetsSource); err != nil {
		t.Fatalf("NetworkPolicy must not be embedded in installer assets: %v", err)
	}

	for _, obj := range decodeObjects(t, renderAPI(t, testAPIImage)) {
		if obj.GetKind() == "NetworkPolicy" {
			t.Fatalf("render-api.sh unexpectedly emitted NetworkPolicy %s/%s", obj.GetNamespace(), obj.GetName())
		}
	}
}

func TestAPINetworkPolicyAdversarialMutationsFailClosed(t *testing.T) {
	t.Parallel()

	root := repositoryRoot(t)
	contract := loadAPIEndpointContract(t)
	rawManifest, err := os.ReadFile(filepath.Join(root, "config", "networkpolicy", "arcadectl-api-ingress.yaml"))
	if err != nil {
		t.Fatalf("read NetworkPolicy manifest: %v", err)
	}

	replaceMustChange := func(t *testing.T, input []byte, old, replacement string) []byte {
		t.Helper()
		mutated := bytes.Replace(input, []byte(old), []byte(replacement), 1)
		if bytes.Equal(mutated, input) {
			t.Fatalf("mutation target %q not found in manifest", old)
		}
		return mutated
	}

	cases := []struct {
		name    string
		mutate  func(t *testing.T, base []byte) []byte
		wantErr string
	}{
		{
			name: "wrong kind",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "kind: NetworkPolicy", "kind: ConfigMap")
			},
			wantErr: "kind = \"ConfigMap\", want NetworkPolicy",
		},
		{
			name: "wrong apiVersion",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "apiVersion: networking.k8s.io/v1", "apiVersion: v1")
			},
			wantErr: "apiVersion = \"v1\", want \"networking.k8s.io/v1\"",
		},
		{
			name: "wrong namespace",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "namespace: arcadectl-system", "namespace: default")
			},
			wantErr: "namespace = \"default\", want \"arcadectl-system\"",
		},
		{
			name: "empty podSelector selects all pods",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  podSelector:\n    matchLabels:\n      app.kubernetes.io/name: arcadectl-api", "  podSelector: {}")
			},
			wantErr: "podSelector.matchLabels is empty",
		},
		{
			name: "wrong podSelector label value",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "      app.kubernetes.io/name: arcadectl-api", "      app.kubernetes.io/name: arcadectl-controller")
			},
			wantErr: "does not exactly match API Deployment selector",
		},
		{
			name: "podSelector selects broad part-of label only",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "      app.kubernetes.io/name: arcadectl-api", "      app.kubernetes.io/part-of: arcadectl")
			},
			wantErr: "does not exactly match API Deployment selector",
		},
		{
			name: "podSelector adds extra label not in service selector",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "      app.kubernetes.io/name: arcadectl-api", "      app.kubernetes.io/name: arcadectl-api\n      app.kubernetes.io/part-of: arcadectl")
			},
			wantErr: "does not exactly match API Service selector",
		},
		{
			name: "podSelector adds matchExpressions",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "      app.kubernetes.io/name: arcadectl-api", "      app.kubernetes.io/name: arcadectl-api\n    matchExpressions:\n      - key: app.kubernetes.io/name\n        operator: Exists")
			},
			wantErr: "podSelector.matchExpressions must be empty",
		},
		{
			name: "policyTypes adds Egress ([Ingress, Egress])",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  policyTypes:\n    - Ingress", "  policyTypes:\n    - Ingress\n    - Egress")
			},
			wantErr: "policyTypes must be exactly [Ingress], got [Ingress Egress]",
		},
		{
			name: "policyTypes is [Egress]",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  policyTypes:\n    - Ingress", "  policyTypes:\n    - Egress")
			},
			wantErr: "policyTypes must be exactly [Ingress], got [Egress]",
		},
		{
			name: "policyTypes is empty []",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  policyTypes:\n    - Ingress", "  policyTypes: []")
			},
			wantErr: "policyTypes must be exactly [Ingress], got []",
		},
		{
			name: "policyTypes has duplicate [Ingress, Ingress]",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  policyTypes:\n    - Ingress", "  policyTypes:\n    - Ingress\n    - Ingress")
			},
			wantErr: "policyTypes must be exactly [Ingress], got [Ingress Ingress]",
		},
		{
			name: "missing policyTypes",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  policyTypes:\n    - Ingress\n", "")
			},
			wantErr: "policyTypes must be exactly [Ingress], got []",
		},
		{
			name: "omitted ingress field",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []\n", "")
			},
			wantErr: "spec.ingress must be explicitly present as []",
		},
		{
			name: "allow-all ingress rule - {}",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - {}")
			},
			wantErr: "no ingress rule is permitted",
		},
		{
			name: "rule allows 8443 with empty from",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - ports:\n        - protocol: TCP\n          port: 8443")
			},
			wantErr: "has empty from (allows ingress from everywhere)",
		},
		{
			name: "rule allows named https port with empty from",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from: []\n      ports:\n        - protocol: TCP\n          port: https")
			},
			wantErr: "allows admin API named port \"https\" (8443)",
		},
		{
			name: "rule allows 8443 from 0.0.0.0/0 ipBlock",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - ipBlock:\n            cidr: 0.0.0.0/0\n      ports:\n        - protocol: TCP\n          port: 8443")
			},
			wantErr: "allows everywhere via wildcard ipBlock \"0.0.0.0/0\"",
		},
		{
			name: "rule allows 8443 from ::/0 ipBlock",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - ipBlock:\n            cidr: ::/0\n      ports:\n        - protocol: TCP\n          port: 8443")
			},
			wantErr: "allows everywhere via wildcard ipBlock \"::/0\"",
		},
		{
			name: "rule allows 8443 from empty namespaceSelector and empty podSelector",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - namespaceSelector: {}\n          podSelector: {}\n      ports:\n        - protocol: TCP\n          port: 8443")
			},
			wantErr: "uses empty namespaceSelector {} with empty podSelector {}",
		},
		{
			name: "rule allows 8443 from empty namespaceSelector alone",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - namespaceSelector: {}\n      ports:\n        - protocol: TCP\n          port: 8443")
			},
			wantErr: "uses empty namespaceSelector {} without podSelector",
		},
		{
			name: "rule allows 8443 from empty podSelector alone",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - podSelector: {}\n      ports:\n        - protocol: TCP\n          port: 8443")
			},
			wantErr: "uses empty podSelector {} without namespaceSelector",
		},
		{
			name: "rule omits explicit ports",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: arcadectl-system\n          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: arcadectl-controller")
			},
			wantErr: "omits explicit ports",
		},
		{
			name: "rule has port entry without port number or name",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: arcadectl-system\n          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: arcadectl-controller\n      ports:\n        - protocol: TCP")
			},
			wantErr: "has nil port (allows all ports)",
		},
		{
			name: "rule uses endPort range",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: arcadectl-system\n          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: arcadectl-controller\n      ports:\n        - protocol: TCP\n          port: 8081\n          endPort: 8443")
			},
			wantErr: "uses forbidden endPort range",
		},
		{
			name: "rule allows unjustified 8443 from specific peer",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: arcadectl-system\n          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: arcadectl-controller\n      ports:\n        - protocol: TCP\n          port: 8443")
			},
			wantErr: "allows admin API port 8443 (https)",
		},
		{
			name: "rule allows unjustified 8081 health port from pod network",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: kube-system\n          podSelector:\n            matchLabels:\n              component: kubelet\n      ports:\n        - protocol: TCP\n          port: 8081")
			},
			wantErr: "allows probe port 8081 (health)",
		},
		{
			name: "rule allows arbitrary unjustified port",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress:\n    - from:\n        - namespaceSelector:\n            matchLabels:\n              kubernetes.io/metadata.name: arcadectl-system\n          podSelector:\n            matchLabels:\n              app.kubernetes.io/name: arcadectl-controller\n      ports:\n        - protocol: TCP\n          port: 9090")
			},
			wantErr: "port \"9090\" is not permitted",
		},
		{
			name: "unknown YAML field rejected by strict decoder",
			mutate: func(t *testing.T, base []byte) []byte {
				return replaceMustChange(t, base, "  ingress: []", "  ingress: []\n  unrecognizedField: true")
			},
			wantErr: "strict YAML unmarshal failed",
		},
		{
			name: "multiple YAML documents rejected",
			mutate: func(t *testing.T, base []byte) []byte {
				return append(slices.Clone(base), []byte("\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\n")...)
			},
			wantErr: "expected exactly 1 YAML document, got 2",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mutated := tc.mutate(t, rawManifest)
			err := validateAPINetworkPolicyManifest(mutated, contract)
			if err == nil {
				t.Fatalf("mutation %q unexpectedly passed validation", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("mutation %q failed with %q, want substring %q", tc.name, err.Error(), tc.wantErr)
			}
			t.Logf("rejected broken manifest (%s): %v", tc.name, err)
		})
	}

	t.Run("embedded networkpolicy in installer FS is rejected", func(t *testing.T) {
		t.Parallel()
		assetsSource, err := os.ReadFile(filepath.Join(root, "config", "assets.go"))
		if err != nil {
			t.Fatalf("read config/assets.go: %v", err)
		}
		brokenFS := fstest.MapFS{
			"networkpolicy/arcadectl-api-ingress.yaml": &fstest.MapFile{Data: rawManifest},
		}
		err = validateNetworkPolicyNotEmbedded(brokenFS, config.LegacyInstallation, assetsSource)
		if err == nil || !strings.Contains(err.Error(), "embeds forbidden networkpolicy path") {
			t.Fatalf("expected embedded networkpolicy path failure, got: %v", err)
		}
		t.Logf("rejected embedded networkpolicy in FS: %v", err)

		mutatedAssets := replaceMustChange(t, assetsSource, "api/deployment.yaml.tmpl", "api/deployment.yaml.tmpl networkpolicy/*.yaml")
		err = validateNetworkPolicyNotEmbedded(config.Installation, config.LegacyInstallation, mutatedAssets)
		if err == nil || !strings.Contains(err.Error(), "config/assets.go") {
			t.Fatalf("expected assets.go embed list mutation failure, got: %v", err)
		}
		t.Logf("rejected mutated config/assets.go embed directive: %v", err)
	})
}

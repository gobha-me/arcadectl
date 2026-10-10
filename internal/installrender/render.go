// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installrender binds authenticated packages to reviewed resource
// semantics. Compatibility profiles are declarations, not runtime evidence.
package installrender

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"slices"
	"strings"

	"github.com/gobha-me/arcadectl/config"
	"github.com/gobha-me/arcadectl/internal/installpackage"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

const (
	DefaultNamespace = "arcadectl-system"
	LegacySourceSHA  = "7dcbad6497782c198c7b142a6a8b902dead4b79e"
	Profile135       = "kubernetes-1.35.8"
	Profile137       = "kubernetes-1.37.0"
	// Freeze the entire embedded config surface at LegacySourceSHA. A future
	// template/schema edit must not silently manufacture a package claiming the
	// predecessor source: preserve its assets separately or reject that renderer.
	legacyAssetsSHA256 = "092b6c22e136be7fde6029e45498145246962a8c555bb85bf512b04e273dbe3b"
)

var ErrInvalid = errors.New("installation package does not match the trusted renderer contract")

// SupportedProfiles returns fresh declarations. Actual certification must be
// checked separately by the installer/release workflow.
func SupportedProfiles(legacy bool) []installpackage.Profile {
	profiles := []installpackage.Profile{{ID: Profile137, KubernetesVersion: "1.37.0", PodSecurityVersion: "v1.37"}}
	if !legacy {
		profiles = append(profiles, installpackage.Profile{ID: Profile135, KubernetesVersion: "1.35.8", PodSecurityVersion: "v1.35"})
	}
	slices.SortFunc(profiles, func(a, b installpackage.Profile) int { return strings.Compare(a.ID, b.ID) })
	return profiles
}

// RequiredPrerequisites declares the complete lifecycle's external contracts.
// These are not evidence of their availability. TLS/admission/Pod security must
// be checked before admission starts; storage/network/repository readiness is
// also checked when the corresponding game/data operation is requested. The
// installer does not provision a storage driver, LoadBalancer or S3 repository.
func RequiredPrerequisites() []string {
	return []string{"api-tls", "csi-persistent-storage", "digest-registry-access", "game-loadbalancer-networking", "restic-s3-repository", "restricted-pods", "validating-admission-policies"}
}

var controllerFiles = []string{
	"install/service-account.yaml", "rbac/role.yaml", "install/role-binding.yaml",
	"install/volumeattachment-cluster-role.yaml", "install/volumeattachment-cluster-role-binding.yaml",
	"install/destroy-service-account.yaml", "rbac/destroy-role.yaml", "install/destroy-role-binding.yaml",
	"install/destroy-volumeattachment-cluster-role.yaml", "install/destroy-volumeattachment-cluster-role-binding.yaml",
	"install/backup-worker-admission-policy.yaml", "install/backup-worker-admission-policy-binding.yaml",
	"install/restore-worker-admission-policy.yaml", "install/restore-worker-admission-policy-binding.yaml",
	"install/restore-candidate-pvc-admission-policy.yaml", "install/restore-candidate-pvc-admission-policy-binding.yaml",
	"install/destroy-worker-admission-policy.yaml", "install/destroy-worker-admission-policy-binding.yaml",
	"install/destroy-pvc-admission-policy.yaml", "install/destroy-pvc-admission-policy-binding.yaml",
	"install/destroy-unsafe-admission-policy.yaml", "install/destroy-unsafe-admission-policy-binding.yaml",
	"install/deployment.yaml.tmpl",
}

// RenderPayloads renders reviewed inputs as deterministic JSON documents with
// YAML separators. CRD schema hashes cover encoding/json of each typed version
// schema (all schemas for this contract comprise the sole v1alpha1 version).
func RenderPayloads(images installpackage.Images, legacy bool) (map[string][]byte, []installpackage.CRD, error) {
	if len(images.Controller) > 512 || len(images.API) > 512 {
		return nil, nil, ErrInvalid
	}
	if legacy && !legacyAssetsMatch() {
		return nil, nil, ErrInvalid
	}
	var assets fs.FS = config.Installation
	if legacy {
		var err error
		assets, err = fs.Sub(config.LegacyInstallation, "legacy7dcbad")
		if err != nil {
			return nil, nil, ErrInvalid
		}
	}
	// The package parser owns the strict image grammar. Validate through a small
	// complete metadata envelope rather than duplicating a weaker image regex.
	anchors, err := readObjects(assets, []string{"install/anchors.yaml"}, images)
	if err != nil || len(anchors) != 6 {
		return nil, nil, ErrInvalid
	}
	crds, err := declarations(anchors)
	if err != nil {
		return nil, nil, err
	}
	controllers, err := readObjects(assets, controllerFiles, images)
	if err != nil || len(controllers) != 27 {
		return nil, nil, ErrInvalid
	}
	api, err := readObjects(assets, []string{"api/service-account.yaml", "api/role.yaml", "api/service.yaml", "api/deployment.yaml.tmpl"}, images)
	if err != nil || len(api) != 5 {
		return nil, nil, ErrInvalid
	}
	if !legacy {
		deployment := api[len(api)-1]
		containers, found, err := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
		if err != nil || !found || len(containers) != 1 {
			return nil, nil, ErrInvalid
		}
		container, ok := containers[0].(map[string]any)
		if !ok {
			return nil, nil, ErrInvalid
		}
		container["args"] = []any{"--namespace=$(POD_NAMESPACE)"}
		env, ok := container["env"].([]any)
		if !ok {
			return nil, nil, ErrInvalid
		}
		container["env"] = append(env, map[string]any{"name": "POD_NAMESPACE", "valueFrom": map[string]any{"fieldRef": map[string]any{"fieldPath": "metadata.namespace"}}})
		if unstructured.SetNestedSlice(deployment.Object, containers, "spec", "template", "spec", "containers") != nil {
			return nil, nil, ErrInvalid
		}
	}
	payloads := map[string][]byte{}
	for path, objects := range map[string][]*unstructured.Unstructured{installpackage.AnchorsPath: anchors, installpackage.ControllerPath: controllers, installpackage.APIPath: api} {
		body, err := encodeObjects(objects)
		if err != nil {
			return nil, nil, err
		}
		payloads[path] = body
	}
	metadata := installpackage.Manifest{FormatVersion: installpackage.FormatVersion, RendererVersion: installpackage.RendererVersion, PackageVersion: "0.0.0", SourceSHA: strings.Repeat("1", 40), SourceEpoch: 1, Images: images, Profiles: SupportedProfiles(legacy), Prerequisites: RequiredPrerequisites(), CRDs: crds}
	if _, err := installpackage.Build(metadata, payloads); err != nil {
		return nil, nil, ErrInvalid
	}
	return payloads, crds, nil
}

func legacyAssetsMatch() bool {
	assets, err := fs.Sub(config.LegacyInstallation, "legacy7dcbad")
	return err == nil && legacyAssetTreeMatches(assets)
}

func legacyAssetTreeMatches(assets fs.FS) bool {
	var paths []string
	err := fs.WalkDir(assets, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return false
	}
	slices.Sort(paths)
	hash := sha256.New()
	for _, path := range paths {
		body, err := fs.ReadFile(assets, path)
		if err != nil {
			return false
		}
		sum := sha256.Sum256(body)
		_, _ = fmt.Fprintf(hash, "%x  config/%s\n", sum, path)
	}
	return hex.EncodeToString(hash.Sum(nil)) == legacyAssetsSHA256
}

func readObjects(assets fs.FS, files []string, images installpackage.Images) ([]*unstructured.Unstructured, error) {
	var objects []*unstructured.Unstructured
	for _, path := range files {
		body, err := fs.ReadFile(assets, path)
		if err != nil {
			return nil, ErrInvalid
		}
		if strings.HasSuffix(path, "deployment.yaml.tmpl") {
			marker, value, count := "@@CONTROLLER_IMAGE@@", images.Controller, 4
			if strings.HasPrefix(path, "api/") {
				marker, value, count = "@@API_IMAGE@@", images.API, 1
			}
			if bytes.Count(body, []byte(marker)) != count {
				return nil, ErrInvalid
			}
			// JSON/YAML metacharacters must never reach template substitution.
			if strings.ContainsAny(value, "\r\n\t '\"{}[]#&*!|>,%`\\") {
				return nil, ErrInvalid
			}
			body = bytes.ReplaceAll(body, []byte(marker), []byte(value))
		}
		reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(body)))
		for {
			doc, err := reader.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, ErrInvalid
			}
			if len(bytes.TrimSpace(doc)) == 0 {
				continue
			}
			encoded, err := yaml.YAMLToJSONStrict(doc)
			if err != nil {
				return nil, ErrInvalid
			}
			object := &unstructured.Unstructured{}
			if object.UnmarshalJSON(encoded) != nil || object.Object == nil {
				return nil, ErrInvalid
			}
			objects = append(objects, object)
		}
	}
	return objects, nil
}

func encodeObjects(objects []*unstructured.Unstructured) ([]byte, error) {
	var result bytes.Buffer
	for _, object := range objects {
		body, err := json.Marshal(object.Object)
		if err != nil {
			return nil, ErrInvalid
		}
		result.WriteString("---\n")
		result.Write(body)
		result.WriteByte('\n')
	}
	return result.Bytes(), nil
}

func declarations(anchors []*unstructured.Unstructured) ([]installpackage.CRD, error) {
	var result []installpackage.CRD
	for _, object := range anchors {
		if object.GetKind() != "CustomResourceDefinition" {
			continue
		}
		body, err := json.Marshal(object.Object)
		if err != nil {
			return nil, ErrInvalid
		}
		var crd apiextensions.CustomResourceDefinition
		if json.Unmarshal(body, &crd) != nil || len(crd.Spec.Versions) != 1 {
			return nil, ErrInvalid
		}
		version := crd.Spec.Versions[0]
		if version.Name != "v1alpha1" || !version.Storage || !version.Served || version.Schema == nil || crd.Spec.Conversion != nil && crd.Spec.Conversion.Strategy != apiextensions.NoneConverter {
			return nil, ErrInvalid
		}
		schema, err := json.Marshal(version.Schema)
		if err != nil {
			return nil, ErrInvalid
		}
		sum := sha256.Sum256(schema)
		result = append(result, installpackage.CRD{Name: crd.Name, SchemaSHA256: hex.EncodeToString(sum[:]), StorageVersion: version.Name, ServedVersions: []string{version.Name}, ConversionStrategy: "None"})
	}
	slices.SortFunc(result, func(a, b installpackage.CRD) int { return strings.Compare(a.Name, b.Name) })
	names := installpackage.CanonicalCRDNames()
	if len(result) != len(names) {
		return nil, ErrInvalid
	}
	for i, name := range names {
		if result[i].Name != name {
			return nil, ErrInvalid
		}
	}
	return result, nil
}

// Phase enables the engine to install retained anchors/policies before admitting
// runtime authority. Resource ordering within each phase is deterministic.
type Phase string

const (
	Anchors     Phase = "anchors"
	Policies    Phase = "policies"
	Controllers Phase = "controllers"
	API         Phase = "api"
)

type Resource struct {
	Object   *unstructured.Unstructured
	Retained bool
	Phase    Phase
}
type Plan struct {
	resources []Resource
	namespace string
	profile   installpackage.Profile
	manifest  installpackage.Manifest
	digest    string
}

func (p *Plan) IsTrusted() bool { return p != nil && p.digest != "" && len(p.resources) == 38 }
func (p *Plan) Resources() []Resource {
	if p == nil {
		return nil
	}
	result := make([]Resource, len(p.resources))
	for i, r := range p.resources {
		result[i] = Resource{Object: r.Object.DeepCopy(), Retained: r.Retained, Phase: r.Phase}
	}
	return result
}
func (p *Plan) Namespace() string {
	if p == nil {
		return ""
	}
	return p.namespace
}
func (p *Plan) Profile() installpackage.Profile {
	if p == nil {
		return installpackage.Profile{}
	}
	return p.profile
}
func (p *Plan) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}
func (p *Plan) Manifest() installpackage.Manifest {
	if p == nil {
		return installpackage.Manifest{}
	}
	body, _ := json.Marshal(p.manifest)
	var result installpackage.Manifest
	_ = json.Unmarshal(body, &result)
	return result
}

// Compile checks sealed verification through defensive accessors and permits
// only byte-exact canonical payloads rendered by this binary. It does not repeat
// signature verification or certify declared source/image provenance.
func Compile(pkg *installpackage.VerifiedPackage, namespace, profileID string) (*Plan, error) {
	if !pkg.IsVerified() {
		return nil, installpackage.ErrUnverified
	}
	if !ValidNamespace(namespace) {
		return nil, ErrInvalid
	}
	metadata, err := pkg.Manifest()
	if err != nil {
		return nil, ErrInvalid
	}
	if !slices.Equal(metadata.Prerequisites, RequiredPrerequisites()) {
		return nil, ErrInvalid
	}
	legacy := metadata.SourceSHA == LegacySourceSHA
	if legacy && namespace != DefaultNamespace || !reflect.DeepEqual(metadata.Profiles, SupportedProfiles(legacy)) {
		return nil, ErrInvalid
	}
	var profile installpackage.Profile
	for _, candidate := range metadata.Profiles {
		if candidate.ID == profileID {
			profile = candidate
		}
	}
	if profile.ID == "" {
		return nil, ErrInvalid
	}
	for _, previous := range metadata.Predecessors {
		if legacy || previous.SourceSHA != LegacySourceSHA || previous.Namespace != DefaultNamespace || !slices.Equal(previous.ProfileIDs, []string{Profile137}) {
			return nil, ErrInvalid
		}
	}
	payloads, crds, err := RenderPayloads(metadata.Images, legacy)
	if err != nil || !reflect.DeepEqual(metadata.CRDs, crds) {
		return nil, ErrInvalid
	}
	plan := &Plan{namespace: namespace, profile: profile, manifest: metadata}
	plan.digest, err = pkg.Digest()
	if err != nil {
		return nil, ErrInvalid
	}
	for _, path := range []string{installpackage.AnchorsPath, installpackage.ControllerPath, installpackage.APIPath} {
		actual, err := pkg.Payload(path)
		if err != nil || !bytes.Equal(actual, payloads[path]) {
			return nil, ErrInvalid
		}
	}
	for _, phase := range []Phase{Anchors, Controllers, API} {
		// Decode the already accepted deterministic package bytes, preserving its
		// current/legacy API template rather than rerendering the raw API inputs.
		path := installpackage.AnchorsPath
		if phase == Controllers {
			path = installpackage.ControllerPath
		}
		if phase == API {
			path = installpackage.APIPath
		}
		objects, err := decodeRendered(payloads[path])
		if err != nil {
			return nil, ErrInvalid
		}
		for _, object := range objects {
			resourcePhase := phase
			retained := phase == Anchors
			if object.GetKind() == "ValidatingAdmissionPolicy" || object.GetKind() == "ValidatingAdmissionPolicyBinding" {
				resourcePhase = Policies
				retained = true
			}
			plan.resources = append(plan.resources, Resource{Object: object, Retained: retained, Phase: resourcePhase})
		}
	}
	if err := parameterize(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func decodeRendered(body []byte) ([]*unstructured.Unstructured, error) {
	var result []*unstructured.Unstructured
	for _, document := range bytes.Split(body, []byte("---\n")) {
		if len(bytes.TrimSpace(document)) == 0 {
			continue
		}
		object := &unstructured.Unstructured{}
		if object.UnmarshalJSON(document) != nil || object.Object == nil {
			return nil, ErrInvalid
		}
		result = append(result, object)
	}
	return result, nil
}

func ValidNamespace(value string) bool {
	return len(validation.IsDNS1123Label(value)) == 0 && value != "default" && value != "kube-system" && value != "kube-public" && value != "kube-node-lease" && !strings.HasPrefix(value, "kube-")
}

func parameterize(plan *Plan) error {
	names := map[string]string{}
	if plan.namespace != DefaultNamespace {
		sum := sha256.Sum256([]byte(plan.namespace))
		suffix := "-" + hex.EncodeToString(sum[:6])
		for _, r := range plan.resources {
			kind := r.Object.GetKind()
			if kind == "ClusterRole" || kind == "ClusterRoleBinding" || kind == "ValidatingAdmissionPolicy" || kind == "ValidatingAdmissionPolicyBinding" {
				base := r.Object.GetName()
				if len(base) > 63-len(suffix) {
					base = base[:63-len(suffix)]
				}
				names[r.Object.GetName()] = base + suffix
			}
		}
	}
	for _, resource := range plan.resources {
		object := resource.Object
		if renamed, ok := names[object.GetName()]; ok && object.GetNamespace() == "" {
			object.SetName(renamed)
		}
		if object.GetNamespace() == DefaultNamespace {
			object.SetNamespace(plan.namespace)
		}
		switch object.GetKind() {
		case "Namespace":
			object.SetName(plan.namespace)
			labels := object.GetLabels()
			for _, mode := range []string{"enforce", "audit", "warn"} {
				labels["pod-security.kubernetes.io/"+mode+"-version"] = plan.profile.PodSecurityVersion
			}
			object.SetLabels(labels)
		case "RoleBinding", "ClusterRoleBinding":
			subjects, found, err := unstructured.NestedSlice(object.Object, "subjects")
			if err != nil || !found {
				return ErrInvalid
			}
			for _, item := range subjects {
				subject, ok := item.(map[string]any)
				if !ok {
					return ErrInvalid
				}
				if subject["kind"] == "ServiceAccount" && subject["namespace"] == DefaultNamespace {
					subject["namespace"] = plan.namespace
				}
			}
			if unstructured.SetNestedSlice(object.Object, subjects, "subjects") != nil {
				return ErrInvalid
			}
			ref, found, err := unstructured.NestedMap(object.Object, "roleRef")
			if err != nil || !found {
				return ErrInvalid
			}
			if ref["kind"] == "ClusterRole" {
				name, ok := ref["name"].(string)
				if !ok {
					return ErrInvalid
				}
				if renamed, ok := names[name]; ok {
					ref["name"] = renamed
				}
			}
			if unstructured.SetNestedMap(object.Object, ref, "roleRef") != nil {
				return ErrInvalid
			}
		case "ValidatingAdmissionPolicy":
			for _, section := range []struct{ name, key string }{{"variables", "expression"}, {"validations", "expression"}, {"auditAnnotations", "valueExpression"}} {
				items, found, err := unstructured.NestedSlice(object.Object, "spec", section.name)
				if err != nil {
					return ErrInvalid
				}
				if !found {
					continue
				}
				for _, item := range items {
					entry, ok := item.(map[string]any)
					if !ok {
						return ErrInvalid
					}
					expression, ok := entry[section.key].(string)
					if !ok {
						return ErrInvalid
					}
					entry[section.key] = strings.ReplaceAll(expression, "system:serviceaccount:"+DefaultNamespace+":", "system:serviceaccount:"+plan.namespace+":")
				}
				if unstructured.SetNestedSlice(object.Object, items, "spec", section.name) != nil {
					return ErrInvalid
				}
			}
		case "ValidatingAdmissionPolicyBinding":
			name, found, err := unstructured.NestedString(object.Object, "spec", "policyName")
			if err != nil || !found {
				return ErrInvalid
			}
			if renamed, ok := names[name]; ok {
				if unstructured.SetNestedField(object.Object, renamed, "spec", "policyName") != nil {
					return ErrInvalid
				}
			}
			if unstructured.SetNestedField(object.Object, plan.namespace, "spec", "matchResources", "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}

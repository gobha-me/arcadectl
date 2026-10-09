// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installbaseline

import (
	"bytes"
	"slices"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Resource is a public, defensive copy of a closed baseline template. The hash
// binds the complete namespace-parameterized template, not the signed payload's
// default-namespace bytes. Cluster identity and ownership are separate proofs.
type Resource struct {
	Object         *unstructured.Unstructured
	TemplateSHA256 string
}

// Plan is sealed by semantic compilation after external-key authentication.
// Baseline resources never belong to the rollbackable runtime-package inventory.
type Plan struct {
	trusted   bool
	namespace string
	profile   string
	digest    string
	manifest  []byte
	resources []Resource
}

// Compile permits only this binary's byte-exact reviewed baseline. A valid
// signature over arbitrary or weakened policy bytes does not authorize them.
func Compile(verified *Verified, namespace, profile string) (*Plan, error) {
	if !verified.IsVerified() {
		return nil, ErrUnverified
	}
	metadata, err := verified.Manifest()
	if err != nil || !slices.Contains(metadata.Profiles, profile) {
		return nil, ErrInvalid
	}
	reviewed, err := reviewedPayload()
	if err != nil || !bytes.Equal(verified.payload, reviewed) {
		return nil, ErrInvalid
	}
	objects, err := Render(namespace)
	if err != nil || len(objects) != ResourceCount {
		return nil, ErrInvalid
	}
	manifestDigest, err := verified.Digest()
	if err != nil {
		return nil, ErrUnverified
	}
	plan := &Plan{trusted: true, namespace: namespace, profile: profile, digest: manifestDigest, manifest: bytes.Clone(verified.manifest)}
	for _, object := range objects {
		body, err := canonicalEncode(object)
		if err != nil {
			return nil, ErrInvalid
		}
		plan.resources = append(plan.resources, Resource{object.DeepCopy(), digest(body)})
	}
	return plan, nil
}

func (p *Plan) IsTrusted() bool {
	return p != nil && p.trusted && p.digest != "" && len(p.resources) == ResourceCount
}

func (p *Plan) Namespace() string {
	if !p.IsTrusted() {
		return ""
	}
	return p.namespace
}

func (p *Plan) Profile() string {
	if !p.IsTrusted() {
		return ""
	}
	return p.profile
}

// Digest binds the original signed artifact, independent of chosen namespace.
func (p *Plan) Digest() string {
	if !p.IsTrusted() {
		return ""
	}
	return p.digest
}

func (p *Plan) Manifest() (Manifest, error) {
	if !p.IsTrusted() {
		return Manifest{}, ErrUnverified
	}
	return ParseManifest(p.manifest)
}

func (p *Plan) Resources() []Resource {
	if !p.IsTrusted() {
		return nil
	}
	result := make([]Resource, len(p.resources))
	for index, resource := range p.resources {
		result[index] = Resource{resource.Object.DeepCopy(), resource.TemplateSHA256}
	}
	return result
}

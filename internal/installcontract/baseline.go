// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

// NewBaseline creates a separate sealed matching contract, not additional
// runtime-package inventory. V1 security templates support creation/readback,
// never runtime update/rollback/delete. Ownership and admission health/behavior
// must still be independently established by the baseline engine.
func NewBaseline(plan *installbaseline.Plan) (*Contract, error) {
	if !plan.IsTrusted() {
		return nil, ErrInvalid
	}
	contract := &Contract{baseline: plan, resources: map[installstate.Key]installrender.Resource{}, templates: map[templateKey]*Template{}}
	for _, resource := range plan.Resources() {
		object := resource.Object
		key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Namespace: object.GetNamespace(), Name: object.GetName()}
		if contract.resources[key].Object != nil {
			return nil, ErrInvalid
		}
		contract.resources[key] = installrender.Resource{Object: object.DeepCopy(), Retained: true, Phase: installrender.Policies}
		template, err := contract.compileTemplate(key, false)
		if err != nil {
			return nil, ErrInvalid
		}
		body, err := json.Marshal(template.resource.Object.Object)
		if err != nil {
			return nil, ErrInvalid
		}
		canonical, err := canonicaljson.CanonicalJSON(body)
		if err != nil {
			return nil, ErrInvalid
		}
		sum := sha256.Sum256(canonical)
		if hex.EncodeToString(sum[:]) != resource.TemplateSHA256 {
			return nil, ErrInvalid
		}
		// Baseline hashes bind canonical namespace-parameterized templates.
		// Historical runtime hashes continue using their unchanged raw format.
		template.hash = resource.TemplateSHA256
		contract.templates[templateKey{key, false}] = template
	}
	if len(contract.templates) != installbaseline.ResourceCount {
		return nil, ErrInvalid
	}
	return contract, nil
}

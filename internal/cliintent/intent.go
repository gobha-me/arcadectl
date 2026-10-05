// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package cliintent contains exact, non-secret prepared HTTP intents.
package cliintent

import (
	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
)

type Intent struct {
	Action            string                  `json:"action"`
	Method            string                  `json:"method"`
	Path              string                  `json:"path"`
	Body              []byte                  `json:"body"`
	Conditional       adminclient.Conditional `json:"conditional"`
	ParentOperationID string                  `json:"parentOperationId,omitempty"`
	DestroyPreview    *adminv1.DestroyPreview `json:"destroyPreview,omitempty"`
	DestroyRef        *adminv1.ExactReference `json:"destroyRef,omitempty"`
}

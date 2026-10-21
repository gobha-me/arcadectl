// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"github.com/gobha-me/arcadectl/internal/installcontract"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

// Only independent named GETs inside one frozen public catalog overlap. This
// private bound is not caller configurable. Complete passes, original fences,
// authorization, behavioral probes and effects keep their existing order.
const admissionReadLanes = 8

// Freeze the recorded mixed active/target template, never a prospective target
// replacement or caller-supplied object. Each worker owns its result slot.
type admissionOriginalRead struct {
	resource  installstate.Resource
	template  *installcontract.Template
	targetCRD *installcontract.Template
}

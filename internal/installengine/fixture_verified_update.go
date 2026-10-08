// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"reflect"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Whole-return contract for the named VerifiedBackup no-op UPDATE, not an
// effect, current phase, actor permission or behavior-completion capability.
// The finite driver must supply the freshly whole-validated original from a
// complete phase, use that exact RV in one administrator dry-run UPDATE, and
// independently reprove every original/phase afterwards. CREATE responses or
// matching-name observations cannot supply original ownership.
//
// No bookkeeping delta is guessed: a no-op must preserve every raw field,
// including manager order/timestamps and warm cancellation status. Native
// certification on both profiles is still required before producer activation.
func (f *fixtureLedger) validateVerifiedCancelledUnchangedUpdate(before, after *unstructured.Unstructured, phase *fixturePhaseBaseline, observed time.Time) error {
	if f == nil || f.document.Recipe != fixtureRecipeV2 || before == nil || after == nil || phase == nil || f.validatePhaseFixture(fixtureVerifiedCancelledDestroy, before, phase, observed) != nil {
		return ErrFixtures
	}
	var typed arcadev1.GameDestroy
	if decodeServing(after, &typed) != nil || !reflect.DeepEqual(before.Object, after.Object) {
		return ErrFixtures
	}
	return nil
}

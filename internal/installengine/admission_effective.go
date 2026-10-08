// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

// VerifyEffective is the complete closed production path, never an alias for
// configuration or the six CREATE pairs. It must finish a NEW full behavior
// matrix, drain every original by exact UID/RV, prove actual complete absence,
// and retire the protected run before ordinary lifecycle effects may resume.
func (a *ClusterAdmission) VerifyEffective(ctx context.Context, request LifecycleCheck) error {
	if a == nil || a.prerequisites == nil || ctx == nil || request.Checkpoint != AdmissionEffective || request.Snapshot == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	driver, err := a.newAdmissionDriver(ctx, request)
	if err != nil {
		return err
	}
	return driver.complete(ctx)
}

func (driver *fixtureAdmissionDriver) complete(ctx context.Context) error {
	if driver == nil || driver.wire == nil || driver.wire.ledger == nil || ctx == nil {
		return ErrFixtures
	}
	f := driver.wire.ledger
	defer f.close()
	if driver.run(ctx) != nil {
		return ErrFixtures // incomplete/uncertain originals remain durably fenced
	}
	for slot := len(f.document.Entries) - 1; slot >= 0; slot-- {
		err := driver.wire.removeAcknowledgedMarkerOriginal(ctx, slot)
		if err != nil {
			if f.document.Entries[slot].State != fixtureDeleteAttempted {
				return ErrFixtures
			}
			// Original DELETE was already attempted. This route can now ONLY
			// observe its disappearance, never replay it—even after lost ACK.
			if wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 90*time.Second, true, func(ctx context.Context) (bool, error) {
				return driver.wire.removeAcknowledgedMarkerOriginal(ctx, slot) == nil, nil
			}) != nil {
				return ErrFixtures
			}
		}
	}
	if driver.wire.retireDrained(ctx) != nil {
		return ErrFixtures
	}
	a, request := driver.wire.actors.admission, driver.wire.actors.request
	if _, err := a.configured(ctx, request); err != nil || a.prerequisites.original(ctx, request.Snapshot) != nil || a.prerequisites.engine.fixtureFence(request.Snapshot) != nil {
		return ErrAdmission
	}
	return nil
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/gobha-me/arcadectl/internal/installrender"
	authv1 "k8s.io/api/authorization/v1"
)

// Four fixed read-only lanes per original actor; never parallelize complete
// witnesses, passes or probes. Two actors therefore open at most eight SSARs,
// including response-body consumption, without multiplying other collectors.
const baselineReviewLanesPerActor = 4

// Private catalog component, not runtime authority. Rows are independent
// nonpersistent evaluations, not a transaction or continuously absent grants.
// All eight lanes JOIN before the caller's unchanged original, executable,
// actor and rule closes, and before another catalog pass opens.
func baselineDeniedReviews(ctx context.Context, scope *baselineDeniedScope, clients map[admissionActor]*HTTPAccess) error {
	if ctx == nil || ctx.Err() != nil || scope == nil || !installrender.ValidNamespace(scope.namespace) || len(scope.rows) != 2 || len(clients) != 2 {
		return ErrSecurityBaseline
	}
	actors := [2]admissionActor{ordinaryControllerActor, destroyControllerActor}
	var frozen [2]*HTTPAccess
	// SSAR-only actorWireTransport clients intentionally have no generic
	// native-forwarding capability. Require proofRequest inputs, not forwarding.
	for i, actor := range actors {
		client := clients[actor]
		if client == nil || client.client == nil || client.base == nil || client.actor == nil || client.actor.actor != actor || client.actor.namespace != scope.namespace || client.actor.username != "system:serviceaccount:"+scope.namespace+":"+actor.account() || client.actor.purpose != baselineDeniedReviewPurpose || client.actor.deniedScope != scope || len(scope.rows[actor]) == 0 {
			return ErrSecurityBaseline
		}
		frozen[i] = client
	}
	// Validate BOTH lanes before launching either. Cancellation is private to
	// this invocation; refusal is never retried and a canceled sibling must join.
	reviews, cancel := context.WithCancel(ctx)
	defer cancel()
	var group sync.WaitGroup
	var refused atomic.Bool
	for i, client := range frozen {
		rows := scope.rows[actors[i]]
		for lane := range baselineReviewLanesPerActor {
			group.Go(func() {
				for index := lane; index < len(rows); index += baselineReviewLanesPerActor {
					if reviews.Err() != nil || client.authorizationDecision(reviews, authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: rows[index].attributes()}, false) != nil {
						refused.Store(true)
						cancel()
						return
					}
				}
			})
		}
	}
	group.Wait()
	if refused.Load() || ctx.Err() != nil {
		return ErrSecurityBaseline
	}
	return nil
}

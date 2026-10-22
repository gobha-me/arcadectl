// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"sync"
	"sync/atomic"

	authv1 "k8s.io/api/authorization/v1"
)

// Containment keeps four fixed read-only lanes per original actor, at most
// eight SSARs including response-body consumption. Its bound is independent
// of the larger denied catalog below.
const baselineReviewLanesPerActor = 4

// Only the fresh denied catalog uses eight fixed lanes per original actor,
// at most sixteen SSARs including response-body consumption. Complete
// witnesses, passes, probes and other collectors remain serial and unchanged.
const baselineDeniedReviewLanesPerActor = 8

// Private catalog component, not runtime authority. Rows are independent
// nonpersistent evaluations, not a transaction or continuously absent grants.
// All sixteen lanes JOIN before the caller's unchanged original, executable,
// actor and rule closes, and before another catalog pass opens.
func baselineDeniedReviews(ctx context.Context, scope *baselineDeniedScope, clients map[admissionActor]*HTTPAccess) error {
	if ctx == nil || ctx.Err() != nil || !scope.valid() || len(clients) != 2 {
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
	// Validate BOTH actors before launching any row. Cancellation is private to
	// this invocation; refusal is never retried and a canceled sibling must join.
	reviews, cancel := context.WithCancel(ctx)
	defer cancel()
	var group sync.WaitGroup
	var refused atomic.Bool
	for i, client := range frozen {
		rows := scope.rows[actors[i]]
		for lane := range baselineDeniedReviewLanesPerActor {
			group.Go(func() {
				for index := lane; index < len(rows); index += baselineDeniedReviewLanesPerActor {
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

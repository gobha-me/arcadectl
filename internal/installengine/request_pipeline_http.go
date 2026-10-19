// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"net/http"
)

// Exactly one unchanged client.Do call. The original request/context, wire
// guards, redirects, cancellation and body ownership remain with their callers.
// Do includes guarded native response capture, not only underlying headers.
func requestPipelineDo(client *http.Client, request *http.Request) (*http.Response, error) {
	var ctx context.Context
	if request != nil {
		ctx = request.Context()
	}
	span := beginRequestPipelineCost(ctx, pipelineClientDo)
	defer span.finish()
	return client.Do(request)
}

// RequestPipelineSnapshot is independent of the frozen LifecycleCosts.Snapshot
// schema. Its fixed scalar rows are diagnostic only and must be read after
// joined operations. Inclusive rows overlap and do not measure SDK or CPU time.
// Outer body/validation rows cover ordinary and proof replies; guarded native
// parsing is inside post-headers. Uninstrumented local work is not accounted for.
func (c *LifecycleCosts) RequestPipelineSnapshot() string {
	var pipeline *requestPipelineCosts
	if c != nil {
		pipeline = c.pipeline
	}
	return pipeline.snapshot()
}

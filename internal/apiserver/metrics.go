// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package apiserver

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Each boundary owns its registry: no global collectors, object labels, or
// arbitrary caller-provided metric producers enter the private scrape surface.
type requestTelemetry struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	handler  http.Handler
}

func newRequestTelemetry() *requestTelemetry {
	registry := prometheus.NewRegistry()
	t := &requestTelemetry{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "arcadectl_api_requests_total",
			Help: "Completed guarded API requests, by fixed action, result and outcome-audit acknowledgement.",
		}, []string{"action", "result", "audit"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "arcadectl_api_request_duration_seconds",
			Help:    "Guarded API handler duration including outcome audit; not asynchronous operation completion time.",
			Buckets: []float64{0.005, 0.025, 0.1, 0.5, 1, 2, 5, 15},
		}, []string{"action", "result", "audit"}),
	}
	registry.MustRegister(t.requests, t.duration)
	t.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{DisableCompression: true, MaxRequestsInFlight: 2})
	return t
}

func metricRequestAction(action Action) string {
	if isReadAction(action) || isMutationAction(action) {
		return string(action)
	}
	return "unmatched"
}

func metricRequestResult(result string) string {
	switch result {
	case "unauthenticated", "unavailable", "forbidden", "succeeded", "rejected", "internal":
		return result
	default:
		return "unknown"
	}
}

func (t *requestTelemetry) observe(action Action, result string, acknowledged bool, elapsed time.Duration) {
	if t == nil {
		return
	}
	audit := "unavailable"
	if acknowledged {
		audit = "acknowledged"
	}
	actionLabel, resultLabel := metricRequestAction(action), metricRequestResult(result)
	t.requests.WithLabelValues(actionLabel, resultLabel, audit).Inc()
	if elapsed >= 0 {
		t.duration.WithLabelValues(actionLabel, resultLabel, audit).Observe(elapsed.Seconds())
	}
}

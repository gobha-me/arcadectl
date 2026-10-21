// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"strings"
	"sync/atomic"
)

type gcPagesDiagnostic struct {
	value atomic.Pointer[string]
}

// Each completion writes only its own recorder. A late earlier attempt cannot
// republish a pointer after a newer attempt or checkpoint cleared it.
func beginGCPagesDiagnostic(ctx context.Context) func(string) {
	if ctx == nil {
		return func(string) {}
	}
	d, ok := ctx.Value(lifecycleDiagnosticKey{}).(*LifecycleDiagnostic)
	if !ok || d == nil {
		return func(string) {}
	}
	recorder := &gcPagesDiagnostic{}
	d.gcPages.Store(recorder)
	return func(value string) {
		if validGCPagesSnapshot(value) {
			recorder.value.Store(&value)
		}
	}
}

func validGCPagesSnapshot(value string) bool {
	if len(value) > 96 {
		return false
	}
	fields := strings.Split(value, " ")
	if len(fields) != 3 {
		return false
	}
	switch fields[0] {
	case "reason=unknown", "reason=context", "reason=fetch-unclassified", "reason=shape", "reason=bytes", "reason=identity", "reason=objects", "reason=continuation", "reason=pages":
	default:
		return false
	}
	switch fields[1] {
	case "inner=unknown", "inner=active", "inner=cancelled", "inner=deadline":
	default:
		return false
	}
	switch fields[2] {
	case "caller=unknown", "caller=active", "caller=cancelled", "caller=deadline":
	default:
		return false
	}
	return true
}

// GCPagesSnapshot is optional same-attempt refusal progress, not an underlying
// fetch cause, successful observation, authority, or retry classification.
func (d *LifecycleDiagnostic) GCPagesSnapshot() string {
	if d == nil {
		return ""
	}
	recorder := d.gcPages.Load()
	if recorder == nil {
		return ""
	}
	value := recorder.value.Load()
	if value == nil || !validGCPagesSnapshot(*value) {
		return ""
	}
	return *value
}

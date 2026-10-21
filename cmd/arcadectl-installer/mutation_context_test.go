// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mutationUnexpectedContext struct{ context.Context }

func (mutationUnexpectedContext) Err() error {
	return errors.New("PRIVATE-PROVIDER-DETAIL-DO-NOT-PRINT")
}

func TestMutationContextStatusContainsOnlyClosedLabels(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, expire := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer expire()
	for _, test := range []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"nil", nil, "unknown"},
		{"active", t.Context(), "active"},
		{"cancelled", cancelled, "cancelled"},
		{"expired", expired, "deadline"},
		{"provider-detail", mutationUnexpectedContext{t.Context()}, "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if actual := mutationContextStatus(test.ctx); actual != test.want {
				t.Fatal("context classification escaped its closed label set")
			}
		})
	}
}

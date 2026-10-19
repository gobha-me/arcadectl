// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// Test-only labels for the existing one-shot, pre-fixture baseline conjunction.
// Observation and object mapping have ALREADY run, in that order, even when
// observation failed. Do not retry a proof or move its original time sample.
func warmInitialBaselineDiagnostic[T any](observationErr, mapErr error, baseline T, controllers func() error, leaders func(T, T, time.Time) error, now func() time.Time) string {
	if observationErr != nil {
		return "observation"
	}
	if mapErr != nil {
		return "object-map"
	}
	if controllers() != nil {
		return "controllers"
	}
	if leaders(baseline, baseline, now().UTC()) != nil {
		return "leaders"
	}
	return ""
}

func TestWarmInitialBaselineDiagnosticOrderingAndClosedStages(t *testing.T) {
	refusal := errors.New("PRIVATE-CANARY provider error must never become a label")
	for _, test := range []struct {
		name                         string
		observation, mapping, checks error
		leader                       error
		want                         string
		calls                        []string
	}{
		{"observation-first", refusal, refusal, refusal, refusal, "observation", []string{"observation", "object-map"}},
		{"object-map", nil, refusal, refusal, refusal, "object-map", []string{"observation", "object-map"}},
		{"controllers", nil, nil, refusal, refusal, "controllers", []string{"observation", "object-map", "controllers"}},
		{"leaders", nil, nil, nil, refusal, "leaders", []string{"observation", "object-map", "controllers", "now", "leaders"}},
		{"success", nil, nil, nil, nil, "", []string{"observation", "object-map", "controllers", "now", "leaders"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseline := &struct{ marker int }{17}
			instant := time.Date(2026, 1, 2, 3, 4, 5, 6, time.FixedZone("synthetic", 3600))
			var calls []string
			stage := warmInitialBaselineDiagnostic(
				func() error { calls = append(calls, "observation"); return test.observation }(),
				func() error { calls = append(calls, "object-map"); return test.mapping }(),
				baseline,
				func() error { calls = append(calls, "controllers"); return test.checks },
				func(original, current *struct{ marker int }, observed time.Time) error {
					calls = append(calls, "leaders")
					if original != baseline || current != baseline || !observed.Equal(instant) || observed.Location() != time.UTC {
						t.Fatal("baseline operands or original UTC sample changed")
					}
					return test.leader
				},
				func() time.Time { calls = append(calls, "now"); return instant },
			)
			if stage != test.want || !reflect.DeepEqual(calls, test.calls) || baseline.marker != 17 {
				t.Fatal("closed diagnostic changed call order, short-circuiting, sample count or operands")
			}
		})
	}
	for _, site := range []string{"controllers", "now", "leaders"} {
		t.Run("panic-"+site, func(t *testing.T) {
			defer func() {
				if recover() != refusal {
					t.Fatal("diagnostic recovered, replaced or omitted a callback panic")
				}
			}()
			warmInitialBaselineDiagnostic(nil, nil, 17,
				func() error {
					if site == "controllers" {
						panic(refusal)
					}
					return nil
				},
				func(int, int, time.Time) error {
					if site == "leaders" {
						panic(refusal)
					}
					return nil
				},
				func() time.Time {
					if site == "now" {
						panic(refusal)
					}
					return time.Time{}
				},
			)
		})
	}
}

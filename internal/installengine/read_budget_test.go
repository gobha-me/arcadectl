// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

func TestInstallerReadBudgetSharedOnlyForUnspecifiedSettings(t *testing.T) {
	for _, direct := range []bool{false, true} {
		for _, settings := range []struct {
			name    string
			qps     float32
			burst   int
			limiter flowcontrol.RateLimiter
		}{{name: "unspecified"}, {name: "low-qps", qps: 1, burst: 1}, {name: "qps-only", qps: 3}, {name: "burst-only", burst: 3}, {name: "negative-qps", qps: -1}, {name: "explicit-limiter", limiter: flowcontrol.NewFakeAlwaysRateLimiter()}} {
			t.Run(settings.name+map[bool]string{false: "/regular", true: "/direct"}[direct], func(t *testing.T) {
				original := &rest.Config{Host: "https://cluster.example", BearerToken: "TEST-ONLY-READ-BUDGET", QPS: settings.qps, Burst: settings.burst, RateLimiter: settings.limiter}
				a, err := newHTTPAccess(original, direct)
				if err != nil {
					t.Fatal("frozen static access construction refused")
				}
				one, two := a.readConfig(), a.readConfig()
				if original.QPS != settings.qps || original.Burst != settings.burst || original.RateLimiter != settings.limiter || a.frozen.QPS != settings.qps || a.frozen.Burst != settings.burst || a.frozen.RateLimiter != settings.limiter || one.Host != original.Host || one.BearerToken != original.BearerToken {
					t.Fatal("read derivation changed original effect configuration or identity")
				}
				if settings.name == "unspecified" {
					if a.readLimiter == nil || one.RateLimiter != a.readLimiter || two.RateLimiter != one.RateLimiter || one.RateLimiter.QPS() != 100 || one.QPS != 100 || one.Burst != 20 || two.QPS != 100 || two.Burst != 20 {
						t.Fatal("observer reconstruction replenished an independent or unbounded budget")
					}
					// Changing a returned config cannot alter future derivations
					// or affect the default shared bucket in the original access.
					one.QPS, one.Burst, one.RateLimiter = -1, 999, nil
					fresh := a.readConfig()
					if fresh.QPS != 100 || fresh.Burst != 20 || fresh.RateLimiter != a.readLimiter {
						t.Fatal("read config mutation escaped defensive derivation")
					}
				} else if a.readLimiter != nil || one.QPS != settings.qps || one.Burst != settings.burst || one.RateLimiter != settings.limiter || two.RateLimiter != settings.limiter {
					t.Fatal("explicit caller rate settings were replaced or bypassed")
				}
			})
		}
	}
}

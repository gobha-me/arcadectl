//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

func sdkRateControlParent(t *testing.T) (*HTTPAccess, *sdkWaitDiagnosticLimiter) {
	t.Helper()
	a, err := NewDirectHTTPAccess(&rest.Config{Host: "https://cluster.example", BearerToken: "TEST-ONLY-SDK-RATE"})
	if err != nil {
		t.Fatal("synthetic read parent unavailable")
	}
	bucket, ok := a.readLimiter.(*sdkWaitDiagnosticLimiter)
	if !ok || !kindSDKRateInherited(a, bucket, 200) {
		t.Fatal("constructor did not establish the shared default")
	}
	return a, bucket
}

func TestKindSDKRatePilotRealObserverWaitRefusals(t *testing.T) {
	newPhase := fixtureV3PhaseFactory(t)
	for _, qps := range []int{200, 400} {
		h := newPhase(t)
		f := h.f.wire.ledger
		beforeBody, beforeID := append([]byte(nil), f.body...), f.identity
		config := rest.CopyConfig(h.f.actor.admission.prerequisites.access.frozen)
		config.QPS, config.Burst, config.RateLimiter = 0, 0, nil
		parent, err := NewDirectHTTPAccess(config)
		if err != nil {
			t.Fatal("observer control parent unavailable")
		}
		t.Cleanup(parent.pool.(*http.Transport).CloseIdleConnections)
		initial, ok := parent.readLimiter.(*sdkWaitDiagnosticLimiter)
		if !ok {
			t.Fatal("observer control default wrapper missing")
		}
		bucket, err := kindSDKRateSelect(parent, initial, qps)
		if err != nil {
			t.Fatal("observer control rate refused")
		}
		var waits, requests, stop, stoppedAt atomic.Int64
		var first [3]atomic.Int64
		var cancel context.CancelFunc
		bucket.RateLimiter = sdkWaitFixtureLimiter{RateLimiter: bucket.RateLimiter, wait: func(ctx context.Context) error {
			count := waits.Add(1)
			if stop.Load() == count {
				stoppedAt.Store(requests.Load())
				cancel()
				return ctx.Err()
			}
			return nil
		}}
		var base func(http.ResponseWriter, *http.Request) bool
		h.f.actor.withState(func() {
			base = h.f.actor.fixtureHandler
			h.f.actor.fixtureHandler = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodGet {
					t.Error("observer sent a non-read request")
				}
				meta := strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadata")
				if r.URL.Path != "/api/v1/namespaces/"+h.f.actor.request.Snapshot.Anchor().Namespace || meta {
					requests.Add(1)
					kind := 2
					if meta {
						kind = 1
					} else if r.URL.Query().Get("limit") != "" {
						kind = 0
					}
					first[kind].CompareAndSwap(0, waits.Load())
				}
				return base(w, r)
			}
		})
		defer h.f.actor.withState(func() { h.f.actor.fixtureHandler = base })
		collect := func(ctx context.Context, manual bool) (bool, error) {
			// HTTP EOF can precede the fixture handler's final state updates.
			// Join that protected tail before reading/resetting control counters.
			defer h.f.actor.withState(func() {})
			observer, err := installobserve.New(parent.readConfig(), f.engine.journal, h.f.actor.request.Target)
			if err != nil {
				return false, err
			}
			if manual {
				value, err := observer.CollectExecutables(ctx, h.f.actor.request.Snapshot.Anchor())
				return value != nil, err
			}
			value, err := observer.Collect(ctx, h.f.actor.request.Snapshot.Anchor())
			return value != nil, err
		}
		for _, manual := range []bool{false, true} {
			waits.Store(0)
			requests.Store(0)
			ctx, costs := WithLifecycleCosts(t.Context())
			present, err := collect(ctx, manual)
			if err != nil || !present || waits.Load() <= 0 || requests.Load() != waits.Load() || costs.metrics[costSDKWait].calls.Load() != uint64(waits.Load()) || costs.metrics[costSDKWait].returned.Load() != uint64(waits.Load()) {
				t.Fatal("real observer Wait/request census or shared delegate changed")
			}
			if manual && waits.Load() != 8 {
				t.Fatal("manual executable reader bypassed the one shared limiter")
			}
		}
		for path := 0; path < 4; path++ {
			at := int64(1)
			if path < 3 {
				at = first[path].Load()
			}
			if at <= 0 {
				t.Fatal("dynamic, metadata or discovery path was not exercised")
			}
			waits.Store(0)
			requests.Store(0)
			stop.Store(at)
			stoppedAt.Store(-1)
			child, done := context.WithCancel(t.Context())
			cancel = done
			ctx, costs := WithLifecycleCosts(child)
			present, err := collect(ctx, path == 3)
			state := child.Err()
			done()
			if err == nil || present || state != context.Canceled || t.Context().Err() != nil || waits.Load() != at || requests.Load() != at-1 || requests.Load() != stoppedAt.Load() || costs.metrics[costSDKWait].calls.Load() != uint64(at) || costs.metrics[costSDKWait].returned.Load() != uint64(at) {
				t.Fatal("real observer Wait refusal sent dependent HTTP or failed cancellation/join")
			}
		}
		phaseBarrierUnchanged(t, h, beforeBody, beforeID)
	}
}

func TestKindSDKRatePilotFreshSharedBucket(t *testing.T) {
	parent, previous := sdkRateControlParent(t)
	frozen := rest.CopyConfig(parent.frozen)
	seen := map[*sdkWaitDiagnosticLimiter]bool{previous: true}
	for _, qps := range [4]int{200, 400, 400, 200} {
		stale, err := parent.actorClient(ordinaryControllerActor, "fixture")
		if err != nil {
			t.Fatal("synthetic old actor unavailable")
		}
		oldSDK, err := kubernetes.NewForConfig(stale.readConfig())
		if err != nil || oldSDK.CoreV1().RESTClient().GetRateLimiter() != previous {
			t.Fatal("synthetic old SDK did not retain its original bucket")
		}
		bucket, err := kindSDKRateSelect(parent, previous, qps)
		if err != nil || seen[bucket] || bucket == previous || !kindSDKRateInherited(parent, bucket, qps) || kindSDKRateInherited(stale, bucket, qps) {
			t.Fatal("arm reused a bucket or accepted a stale client")
		}
		if oldSDK.CoreV1().RESTClient().GetRateLimiter() != previous {
			t.Fatal("replacement silently mutated an already-constructed SDK client")
		}
		seen[bucket] = true
		actor, err := parent.actorClient(ordinaryControllerActor, "fixture")
		if err != nil || !kindSDKRateInherited(actor, bucket, qps) {
			t.Fatal("fresh real actor factory lost the current bucket")
		}
		for _, access := range []*HTTPAccess{parent, actor} {
			client, err := kubernetes.NewForConfig(access.readConfig())
			if err != nil {
				t.Fatal("synthetic SDK construction refused")
			}
			for _, limiter := range []flowcontrol.RateLimiter{client.CoreV1().RESTClient().GetRateLimiter(), client.AppsV1().RESTClient().GetRateLimiter(), client.AdmissionregistrationV1().RESTClient().GetRateLimiter(), client.CoordinationV1().RESTClient().GetRateLimiter(), client.Discovery().RESTClient().GetRateLimiter()} {
				if limiter != bucket || limiter.QPS() != float32(qps) {
					t.Fatal("SDK group minted or retained a different effective bucket")
				}
			}
		}
		if !reflect.DeepEqual(parent.frozen, frozen) {
			t.Fatal("arm changed frozen caller configuration")
		}
		previous = bucket
	}
}

func TestKindSDKRatePilotRefusesExplicitAndStalePolicy(t *testing.T) {
	for _, change := range []string{"qps", "burst", "limiter", "foreign-wrapper", "nil-delegate", "stale", "actor-parent", "unsupported-rate"} {
		t.Run(change, func(t *testing.T) {
			parent, previous := sdkRateControlParent(t)
			qps := 400
			switch change {
			case "qps":
				parent.frozen.QPS = 1
			case "burst":
				parent.frozen.Burst = 1
			case "limiter":
				parent.frozen.RateLimiter = flowcontrol.NewFakeAlwaysRateLimiter()
			case "foreign-wrapper":
				parent.readLimiter = flowcontrol.NewFakeAlwaysRateLimiter()
			case "nil-delegate":
				previous.RateLimiter = nil
			case "stale":
				previous = &sdkWaitDiagnosticLimiter{RateLimiter: flowcontrol.NewTokenBucketRateLimiter(200, 20)}
			case "actor-parent":
				parent.actor = &actorWireIdentity{}
			case "unsupported-rate":
				qps = 300
			}
			before := parent.readLimiter
			if bucket, err := kindSDKRateSelect(parent, previous, qps); err == nil || bucket != nil || parent.readLimiter != before {
				t.Fatal("ineligible policy was changed or accepted")
			}
		})
	}
	if bucket, err := kindSDKRateSelect(nil, nil, 200); err == nil || bucket != nil {
		t.Fatal("nil parent accepted")
	}
}

func TestKindSDKRatePilotFixedBracketAndNoQuotaChanges(t *testing.T) {
	source, parent := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if !kindSDKRatePilotOptIn("1", "true", "true", source, parent) {
		t.Fatal("exact disposable opt-in refused")
	}
	for _, args := range [][5]string{{"", "true", "true", source, parent}, {"1", "false", "true", source, parent}, {"1", "true", "false", source, parent}, {"1", "true", "true", "PRIVATE-CANARY", parent}, {"1", "true", "true", source, ""}, {"1", "true", "true", source, source}} {
		if kindSDKRatePilotOptIn(args[0], args[1], args[2], args[3], args[4]) {
			t.Fatal("incomplete opt-in accepted")
		}
	}
	var order []int
	good := func(index, qps int) (kindSDKRateSample, error) {
		order = append(order, qps)
		wall := 100 * time.Nanosecond
		if qps == 400 {
			wall = 85 * time.Nanosecond
		}
		return kindSDKRateSample{qps: qps, wall: wall, waits: 3, returned: 3, inclusiveNS: 5}, nil
	}
	samples, err := runKindSDKRateBracket(t.Context(), good)
	if err != nil || !reflect.DeepEqual(order, []int{200, 400, 400, 200}) || !kindSDKRateUseful(samples) {
		t.Fatal("fixed complete bracket or threshold equality changed")
	}
	for _, index := range []int{1, 2} {
		bad := samples
		bad[index].wall++
		if kindSDKRateUseful(bad) {
			t.Fatal("only one improved candidate accepted")
		}
	}
	bad := samples
	bad[3].wall = 110 * time.Nanosecond
	bad[1].wall = 93 * time.Nanosecond
	bad[2].wall = 93 * time.Nanosecond
	if kindSDKRateUseful(bad) {
		t.Fatal("slower baseline selected")
	}
	for _, mode := range []string{"refusal", "cancel", "unfinished-wait", "wrong-qps", "over-budget"} {
		ctx, cancel := context.WithCancel(t.Context())
		calls := 0
		_, err := runKindSDKRateBracket(ctx, func(index, qps int) (kindSDKRateSample, error) {
			calls++
			value, _ := good(index, qps)
			if index == 1 {
				switch mode {
				case "refusal":
					return kindSDKRateSample{}, ErrFixtures
				case "cancel":
					cancel()
				case "unfinished-wait":
					value.returned--
				case "wrong-qps":
					value.qps = 300
				case "over-budget":
					value.wall = 40*time.Minute + 1
				}
			}
			return value, nil
		})
		cancel()
		if err == nil || calls != 2 {
			t.Fatal("partial proof retried or advanced bracket")
		}
	}
	if _, err := runKindSDKRateBracket(nil, good); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := runKindSDKRateBracket(t.Context(), nil); err == nil {
		t.Fatal("nil proof accepted")
	}
	// Source-only check of fixed burst and no validation-token consumption. The
	// native constructor must not acquire quota/restore machinery from d0e.
	body, err := os.ReadFile("kind_sdk_rate_pilot_test.go")
	if err != nil {
		t.Fatal("pilot source unavailable")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "pilot", body, 0)
	if err != nil {
		t.Fatal("pilot source invalid")
	}
	buckets, nativeFixtures := 0, 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			if selector.Sel.Name == "NewTokenBucketRateLimiter" {
				buckets++
				literal, ok := call.Args[1].(*ast.BasicLit)
				if !ok || literal.Value != "20" {
					t.Fatal("burst changed")
				}
			}
			if selector.Sel.Name == "TryAccept" || selector.Sel.Name == "setPilotCPUs" || selector.Sel.Name == "inspectPilotCPUs" {
				t.Fatal("validation consumed tokens or changed CPU quota")
			}
		}
		if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "targetKindFixtureImagesV2" {
			nativeFixtures++
		}
		return true
	})
	if buckets != 1 || nativeFixtures != 1 {
		t.Fatal("extra bucket factory or fixture introduced")
	}
}

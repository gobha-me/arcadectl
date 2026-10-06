// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/gobha-me/arcadectl/internal/adminauth"
)

func TestActivationPrivateTraceFixedFirstRefusalAndConcurrency(t *testing.T) {
	traceActivation(nil, activationSelf)
	traceActivation(context.Background(), activationSelf)
	var absent *activationTrace
	if absent.stage() != "unknown" {
		t.Fatal("nil trace exposed diagnostics")
	}
	trace := &activationTrace{}
	ctx := context.WithValue(context.Background(), activationTraceKey{}, trace)
	if trace.stage() != "unknown" {
		t.Fatal("unstarted trace manufactured evidence")
	}
	traceActivation(ctx, activationServingDialMatch)
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() { traceActivation(ctx, activationSelf) })
	}
	group.Wait()
	traceActivation(ctx, activationComplete)
	if trace.stage() != "serving-dial-mismatch" {
		t.Fatal("generic outer error/success replaced original refusal")
	}
	trace = &activationTrace{}
	ctx = context.WithValue(context.Background(), activationTraceKey{}, trace)
	traceActivation(ctx, activationComplete)
	traceActivation(ctx, activationOriginalAfter)
	if trace.stage() != "original-after" {
		t.Fatal("inner success masked a later original-witness refusal")
	}
	trace = &activationTrace{}
	ctx = context.WithValue(context.Background(), activationTraceKey{}, trace)
	traceActivation(ctx, activationStep(999))
	if trace.stage() != "unknown" {
		t.Fatal("unknown diagnostic manufactured a message")
	}
}

func TestActivationPrivateTraceMatchesActualRefusalWithoutReplayOrLeak(t *testing.T) {
	for _, scenario := range []struct {
		name, stage string
		requests    int32
	}{
		{"success", "complete", 1},
		{"connection", "connection-open", 0},
		{"pod-at-dial", "serving-dial-mismatch", 0},
		{"secret-at-dial", "binding-dial-mismatch", 0},
		{"pod-after-auth", "serving-after-mismatch", 1},
		{"secret-after-auth", "binding-after-mismatch", 1},
		{"wrong-namespace", "auth-self-identity", 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			x := newServingFixture(t)
			namespace := x.f.plan.Namespace()
			if scenario.name == "wrong-namespace" {
				namespace = "foreign"
			}
			mutate := func() {
				if scenario.name == "pod-at-dial" || scenario.name == "pod-after-auth" {
					x.access.pod.ResourceVersion = "11"
				} else {
					x.secrets.objects[adminauth.CredentialSecretName].ResourceVersion = "11"
				}
			}
			var onRequest func()
			if scenario.name == "pod-after-auth" || scenario.name == "secret-after-auth" {
				onRequest = mutate
			}
			requests := activationServer(t, x, namespace, onRequest)
			if scenario.name == "connection" {
				x.activation.dial = func(context.Context, *Serving) (net.Conn, error) { return nil, errors.New("PRIVATE-CANARY") }
			} else if scenario.name == "pod-at-dial" || scenario.name == "secret-at-dial" {
				original := x.activation.dial
				x.activation.dial = func(ctx context.Context, serving *Serving) (net.Conn, error) {
					conn, err := original(ctx, serving)
					mutate()
					return conn, err
				}
			}
			trace := &activationTrace{}
			ctx := context.WithValue(t.Context(), activationTraceKey{}, trace)
			err := x.activation.VerifyDirect(ctx, x.f.snapshot, x.options)
			if scenario.name == "success" {
				if err != nil {
					t.Fatal("traced actual activation failed")
				}
			} else if err != ErrActivation || err.Error() != ErrActivation.Error() {
				t.Fatal("diagnostic changed error semantics or exposed private error")
			}
			if trace.stage() != scenario.stage || requests.Load() != scenario.requests {
				t.Fatalf("same-attempt diagnosis/replay: stage=%s requests=%d", trace.stage(), requests.Load())
			}
		})
	}
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

func TestControllerReadinessHTTPDoesNotReportEarlySuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var synced atomic.Bool
	handler := &healthz.Handler{Checks: map[string]healthz.Checker{"cache": controllerReadiness(ctx, func(context.Context) bool { return synced.Load() })}}
	server := httptest.NewServer(http.StripPrefix("/readyz", handler))
	defer server.Close()
	checkStatus := func(wantReady bool) {
		t.Helper()
		response, err := server.Client().Get(server.URL + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if gotReady := response.StatusCode >= 200 && response.StatusCode < 300; gotReady != wantReady {
			t.Fatalf("HTTP readiness status=%d ready=%t want=%t", response.StatusCode, gotReady, wantReady)
		}
	}
	checkStatus(false)
	synced.Store(true)
	checkStatus(true)
	cancel()
	checkStatus(false)
}

type readinessTestInformer struct{ cache.Informer }

type readinessTestSource struct {
	t       *testing.T
	objects []string
	failAt  int
	nilAt   int
	cancel  context.CancelFunc
}

func (source *readinessTestSource) GetInformer(ctx context.Context, object client.Object, options ...cache.InformerGetOption) (cache.Informer, error) {
	source.t.Helper()
	settings := &cache.InformerGetOptions{}
	for _, option := range options {
		option(settings)
	}
	if settings.BlockUntilSynced == nil || *settings.BlockUntilSynced {
		source.t.Fatal("startup informer registration waits for a cache that has not started")
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 30*time.Second {
		source.t.Fatal("startup informer preparation has no finite context")
	}
	source.objects = append(source.objects, reflect.TypeOf(object).Elem().Name())
	if len(source.objects) == source.failAt {
		return nil, errors.New("PRIVATE-READINESS-CANARY")
	}
	if len(source.objects) == source.nilAt {
		return nil, nil
	}
	if source.cancel != nil {
		source.cancel()
	}
	return &readinessTestInformer{}, nil
}

func TestReadinessRegistersAllWatchedFamiliesBeforeCacheStart(t *testing.T) {
	for _, test := range []struct {
		mode string
		want []string
	}{
		{"normal", []string{"ArcadeOperation", "ConfigMap", "Deployment", "GameBackup", "GameRestore", "GameServer", "Job", "Lease", "PersistentVolumeClaim", "Role", "RoleBinding", "Service", "ServiceAccount"}},
		{"destroy", []string{"ConfigMap", "GameDestroy", "Job", "Role", "RoleBinding", "ServiceAccount"}},
	} {
		t.Run(test.mode, func(t *testing.T) {
			source := &readinessTestSource{t: t}
			if err := prepareReadinessInformers(t.Context(), source, test.mode); err != nil {
				t.Fatal(err)
			}
			slices.Sort(source.objects)
			if !slices.Equal(source.objects, test.want) {
				t.Fatal("readiness watch set changed or gained unrelated authority", source.objects)
			}
		})
	}
	for _, test := range []struct{ failure, nilInformer int }{{1, 0}, {5, 0}, {0, 1}} {
		source := &readinessTestSource{t: t, failAt: test.failure, nilAt: test.nilInformer}
		if err := prepareReadinessInformers(t.Context(), source, "normal"); err != errControllerNotReady || strings.Contains(err.Error(), "CANARY") {
			t.Fatal("preparation failure was accepted or leaked its underlying error")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	source := &readinessTestSource{t: t, cancel: cancel}
	if prepareReadinessInformers(ctx, source, "normal") != errControllerNotReady || len(source.objects) != 1 {
		t.Fatal("canceled preparation continued registering informers")
	}
	if prepareReadinessInformers(t.Context(), source, "unknown") != errControllerNotReady || prepareReadinessInformers(nil, source, "normal") != errControllerNotReady || prepareReadinessInformers(t.Context(), nil, "normal") != errControllerNotReady {
		t.Fatal("invalid readiness configuration was accepted")
	}
}

func TestControllerReadinessRequiresCacheSyncAndStopsOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var synced atomic.Bool
	var calls atomic.Int32
	check := controllerReadiness(ctx, func(context.Context) bool {
		calls.Add(1)
		return synced.Load()
	})
	request := httptest.NewRequest("GET", "/readyz", nil)
	if check(request) != errControllerNotReady {
		t.Fatal("unsynchronized informer cache reported ready")
	}
	synced.Store(true)
	if check(request) != nil {
		t.Fatal("synchronized informer cache did not become ready")
	}
	cancel()
	before := calls.Load()
	if check(request) != errControllerNotReady || calls.Load() != before {
		t.Fatal("stopped manager reported ready or started a new cache wait")
	}
	for _, check := range []func(*http.Request) error{controllerReadiness(nil, nil), controllerReadiness(t.Context(), nil)} {
		if check(nil) != errControllerNotReady {
			t.Fatal("incomplete checker configuration reported ready")
		}
	}
}

func TestControllerReadinessWaitUsesRequestAndManagerCancellation(t *testing.T) {
	for _, cancelManager := range []bool{false, true} {
		lifecycle, stopManager := context.WithCancel(t.Context())
		requestCtx, stopRequest := context.WithCancel(t.Context())
		entered := make(chan struct{})
		finished := make(chan error, 1)
		check := controllerReadiness(lifecycle, func(ctx context.Context) bool {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
				t.Error("cache wait is not bounded by a one-second probe deadline")
			}
			close(entered)
			<-ctx.Done()
			return true // cancellation must still override a late positive result
		})
		go func() { finished <- check(httptest.NewRequest("GET", "/readyz", nil).WithContext(requestCtx)) }()
		<-entered
		if cancelManager {
			stopManager()
		} else {
			stopRequest()
		}
		select {
		case err := <-finished:
			if err != errControllerNotReady {
				t.Error("canceled readiness wait accepted a late positive result")
			}
		case <-time.After(2 * time.Second):
			t.Error("canceled readiness wait did not terminate")
		}
		stopManager()
		stopRequest()
	}
}

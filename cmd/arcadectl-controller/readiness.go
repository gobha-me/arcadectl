// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var errControllerNotReady = errors.New("controller dependencies are not ready")

type readinessInformers interface {
	GetInformer(context.Context, client.Object, ...cache.InformerGetOption) (cache.Informer, error)
}

// Register exactly the watched families before the health server can start.
// Otherwise WaitForCacheSync can observe an empty informer set before the
// controllers have registered their sources and report a premature success.
// These are the existing SetupWithManager watches, not new read authority.
func prepareReadinessInformers(ctx context.Context, informers readinessInformers, mode string) error {
	if ctx == nil || informers == nil || mode != "normal" && mode != "destroy" {
		return errControllerNotReady
	}
	objects := []client.Object{&corev1.ConfigMap{}, &corev1.ServiceAccount{}, &rbacv1.Role{}, &rbacv1.RoleBinding{}, &batchv1.Job{}}
	if mode == "destroy" {
		objects = append(objects, &arcade.GameDestroy{})
	} else {
		objects = append(objects, &arcade.GameServer{}, &arcade.GameBackup{}, &arcade.GameRestore{}, &arcade.ArcadeOperation{}, &appsv1.Deployment{}, &corev1.Service{}, &coordinationv1.Lease{}, &corev1.PersistentVolumeClaim{})
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, object := range objects {
		if ctx.Err() != nil {
			return errControllerNotReady
		}
		if informer, err := informers.GetInformer(ctx, object, cache.BlockUntilSynced(false)); err != nil || informer == nil {
			return errControllerNotReady
		}
	}
	if ctx.Err() != nil {
		return errControllerNotReady
	}
	return nil
}

// Readiness is separate from process liveness. Cache synchronization uses a
// bounded request context and must never outlive manager shutdown. No provider
// error, object identity, credential or raw Kubernetes response is projected.
func controllerReadiness(lifecycle context.Context, waitForCacheSync func(context.Context) bool) healthz.Checker {
	return func(request *http.Request) error {
		if lifecycle == nil || lifecycle.Err() != nil || waitForCacheSync == nil || request == nil || request.Context().Err() != nil {
			return errControllerNotReady
		}
		ctx, cancel := context.WithTimeout(request.Context(), time.Second)
		stop := context.AfterFunc(lifecycle, cancel)
		defer stop()
		defer cancel()
		if !waitForCacheSync(ctx) || ctx.Err() != nil || lifecycle.Err() != nil {
			return errControllerNotReady
		}
		return nil
	}
}

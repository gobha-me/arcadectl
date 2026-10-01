// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/controller"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	var metricsAddress string
	var healthAddress string
	var watchNamespace string
	var backupWorkerImage string
	var leaderElection bool
	flag.StringVar(&metricsAddress, "metrics-bind-address", ":8080", "address for the metrics endpoint")
	flag.StringVar(&healthAddress, "health-probe-bind-address", ":8081", "address for health probes")
	flag.StringVar(&watchNamespace, "watch-namespace", os.Getenv("POD_NAMESPACE"), "single namespace containing GameServers and their resources")
	flag.StringVar(&backupWorkerImage, "backup-worker-image", os.Getenv("BACKUP_WORKER_IMAGE"), "backup worker image pinned by sha256 digest")
	flag.BoolVar(&leaderElection, "leader-elect", false, "enable leader election")
	loggerOptions := zap.Options{Development: false}
	loggerOptions.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&loggerOptions)))
	setupLog := ctrl.Log.WithName("setup")

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(batchv1.AddToScheme(scheme))
	utilruntime.Must(arcadev1alpha1.AddToScheme(scheme))
	utilruntime.Must(coordinationv1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))
	utilruntime.Must(storagev1.AddToScheme(scheme))
	gameCatalog, err := controllerCatalog()
	if err != nil {
		setupLog.Error(err, "build game catalog")
		os.Exit(1)
	}

	options, err := managerOptions(scheme, watchNamespace, metricsAddress, healthAddress, leaderElection)
	if err != nil {
		setupLog.Error(err, "validate manager options")
		os.Exit(1)
	}
	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		setupLog.Error(err, "create manager")
		os.Exit(1)
	}

	reconciler := &controller.GameServerReconciler{
		Client:    manager.GetClient(),
		APIReader: manager.GetAPIReader(),
		Scheme:    manager.GetScheme(),
		Catalog:   gameCatalog,
	}
	if err := reconciler.SetupWithManager(manager); err != nil {
		setupLog.Error(err, "register GameServer controller")
		os.Exit(1)
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$`).MatchString(backupWorkerImage) {
		setupLog.Error(errors.New("backup worker image must be a lowercase repository pinned by sha256 digest"), "validate backup worker image")
		os.Exit(1)
	}
	backupReconciler := &controller.GameBackupReconciler{
		Client: manager.GetClient(), APIReader: manager.GetAPIReader(), Scheme: manager.GetScheme(), Catalog: gameCatalog, WorkerImage: backupWorkerImage,
	}
	if err := backupReconciler.SetupWithManager(manager); err != nil {
		setupLog.Error(err, "register GameBackup controller")
		os.Exit(1)
	}
	restoreReconciler := &controller.GameRestoreReconciler{
		Client: manager.GetClient(), APIReader: manager.GetAPIReader(), Scheme: manager.GetScheme(), Catalog: gameCatalog, WorkerImage: backupWorkerImage,
	}
	if err := restoreReconciler.SetupWithManager(manager); err != nil {
		setupLog.Error(err, "register GameRestore controller")
		os.Exit(1)
	}
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "register health check")
		os.Exit(1)
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "register readiness check")
		os.Exit(1)
	}

	setupLog.Info("starting controller manager")
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "manager stopped")
		os.Exit(1)
	}
}

func managerOptions(scheme *runtime.Scheme, watchNamespace, metricsAddress, healthAddress string, leaderElection bool) (ctrl.Options, error) {
	watchNamespace = strings.TrimSpace(watchNamespace)
	if watchNamespace == "" {
		return ctrl.Options{}, errors.New("watch namespace is required")
	}
	if problems := validation.IsDNS1123Label(watchNamespace); len(problems) > 0 {
		return ctrl.Options{}, fmt.Errorf("invalid watch namespace: %s", strings.Join(problems, "; "))
	}
	return ctrl.Options{
		Scheme: scheme,
		Cache: cache.Options{DefaultNamespaces: map[string]cache.Config{
			watchNamespace: {},
		}},
		Metrics:                 metricsserver.Options{BindAddress: metricsAddress},
		HealthProbeBindAddress:  healthAddress,
		LeaderElection:          leaderElection,
		LeaderElectionID:        "controller.arcade.gobha.me",
		LeaderElectionNamespace: watchNamespace,
	}, nil
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/catalog"
	"github.com/gobha-me/arcadectl/internal/controller"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	var metricsAddress string
	var healthAddress string
	var leaderElection bool
	flag.StringVar(&metricsAddress, "metrics-bind-address", ":8080", "address for the metrics endpoint")
	flag.StringVar(&healthAddress, "health-probe-bind-address", ":8081", "address for health probes")
	flag.BoolVar(&leaderElection, "leader-elect", false, "enable leader election")
	loggerOptions := zap.Options{Development: false}
	loggerOptions.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&loggerOptions)))
	setupLog := ctrl.Log.WithName("setup")

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(arcadev1alpha1.AddToScheme(scheme))
	gameCatalog, err := catalog.Builtins()
	if err != nil {
		setupLog.Error(err, "build game catalog")
		os.Exit(1)
	}

	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddress},
		HealthProbeBindAddress: healthAddress,
		LeaderElection:         leaderElection,
		LeaderElectionID:       "controller.arcade.gobha.me",
	})
	if err != nil {
		setupLog.Error(err, "create manager")
		os.Exit(1)
	}

	reconciler := &controller.GameServerReconciler{
		Client:  manager.GetClient(),
		Scheme:  manager.GetScheme(),
		Catalog: gameCatalog,
	}
	if err := reconciler.SetupWithManager(manager); err != nil {
		setupLog.Error(err, "register GameServer controller")
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

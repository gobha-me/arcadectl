// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	arcadev1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/apiserver"
	"github.com/gobha-me/arcadectl/internal/catalog"
	platformimage "github.com/gobha-me/arcadectl/internal/platform/image"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type options struct {
	listen, healthListen, verifierFile, certificateFile, keyFile string
}

func parseOptions(args []string) (options, error) {
	var config options
	flags := flag.NewFlagSet("arcadectl-api", flag.ContinueOnError)
	// Raw invalid flag arguments and filenames do not belong in diagnostics.
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.listen, "listen", ":8443", "HTTPS listen address")
	flags.StringVar(&config.healthListen, "health-listen", ":8081", "private health listen address")
	flags.StringVar(&config.verifierFile, "verifier-file", "/var/run/arcadectl/auth/auth.json", "projected verifier bundle file")
	flags.StringVar(&config.certificateFile, "tls-cert-file", "/var/run/arcadectl/tls/tls.crt", "TLS certificate file")
	flags.StringVar(&config.keyFile, "tls-key-file", "/var/run/arcadectl/tls/tls.key", "TLS private key file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || config.listen == "" || config.healthListen == "" || config.listen == config.healthListen || config.verifierFile == "" || config.certificateFile == "" || config.keyFile == "" {
		return options{}, errors.New("invalid API configuration")
	}
	return config, nil
}

func newServers(config options, auditOutput io.Writer) (*http.Server, *http.Server, *adminauth.FileVerifier, error) {
	certificate, err := tls.LoadX509KeyPair(config.certificateFile, config.keyFile)
	if err != nil {
		return nil, nil, nil, errors.New("API TLS configuration unavailable")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, nil, nil, errors.New("API TLS configuration unavailable")
	}
	certificate.Leaf = leaf
	verifier := adminauth.NewFileVerifier(config.verifierFile, time.Now)
	_ = verifier.Reload()
	boundary, err := apiserver.New(apiserver.Config{
		Authenticator: verifier, Authorizer: apiserver.AdministratorAuthorizer{},
		Audit: apiserver.NewJSONAudit(auditOutput), Namespace: adminauth.CredentialNamespace,
	})
	if err != nil {
		return nil, nil, nil, errors.New("API boundary configuration unavailable")
	}
	api := &http.Server{
		Addr: config.listen, Handler: boundary,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8192,
		// net/http diagnostics can contain caller-controlled request bytes. Audit
		// is the sole request log; operational failures use fixed messages below.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	health := &http.Server{
		Addr: config.healthListen, Handler: tlsHealthHandler(boundary.HealthHandler(), leaf, time.Now),
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second,
		MaxHeaderBytes: 2048, ErrorLog: log.New(io.Discard, "", 0),
	}
	return api, health, verifier, nil
}

func tlsHealthHandler(next http.Handler, leaf *x509.Certificate, clock func() time.Time) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/readyz" && (request.Method == http.MethodGet || request.Method == http.MethodHead) {
			now := clock()
			if leaf == nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
				writer.Header().Set("Cache-Control", "no-store")
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(writer, "{\"version\":\"v1\",\"code\":\"unavailable\"}\n")
				return
			}
		}
		next.ServeHTTP(writer, request)
	})
}

func run(ctx context.Context, config options, auditOutput io.Writer) error {
	api, health, verifier, err := newServers(config, auditOutput)
	if err != nil {
		return err
	}
	boundary, ok := api.Handler.(*apiserver.Server)
	if !ok {
		return errors.New("API operation boundary unavailable")
	}
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return errors.New("API Kubernetes configuration unavailable")
	}
	clusterConfig.Timeout = 10 * time.Second
	scheme := runtime.NewScheme()
	if arcadev1.AddToScheme(scheme) != nil {
		return errors.New("API resource schema unavailable")
	}
	clusterClient, err := client.New(clusterConfig, client.Options{Scheme: scheme})
	if err != nil {
		return errors.New("API Kubernetes client unavailable")
	}
	gameCatalog, err := catalog.Builtins()
	if err != nil {
		return errors.New("API game catalog unavailable")
	}
	if err := boundary.RegisterOperations(apiserver.OperationsConfig{Store: apiserver.NewKubernetesReceiptStore(clusterClient, clusterClient), Catalog: gameCatalog, Resolver: platformimage.NewRegistryResolver()}); err != nil {
		return errors.New("API operation routes unavailable")
	}
	apiListener, err := net.Listen("tcp", config.listen)
	if err != nil {
		return errors.New("API listener unavailable")
	}
	defer apiListener.Close()
	healthListener, err := net.Listen("tcp", config.healthListen)
	if err != nil {
		return errors.New("API health listener unavailable")
	}
	defer healthListener.Close()
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	reloadDone := make(chan struct{})
	go func() {
		defer close(reloadDone)
		_ = verifier.Run(workerContext, time.Second)
	}()
	serveErrors := make(chan error, 2)
	go func() { serveErrors <- api.ServeTLS(apiListener, "", "") }()
	go func() { serveErrors <- health.Serve(healthListener) }()
	var serveError error
	select {
	case <-ctx.Done():
	case err := <-serveErrors:
		if err != nil && !isServerClosed(err) {
			serveError = errors.New("API serving failed")
		}
	}
	cancel()
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	// Stop admission first, then the private health server; forced Close only
	// follows the bounded graceful shutdown deadline.
	if api.Shutdown(shutdownContext) != nil {
		_ = api.Close()
	}
	if health.Shutdown(shutdownContext) != nil {
		_ = health.Close()
	}
	<-reloadDone
	return serveError
}

func isServerClosed(err error) bool { return errors.Is(err, http.ErrServerClosed) }

func main() {
	// A closed stdout audit pipe must become a guarded write failure rather
	// than terminating the process before an applied mutation's truthful reply.
	disableAuditPipeTermination()
	config, err := parseOptions(os.Args[1:])
	if err == nil {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		err = run(ctx, config, os.Stdout)
	}
	if err != nil {
		// All errors returned above are fixed, credential-free operational text.
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func disableAuditPipeTermination() { signal.Ignore(syscall.SIGPIPE) }

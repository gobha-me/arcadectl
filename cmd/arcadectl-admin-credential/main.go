// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const defaultCredentialLifetime = 30 * 24 * time.Hour

const defaultActivationPollInterval = time.Second

type commandOptions struct {
	command       string
	output        string
	kubeconfig    string
	kubeContext   string
	lifetime      time.Duration
	timeout       time.Duration
	apiURL        string
	caFile        string
	tlsServerName string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	options, err := parseOptions(arguments)
	if err != nil {
		_, _ = io.WriteString(stderr, "invalid administrator credential command\n")
		return 2
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = options.kubeconfig
	overrides := &clientcmd.ConfigOverrides{CurrentContext: options.kubeContext}
	configuration, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides).ClientConfig()
	if err != nil {
		_, _ = io.WriteString(stderr, "Kubernetes administrator configuration is unavailable\n")
		return 3
	}
	client, err := kubernetes.NewForConfig(configuration)
	if err != nil {
		_, _ = io.WriteString(stderr, "Kubernetes administrator client is unavailable\n")
		return 3
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	cluster := clientGoAccess{client: client}
	switch options.command {
	case "init":
		err = initializeCredential(ctx, cluster, options.output, time.Now(), options.lifetime)
		if err == nil {
			_, _ = io.WriteString(stdout, "administrator credential initialized; API activation not yet verified\n")
			return 0
		}
	case "rotate":
		var probe *httpCredentialProbe
		probe, err = newHTTPCredentialProbe(options.apiURL, options.caFile, options.tlsServerName)
		if err == nil {
			err = rotateCredential(ctx, cluster, probe, options.output, time.Now(), options.lifetime, defaultActivationPollInterval)
		}
		if err == nil {
			_, _ = io.WriteString(stdout, "administrator credential rotated and activated\n")
			return 0
		}
	}
	writeFixedFailure(stderr, err)
	return failureExitCode(err)
}

func parseOptions(arguments []string) (commandOptions, error) {
	if len(arguments) == 0 || (arguments[0] != "init" && arguments[0] != "rotate") {
		return commandOptions{}, errors.New("invalid command")
	}
	options := commandOptions{command: arguments[0], lifetime: defaultCredentialLifetime, timeout: 5 * time.Minute}
	flags := flag.NewFlagSet(arguments[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.output, "output", "", "private credential output path")
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "Kubernetes administrator configuration")
	flags.StringVar(&options.kubeContext, "context", "", "Kubernetes context")
	flags.DurationVar(&options.lifetime, "lifetime", options.lifetime, "credential lifetime")
	flags.DurationVar(&options.timeout, "timeout", options.timeout, "operation timeout")
	if options.command == "rotate" {
		flags.StringVar(&options.apiURL, "api-url", "", "trusted Arcadectl API self endpoint")
		flags.StringVar(&options.caFile, "ca-file", "", "trusted API certificate authority")
		flags.StringVar(&options.tlsServerName, "tls-server-name", "", "trusted API TLS server name")
	}
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || options.output == "" || options.lifetime <= 0 || options.timeout <= 0 {
		return commandOptions{}, errors.New("invalid options")
	}
	if options.command == "rotate" && (options.apiURL == "" || options.caFile == "") {
		return commandOptions{}, errors.New("rotation probe is required")
	}
	return options, nil
}

func writeFixedFailure(writer io.Writer, err error) {
	switch {
	case errors.Is(err, errPrivateOutput):
		_, _ = io.WriteString(writer, "private credential output failed before a confirmed cluster mutation\n")
	case errors.Is(err, errCredentialConflict):
		_, _ = io.WriteString(writer, "credential mutation conflicted and was not retried; private output was retained but is inactive\n")
	case errors.Is(err, errMutationUnconfirmed):
		_, _ = io.WriteString(writer, "credential mutation is unconfirmed; private output was retained\n")
	case errors.Is(err, errTopologyUnavailable):
		_, _ = io.WriteString(writer, "API topology is not eligible for credential rotation; no mutation was attempted\n")
	case errors.Is(err, errActivationIncomplete):
		_, _ = io.WriteString(writer, "credential activation is incomplete; private output and committed Secret were retained\n")
	default:
		_, _ = io.WriteString(writer, "administrator credential operation failed safely\n")
	}
}

func failureExitCode(err error) int {
	switch {
	case errors.Is(err, errCredentialConflict):
		return 4
	case errors.Is(err, errMutationUnconfirmed):
		return 5
	case errors.Is(err, errActivationIncomplete), errors.Is(err, errTopologyUnavailable):
		return 6
	default:
		return 3
	}
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// arcadectl-installer is a separate Kubernetes administrator boundary. At this
// checkpoint only read-only recovery inspection is available; lifecycle effects
// require the complete closed proof provider, never partial successful checks.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gobha-me/arcadectl/internal/installengine"
	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	yamlstream "go.yaml.in/yaml/v3"
	"k8s.io/client-go/rest"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	strictjson "sigs.k8s.io/json"
	"sigs.k8s.io/yaml"
)

const usage = "usage: arcadectl-installer inspect --namespace NAME --profile ID --bootstrap-package ABS_PATH --package ABS_PATH [--package ABS_PATH ...] --trust-key ABS_PATH --state-dir ABS_PATH --bootstrap-receipt NAME --kubeconfig ABS_PATH --context NAME [--timeout 5m]\nRead-only recovery inspection; lifecycle mutation commands remain unavailable.\n"

var errArguments = errors.New("invalid installation inspection arguments")
var errInputs = errors.New("trusted installation inspection inputs are unavailable or invalid")

type packagePaths []string

func (p *packagePaths) String() string { return "" }
func (p *packagePaths) Set(value string) error {
	if len(*p) >= 3 || !absolutePath(value) {
		return errArguments
	}
	*p = append(*p, value)
	return nil
}

type options struct {
	namespace, profile, bootstrapPackage, trustKey, stateDir, receipt, kubeconfig, kubeContext string
	packages                                                                                   packagePaths
	timeout                                                                                    time.Duration
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	cancel()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return 1
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help") {
		if n, err := io.WriteString(stdout, usage); err != nil || n != len(usage) {
			_, _ = io.WriteString(stderr, "installation inspection output unavailable\n")
			return 1
		}
		return 0
	}
	o, err := parseOptions(args)
	if err != nil {
		_, _ = io.WriteString(stderr, errArguments.Error()+"\n")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	if ctx.Err() != nil {
		_, _ = io.WriteString(stderr, installengine.ErrRecovery.Error()+"\n")
		return 4
	}
	reporter, receipt, files, err := loadReporter(o)
	if err != nil {
		_, _ = io.WriteString(stderr, errInputs.Error()+"\n")
		return 3
	}
	defer files.Close()
	report, err := reporter.Collect(ctx, receipt)
	if err != nil || ctx.Err() != nil {
		_, _ = io.WriteString(stderr, installengine.ErrRecovery.Error()+"\n")
		return 4
	}
	body := report.Bytes()
	if n, err := stdout.Write(body); err != nil || n != len(body) {
		_, _ = io.WriteString(stderr, "installation inspection output unavailable; no cluster effects were requested\n")
		return 1
	}
	return 0
}

func absolutePath(value string) bool {
	return value != "/" && len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func parseOptions(args []string) (options, error) {
	o := options{}
	if len(args) == 0 || args[0] != "inspect" {
		return o, errArguments
	}
	set := flag.NewFlagSet("inspect", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&o.namespace, "namespace", "", "explicit original installation namespace")
	set.StringVar(&o.profile, "profile", "", "explicit signed profile")
	set.StringVar(&o.bootstrapPackage, "bootstrap-package", "", "original signed bootstrap package")
	set.Var(&o.packages, "package", "current trusted package (one to three)")
	set.StringVar(&o.trustKey, "trust-key", "", "external trust key")
	set.StringVar(&o.stateDir, "state-dir", "", "existing protected receipts directory")
	set.StringVar(&o.receipt, "bootstrap-receipt", "", "original receipt filename")
	set.StringVar(&o.kubeconfig, "kubeconfig", "", "explicit protected static Kubernetes configuration")
	set.StringVar(&o.kubeContext, "context", "", "explicit Kubernetes context")
	set.DurationVar(&o.timeout, "timeout", 5*time.Minute, "bounded inspection timeout")
	if set.Parse(args[1:]) != nil || set.NArg() != 0 || !installrender.ValidNamespace(o.namespace) || o.profile == "" || o.kubeContext == "" || o.receipt == "" || len(o.packages) == 0 || o.timeout < time.Second || o.timeout > 5*time.Minute {
		return options{}, errArguments
	}
	for _, path := range []string{o.bootstrapPackage, o.trustKey, o.stateDir, o.kubeconfig} {
		if !absolutePath(path) {
			return options{}, errArguments
		}
	}
	return o, nil
}

func loadReporter(o options) (*installengine.RecoveryReporter, *installstate.BootstrapReceipt, *privatefs.Store, error) {
	trust, err := installfiles.ReadTrustKey(o.trustKey)
	if err != nil {
		return nil, nil, nil, errInputs
	}
	bootstrap, err := installfiles.Load(o.bootstrapPackage, trust)
	if err != nil {
		return nil, nil, nil, errInputs
	}
	original, err := installrender.Compile(bootstrap, o.namespace, o.profile)
	if err != nil {
		return nil, nil, nil, errInputs
	}
	plans := []*installrender.Plan{}
	for _, path := range o.packages {
		pkg, err := installfiles.Load(path, trust)
		if err != nil {
			return nil, nil, nil, errInputs
		}
		plan, err := installrender.Compile(pkg, o.namespace, o.profile)
		if err != nil {
			return nil, nil, nil, errInputs
		}
		plans = append(plans, plan)
	}
	configuration, err := loadStaticConfig(o)
	if err != nil {
		return nil, nil, nil, errInputs
	}
	access, err := installengine.NewHTTPAccess(configuration)
	if err != nil {
		return nil, nil, nil, errInputs
	}
	files, err := privatefs.Open(o.stateDir, false)
	if err != nil {
		return nil, nil, nil, errInputs
	}
	fail := func() (*installengine.RecoveryReporter, *installstate.BootstrapReceipt, *privatefs.Store, error) {
		_ = files.Close()
		return nil, nil, nil, errInputs
	}
	receipt, err := installstate.LoadBootstrap(files, o.receipt, original)
	if err != nil {
		return fail()
	}
	store, err := installstate.New(access.Namespaces(), plans...)
	if err != nil {
		return fail()
	}
	engine, err := installengine.NewWithAccess(access, store, files, plans...)
	if err != nil {
		return fail()
	}
	reporter, err := installengine.NewRecoveryReporter(engine, access)
	if err != nil {
		return fail()
	}
	return reporter, receipt, files, nil
}

// Parse a bounded protected snapshot and construct static REST configuration
// directly. No SDK loader/converter may open reference files, invoke plugins,
// select defaults, strip URL parts, merge environment or persist credentials.
// NewHTTPAccess freezes the remaining selected absolute file references using
// protected reads BEFORE constructing the actual HTTP transport.
func loadStaticConfig(o options) (*rest.Config, error) {
	body, _, err := privatefs.ReadAbsolute(o.kubeconfig, 1024*1024, privatefs.Private)
	if err != nil {
		return nil, errInputs
	}
	// YAMLToJSONStrict alone consumes only the first YAML document. Validate
	// the complete stream without expanding alias nodes before typed decoding.
	stream := yamlstream.NewDecoder(bytes.NewReader(body))
	var document, trailing yamlstream.Node
	if stream.Decode(&document) != nil || stream.Decode(&trailing) != io.EOF {
		return nil, errInputs
	}
	jsonBody, err := yaml.YAMLToJSONStrict(body)
	if err != nil {
		return nil, errInputs
	}
	var raw configv1.Config
	strictErrors, err := strictjson.UnmarshalStrict(jsonBody, &raw)
	if err != nil || len(strictErrors) != 0 || raw.Kind != "Config" || raw.APIVersion != "v1" {
		return nil, errInputs
	}
	var selected *configv1.Context
	contexts := map[string]bool{}
	for i := range raw.Contexts {
		entry := &raw.Contexts[i]
		if entry.Name == "" || contexts[entry.Name] {
			return nil, errInputs
		}
		contexts[entry.Name] = true
		if entry.Name == o.kubeContext {
			selected = &entry.Context
		}
	}
	if selected == nil || selected.Cluster == "" || selected.AuthInfo == "" || selected.Namespace != "" && selected.Namespace != o.namespace {
		return nil, errInputs
	}
	var cluster *configv1.Cluster
	clusters := map[string]bool{}
	for i := range raw.Clusters {
		entry := &raw.Clusters[i]
		if entry.Name == "" || clusters[entry.Name] {
			return nil, errInputs
		}
		clusters[entry.Name] = true
		if entry.Name == selected.Cluster {
			cluster = &entry.Cluster
		}
	}
	var auth *configv1.AuthInfo
	users := map[string]bool{}
	for i := range raw.AuthInfos {
		entry := &raw.AuthInfos[i]
		if entry.Name == "" || users[entry.Name] {
			return nil, errInputs
		}
		users[entry.Name] = true
		if entry.Name == selected.AuthInfo {
			auth = &entry.AuthInfo
		}
	}
	if cluster == nil || auth == nil || cluster.InsecureSkipTLSVerify || cluster.ProxyURL != "" || cluster.CertificateAuthority == "" && len(cluster.CertificateAuthorityData) == 0 || auth.Exec != nil || auth.AuthProvider != nil || auth.Impersonate != "" || auth.ImpersonateUID != "" || len(auth.ImpersonateGroups) != 0 || len(auth.ImpersonateUserExtra) != 0 {
		return nil, errInputs
	}
	endpoint, err := url.Parse(cluster.Server)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || strings.ContainsAny(cluster.Server, "?#") || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" || endpoint.RawPath != "" || endpoint.Path != "" && endpoint.Path != "/" {
		return nil, errInputs
	}
	for _, source := range []struct {
		path string
		data []byte
	}{{cluster.CertificateAuthority, cluster.CertificateAuthorityData}, {auth.ClientCertificate, auth.ClientCertificateData}, {auth.ClientKey, auth.ClientKeyData}} {
		if source.path != "" && (!absolutePath(source.path) || len(source.data) != 0) {
			return nil, errInputs
		}
	}
	if auth.TokenFile != "" && (!absolutePath(auth.TokenFile) || auth.Token != "") {
		return nil, errInputs
	}
	cert := auth.ClientCertificate != "" || len(auth.ClientCertificateData) != 0
	key := auth.ClientKey != "" || len(auth.ClientKeyData) != 0
	if cert != key {
		return nil, errInputs
	}
	bearer := auth.Token != "" || auth.TokenFile != ""
	basic := auth.Username != "" || auth.Password != ""
	if basic && (auth.Username == "" || auth.Password == "") {
		return nil, errInputs
	}
	methods := 0
	for _, present := range []bool{cert, bearer, basic} {
		if present {
			methods++
		}
	}
	if methods != 1 || len(auth.Token) > 65536 || strings.ContainsAny(auth.Token, "\r\n\t ") {
		return nil, errInputs
	}
	return &rest.Config{Host: cluster.Server, Username: auth.Username, Password: auth.Password, BearerToken: auth.Token, BearerTokenFile: auth.TokenFile,
		TLSClientConfig: rest.TLSClientConfig{ServerName: cluster.TLSServerName, CAFile: cluster.CertificateAuthority, CAData: cluster.CertificateAuthorityData,
			CertFile: auth.ClientCertificate, CertData: auth.ClientCertificateData, KeyFile: auth.ClientKey, KeyData: auth.ClientKeyData},
		DisableCompression: cluster.DisableCompression, Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }}, nil
}

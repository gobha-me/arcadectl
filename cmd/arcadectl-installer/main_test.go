// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installengine"
	"golang.org/x/sys/unix"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

func staticFixture(t *testing.T) (options, configv1.Config) {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	o := options{namespace: "isolated-install", kubeContext: "explicit", kubeconfig: filepath.Join(base, "kubeconfig.json")}
	raw := configv1.Config{Kind: "Config", APIVersion: "v1", CurrentContext: "wrong-default",
		Contexts:  []configv1.NamedContext{{Name: "explicit", Context: configv1.Context{Cluster: "cluster", AuthInfo: "admin", Namespace: o.namespace}}},
		Clusters:  []configv1.NamedCluster{{Name: "cluster", Cluster: configv1.Cluster{Server: "https://cluster.example", CertificateAuthorityData: []byte("FAKE-CA")}}},
		AuthInfos: []configv1.NamedAuthInfo{{Name: "admin", AuthInfo: configv1.AuthInfo{Token: "PRIVATE-CANARY"}}}}
	return o, raw
}

func writeStatic(t *testing.T, o options, raw configv1.Config) {
	t.Helper()
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.kubeconfig, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestStaticConfigurationUsesOnlyExplicitContextAndNoEnvironmentRouting(t *testing.T) {
	o, raw := staticFixture(t)
	writeStatic(t, o, raw)
	t.Setenv("KUBECONFIG", "PRIVATE-CANARY")
	t.Setenv("HTTPS_PROXY", "http://PRIVATE-CANARY.invalid")
	t.Setenv("SSL_CERT_FILE", "PRIVATE-CANARY")
	c, err := loadStaticConfig(o)
	if err != nil || c == nil || c.Host != "https://cluster.example" || c.BearerToken != "PRIVATE-CANARY" || c.ExecProvider != nil || c.AuthProvider != nil || c.Proxy != nil {
		t.Fatal("explicit static configuration not preserved")
	}
	// The installer explicitly selects NewDirectHTTPAccess at the connection
	// boundary. No arbitrary routing callback is carried in its input config.
}

func TestStaticConfigurationRefusesAmbiguousOrImplicitInputs(t *testing.T) {
	for _, fault := range []string{"missing-context", "missing-cluster", "missing-user", "duplicate-context", "duplicate-cluster", "duplicate-user", "namespace", "exec", "auth-provider", "impersonate", "impersonate-uid", "impersonate-groups", "impersonate-extra", "proxy", "insecure", "missing-ca", "ca-conflict", "http", "userinfo", "query", "empty-query", "fragment", "empty-fragment", "path", "raw-path", "anonymous", "mixed-auth", "missing-cert", "partial-basic", "relative-ca", "relative-token", "token-conflict", "bad-token", "unknown-field", "field-alias", "duplicate-key", "multi-document", "empty-document", "trailing-garbage", "unsafe-file", "symlink"} {
		t.Run(fault, func(t *testing.T) {
			o, raw := staticFixture(t)
			a, c := &raw.AuthInfos[0].AuthInfo, &raw.Clusters[0].Cluster
			switch fault {
			case "missing-context":
				o.kubeContext = "absent"
			case "missing-cluster":
				raw.Contexts[0].Context.Cluster = "absent"
			case "missing-user":
				raw.Contexts[0].Context.AuthInfo = "absent"
			case "duplicate-context":
				raw.Contexts = append(raw.Contexts, raw.Contexts[0])
			case "duplicate-cluster":
				raw.Clusters = append(raw.Clusters, raw.Clusters[0])
			case "duplicate-user":
				raw.AuthInfos = append(raw.AuthInfos, raw.AuthInfos[0])
			case "namespace":
				raw.Contexts[0].Context.Namespace = "foreign"
			case "exec":
				a.Exec = &configv1.ExecConfig{Command: "PRIVATE-CANARY"}
			case "auth-provider":
				a.AuthProvider = &configv1.AuthProviderConfig{Name: "PRIVATE-CANARY"}
			case "impersonate":
				a.Impersonate = "PRIVATE-CANARY"
			case "impersonate-uid":
				a.ImpersonateUID = "PRIVATE-CANARY"
			case "impersonate-groups":
				a.ImpersonateGroups = []string{"PRIVATE-CANARY"}
			case "impersonate-extra":
				a.ImpersonateUserExtra = map[string][]string{"private": {"PRIVATE-CANARY"}}
			case "proxy":
				c.ProxyURL = "http://PRIVATE-CANARY.invalid"
			case "insecure":
				c.InsecureSkipTLSVerify = true
			case "missing-ca":
				c.CertificateAuthorityData = nil
			case "ca-conflict":
				c.CertificateAuthority = "/PRIVATE-CANARY"
			case "http":
				c.Server = "http://PRIVATE-CANARY.invalid"
			case "userinfo":
				c.Server = "https://PRIVATE-CANARY@cluster.example"
			case "query":
				c.Server += "?PRIVATE-CANARY"
			case "empty-query":
				c.Server += "?"
			case "fragment":
				c.Server += "#PRIVATE-CANARY"
			case "empty-fragment":
				c.Server += "#"
			case "path":
				c.Server += "/PRIVATE-CANARY"
			case "raw-path":
				c.Server += "/%2f"
			case "anonymous":
				a.Token = ""
			case "mixed-auth":
				a.Username, a.Password = "admin", "PRIVATE-CANARY"
			case "missing-cert":
				a.Token = ""
				a.ClientKeyData = []byte("PRIVATE-CANARY")
			case "partial-basic":
				a.Token = ""
				a.Username = "PRIVATE-CANARY"
			case "relative-ca":
				c.CertificateAuthorityData = nil
				c.CertificateAuthority = "PRIVATE-CANARY"
			case "relative-token":
				a.Token = ""
				a.TokenFile = "PRIVATE-CANARY"
			case "token-conflict":
				a.TokenFile = "/PRIVATE-CANARY"
			case "bad-token":
				a.Token = "PRIVATE-CANARY\n"
			}
			writeStatic(t, o, raw)
			body, err := os.ReadFile(o.kubeconfig)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "unknown-field":
				body = append([]byte(`{"PRIVATE-CANARY":true,`), body[1:]...)
			case "field-alias":
				body = bytes.Replace(body, []byte(`"server"`), []byte(`"Server"`), 1)
			case "duplicate-key":
				body = append([]byte(`{"kind":"PRIVATE-CANARY",`), body[1:]...)
			case "multi-document":
				body = append(body, []byte("\n---\nkind: PRIVATE-CANARY\n")...)
			case "empty-document":
				body = append(body, []byte("\n---\n")...)
			case "trailing-garbage":
				body = append(body, []byte("\nPRIVATE-CANARY")...)
			}
			if err := os.WriteFile(o.kubeconfig, body, 0600); err != nil {
				t.Fatal(err)
			}
			if fault == "unsafe-file" {
				if err := os.Chmod(o.kubeconfig, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "symlink" {
				original := o.kubeconfig
				o.kubeconfig = filepath.Join(filepath.Dir(original), "linked")
				if err := os.Symlink(original, o.kubeconfig); err != nil {
					t.Fatal(err)
				}
			}
			cOut, err := loadStaticConfig(o)
			if err == nil || cOut != nil || strings.Contains(err.Error(), "PRIVATE-CANARY") {
				t.Fatal("unsafe input accepted or reflected")
			}
		})
	}
}

func TestSelectedReferenceFilesRemainProtectedBeforeAnySDKOpen(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("configuration validation contacted network") }))
	defer server.Close()
	for _, special := range []string{"fifo", "symlink", "world-readable"} {
		t.Run(special, func(t *testing.T) {
			o, raw := staticFixture(t)
			raw.Clusters[0].Cluster.CertificateAuthorityData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			path := filepath.Join(filepath.Dir(o.kubeconfig), "token")
			switch special {
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("/PRIVATE-CANARY", path); err != nil {
					t.Fatal(err)
				}
			case "world-readable":
				if err := os.WriteFile(path, []byte("PRIVATE-CANARY"), 0644); err != nil {
					t.Fatal(err)
				}
				// The negative fixture must remain world-readable even when
				// tests run under the administrator's protective umask.
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			raw.AuthInfos[0].AuthInfo.Token = ""
			raw.AuthInfos[0].AuthInfo.TokenFile = path
			writeStatic(t, o, raw)
			c, err := loadStaticConfig(o)
			if err != nil {
				t.Fatal("reference must reach protected snapshot boundary")
			}
			if access, err := installengine.NewDirectHTTPAccess(c); err == nil || access != nil || strings.Contains(err.Error(), "PRIVATE-CANARY") {
				t.Fatal("unsafe token reference admitted")
			}
		})
	}
}

func TestProtectedStaticTokenFileIsFrozenBeforeTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("configuration validation contacted network") }))
	defer server.Close()
	o, raw := staticFixture(t)
	path := filepath.Join(filepath.Dir(o.kubeconfig), "token")
	if err := os.WriteFile(path, []byte("PRIVATE-CANARY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw.Clusters[0].Cluster.CertificateAuthorityData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	raw.AuthInfos[0].AuthInfo.Token = ""
	raw.AuthInfos[0].AuthInfo.TokenFile = path
	writeStatic(t, o, raw)
	c, err := loadStaticConfig(o)
	if err != nil {
		t.Fatal(err)
	}
	if access, err := installengine.NewDirectHTTPAccess(c); err != nil || access == nil {
		t.Fatal("protected static reference rejected", err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("PRIVATE-CANARY") }

func TestInspectionArgumentAndOutputBoundaries(t *testing.T) {
	for _, args := range [][]string{nil, {"install"}, {"inspect", "--token", "PRIVATE-CANARY"}, {"inspect", "--kubeconfig", "PRIVATE-CANARY"}} {
		var out, diagnostics bytes.Buffer
		if code := run(context.Background(), args, &out, &diagnostics); code != 2 || out.Len() != 0 || strings.Contains(diagnostics.String(), "PRIVATE-CANARY") {
			t.Fatal("argument error reflected or effects allowed")
		}
	}
	for _, writer := range []io.Writer{shortWriter{}, brokenWriter{}} {
		var diagnostics bytes.Buffer
		if code := run(context.Background(), []string{"--help"}, writer, &diagnostics); code != 1 || strings.Contains(diagnostics.String(), "PRIVATE-CANARY") {
			t.Fatal("output error hidden/reflected")
		}
	}
	var out, diagnostics bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &out, &diagnostics); code != 0 || out.String() != usage || diagnostics.Len() != 0 {
		t.Fatal("help requires external inputs")
	}
}

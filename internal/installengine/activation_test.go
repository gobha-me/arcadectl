// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/apiserver"
)

// A real HTTPS boundary, verifier and client authenticate over an owned test
// connection. Kubernetes workload observations are fixtures, not a running Pod
// or full installer lifecycle claim. The dial seam is private to this package.
func activationServer(t *testing.T, x *servingFixture, namespace string, onRequest func()) *atomic.Int32 {
	t.Helper()
	verifierFile := filepath.Join(filepath.Dir(x.tls.KeyFile), "verifier.json")
	if os.WriteFile(verifierFile, x.secrets.objects[adminauth.CredentialSecretName].Data[adminauth.VerifierSecretKey], 0600) != nil {
		t.Fatal("verifier fixture")
	}
	verifier := adminauth.NewFileVerifier(verifierFile, time.Now)
	if err := verifier.Reload(); err != nil {
		t.Fatal(err)
	}
	boundary, err := apiserver.New(apiserver.Config{Authenticator: verifier, Authorizer: apiserver.AdministratorAuthorizer{}, Audit: apiserver.NewJSONAudit(io.Discard), Namespace: namespace})
	if err != nil {
		t.Fatal(err)
	}
	requests := &atomic.Int32{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/v1/auth/self" || r.ProtoMajor != 1 {
			t.Error("activation used unexpected route")
		}
		if onRequest != nil {
			onRequest()
		}
		boundary.ServeHTTP(w, r)
	}))
	pair, err := tls.LoadX509KeyPair(x.tls.CertificateFile, x.tls.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	x.activation.dial = func(ctx context.Context, proved *Serving) (net.Conn, error) {
		if proved.namespace != x.f.plan.Namespace() || proved.podUID != "original-pod" || proved.address != "10.244.0.10" {
			t.Error("dial was not derived from original serving evidence")
			return nil, ErrActivation
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	return requests
}

func TestActivationAuthenticatesRealHTTPSBoundaryWithoutMutations(t *testing.T) {
	x := newServingFixture(t)
	requests := activationServer(t, x, x.f.plan.Namespace(), nil)
	before := x.f.snapshot.Bytes()
	if err := x.activation.VerifyDirect(context.Background(), x.f.snapshot, x.options); err != nil {
		t.Fatal("real activation failed", err)
	}
	after, err := x.f.store.Load(context.Background(), x.f.snapshot.Anchor())
	if err != nil || string(before) != string(after.Bytes()) || requests.Load() != 1 || x.secrets.writes != 2 {
		t.Fatal("activation changed journal or Secrets, or repeated authentication")
	}
}

func TestActivationRefusesRouteAndCredentialDrift(t *testing.T) {
	for _, change := range []string{"wrong-namespace", "pod-at-dial", "secret-at-dial", "secret-rv-at-dial", "file-at-dial", "pod-after-auth", "secret-after-auth", "secret-rv-after-auth", "file-after-auth", "untrusted-ca", "foreign-client", "changed-secret-read"} {
		t.Run(change, func(t *testing.T) {
			x := newServingFixture(t)
			namespace := x.f.plan.Namespace()
			if change == "wrong-namespace" {
				namespace = "foreign-installation"
			}
			mutate := func() {
				switch change {
				case "pod-at-dial", "pod-after-auth":
					x.access.pod.ResourceVersion = "11"
				case "secret-at-dial", "secret-after-auth", "changed-secret-read":
					x.secrets.objects[adminauth.CredentialSecretName].UID = "foreign-secret"
				case "secret-rv-at-dial", "secret-rv-after-auth":
					x.secrets.objects[adminauth.CredentialSecretName].ResourceVersion = "11"
				case "file-at-dial", "file-after-auth":
					body, err := os.ReadFile(x.options.CredentialFile)
					if err != nil || os.WriteFile(x.options.CredentialFile, append(body, '\n'), 0600) != nil {
						t.Error("fixture file drift")
					}
				}
			}
			var onRequest func()
			if change == "pod-after-auth" || change == "secret-after-auth" || change == "secret-rv-after-auth" || change == "file-after-auth" {
				onRequest = mutate
			}
			requests := activationServer(t, x, namespace, onRequest)
			if change == "pod-at-dial" || change == "secret-at-dial" || change == "secret-rv-at-dial" || change == "file-at-dial" {
				originalDial := x.activation.dial
				x.activation.dial = func(ctx context.Context, s *Serving) (net.Conn, error) {
					conn, err := originalDial(ctx, s)
					mutate()
					return conn, err
				}
			}
			if change == "changed-secret-read" {
				// Mutation on the validated GET itself must not be laundered by
				// a previous successful check followed by an unvalidated reread.
				x.secrets.get = func(name string) error {
					if name == adminauth.CredentialSecretName {
						mutate()
					}
					return nil
				}
			}
			if change == "untrusted-ca" {
				other := fixtureTLS(t, namespace, time.Now())
				x.options.CAFile = other.CAFile
			}
			if change == "foreign-client" {
				other := newServingFixture(t)
				x.options.CredentialFile = other.options.CredentialFile
			}
			err := x.activation.VerifyDirect(context.Background(), x.f.snapshot, x.options)
			if !errors.Is(err, ErrActivation) || err.Error() != ErrActivation.Error() {
				t.Fatal("drift accepted or private diagnostic exposed")
			}
			want := int32(0)
			if onRequest != nil || change == "wrong-namespace" {
				want = 1
			}
			if requests.Load() != want {
				t.Fatal("credentials left an unproved connection or authentication retried")
			}
		})
	}
}

func TestActivationPinsServingTLSLeafBeforeAuthorization(t *testing.T) {
	for _, change := range []string{"same-ca-san-other-leaf", "wrong-san", "expired-leaf", "other-ca"} {
		t.Run(change, func(t *testing.T) {
			x := newServingFixture(t)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "different test-only API"}, DNSNames: []string{"arcadectl-api." + x.f.plan.Namespace() + ".svc"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if change == "wrong-san" {
				leaf.DNSNames = []string{"foreign.svc"}
			}
			if change == "expired-leaf" {
				leaf.NotBefore, leaf.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
			}
			if change == "other-ca" {
				other := fixtureTLS(t, x.f.plan.Namespace(), now)
				x.tls.CertificateFile, x.tls.KeyFile = other.CertificateFile, other.KeyFile
			} else {
				der, err := x509.CreateCertificate(rand.Reader, leaf, x.issuer, &key.PublicKey, x.issuerKey)
				if err != nil {
					t.Fatal(err)
				}
				pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				if os.WriteFile(x.tls.CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600) != nil || os.WriteFile(x.tls.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600) != nil {
					t.Fatal("alternate test-only certificate")
				}
			}
			requests := activationServer(t, x, x.f.plan.Namespace(), nil)
			if err := x.activation.VerifyDirect(context.Background(), x.f.snapshot, x.options); !errors.Is(err, ErrActivation) || requests.Load() != 0 {
				t.Fatal("foreign TLS peer received authorization or activation succeeded")
			}
		})
	}
}

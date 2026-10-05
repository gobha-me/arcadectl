// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func fixtureTLS(t *testing.T, namespace string, now time.Time) CredentialOptions {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test-only API"}, DNSNames: []string{"arcadectl-api." + namespace + ".svc"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	if os.Chmod(base, 0700) != nil {
		t.Fatal("private fixture")
	}
	opts := CredentialOptions{Now: now, AdminLifetime: time.Hour, CertificateFile: filepath.Join(base, "certificate.pem"), KeyFile: filepath.Join(base, "key.pem"), CAFile: filepath.Join(base, "ca.pem")}
	for path, body := range map[string][]byte{opts.CertificateFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), opts.KeyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), opts.CAFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})} {
		if os.WriteFile(path, body, 0600) != nil {
			t.Fatal("private fixture file")
		}
	}
	return opts
}

type fakePrivateSecrets struct {
	f               *fixture
	objects         map[string]*corev1.Secret
	writes, dryRuns int
	write           func(*corev1.Secret) (*corev1.Secret, error)
	get             func(string) error
	dry             func(*corev1.Secret) *corev1.Secret
}

func (a *fakePrivateSecrets) Get(_ context.Context, namespace, name string) (*corev1.Secret, error) {
	if namespace != a.f.plan.Namespace() {
		a.f.access.t.Fatal("wrong private namespace")
	}
	if a.get != nil {
		if err := a.get(name); err != nil {
			return nil, err
		}
	}
	if o := a.objects[name]; o != nil {
		return o.DeepCopy(), nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
}
func (a *fakePrivateSecrets) Create(ctx context.Context, o *corev1.Secret, dry bool) (*corev1.Secret, error) {
	if dry {
		a.dryRuns++
		if a.dry != nil {
			return a.dry(o.DeepCopy()), nil
		}
		return o.DeepCopy(), nil
	}
	a.writes++
	s, err := a.f.store.Load(ctx, a.f.snapshot.Anchor())
	if err != nil {
		a.f.access.t.Fatal(err)
	}
	p := s.Document().Pending
	if p == nil || p.Action != installstate.Create || p.Key != secretKey(o.Namespace, o.Name) || p.CreateNonce != o.Annotations[installstate.MutationAnnotation] || p.AfterSHA256 != "" {
		a.f.access.t.Fatal("private effect without exact public intent")
	}
	// Check standard private output exists BEFORE effect, without printing it.
	if _, _, err := a.f.engine.files.Read("admin-client-"+s.Anchor().InstallationID+".json", 4096); err != nil {
		a.f.access.t.Fatal("private client not saved")
	}
	if _, _, err := a.f.engine.files.Read("api-ca-"+s.Anchor().InstallationID+".pem", 65536); err != nil {
		a.f.access.t.Fatal("CA output not saved")
	}
	if a.write != nil {
		return a.write(o.DeepCopy())
	}
	result := o.DeepCopy()
	result.UID = types.UID("original-" + o.Name)
	result.ResourceVersion = fmt.Sprint(a.writes + 100)
	a.objects[o.Name] = result.DeepCopy()
	return result, nil
}
func secretFixture(t *testing.T) (*fixture, *SecretWorkflow, *fakePrivateSecrets, *Credentials, CredentialOptions) {
	t.Helper()
	f := newFixture(t, false)
	now := time.Date(2026, 10, 5, 21, 0, 0, 0, time.UTC)
	opts := fixtureTLS(t, f.plan.Namespace(), now)
	c, err := f.engine.PrepareCredentials(context.Background(), f.snapshot, opts)
	if err != nil {
		t.Fatal(err)
	}
	access := &fakePrivateSecrets{f: f, objects: map[string]*corev1.Secret{}}
	w, err := NewSecretWorkflow(f.engine, access)
	if err != nil {
		t.Fatal(err)
	}
	return f, w, access, c, opts
}

func TestPrepareAndResumeCredentialsPreservePrivateMaterialAndRedactFormatting(t *testing.T) {
	f, _, _, c, opts := secretFixture(t)
	resumed, err := f.engine.LoadCredentials(context.Background(), f.snapshot, opts.Now.Add(time.Minute))
	if err != nil || !bytes.Equal(c.body, resumed.body) {
		t.Fatal("resume changed private candidate")
	}
	private, err := adminauth.ParseClientCredential(c.admin.PrivateBytes())
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprint(c), fmt.Sprintf("%#v", c), fmt.Sprint(c.admin), fmt.Sprintf("%#v", c.admin)} {
		if strings.Contains(formatted, private.Token) || strings.Contains(formatted, "PRIVATE KEY") {
			t.Fatal("private diagnostic formatting")
		}
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%d", "%q"} {
		for _, value := range []any{c, *c, c.admin, *c.admin} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, private.Token) || strings.Contains(formatted, "PRIVATE KEY") || !strings.Contains(formatted, "private") {
				t.Fatal("private value formatting escaped redaction")
			}
		}
	}
	if _, err := f.engine.PrepareCredentials(context.Background(), f.snapshot, opts); !errors.Is(err, ErrCredentials) {
		t.Fatal("existing private candidate overwritten")
	}
	if _, err := f.engine.LoadCredentials(context.Background(), f.snapshot, opts.Now.Add(time.Hour)); !errors.Is(err, ErrCredentials) {
		t.Fatal("expired token regenerated")
	}
	if err := c.ExportClient("private-client.json"); err != nil {
		t.Fatal(err)
	}
	if err := c.ExportClient("private-client.json"); err != nil {
		t.Fatal("exact private export not idempotent")
	}
	body, _, err := f.engine.files.Read("private-client.json", 4096)
	if err != nil || !bytes.Equal(body, c.admin.PrivateBytes()) {
		t.Fatal("client output format changed")
	}
}

func TestSecretCreatesAreRetainedAndDoNotPublishPrivateValuesOrHashes(t *testing.T) {
	f, w, a, c, opts := secretFixture(t)
	s := f.snapshot
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		var err error
		s, err = w.Create(context.Background(), s, c, name, opts.Now)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range s.Document().Resources {
			if r.Key.Kind == "Secret" && (!r.Retained || r.TemplateSHA256 != "") {
				t.Fatal("private hash/retention contract changed")
			}
		}
	}
	private, _ := adminauth.ParseClientCredential(c.admin.PrivateBytes())
	for _, canary := range []string{private.Token, adminauth.TokenDigest(private.Token), "PRIVATE KEY", string(c.document.Key)} {
		if bytes.Contains(s.Bytes(), []byte(canary)) {
			t.Fatal("private value leaked into public journal")
		}
	}
	if a.writes != 2 || a.dryRuns != 2 || len(s.Document().Resources) != 3 {
		t.Fatal("unproved private settlement")
	}
	if err := w.VerifyRetained(context.Background(), s, opts.CAFile, opts.Now); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Create(context.Background(), s, c, adminauth.CredentialSecretName, opts.Now); !errors.Is(err, ErrInvalid) || a.writes != 2 {
		t.Fatal("existing Secret replayed")
	}
}

func TestCredentialEnvelopeBindingAndCanonicalResume(t *testing.T) {
	for _, scenario := range []string{"namespace", "namespace-uid", "installation-id", "package", "version", "nonce-shape", "nonce-collision", "noncanonical", "pending-nonce"} {
		t.Run(scenario, func(t *testing.T) {
			f, w, a, c, opts := secretFixture(t)
			s := f.snapshot
			if scenario == "pending-nonce" {
				a.write = func(o *corev1.Secret) (*corev1.Secret, error) {
					o.UID, o.ResourceVersion = "original-admin", "101"
					a.objects[o.Name] = o.DeepCopy()
					a.get = func(string) error { return ErrRead }
					return o, nil
				}
				var err error
				s, err = w.Create(context.Background(), s, c, adminauth.CredentialSecretName, opts.Now)
				if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil {
					t.Fatal("fixture did not preserve pending intent")
				}
				a.get = nil
			}
			doc := c.document
			switch scenario {
			case "namespace":
				doc.Anchor.Namespace = "foreign-system"
			case "namespace-uid":
				doc.Anchor.UID = "foreign-namespace"
			case "installation-id":
				doc.Anchor.InstallationID = strings.Repeat("f", 32)
			case "package":
				doc.PackageSHA256 = strings.Repeat("f", 64)
			case "version":
				doc.Version = "v2"
			case "nonce-shape":
				doc.AdminNonce = "bad-nonce"
			case "nonce-collision":
				doc.AdminNonce = doc.TLSNonce
			case "pending-nonce":
				doc.AdminNonce = doc.TLSNonce
				doc.TLSNonce = c.document.AdminNonce
			}
			body, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			body, err = canonicaljson.CanonicalJSON(body)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "noncanonical" {
				body = append(body, '\n')
			}
			if _, err := f.engine.files.AtomicWrite(credentialName(c.document.Anchor), body, &c.fileIdentity); err != nil {
				t.Fatal(err)
			}
			resumed, err := f.engine.LoadCredentials(context.Background(), s, opts.Now)
			if scenario == "pending-nonce" {
				if err != nil {
					t.Fatal(err)
				}
				if recovered, err := w.Recover(context.Background(), s, resumed, opts.Now); !errors.Is(err, ErrInvalid) || recovered.Document().Pending == nil || a.writes != 1 || a.dryRuns != 1 {
					t.Fatal("changed private nonce authorized pending recovery")
				}
			} else if !errors.Is(err, ErrCredentials) || a.writes != 0 || a.dryRuns != 0 {
				t.Fatal("foreign or noncanonical private envelope accepted")
			}
		})
	}
}

func TestSecretLostResponseAndOriginalUIDRecovery(t *testing.T) {
	for _, scenario := range []string{"lost-committed", "lost-absent", "lost-readback", "replacement", "lost-settlement"} {
		t.Run(scenario, func(t *testing.T) {
			f, w, a, c, opts := secretFixture(t)
			a.write = func(o *corev1.Secret) (*corev1.Secret, error) {
				o.UID = "original-admin"
				o.ResourceVersion = "101"
				ack := o.DeepCopy()
				switch scenario {
				case "lost-committed":
					a.objects[o.Name] = o
					return nil, ErrRead
				case "lost-absent":
					return nil, ErrRead
				case "lost-readback":
					a.get = func(string) error { return ErrRead }
				case "replacement":
					o.UID = "foreign-copied-nonce"
				case "lost-settlement":
					f.nsUpdate = func(*corev1.Namespace) error {
						if f.nsUpdates == 2 {
							return ErrRead
						}
						return nil
					}
				}
				a.objects[o.Name] = o
				return ack, nil
			}
			s, err := w.Create(context.Background(), f.snapshot, c, adminauth.CredentialSecretName, opts.Now)
			if scenario == "lost-committed" {
				if err != nil || s.Document().Pending != nil {
					t.Fatal("lost success not correlated")
				}
				return
			}
			if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil {
				t.Fatal("uncertain private Create settled")
			}
			// Explicitly reload private material and original namespace after restart.
			c, err = f.engine.LoadCredentials(context.Background(), s, opts.Now)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "lost-readback" {
				a.get = nil
			}
			s, err = w.Recover(context.Background(), s, c, opts.Now)
			if scenario == "lost-readback" || scenario == "lost-settlement" {
				if err != nil || s.Document().Pending != nil {
					t.Fatal("original UID not recovered")
				}
			} else if !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal("absence/replacement adopted")
			}
			if a.writes != 1 || a.dryRuns != 1 {
				t.Fatal("private effect replayed")
			}
		})
	}
}

func TestDefiniteSecretCreateRejectionNeverAdoptsRacedCopiedNonce(t *testing.T) {
	for _, rejection := range definitiveCreateErrors() {
		t.Run(rejection.Error(), func(t *testing.T) {
			f, w, a, c, opts := secretFixture(t)
			a.write = func(o *corev1.Secret) (*corev1.Secret, error) {
				o.UID, o.ResourceVersion = "foreign-copied-nonce", "100"
				a.objects[o.Name] = o.DeepCopy()
				return nil, rejection
			}
			s, err := w.Create(context.Background(), f.snapshot, c, adminauth.CredentialSecretName, opts.Now)
			if !errors.Is(err, ErrOutcomeUnknown) || s.Document().Pending == nil || len(s.Document().Resources) != 1 {
				t.Fatal("definitely rejected private Create adopted a raced object")
			}
			if _, err := w.Recover(context.Background(), s, c, opts.Now); !errors.Is(err, ErrOutcomeUnknown) || a.writes != 1 || a.dryRuns != 1 {
				t.Fatal("restart adopted or replayed rejected private Create")
			}
		})
	}
}

func TestSecretDriftForeignObjectsAndChangedPrivateCandidatesFailBeforeEffect(t *testing.T) {
	for _, scenario := range []string{"foreign", "dry-data", "dry-nonce", "dry-label", "dry-owner", "dry-finalizer", "dry-immutable", "dry-stringData", "changed-private-file", "foreign-client-output", "journal-conflict"} {
		t.Run(scenario, func(t *testing.T) {
			f, w, a, c, opts := secretFixture(t)
			switch scenario {
			case "foreign":
				a.objects[adminauth.CredentialSecretName] = &corev1.Secret{}
			case "dry-data":
				a.dry = func(s *corev1.Secret) *corev1.Secret { s.Data["foreign"] = []byte("PRIVATE-CANARY"); return s }
			case "dry-nonce":
				a.dry = func(s *corev1.Secret) *corev1.Secret {
					s.Annotations[installstate.MutationAnnotation] = strings.Repeat("f", 32)
					return s
				}
			case "dry-label":
				a.dry = func(s *corev1.Secret) *corev1.Secret { s.Labels["foreign"] = "true"; return s }
			case "dry-owner":
				a.dry = func(s *corev1.Secret) *corev1.Secret {
					s.OwnerReferences = []metav1.OwnerReference{{UID: "foreign"}}
					return s
				}
			case "dry-finalizer":
				a.dry = func(s *corev1.Secret) *corev1.Secret { s.Finalizers = []string{"foreign"}; return s }
			case "dry-immutable":
				a.dry = func(s *corev1.Secret) *corev1.Secret { yes := true; s.Immutable = &yes; return s }
			case "dry-stringData":
				a.dry = func(s *corev1.Secret) *corev1.Secret {
					s.StringData = map[string]string{"foreign": "PRIVATE-CANARY"}
					return s
				}
			case "changed-private-file":
				if _, err := f.engine.files.AtomicWrite(credentialName(c.document.Anchor), c.body, &c.fileIdentity); err != nil {
					t.Fatal(err)
				}
			case "foreign-client-output":
				if _, err := f.engine.files.CreateExclusive("admin-client-"+f.snapshot.Anchor().InstallationID+".json", []byte("foreign-private-file")); err != nil {
					t.Fatal(err)
				}
			case "journal-conflict":
				f.nsUpdate = func(*corev1.Namespace) error {
					return apierrors.NewConflict(schema.GroupResource{Resource: "namespaces"}, f.plan.Namespace(), ErrConcurrent)
				}
			}
			if _, err := w.Create(context.Background(), f.snapshot, c, adminauth.CredentialSecretName, opts.Now); err == nil || strings.Contains(err.Error(), "CANARY") || a.writes != 0 {
				t.Fatal("unsafe private candidate caused mutation")
			}
		})
	}
}

func TestRetainedCredentialsAllowAdminRotationButRefuseUIDOrFormatSubstitution(t *testing.T) {
	f, w, a, c, opts := secretFixture(t)
	s := f.snapshot
	for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
		var err error
		s, err = w.Create(context.Background(), s, c, name, opts.Now)
		if err != nil {
			t.Fatal(err)
		}
	}
	generated, err := adminauth.GenerateCredential(opts.Now, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	generated.Bundle.Serial = 2
	bundle, err := adminauth.MarshalVerifierBundle(generated.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	live := a.objects[adminauth.CredentialSecretName]
	live.Data = map[string][]byte{adminauth.VerifierSecretKey: bundle, adminauth.TokenSecretKey: []byte(generated.Token)}
	live.ResourceVersion = "999"
	// Original candidate has expired, but validation uses current retained format.
	if err := w.VerifyRetained(context.Background(), s, opts.CAFile, opts.Now.Add(time.Hour)); err != nil {
		t.Fatal("legitimate admin rotation rejected")
	}
	old := live.UID
	live.UID = "foreign-replacement"
	if err := w.VerifyRetained(context.Background(), s, opts.CAFile, opts.Now); !errors.Is(err, ErrOwnership) {
		t.Fatal("retained UID replacement adopted")
	}
	live.UID = old
	live.Labels["foreign"] = "true"
	if err := w.VerifyRetained(context.Background(), s, opts.CAFile, opts.Now); !errors.Is(err, ErrCredentials) {
		t.Fatal("retained format drift accepted")
	}
	if a.writes != 2 {
		t.Fatal("retained verification rotated/rewrote Secrets")
	}
}

func TestTLSAndPrivateCandidateValidationRefuseInvalidInputs(t *testing.T) {
	f, _, _, c, opts := secretFixture(t)
	for _, scenario := range []string{"namespace", "expiry", "wrong-key", "wrong-ca", "garbage-cert", "garbage-key", "zero-time"} {
		t.Run(scenario, func(t *testing.T) {
			cert, key, ca := c.document.Certificate, c.document.Key, c.document.CA
			namespace, now := f.plan.Namespace(), opts.Now
			switch scenario {
			case "namespace":
				namespace = "foreign"
			case "expiry":
				now = now.Add(24 * time.Hour)
			case "wrong-key":
				other := fixtureTLS(t, namespace, now)
				key, _, _ = privatefs.ReadAbsolute(other.KeyFile, 16384, privatefs.Private)
			case "wrong-ca":
				other := fixtureTLS(t, namespace, now)
				ca, _, _ = privatefs.ReadAbsolute(other.CAFile, 65536, privatefs.TrustedPublic)
			case "garbage-cert":
				cert = append([]byte("garbage\n"), cert...)
			case "garbage-key":
				key = append([]byte("garbage\n"), key...)
			case "zero-time":
				now = time.Time{}
			}
			if err := validateTLS(cert, key, ca, namespace, now); !errors.Is(err, ErrCredentials) {
				t.Fatal("invalid TLS candidate accepted")
			}
		})
	}
	if err := os.Chmod(opts.KeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	other := newFixture(t, false)
	if _, err := other.engine.PrepareCredentials(context.Background(), other.snapshot, opts); !errors.Is(err, ErrCredentials) {
		t.Fatal("unprotected private key accepted")
	}
}

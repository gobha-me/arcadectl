// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/admincredential"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ErrCredentials = errors.New("installation private credential candidate is invalid or unavailable")
var nonceID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// CredentialOptions accepts only protected TLS file paths, never inline private
// values or arbitrary Kubernetes fragments. TLS provisioning remains an explicit
// prerequisite; the installer does not provision a CA or storage controller.
type CredentialOptions struct {
	Now                              time.Time
	AdminLifetime                    time.Duration
	CertificateFile, KeyFile, CAFile string
}

type credentialDocument struct {
	Version       string              `json:"version"`
	Anchor        installstate.Anchor `json:"anchor"`
	PackageSHA256 string              `json:"packageSha256"`
	AdminNonce    string              `json:"adminNonce"`
	TLSNonce      string              `json:"tlsNonce"`
	Admin         json.RawMessage     `json:"admin"`
	Certificate   []byte              `json:"certificate"`
	Key           []byte              `json:"key"`
	CA            []byte              `json:"ca"`
}

// Credentials seals a protected candidate to original installation identity.
// Diagnostic formatting is redacted. Only private client/CA exports are provided.
type Credentials struct {
	engine       *Engine
	document     credentialDocument
	fileIdentity privatefs.FileIdentity
	body         []byte
	admin        *admincredential.InitialCandidate
}

func (Credentials) String() string   { return "private installation credentials" }
func (Credentials) GoString() string { return "private installation credentials" }
func (Credentials) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "private installation credentials")
}

func credentialName(anchor installstate.Anchor) string {
	return "credentials-" + anchor.InstallationID + ".json"
}

func (e *Engine) PrepareCredentials(ctx context.Context, s *installstate.Snapshot, opts CredentialOptions) (*Credentials, error) {
	fresh, err := e.current(ctx, s)
	if err != nil {
		return nil, err
	}
	d := fresh.Document()
	if d.Mode != installstate.Install || d.Stage != installstate.Applying || d.Pending != nil {
		return nil, ErrInvalid
	}
	for _, r := range d.Resources {
		if r.Key.Kind == "Secret" {
			return nil, ErrInvalid
		}
	}
	if _, _, err := e.files.Read(credentialName(fresh.Anchor()), canonicaljson.MaxBytes); !errors.Is(err, privatefs.ErrNotFound) {
		return nil, ErrCredentials
	}
	cert, _, err := privatefs.ReadAbsolute(opts.CertificateFile, 65536, privatefs.TrustedPublic)
	if err != nil {
		return nil, ErrCredentials
	}
	key, _, err := privatefs.ReadAbsolute(opts.KeyFile, 16384, privatefs.Private)
	if err != nil {
		return nil, ErrCredentials
	}
	ca, _, err := privatefs.ReadAbsolute(opts.CAFile, 65536, privatefs.TrustedPublic)
	if err != nil || validateTLS(cert, key, ca, d.Namespace, opts.Now) != nil {
		return nil, ErrCredentials
	}
	admin, err := admincredential.PrepareInitialCandidate(d.Namespace, opts.Now, opts.AdminLifetime)
	if err != nil {
		return nil, ErrCredentials
	}
	adminNonce, err := installstate.NewID()
	if err != nil {
		return nil, ErrCredentials
	}
	tlsNonce, err := installstate.NewID()
	if err != nil || tlsNonce == adminNonce {
		return nil, ErrCredentials
	}
	doc := credentialDocument{Version: "v1", Anchor: fresh.Anchor(), PackageSHA256: d.TargetPackage, AdminNonce: adminNonce, TLSNonce: tlsNonce, Admin: admin.PrivateBytes(), Certificate: cert, Key: key, CA: ca}
	body, err := encodeCredentials(doc)
	if err != nil {
		return nil, err
	}
	id, err := e.files.CreateExclusive(credentialName(doc.Anchor), body)
	if err != nil {
		return nil, ErrCredentials
	}
	return &Credentials{engine: e, document: doc, fileIdentity: id, body: body, admin: admin}, nil
}

// LoadCredentials never generates new tokens/certificates or overwrites missing,
// expired, foreign or replaced private output. Resume keeps the same candidates.
func (e *Engine) LoadCredentials(ctx context.Context, s *installstate.Snapshot, now time.Time) (*Credentials, error) {
	fresh, err := e.current(ctx, s)
	if err != nil {
		return nil, err
	}
	return e.loadCredentials(fresh, now)
}
func (e *Engine) loadCredentials(s *installstate.Snapshot, now time.Time) (*Credentials, error) {
	body, id, err := e.files.Read(credentialName(s.Anchor()), canonicaljson.MaxBytes)
	if err != nil {
		return nil, ErrCredentials
	}
	if e.files.ConfirmDurable(credentialName(s.Anchor()), id) != nil {
		return nil, ErrCredentials
	}
	var doc credentialDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil {
		return nil, ErrCredentials
	}
	want, err := encodeCredentials(doc)
	if err != nil || !bytes.Equal(want, body) || doc.Anchor != s.Anchor() || doc.PackageSHA256 != s.Document().TargetPackage || validateTLS(doc.Certificate, doc.Key, doc.CA, doc.Anchor.Namespace, now) != nil {
		return nil, ErrCredentials
	}
	admin, err := admincredential.ResumeInitialCandidate(doc.Anchor.Namespace, doc.Admin, now)
	if err != nil {
		return nil, ErrCredentials
	}
	return &Credentials{engine: e, document: doc, fileIdentity: id, body: body, admin: admin}, nil
}

func encodeCredentials(doc credentialDocument) ([]byte, error) {
	if doc.Version != "v1" || !nonceID.MatchString(doc.AdminNonce) || !nonceID.MatchString(doc.TLSNonce) || doc.AdminNonce == doc.TLSNonce || len(doc.Admin) == 0 || len(doc.Certificate) == 0 || len(doc.Key) == 0 || len(doc.CA) == 0 {
		return nil, ErrCredentials
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, ErrCredentials
	}
	body, err = canonicaljson.CanonicalJSON(body)
	if err != nil {
		return nil, ErrCredentials
	}
	return body, nil
}

func (c *Credentials) secret(name string) (*corev1.Secret, string, error) {
	if c == nil || c.engine == nil || c.admin == nil {
		return nil, "", ErrCredentials
	}
	var secret *corev1.Secret
	var nonce string
	switch name {
	case adminauth.CredentialSecretName:
		var err error
		secret, err = c.admin.Secret()
		if err != nil {
			return nil, "", ErrCredentials
		}
		nonce = c.document.AdminNonce
	case "arcadectl-api-tls":
		secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: c.document.Anchor.Namespace}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{corev1.TLSCertKey: bytes.Clone(c.document.Certificate), corev1.TLSPrivateKeyKey: bytes.Clone(c.document.Key)}}
		nonce = c.document.TLSNonce
	default:
		return nil, "", ErrInvalid
	}
	secret.Annotations = map[string]string{installstate.MutationAnnotation: nonce}
	return secret, nonce, nil
}

// ExportClient writes only the established client-credential JSON, privately
// and exclusively. A supplied existing file is accepted only by exact bytes.
// Paths and private values are never returned in diagnostics.
func (c *Credentials) ExportClient(name string) error {
	if c == nil || c.engine == nil || c.admin == nil {
		return ErrCredentials
	}
	return c.export(name, c.admin.PrivateBytes())
}
func (c *Credentials) ExportCA(name string) error {
	if c == nil || c.engine == nil {
		return ErrCredentials
	}
	return c.export(name, c.document.CA)
}
func (c *Credentials) export(name string, body []byte) error {
	stored, id, err := c.engine.files.Read(credentialName(c.document.Anchor), canonicaljson.MaxBytes)
	if err != nil || id != c.fileIdentity || !bytes.Equal(stored, c.body) {
		return ErrCredentials
	}
	if _, err := c.engine.files.CreateExclusive(name, body); err == nil {
		return nil
	} else if !errors.Is(err, privatefs.ErrExists) {
		return ErrCredentials
	}
	old, id, err := c.engine.files.Read(name, 65536)
	if err != nil || !bytes.Equal(old, body) {
		return ErrCredentials
	}
	if c.engine.files.ConfirmDurable(name, id) != nil {
		return ErrCredentials
	}
	return nil
}

func parseCertificates(body []byte) ([]*x509.Certificate, error) {
	if len(body) == 0 || len(body) > 65536 {
		return nil, ErrCredentials
	}
	var result []*x509.Certificate
	for len(bytes.TrimSpace(body)) > 0 {
		body = bytes.TrimSpace(body)
		if !bytes.HasPrefix(body, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrCredentials
		}
		block, rest := pem.Decode(body)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(result) >= 16 {
			return nil, ErrCredentials
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrCredentials
		}
		result = append(result, cert)
		body = rest
	}
	return result, nil
}
func validateTLS(certPEM, keyPEM, caPEM []byte, namespace string, now time.Time) error {
	if now.IsZero() {
		return ErrCredentials
	}
	certs, err := parseCertificates(certPEM)
	if err != nil || len(certs) == 0 || certs[0].IsCA || !certs[0].NotAfter.After(now) {
		return ErrCredentials
	}
	if len(keyPEM) == 0 || len(keyPEM) > 16384 {
		return ErrCredentials
	}
	block, rest := pem.Decode(keyPEM)
	trimmed := bytes.TrimSpace(keyPEM)
	if block != nil && !bytes.HasPrefix(trimmed, []byte("-----BEGIN "+block.Type+"-----")) {
		return ErrCredentials
	}
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return ErrCredentials
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return ErrCredentials
	}
	switch key := certs[0].PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return ErrCredentials
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return ErrCredentials
		}
	case ed25519.PublicKey:
	default:
		return ErrCredentials
	}
	roots, err := parseCertificates(caPEM)
	if err != nil || len(roots) == 0 {
		return ErrCredentials
	}
	pool, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, cert := range roots {
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ErrCredentials
		}
		pool.AddCert(cert)
	}
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, DNSName: "arcadectl-api." + namespace + ".svc", CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return ErrCredentials
	}
	return nil
}

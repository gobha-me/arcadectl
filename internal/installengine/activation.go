// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
)

var ErrActivation = errors.New("original installation API authenticated activation is unproved")

// Activation checks actual HTTPS self identity, rather than faking an old token
// or accepting a user-provided URL. Direct and native-forward verification use
// the same original identity, TLS and authenticated-response barriers.
type Activation struct {
	engine  *Engine
	serving ServingAccess
	secrets PrivateSecretAccess
	dial    func(context.Context, *Serving) (net.Conn, error)
}

type ActivationOptions struct{ CredentialFile, CAFile string }
type credentialBinding struct {
	client, ca                       privatefs.FileIdentity
	adminUID, adminRV, tlsUID, tlsRV string
	peerSHA256                       [32]byte
}

func nilAccess(value any) bool {
	return value == nil || reflect.ValueOf(value).Kind() == reflect.Pointer && reflect.ValueOf(value).IsNil()
}

// NewActivation uses trusted read-only seams. Production supplies Serving and
// PrivateSecrets from the same HTTPS provider used for bootstrap/inventory.
func NewActivation(engine *Engine, serving ServingAccess, secrets PrivateSecretAccess) (*Activation, error) {
	if engine == nil || nilAccess(serving) || nilAccess(secrets) {
		return nil, ErrInvalid
	}
	return &Activation{engine: engine, serving: serving, secrets: secrets, dial: func(ctx context.Context, s *Serving) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(s.address, "8443"))
	}}, nil
}

func (a *Activation) binding(ctx context.Context, s *installstate.Snapshot, opts ActivationOptions) (credentialBinding, error) {
	w, err := NewSecretWorkflow(a.engine, a.secrets)
	if err != nil {
		return credentialBinding{}, ErrActivation
	}
	retained, caID, err := w.retained(ctx, s, opts.CAFile, time.Now())
	if err != nil {
		return credentialBinding{}, ErrActivation
	}
	raw, clientID, err := privatefs.ReadAbsolute(opts.CredentialFile, adminauth.MaxClientCredentialBytes, privatefs.Private)
	if err != nil {
		return credentialBinding{}, ErrActivation
	}
	client, err := adminauth.ParseClientCredential(raw)
	if err != nil || !client.ExpiresAt.After(time.Now()) {
		return credentialBinding{}, ErrActivation
	}
	admin := retained[adminauth.CredentialSecretName]
	bundle, err := adminauth.ParseVerifierBundle(admin.Data[adminauth.VerifierSecretKey])
	if err != nil || client.CredentialID != bundle.CredentialID || client.Serial != bundle.Serial || !client.ExpiresAt.Equal(bundle.ExpiresAt) || !bytes.Equal([]byte(client.Token), admin.Data[adminauth.TokenSecretKey]) || !adminauth.TokenMatchesBundle(client.Token, bundle) {
		return credentialBinding{}, ErrActivation
	}
	tlsSecret := retained["arcadectl-api-tls"]
	certificates, err := parseCertificates(tlsSecret.Data["tls.crt"])
	if err != nil || len(certificates) == 0 {
		return credentialBinding{}, ErrActivation
	}
	return credentialBinding{client: clientID, ca: caID, adminUID: string(admin.UID), adminRV: admin.ResourceVersion, tlsUID: string(tlsSecret.UID), tlsRV: tlsSecret.ResourceVersion, peerSHA256: sha256.Sum256(certificates[0].Raw)}, nil
}

// VerifyDirect performs no Kubernetes write or credential rotation. Exact
// resource/file observations are repeated before credentials can leave the
// proved connection and after authentication. A changed/unreadable route or
// retained credential remains unproved, never a substituted success.
func (a *Activation) VerifyDirect(ctx context.Context, s *installstate.Snapshot, opts ActivationOptions) error {
	if a == nil {
		return ErrActivation
	}
	return a.verify(ctx, s, opts, a.dial)
}

// VerifyForwarded opens only the sealed original Pod's fixed 8443 subresource.
// It exposes no listener, caller URL/port, reconnect or replacement fallback.
func (a *Activation) VerifyForwarded(ctx context.Context, s *installstate.Snapshot, opts ActivationOptions, provider *HTTPAccess) error {
	if provider == nil || provider.native == nil {
		return ErrActivation
	}
	return a.verify(ctx, s, opts, provider.forwardPod)
}

func (a *Activation) verify(ctx context.Context, s *installstate.Snapshot, opts ActivationOptions, dial func(context.Context, *Serving) (net.Conn, error)) error {
	if a == nil || a.engine == nil || ctx == nil || dial == nil {
		return ErrActivation
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	before, err := a.engine.ObserveServing(ctx, s, a.serving)
	if err != nil {
		return ErrActivation
	}
	binding, err := a.binding(ctx, s, opts)
	if err != nil {
		return ErrActivation
	}
	origin := "https://" + net.JoinHostPort(before.address, "8443")
	client, err := adminclient.LoadBoundWithDialer(adminclient.ContextConfig{Version: "v1", Name: "installation", APIOrigin: origin, TLSServerName: "arcadectl-api." + before.namespace + ".svc", CAFile: opts.CAFile, CredentialFile: opts.CredentialFile}, binding.client, binding.ca, binding.peerSHA256, func(dialCtx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(before.address, "8443") {
			return nil, ErrActivation
		}
		// Own the connection through verification, not the HTTP transport's
		// detached/cancellable connection-acquisition context.
		conn, err := dial(ctx, before)
		if err != nil || conn == nil {
			if conn != nil {
				_ = conn.Close()
			}
			return nil, ErrActivation
		}
		current, err := a.engine.ObserveServing(dialCtx, s, a.serving)
		bound, bindErr := a.binding(dialCtx, s, opts)
		if err != nil || current.fingerprint != before.fingerprint || bindErr != nil || bound != binding {
			_ = conn.Close()
			return nil, ErrActivation
		}
		return conn, nil
	})
	if err != nil {
		return ErrActivation
	}
	defer client.Close()
	identity, err := client.Verify(ctx)
	if err != nil || identity.Namespace != before.namespace || identity.PrincipalID != adminauth.AdminPrincipalID {
		return ErrActivation
	}
	after, err := a.engine.ObserveServing(ctx, s, a.serving)
	bound, bindErr := a.binding(ctx, s, opts)
	if err != nil || after.fingerprint != before.fingerprint || bindErr != nil || bound != binding {
		return ErrActivation
	}
	return nil
}

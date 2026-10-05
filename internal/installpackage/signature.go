// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installpackage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
)

const signatureDomain = "arcadectl/install-package/v1\x00"

type signatureEnvelope struct {
	Version         string `json:"version"`
	Algorithm       string `json:"algorithm"`
	PublicKeySHA256 string `json:"publicKeySha256"`
	Signature       string `json:"signature"`
}

// Sign authenticates canonical metadata, including its payload checksums. It
// does not load files, create keys, or publish anything. Callers must validate
// the actual payloads independently when preparing a signed candidate.
func Sign(manifest []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if _, err := ParseManifest(manifest); err != nil {
		return nil, ErrInvalid
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrSignature
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(derived, privateKey) != 1 {
		return nil, ErrSignature
	}
	publicKey := privateKey[ed25519.SeedSize:]
	envelope := signatureEnvelope{Version: FormatVersion, Algorithm: "Ed25519", PublicKeySHA256: hash(publicKey), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signedMessage(manifest)))}
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, ErrSignature
	}
	canonical, err := canonicaljson.CanonicalJSON(body)
	if err != nil || len(canonical) > MaxSignatureBytes {
		return nil, ErrSignature
	}
	return canonical, nil
}

// VerifiedPackage is a sealed byte-authentication result. Its zero value and nil
// pointers are not verified. All accessors return defensive copies. A verified
// package still needs semantic/security/ownership checks before any mutation.
type VerifiedPackage struct {
	verified bool
	manifest []byte
	payloads map[string][]byte
}

// Verify accepts only an explicitly external trusted key. The envelope has no
// bundled public key and its fingerprint cannot select or establish trust.
func Verify(manifest, signature []byte, payloads map[string][]byte, trustedKey ed25519.PublicKey) (*VerifiedPackage, error) {
	if len(manifest) == 0 || len(manifest) > MaxManifestBytes {
		return nil, ErrInvalid
	}
	if len(signature) == 0 || len(signature) > MaxSignatureBytes || len(trustedKey) != ed25519.PublicKeySize {
		return nil, ErrSignature
	}
	manifest = bytes.Clone(manifest)
	signature = bytes.Clone(signature)
	trustedKey = bytes.Clone(trustedKey)
	metadata, err := ParseManifest(manifest)
	if err != nil || !validPayloadMap(payloads) {
		return nil, ErrInvalid
	}
	var envelope signatureEnvelope
	if strictCanonical(signature, MaxSignatureBytes, &envelope) != nil {
		return nil, ErrSignature
	}
	typed, err := json.Marshal(envelope)
	if err != nil {
		return nil, ErrSignature
	}
	canonical, err := canonicaljson.CanonicalJSON(typed)
	if err != nil || !bytes.Equal(signature, canonical) || envelope.Version != FormatVersion || envelope.Algorithm != "Ed25519" || len(trustedKey) != ed25519.PublicKeySize || envelope.PublicKeySHA256 != hash(trustedKey) {
		return nil, ErrSignature
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != envelope.Signature || !ed25519.Verify(trustedKey, signedMessage(manifest), raw) {
		return nil, ErrSignature
	}
	result := &VerifiedPackage{verified: true, manifest: bytes.Clone(manifest), payloads: make(map[string][]byte, len(payloads))}
	for _, entry := range metadata.Files {
		body := bytes.Clone(payloads[entry.Path])
		if int64(len(body)) != entry.Size || hash(body) != entry.SHA256 {
			return nil, ErrInvalid
		}
		result.payloads[entry.Path] = body
	}
	return result, nil
}

func signedMessage(manifest []byte) []byte { return append([]byte(signatureDomain), manifest...) }

func (p *VerifiedPackage) IsVerified() bool { return p != nil && p.verified }
func (p *VerifiedPackage) Manifest() (Manifest, error) {
	if !p.IsVerified() {
		return Manifest{}, ErrUnverified
	}
	return ParseManifest(p.manifest)
}
func (p *VerifiedPackage) ManifestBytes() ([]byte, error) {
	if !p.IsVerified() {
		return nil, ErrUnverified
	}
	return bytes.Clone(p.manifest), nil
}
func (p *VerifiedPackage) Payload(path string) ([]byte, error) {
	if !p.IsVerified() {
		return nil, ErrUnverified
	}
	body, ok := p.payloads[path]
	if !ok {
		return nil, ErrInvalid
	}
	return bytes.Clone(body), nil
}
func (p *VerifiedPackage) Digest() (string, error) {
	if !p.IsVerified() {
		return "", ErrUnverified
	}
	return hash(p.manifest), nil
}

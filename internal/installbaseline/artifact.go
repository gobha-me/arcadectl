// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installbaseline

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
)

const (
	FormatVersion     = "v1"
	MaxManifestBytes  = 4096
	MaxSignatureBytes = 2048
	MaxPayloadBytes   = 65536
	signatureDomain   = "arcadectl/install-security-baseline/v1\x00"
)

var (
	ErrSignature  = errors.New("installation security baseline authentication failed")
	ErrUnverified = errors.New("installation security baseline is not verified")
	sourcePattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Source/profile metadata is an authenticated declaration, not provenance or
// certification. A release must independently prove the referenced source.
type Manifest struct {
	FormatVersion   string   `json:"formatVersion"`
	BaselineVersion string   `json:"baselineVersion"`
	SourceSHA       string   `json:"sourceSha"`
	SourceEpoch     int64    `json:"sourceEpoch"`
	Profiles        []string `json:"profiles"`
	PayloadSize     int      `json:"payloadSize"`
	PayloadSHA256   string   `json:"payloadSha256"`
}

type signatureEnvelope struct {
	Version         string `json:"version"`
	Algorithm       string `json:"algorithm"`
	PublicKeySHA256 string `json:"publicKeySha256"`
	Signature       string `json:"signature"`
}

func supportedProfiles() []string { return []string{"kubernetes-1.35.8", "kubernetes-1.37.0"} }

// Build creates the one closed, reviewed public payload. It performs no file,
// cluster, signing-key or publication operation.
func Build(sourceSHA string, sourceEpoch int64) ([]byte, []byte, error) {
	payload, err := reviewedPayload()
	if err != nil {
		return nil, nil, ErrInvalid
	}
	metadata := Manifest{FormatVersion, Version, sourceSHA, sourceEpoch, supportedProfiles(), len(payload), digest(payload)}
	body, err := canonicalEncode(metadata)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	if _, err := ParseManifest(body); err != nil {
		return nil, nil, ErrInvalid
	}
	return body, payload, nil
}

func ParseManifest(body []byte) (Manifest, error) {
	var metadata Manifest
	if strictCanonical(body, MaxManifestBytes, &metadata) != nil || metadata.FormatVersion != FormatVersion || metadata.BaselineVersion != Version ||
		!sourcePattern.MatchString(metadata.SourceSHA) || metadata.SourceEpoch <= 0 || metadata.SourceEpoch > 253402300799 ||
		!slices.Equal(metadata.Profiles, supportedProfiles()) || metadata.PayloadSize <= 0 || metadata.PayloadSize > MaxPayloadBytes || !digestPattern.MatchString(metadata.PayloadSHA256) {
		return Manifest{}, ErrInvalid
	}
	return metadata, nil
}

func Sign(manifest []byte, key ed25519.PrivateKey) ([]byte, error) {
	if _, err := ParseManifest(manifest); err != nil {
		return nil, ErrInvalid
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrSignature
	}
	key = bytes.Clone(key)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(derived, key) != 1 {
		return nil, ErrSignature
	}
	return canonicalEncode(signatureEnvelope{FormatVersion, "Ed25519", digest(key[ed25519.SeedSize:]), base64.StdEncoding.EncodeToString(ed25519.Sign(key, signedMessage(manifest)))})
}

// Verified authenticates bounded bytes with an externally established key.
// Its zero value is unverified; semantic compilation and ownership are separate.
type Verified struct {
	verified bool
	manifest []byte
	payload  []byte
}

func Verify(manifest, signature, payload []byte, externalKey ed25519.PublicKey) (*Verified, error) {
	if len(externalKey) != ed25519.PublicKeySize || len(signature) == 0 || len(signature) > MaxSignatureBytes {
		return nil, ErrSignature
	}
	if len(manifest) == 0 || len(manifest) > MaxManifestBytes || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, ErrInvalid
	}
	manifest, signature, payload, externalKey = bytes.Clone(manifest), bytes.Clone(signature), bytes.Clone(payload), bytes.Clone(externalKey)
	metadata, err := ParseManifest(manifest)
	if err != nil || len(payload) != metadata.PayloadSize || len(payload) > MaxPayloadBytes || digest(payload) != metadata.PayloadSHA256 {
		return nil, ErrInvalid
	}
	var envelope signatureEnvelope
	if strictCanonical(signature, MaxSignatureBytes, &envelope) != nil || envelope.Version != FormatVersion || envelope.Algorithm != "Ed25519" || envelope.PublicKeySHA256 != digest(externalKey) {
		return nil, ErrSignature
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != envelope.Signature || !ed25519.Verify(externalKey, signedMessage(manifest), raw) {
		return nil, ErrSignature
	}
	return &Verified{true, manifest, payload}, nil
}

func (v *Verified) IsVerified() bool { return v != nil && v.verified }
func (v *Verified) Manifest() (Manifest, error) {
	if !v.IsVerified() {
		return Manifest{}, ErrUnverified
	}
	return ParseManifest(v.manifest)
}
func (v *Verified) ManifestBytes() ([]byte, error) {
	if !v.IsVerified() {
		return nil, ErrUnverified
	}
	return bytes.Clone(v.manifest), nil
}
func (v *Verified) Payload() ([]byte, error) {
	if !v.IsVerified() {
		return nil, ErrUnverified
	}
	return bytes.Clone(v.payload), nil
}
func (v *Verified) Digest() (string, error) {
	if !v.IsVerified() {
		return "", ErrUnverified
	}
	return digest(v.manifest), nil
}

func reviewedPayload() ([]byte, error) {
	objects, err := Render("arcadectl-system")
	if err != nil {
		return nil, ErrInvalid
	}
	return canonicalEncode(objects)
}
func digest(body []byte) string        { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func signedMessage(body []byte) []byte { return append([]byte(signatureDomain), body...) }
func canonicalEncode(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalid
	}
	canonical, err := canonicaljson.CanonicalJSON(body)
	if err != nil {
		return nil, ErrInvalid
	}
	return canonical, nil
}
func strictCanonical(body []byte, limit int, value any) error {
	if len(body) == 0 || len(body) > limit {
		return ErrInvalid
	}
	canonical, err := canonicaljson.CanonicalJSON(body)
	if err != nil || !bytes.Equal(body, canonical) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	typed, err := canonicalEncode(value)
	if err != nil || !bytes.Equal(body, typed) {
		return ErrInvalid
	}
	return nil
}

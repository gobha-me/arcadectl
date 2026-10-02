// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adminauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

const (
	VerifierBundleVersion    = "v1"
	ClientCredentialVersion  = "v1"
	VerifierDigestAlgorithm  = "sha256"
	GeneratedTokenBytes      = 32
	MaxVerifierBundleBytes   = 4096
	MaxClientCredentialBytes = 4096

	ManagedByLabelKey         = "app.kubernetes.io/managed-by"
	ManagedByLabelValue       = "arcadectl"
	ApplicationNameLabelKey   = "app.kubernetes.io/name"
	ApplicationNameLabelValue = "arcadectl-api"
	ComponentLabelKey         = "app.kubernetes.io/component"
	ComponentLabelValue       = "admin-authentication"
)

var (
	errInvalidCredential = errors.New("invalid administrator credential")
	digestPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uuidPattern          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// VerifierBundle is the sole accepted credential verifier. A bundle never
// contains the bearer token and never represents an old-token grace period.
type VerifierBundle struct {
	Version      string
	CredentialID string
	Serial       uint64
	ExpiresAt    time.Time
	TokenSHA256  string
}

// ClientCredential is the private, versioned output written by the trusted
// administrator utility before it attempts a Kubernetes mutation.
type ClientCredential struct {
	Version              string
	CredentialID         string
	Serial               uint64
	ExpiresAt            time.Time
	Token                string
	PriorSecretUID       string
	PriorResourceVersion string
}

// Credential pairs private client material with its non-secret verifier.
type Credential struct {
	Token  string
	Bundle VerifierBundle
}

type verifierBundleWire struct {
	Version      string `json:"version"`
	CredentialID string `json:"credentialId"`
	Serial       uint64 `json:"serial"`
	ExpiresAt    string `json:"expiresAt"`
	TokenSHA256  string `json:"tokenSha256"`
}

type clientCredentialWire struct {
	Version              string `json:"version"`
	CredentialID         string `json:"credentialId"`
	Serial               uint64 `json:"serial"`
	ExpiresAt            string `json:"expiresAt"`
	Token                string `json:"token"`
	PriorSecretUID       string `json:"priorSecretUid,omitempty"`
	PriorResourceVersion string `json:"priorResourceVersion,omitempty"`
}

// ManagedSecretLabels returns a fresh exact label set for the managed Secret.
func ManagedSecretLabels() map[string]string {
	return map[string]string{
		ManagedByLabelKey:       ManagedByLabelValue,
		ApplicationNameLabelKey: ApplicationNameLabelValue,
		ComponentLabelKey:       ComponentLabelValue,
	}
}

// GenerateCredential creates an opaque 256-bit bearer token and verifier.
func GenerateCredential(now time.Time, lifetime time.Duration) (Credential, error) {
	if lifetime <= 0 {
		return Credential{}, errInvalidCredential
	}
	expiresAt := now.UTC().Add(lifetime)
	if !expiresAt.After(now) {
		return Credential{}, errInvalidCredential
	}
	tokenBytes := make([]byte, GeneratedTokenBytes)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return Credential{}, errors.New("generate administrator credential failed")
	}
	credentialID, err := generateUUID()
	if err != nil {
		return Credential{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	return Credential{
		Token: token,
		Bundle: VerifierBundle{
			Version:      VerifierBundleVersion,
			CredentialID: credentialID,
			Serial:       1,
			ExpiresAt:    expiresAt,
			TokenSHA256:  TokenDigest(token),
		},
	}, nil
}

func generateUUID() (string, error) {
	contents := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, contents); err != nil {
		return "", errors.New("generate credential identity failed")
	}
	contents[6] = (contents[6] & 0x0f) | 0x40
	contents[8] = (contents[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(contents)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

// TokenDigest returns the lowercase SHA-256 digest used by verifier bundles.
func TokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// TokenMatchesBundle verifies a generated token without variable-time string
// comparison. Structural validation makes malformed inputs indistinguishable.
func TokenMatchesBundle(token string, bundle VerifierBundle) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != GeneratedTokenBytes || len(token) != base64.RawURLEncoding.EncodedLen(GeneratedTokenBytes) ||
		base64.RawURLEncoding.EncodeToString(decoded) != token {
		return false
	}
	want, err := hex.DecodeString(bundle.TokenSHA256)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	actual := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(actual[:], want) == 1
}

// MarshalVerifierBundle emits the canonical bounded Secret value.
func MarshalVerifierBundle(bundle VerifierBundle) ([]byte, error) {
	if err := validateVerifierBundle(bundle); err != nil {
		return nil, err
	}
	return json.Marshal(verifierBundleWire{
		Version: bundle.Version, CredentialID: bundle.CredentialID, Serial: bundle.Serial,
		ExpiresAt: bundle.ExpiresAt.UTC().Format(time.RFC3339Nano), TokenSHA256: bundle.TokenSHA256,
	})
}

// ParseVerifierBundle rejects unknown fields, duplicate keys, trailing values,
// noncanonical timestamps, malformed digests, and oversized input.
func ParseVerifierBundle(contents []byte) (VerifierBundle, error) {
	if len(contents) == 0 || len(contents) > MaxVerifierBundleBytes || rejectDuplicateJSONKeys(contents) != nil {
		return VerifierBundle{}, errInvalidCredential
	}
	var wire verifierBundleWire
	if err := decodeStrictJSON(contents, &wire); err != nil {
		return VerifierBundle{}, errInvalidCredential
	}
	expiresAt, err := parseCanonicalTime(wire.ExpiresAt)
	if err != nil {
		return VerifierBundle{}, errInvalidCredential
	}
	bundle := VerifierBundle{
		Version: wire.Version, CredentialID: wire.CredentialID, Serial: wire.Serial,
		ExpiresAt: expiresAt, TokenSHA256: wire.TokenSHA256,
	}
	if err := validateVerifierBundle(bundle); err != nil {
		return VerifierBundle{}, err
	}
	return bundle, nil
}

// MarshalClientCredential emits private client material for an O_EXCL file.
func MarshalClientCredential(credential ClientCredential) ([]byte, error) {
	if err := validateClientCredential(credential); err != nil {
		return nil, err
	}
	return json.Marshal(clientCredentialWire{
		Version: credential.Version, CredentialID: credential.CredentialID, Serial: credential.Serial,
		ExpiresAt: credential.ExpiresAt.UTC().Format(time.RFC3339Nano), Token: credential.Token,
		PriorSecretUID: credential.PriorSecretUID, PriorResourceVersion: credential.PriorResourceVersion,
	})
}

// ParseClientCredential strictly parses a bounded private credential file.
func ParseClientCredential(contents []byte) (ClientCredential, error) {
	if len(contents) == 0 || len(contents) > MaxClientCredentialBytes || rejectDuplicateJSONKeys(contents) != nil {
		return ClientCredential{}, errInvalidCredential
	}
	var wire clientCredentialWire
	if err := decodeStrictJSON(contents, &wire); err != nil {
		return ClientCredential{}, errInvalidCredential
	}
	expiresAt, err := parseCanonicalTime(wire.ExpiresAt)
	if err != nil {
		return ClientCredential{}, errInvalidCredential
	}
	credential := ClientCredential{
		Version: wire.Version, CredentialID: wire.CredentialID, Serial: wire.Serial,
		ExpiresAt: expiresAt, Token: wire.Token, PriorSecretUID: wire.PriorSecretUID,
		PriorResourceVersion: wire.PriorResourceVersion,
	}
	if err := validateClientCredential(credential); err != nil {
		return ClientCredential{}, err
	}
	return credential, nil
}

func validateVerifierBundle(bundle VerifierBundle) error {
	if bundle.Version != VerifierBundleVersion || !uuidPattern.MatchString(bundle.CredentialID) || bundle.Serial == 0 ||
		bundle.ExpiresAt.IsZero() || !digestPattern.MatchString(bundle.TokenSHA256) {
		return errInvalidCredential
	}
	return nil
}

func validateClientCredential(credential ClientCredential) error {
	if credential.Version != ClientCredentialVersion || !uuidPattern.MatchString(credential.CredentialID) || credential.Serial == 0 ||
		credential.ExpiresAt.IsZero() || !TokenMatchesBundle(credential.Token, VerifierBundle{TokenSHA256: TokenDigest(credential.Token)}) {
		return errInvalidCredential
	}
	if (credential.PriorSecretUID == "") != (credential.PriorResourceVersion == "") {
		return errInvalidCredential
	}
	if strings.ContainsAny(credential.PriorSecretUID, "\r\n\x00") || strings.ContainsAny(credential.PriorResourceVersion, "\r\n\x00") {
		return errInvalidCredential
	}
	return nil
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errInvalidCredential
	}
	return parsed, nil
}

func decodeStrictJSON(contents []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errInvalidCredential
	}
	return nil
}

func rejectDuplicateJSONKeys(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidCredential
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidCredential
			}
			if _, exists := seen[key]; exists {
				return errInvalidCredential
			}
			seen[key] = struct{}{}
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errInvalidCredential
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(map[json.Delim]json.Delim{'{': '}', '[': ']'}[delimiter]) {
		return errInvalidCredential
	}
	return nil
}

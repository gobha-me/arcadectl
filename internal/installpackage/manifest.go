// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package installpackage authenticates bounded installation package bytes.
// Verification is not authorization to apply those bytes to Kubernetes and does
// not prove the runtime compatibility declared by package metadata. A separate
// installer must enforce resource semantics, security, ownership and evidence.
package installpackage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gobha-me/arcadectl/internal/canonicaljson"
)

const (
	FormatVersion        = "v1"
	RendererVersion      = "v1"
	MaxManifestBytes     = canonicaljson.MaxBytes
	MaxSignatureBytes    = 2048
	MaxPayloadBytes      = 4 * 1024 * 1024
	MaxTotalPayloadBytes = 12 * 1024 * 1024
	AnchorsPath          = "manifests/anchors.yaml"
	APIPath              = "manifests/api.yaml"
	ControllerPath       = "manifests/controller.yaml"
)

var (
	ErrInvalid          = errors.New("invalid installation package")
	ErrSignature        = errors.New("installation package authentication failed")
	ErrUnverified       = errors.New("installation package is not verified")
	shaPattern          = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	imagePattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$`)
	versionPattern      = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-z0-9]+([.-][a-z0-9]+)*)?$`)
	idPattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	repositoryComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	registryLabel       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	imageTag            = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]{0,127}$`)
)

type Images struct {
	Controller string `json:"controller"`
	API        string `json:"api"`
}

// Profile is a declaration to be checked against actual certification evidence.
// The signature authenticates the declaration, not the claimed support.
type Profile struct {
	ID                 string `json:"id"`
	KubernetesVersion  string `json:"kubernetesVersion"`
	PodSecurityVersion string `json:"podSecurityVersion"`
}

type CRD struct {
	Name               string   `json:"name"`
	SchemaSHA256       string   `json:"schemaSha256"`
	StorageVersion     string   `json:"storageVersion"`
	ServedVersions     []string `json:"servedVersions"`
	ConversionStrategy string   `json:"conversionStrategy"`
}

// Predecessor binds a supported transition to an exact previous canonical
// manifest digest as well as source and image identities.
// It does not permit adopting an existing unowned installation. Current
// predecessor contracts are intentionally default-namespace, no-conversion only.
type Predecessor struct {
	ID            string   `json:"id"`
	PackageSHA256 string   `json:"packageSha256"`
	SourceSHA     string   `json:"sourceSha"`
	Images        Images   `json:"images"`
	Namespace     string   `json:"namespace"`
	ProfileIDs    []string `json:"profileIds"`
}

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	FormatVersion   string        `json:"formatVersion"`
	RendererVersion string        `json:"rendererVersion"`
	PackageVersion  string        `json:"packageVersion"`
	SourceSHA       string        `json:"sourceSha"`
	SourceEpoch     int64         `json:"sourceEpoch"`
	Images          Images        `json:"images"`
	Profiles        []Profile     `json:"profiles"`
	Prerequisites   []string      `json:"prerequisites"`
	CRDs            []CRD         `json:"crds"`
	Predecessors    []Predecessor `json:"predecessors"`
	Files           []File        `json:"files"`
}

// CanonicalCRDNames returns a fresh sorted list; callers cannot change the
// package's canonical five-resource contract by modifying this slice.
func CanonicalCRDNames() []string {
	return []string{"arcadeoperations.arcade.gobha.me", "gamebackups.arcade.gobha.me", "gamedestroys.arcade.gobha.me", "gamerestores.arcade.gobha.me", "gameservers.arcade.gobha.me"}
}

// Build derives all file identities from bytes. Input Files must be empty; no
// caller-supplied checksum, runtime timestamp or input ordering is trusted.
func Build(metadata Manifest, payloads map[string][]byte) ([]byte, error) {
	if len(metadata.Files) != 0 || !boundedMetadata(metadata) || !validPayloadMap(payloads) {
		return nil, ErrInvalid
	}
	// Deep-clone input before sorting to avoid changing caller-owned slices.
	encoded, err := json.Marshal(metadata)
	if err != nil || len(encoded) > MaxManifestBytes {
		return nil, ErrInvalid
	}
	var result Manifest
	if json.Unmarshal(encoded, &result) != nil {
		return nil, ErrInvalid
	}
	slices.SortFunc(result.Profiles, func(a, b Profile) int { return strings.Compare(a.ID, b.ID) })
	slices.Sort(result.Prerequisites)
	slices.SortFunc(result.CRDs, func(a, b CRD) int { return strings.Compare(a.Name, b.Name) })
	for i := range result.CRDs {
		slices.Sort(result.CRDs[i].ServedVersions)
	}
	slices.SortFunc(result.Predecessors, func(a, b Predecessor) int { return strings.Compare(a.ID, b.ID) })
	if result.Predecessors == nil {
		result.Predecessors = []Predecessor{}
	}
	for i := range result.Predecessors {
		slices.Sort(result.Predecessors[i].ProfileIDs)
	}
	for _, path := range []string{AnchorsPath, APIPath, ControllerPath} {
		body := payloads[path]
		result.Files = append(result.Files, File{Path: path, Size: int64(len(body)), SHA256: hash(body)})
	}
	encoded, err = json.Marshal(result)
	if err != nil {
		return nil, ErrInvalid
	}
	canonical, err := canonicaljson.CanonicalJSON(encoded)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := ParseManifest(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

// ParseManifest accepts only one canonical bounded, strictly typed document.
// No whitespace, duplicate keys, unknown fields, aliases or alternate numeric
// representations are accepted, even if their signatures would be valid.
func ParseManifest(body []byte) (Manifest, error) {
	var result Manifest
	if strictCanonical(body, MaxManifestBytes, &result) != nil || validate(result) != nil {
		return Manifest{}, ErrInvalid
	}
	// Case-insensitive field matching and explicit nulls accepted by encoding/json
	// must not create alternate typed wire representations.
	typed, err := json.Marshal(result)
	if err != nil {
		return Manifest{}, ErrInvalid
	}
	canonical, err := canonicaljson.CanonicalJSON(typed)
	if err != nil || !bytes.Equal(body, canonical) {
		return Manifest{}, ErrInvalid
	}
	return result, nil
}

func strictCanonical(body []byte, maximum int, target any) error {
	if len(body) == 0 || len(body) > maximum {
		return ErrInvalid
	}
	canonical, err := canonicaljson.CanonicalJSON(body)
	if err != nil || !bytes.Equal(body, canonical) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrInvalid
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validate(m Manifest) error {
	if m.FormatVersion != FormatVersion || m.RendererVersion != RendererVersion || !validVersion(m.PackageVersion) || !validSHA(m.SourceSHA) || m.SourceEpoch <= 0 || m.SourceEpoch > 253402300799 || !validImages(m.Images) {
		return ErrInvalid
	}
	if !boundedMetadata(m) || m.Predecessors == nil {
		return ErrInvalid
	}
	profileIDs := make([]string, 0, len(m.Profiles))
	for _, p := range m.Profiles {
		if !idPattern.MatchString(p.ID) || !validKubernetesVersion(p.KubernetesVersion) || p.PodSecurityVersion != securityVersion(p.KubernetesVersion) {
			return ErrInvalid
		}
		profileIDs = append(profileIDs, p.ID)
	}
	if !strictSorted(profileIDs) || !strictSorted(m.Prerequisites) {
		return ErrInvalid
	}
	for _, prerequisite := range m.Prerequisites {
		if !idPattern.MatchString(prerequisite) {
			return ErrInvalid
		}
	}
	names := CanonicalCRDNames()
	if len(m.CRDs) != len(names) {
		return ErrInvalid
	}
	for i, crd := range m.CRDs {
		if crd.Name != names[i] || !validDigest(crd.SchemaSHA256) || crd.StorageVersion != "v1alpha1" || !slices.Equal(crd.ServedVersions, []string{"v1alpha1"}) || crd.ConversionStrategy != "None" {
			return ErrInvalid
		}
	}
	predecessorIDs := make([]string, 0, len(m.Predecessors))
	for _, previous := range m.Predecessors {
		if !idPattern.MatchString(previous.ID) || !validDigest(previous.PackageSHA256) || !validSHA(previous.SourceSHA) || previous.SourceSHA == m.SourceSHA || !validImages(previous.Images) || previous.Namespace != "arcadectl-system" || len(previous.ProfileIDs) == 0 || !strictSorted(previous.ProfileIDs) {
			return ErrInvalid
		}
		for _, id := range previous.ProfileIDs {
			if !slices.Contains(profileIDs, id) {
				return ErrInvalid
			}
		}
		predecessorIDs = append(predecessorIDs, previous.ID)
	}
	if len(predecessorIDs) > 0 && !strictSorted(predecessorIDs) {
		return ErrInvalid
	}
	paths := []string{AnchorsPath, APIPath, ControllerPath}
	if len(m.Files) != len(paths) {
		return ErrInvalid
	}
	var total int64
	for i, f := range m.Files {
		if f.Path != paths[i] || f.Size <= 0 || f.Size > MaxPayloadBytes || !validDigest(f.SHA256) {
			return ErrInvalid
		}
		total += f.Size
	}
	if total > MaxTotalPayloadBytes {
		return ErrInvalid
	}
	return nil
}

func validPayloadMap(payloads map[string][]byte) bool {
	if len(payloads) != 3 {
		return false
	}
	total := 0
	for path, body := range payloads {
		if path != AnchorsPath && path != APIPath && path != ControllerPath || len(body) == 0 || len(body) > MaxPayloadBytes {
			return false
		}
		total += len(body)
	}
	return total <= MaxTotalPayloadBytes
}

func validImages(images Images) bool { return validImage(images.Controller) && validImage(images.API) }
func validImage(value string) bool {
	if len(value) > 512 || !imagePattern.MatchString(value) {
		return false
	}
	repository, digest, found := strings.Cut(value, "@sha256:")
	segments := strings.Split(repository, "/")
	for i, segment := range segments {
		if i == 0 && len(segments) > 1 && (strings.ContainsAny(segment, ".:") || segment == "localhost") {
			host, port, hasPort := strings.Cut(segment, ":")
			if len(host) > 253 {
				return false
			}
			for _, label := range strings.Split(host, ".") {
				if !registryLabel.MatchString(label) {
					return false
				}
			}
			if hasPort {
				parsed, err := strconv.Atoi(port)
				if err != nil || parsed < 1 || parsed > 65535 || strconv.Itoa(parsed) != port {
					return false
				}
			}
			continue
		}
		if i == len(segments)-1 {
			component, tag, hasTag := strings.Cut(segment, ":")
			if hasTag && !imageTag.MatchString(tag) {
				return false
			}
			segment = component
		}
		if !repositoryComponent.MatchString(segment) {
			return false
		}
	}
	return found && validDigest(digest)
}
func boundedMetadata(m Manifest) bool {
	if len(m.Profiles) < 1 || len(m.Profiles) > 8 || len(m.Prerequisites) < 1 || len(m.Prerequisites) > 16 || len(m.CRDs) != 5 || len(m.Predecessors) > 8 {
		return false
	}
	if len(m.FormatVersion) > 16 || len(m.RendererVersion) > 16 || len(m.PackageVersion) > 64 || len(m.SourceSHA) > 40 || len(m.Images.Controller) > 512 || len(m.Images.API) > 512 {
		return false
	}
	for _, p := range m.Profiles {
		if len(p.ID) > 64 || len(p.KubernetesVersion) > 32 || len(p.PodSecurityVersion) > 32 {
			return false
		}
	}
	for _, p := range m.Prerequisites {
		if len(p) > 64 {
			return false
		}
	}
	for _, c := range m.CRDs {
		if len(c.Name) > 128 || len(c.SchemaSHA256) > 64 || len(c.StorageVersion) > 32 || len(c.ConversionStrategy) > 32 || len(c.ServedVersions) != 1 || len(c.ServedVersions[0]) > 32 {
			return false
		}
	}
	for _, p := range m.Predecessors {
		if len(p.ID) > 64 || len(p.PackageSHA256) > 64 || len(p.SourceSHA) > 40 || len(p.Namespace) > 63 || len(p.Images.Controller) > 512 || len(p.Images.API) > 512 || len(p.ProfileIDs) < 1 || len(p.ProfileIDs) > 8 {
			return false
		}
		for _, id := range p.ProfileIDs {
			if len(id) > 64 {
				return false
			}
		}
	}
	return true
}
func validVersion(value string) bool { return len(value) <= 64 && versionPattern.MatchString(value) }
func validKubernetesVersion(value string) bool {
	return len(value) <= 32 && versionPattern.MatchString(value) && strings.HasPrefix(value, "1.") && !strings.Contains(value, "-")
}
func securityVersion(value string) string {
	fields := strings.Split(value, ".")
	if len(fields) != 3 {
		return ""
	}
	return "v" + fields[0] + "." + fields[1]
}
func validSHA(value string) bool {
	return shaPattern.MatchString(value) && value != strings.Repeat("0", 40)
}
func validDigest(value string) bool {
	return digestPattern.MatchString(value) && value != strings.Repeat("0", 64)
}
func strictSorted(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] >= values[i] {
			return false
		}
	}
	return true
}
func hash(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

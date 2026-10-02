// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package image resolves adapter-curated public image versions to immutable
// registry digests without accepting caller-selected repositories or tags.
package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/platform/game"
)

const (
	maxManifestBytes = 4 << 20
	maxTokenBytes    = 16 << 10
	maxChallengeSize = 4096
	maxBearerSize    = 8192
)

const manifestAccept = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json"

var (
	// ErrVersionUnavailable means the curated tag does not currently exist.
	ErrVersionUnavailable = errors.New("image version is unavailable in the curated repository")
	// ErrRegistryUnavailable means the trusted public registry could not be
	// reached or did not complete the bounded exchange.
	ErrRegistryUnavailable = errors.New("public image registry is unavailable")
	// ErrRegistryResponseInvalid means the registry returned data that could not
	// be bound to one verified manifest digest.
	ErrRegistryResponseInvalid = errors.New("public image registry response is invalid")

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	bearerPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)
)

// Resolution is the exact adapter-owned tag lookup and verified immutable
// digest. Repository and Tag are provenance; workloads consume Digest only.
type Resolution struct {
	Repository string
	Tag        string
	Digest     string
}

// VersionResolver resolves one adapter-curated version without allowing a
// caller to supply a repository or raw image tag.
type VersionResolver interface {
	Resolve(context.Context, game.Definition, string) (Resolution, error)
}

// RegistryResolver performs bounded anonymous HTTPS OCI Distribution pulls.
// Its transport ignores proxy environment variables and refuses redirects.
type RegistryResolver struct {
	client *http.Client
}

var _ VersionResolver = (*RegistryResolver)(nil)

// NewRegistryResolver constructs the production public-registry resolver.
func NewRegistryResolver() *RegistryResolver {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Second
	transport.ExpectContinueTimeout = time.Second
	transport.DisableCompression = true
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.MaxIdleConns = 8
	transport.MaxIdleConnsPerHost = 2
	return &RegistryResolver{client: &http.Client{
		Transport: transport,
		Timeout:   12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

// Resolve maps version through the adapter policy and verifies the returned
// manifest bytes against the registry's Docker-Content-Digest header.
func (resolver *RegistryResolver) Resolve(ctx context.Context, definition game.Definition, version string) (Resolution, error) {
	tag, err := game.ResolveVersionTag(definition, version)
	if err != nil {
		return Resolution{}, err
	}
	registry, repository, ok := strings.Cut(definition.ImageRepository, "/")
	if !ok || registry == "" || repository == "" || resolver == nil || resolver.client == nil {
		return Resolution{}, ErrRegistryUnavailable
	}
	manifestURL := "https://" + registry + "/v2/" + repository + "/manifests/" + url.PathEscape(tag)
	digest, challenge, err := resolver.fetchManifest(ctx, manifestURL, "")
	if err == nil {
		return Resolution{Repository: definition.ImageRepository, Tag: tag, Digest: digest}, nil
	}
	if challenge == "" {
		return Resolution{}, err
	}
	token, err := resolver.fetchAnonymousToken(ctx, registry, repository, challenge)
	if err != nil {
		return Resolution{}, err
	}
	digest, secondChallenge, err := resolver.fetchManifest(ctx, manifestURL, token)
	if err != nil || secondChallenge != "" {
		if errors.Is(err, ErrVersionUnavailable) {
			return Resolution{}, err
		}
		return Resolution{}, ErrRegistryUnavailable
	}
	return Resolution{Repository: definition.ImageRepository, Tag: tag, Digest: digest}, nil
}

func (resolver *RegistryResolver) fetchManifest(ctx context.Context, endpoint, token string) (string, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", ErrRegistryUnavailable
	}
	request.Header.Set("Accept", manifestAccept)
	request.Header.Set("User-Agent", "arcadectl-image-resolver/1")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := resolver.client.Do(request)
	if err != nil {
		return "", "", ErrRegistryUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized && token == "" {
		challenges := response.Header.Values("WWW-Authenticate")
		if len(challenges) != 1 || len(challenges[0]) > maxChallengeSize {
			return "", "", ErrRegistryResponseInvalid
		}
		return "", challenges[0], ErrRegistryUnavailable
	}
	if response.StatusCode == http.StatusNotFound {
		return "", "", ErrVersionUnavailable
	}
	if response.StatusCode != http.StatusOK {
		return "", "", ErrRegistryUnavailable
	}
	if response.ContentLength > maxManifestBytes {
		return "", "", ErrRegistryResponseInvalid
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxManifestBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxManifestBytes {
		return "", "", ErrRegistryResponseInvalid
	}
	digestHeaders := response.Header.Values("Docker-Content-Digest")
	if len(digestHeaders) != 1 || !digestPattern.MatchString(digestHeaders[0]) {
		return "", "", ErrRegistryResponseInvalid
	}
	want := "sha256:" + hex.EncodeToString(sum256(body))
	if digestHeaders[0] != want {
		return "", "", ErrRegistryResponseInvalid
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return "", "", ErrRegistryResponseInvalid
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || !supportedManifestType(mediaType) {
		return "", "", ErrRegistryResponseInvalid
	}
	var descriptor struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&descriptor); err != nil || decoder.Decode(&struct{}{}) != io.EOF || descriptor.SchemaVersion != 2 || descriptor.MediaType != "" && descriptor.MediaType != mediaType {
		return "", "", ErrRegistryResponseInvalid
	}
	return want, "", nil
}

func sum256(contents []byte) []byte {
	sum := sha256.Sum256(contents)
	return sum[:]
}

func supportedManifestType(value string) bool {
	switch value {
	case "application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json":
		return true
	default:
		return false
	}
}

type bearerChallenge struct {
	realm   string
	service string
	scope   string
}

func (resolver *RegistryResolver) fetchAnonymousToken(ctx context.Context, registry, repository, rawChallenge string) (string, error) {
	challenge, err := parseBearerChallenge(rawChallenge)
	if err != nil || challenge.service != registry || challenge.scope != "repository:"+repository+":pull" {
		return "", ErrRegistryResponseInvalid
	}
	realm, err := url.Parse(challenge.realm)
	if err != nil || realm.Scheme != "https" || realm.Host != registry || realm.User != nil || realm.Path == "" || realm.RawQuery != "" || realm.Fragment != "" || realm.Opaque != "" {
		return "", ErrRegistryResponseInvalid
	}
	query := realm.Query()
	query.Set("service", challenge.service)
	query.Set("scope", challenge.scope)
	realm.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", ErrRegistryUnavailable
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "arcadectl-image-resolver/1")
	response, err := resolver.client.Do(request)
	if err != nil {
		return "", ErrRegistryUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrRegistryUnavailable
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return "", ErrRegistryResponseInvalid
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		return "", ErrRegistryResponseInvalid
	}
	if response.ContentLength > maxTokenBytes {
		return "", ErrRegistryResponseInvalid
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxTokenBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxTokenBytes {
		return "", ErrRegistryResponseInvalid
	}
	var payload struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&payload); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", ErrRegistryResponseInvalid
	}
	token := payload.Token
	if token == "" {
		token = payload.AccessToken
	} else if payload.AccessToken != "" && payload.AccessToken != token {
		return "", ErrRegistryResponseInvalid
	}
	if len(token) == 0 || len(token) > maxBearerSize || !bearerPattern.MatchString(token) {
		return "", ErrRegistryResponseInvalid
	}
	return token, nil
}

func parseBearerChallenge(raw string) (bearerChallenge, error) {
	if len(raw) > maxChallengeSize || len(raw) < len("Bearer ") || !strings.EqualFold(raw[:len("Bearer ")], "Bearer ") {
		return bearerChallenge{}, ErrRegistryResponseInvalid
	}
	parameters := make(map[string]string, 3)
	remainder := raw[len("Bearer "):]
	for remainder != "" {
		remainder = strings.TrimSpace(remainder)
		separator := strings.IndexByte(remainder, '=')
		if separator <= 0 {
			return bearerChallenge{}, ErrRegistryResponseInvalid
		}
		name := strings.ToLower(strings.TrimSpace(remainder[:separator]))
		remainder = strings.TrimSpace(remainder[separator+1:])
		if remainder == "" || remainder[0] != '"' {
			return bearerChallenge{}, ErrRegistryResponseInvalid
		}
		end := 1
		for end < len(remainder) {
			if remainder[end] == '\\' {
				end += 2
				continue
			}
			if remainder[end] == '"' {
				break
			}
			end++
		}
		if end >= len(remainder) {
			return bearerChallenge{}, ErrRegistryResponseInvalid
		}
		value, err := strconv.Unquote(remainder[:end+1])
		if err != nil || value == "" || strings.ContainsAny(value, "\r\n") {
			return bearerChallenge{}, ErrRegistryResponseInvalid
		}
		if _, duplicate := parameters[name]; duplicate {
			return bearerChallenge{}, ErrRegistryResponseInvalid
		}
		parameters[name] = value
		remainder = strings.TrimSpace(remainder[end+1:])
		if remainder == "" {
			break
		}
		if remainder[0] != ',' {
			return bearerChallenge{}, ErrRegistryResponseInvalid
		}
		remainder = remainder[1:]
	}
	if len(parameters) != 3 || parameters["realm"] == "" || parameters["service"] == "" || parameters["scope"] == "" {
		return bearerChallenge{}, ErrRegistryResponseInvalid
	}
	return bearerChallenge{realm: parameters["realm"], service: parameters["service"], scope: parameters["scope"]}, nil
}

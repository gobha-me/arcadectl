// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package data

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
)

const (
	RepositoryKeyRepository      = "repository"
	RepositoryKeyPassword        = "password"
	RepositoryKeyAccessKeyID     = "awsAccessKeyID"
	RepositoryKeySecretAccessKey = "awsSecretAccessKey"
	RepositoryKeySessionToken    = "awsSessionToken"
	RepositoryKeyCACertificate   = "ca.crt"
)

var repositorySecretLimits = map[string]int{
	RepositoryKeyRepository:      2048,
	RepositoryKeyPassword:        4096,
	RepositoryKeyAccessKeyID:     1024,
	RepositoryKeySecretAccessKey: 4096,
	RepositoryKeySessionToken:    8192,
	RepositoryKeyCACertificate:   1 << 20,
}

// ValidateRepositorySecretData applies the complete, bounded worker Secret
// contract without returning or formatting any credential value.
func ValidateRepositorySecretData(data map[string][]byte) error {
	for key, value := range data {
		limit, allowed := repositorySecretLimits[key]
		if !allowed {
			return errors.New("repository Secret contains an unsupported key")
		}
		if len(value) == 0 || len(value) > limit || bytes.IndexByte(value, 0) >= 0 {
			return errors.New("repository Secret key is invalid")
		}
		if key != RepositoryKeyCACertificate && bytes.ContainsAny(value, "\r\n") {
			return errors.New("repository Secret key is invalid")
		}
	}
	for _, key := range []string{RepositoryKeyRepository, RepositoryKeyPassword, RepositoryKeyAccessKeyID, RepositoryKeySecretAccessKey} {
		if len(data[key]) == 0 {
			return errors.New("repository Secret is incomplete")
		}
	}
	if !validS3Repository(string(data[RepositoryKeyRepository])) {
		return errors.New("repository must be a bounded S3-compatible URL")
	}
	return nil
}

func validS3Repository(repository string) bool {
	if !strings.HasPrefix(repository, "s3:http://") && !strings.HasPrefix(repository, "s3:https://") {
		return false
	}
	parsed, err := url.Parse(strings.TrimPrefix(repository, "s3:"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	return len(parts) >= 1 && parts[0] != "" && parsed.Path == parsed.EscapedPath()
}

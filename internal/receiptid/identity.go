// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

// Package receiptid shares the existing versioned receipt identity without Kubernetes dependencies.
package receiptid

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

var ErrInvalid = errors.New("invalid receipt identity")
var namespacePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
var principalPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func KeyDigest(namespace, principal, key string) (string, error) {
	if !namespacePattern.MatchString(namespace) || !principalPattern.MatchString(principal) || !keyPattern.MatchString(key) {
		return "", ErrInvalid
	}
	sum := sha256.Sum256([]byte("arcadectl/idempotency/v1\x00" + namespace + "\x00" + principal + "\x00" + key))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ReceiptName(namespace, principal, key string) (string, error) {
	digest, err := KeyDigest(namespace, principal, key)
	if err != nil {
		return "", ErrInvalid
	}
	return NameForKeyDigest(digest)
}

func NameForKeyDigest(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", ErrInvalid
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	if err != nil {
		return "", ErrInvalid
	}
	return "ao-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded)), nil
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"errors"
)

// ResolveVersionTag applies an adapter-owned version policy. It never accepts
// a repository or tag from the caller, and its result is safe for an OCI
// manifest request.
func ResolveVersionTag(definition Definition, version string) (string, error) {
	if err := validateRepository(definition.ImageRepository); err != nil {
		return "", errors.New("image version repository is invalid")
	}
	if err := validateVersionPolicy(definition.VersionPolicy); err != nil || definition.VersionPolicy == nil {
		return "", errors.New("image version selection is not supported by this adapter")
	}
	if len(version) == 0 || len(version) > maxVersionLength || !versionTokenPattern.MatchString(version) {
		return "", errors.New("image version must be a bounded version token")
	}
	policy := definition.VersionPolicy
	compiled, err := compileVersionPattern(policy.Pattern)
	if err != nil || !compiled.MatchString(version) {
		return "", errors.New("image version does not satisfy the adapter policy")
	}
	tag := policy.TagPrefix + version
	if !tagPattern.MatchString(tag) {
		return "", errors.New("resolved image tag is invalid")
	}
	return tag, nil
}

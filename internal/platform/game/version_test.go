// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package game

import (
	"strings"
	"testing"
)

func TestResolveVersionTag(t *testing.T) {
	t.Parallel()
	definition := validDefinition()
	definition.VersionPolicy = &VersionPolicy{Pattern: `^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`, TagPrefix: "release-"}

	tag, err := ResolveVersionTag(definition, "2.0.72")
	if err != nil {
		t.Fatalf("ResolveVersionTag() error = %v", err)
	}
	if tag != "release-2.0.72" {
		t.Fatalf("ResolveVersionTag() = %q", tag)
	}

	for _, version := range []string{"", "2.0", "latest", "2.0.72/other", "2.0.72\n", strings.Repeat("1", 65)} {
		if _, err := ResolveVersionTag(definition, version); err == nil {
			t.Errorf("ResolveVersionTag() accepted %q", version)
		}
	}
}

func TestVersionPolicyValidation(t *testing.T) {
	t.Parallel()
	tests := []VersionPolicy{
		{},
		{Pattern: `[0-9]+$`},
		{Pattern: `^[0-9]+`},
		{Pattern: `^$`},
		{Pattern: `^[$`},
		{Pattern: "^" + strings.Repeat("a", maxVersionPattern) + "$"},
		{Pattern: `^[0-9]+$`, TagPrefix: "bad/prefix"},
		{Pattern: `^[0-9]+$`, TagPrefix: strings.Repeat("a", maxTagPrefix+1)},
	}
	for _, policy := range tests {
		definition := validDefinition()
		definition.VersionPolicy = &policy
		if err := definition.Validate(); err == nil {
			t.Errorf("Validate() accepted policy %#v", policy)
		}
	}

	definition := validDefinition()
	definition.VersionPolicy = &VersionPolicy{Pattern: `^[0-9]+$`, TagPrefix: "v"}
	if err := definition.Validate(); err != nil {
		t.Fatalf("Validate() rejected version policy: %v", err)
	}
	definition.VersionPolicy.Pattern = `^1$|2$`
	if tag, err := ResolveVersionTag(definition, "2"); err != nil || tag != "v2" {
		t.Fatalf("platform anchoring rejected a complete alternation match: tag=%q err=%v", tag, err)
	}
	if _, err := ResolveVersionTag(definition, "x2"); err == nil {
		t.Fatal("platform anchoring accepted a partial alternation match")
	}
}

func TestCloneCopiesVersionPolicy(t *testing.T) {
	t.Parallel()
	original := validDefinition()
	original.VersionPolicy = &VersionPolicy{Pattern: `^[0-9]+$`, TagPrefix: "v"}
	clone := original.Clone()
	clone.VersionPolicy.TagPrefix = "changed-"
	if original.VersionPolicy.TagPrefix != "v" {
		t.Fatal("Clone() aliased the version policy")
	}
}

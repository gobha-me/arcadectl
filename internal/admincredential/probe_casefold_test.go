// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type caseFoldSelfMember struct {
	key   string
	value string
}

func caseFoldSelfMembers() []caseFoldSelfMember {
	return []caseFoldSelfMember{
		{"version", "v1"},
		{"principalId", "fixture-principal"},
		{"credentialId", "fixture-credential"},
		{"expiresAt", "2031-02-03T04:05:06Z"},
		{"namespace", "fixture-namespace"},
	}
}

// Keys are JSON source text so adversarial callers can supply Unicode escapes.
func caseFoldSelfBody(members []caseFoldSelfMember) []byte {
	parts := make([]string, 0, len(members))
	for _, member := range members {
		parts = append(parts, fmt.Sprintf(`"%s":%q`, member.key, member.value))
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

func caseFoldSelfExpected() selfResponse {
	return selfResponse{
		Version: "v1", PrincipalID: "fixture-principal", CredentialID: "fixture-credential",
		ExpiresAt: "2031-02-03T04:05:06Z", Namespace: "fixture-namespace",
	}
}

func TestParseSelfResponseCaseFoldDuplicates(t *testing.T) {
	mixedKeys := []string{"Version", "PrincipalId", "CredentialId", "ExpiresAt", "Namespace"}
	for index, field := range caseFoldSelfMembers() {
		variants := []struct{ name, key string }{
			{"upper", strings.ToUpper(field.key)},
			{"lower", strings.ToLower(field.key)},
			{"mixed", mixedKeys[index]},
		}
		for _, variant := range variants {
			for _, position := range []string{"first", "last"} {
				for _, values := range []string{"identical", "different"} {
					t.Run(field.key+"/"+variant.name+"/"+position+"/"+values, func(t *testing.T) {
						members := caseFoldSelfMembers()
						// version and namespace are already lowercase. Pair their lower
						// variant with uppercase so this remains a case-fold regression.
						if members[index].key == variant.key {
							members[index].key = strings.ToUpper(field.key)
						}
						duplicate := caseFoldSelfMember{variant.key, field.value}
						if values == "different" {
							duplicate.value = "alternate-value"
						}
						if position == "first" {
							members = append([]caseFoldSelfMember{duplicate}, members...)
						} else {
							members = append(members, duplicate)
						}
						response, err := parseSelfResponse(caseFoldSelfBody(members))
						if !errors.Is(err, ErrActivationIncomplete) {
							t.Fatalf("case-folded duplicate accepted: response=%+v, err=%v; want ErrActivationIncomplete", response, err)
						}
					})
				}
			}
		}
	}
}

func TestParseSelfResponseCaseFoldControls(t *testing.T) {
	t.Run("canonical", func(t *testing.T) {
		response, err := parseSelfResponse(caseFoldSelfBody(caseFoldSelfMembers()))
		if err != nil || response != caseFoldSelfExpected() {
			t.Fatalf("canonical response = %+v, %v; want %+v, nil", response, err, caseFoldSelfExpected())
		}
	})
	mixedKeys := []string{"Version", "PrincipalId", "CredentialId", "ExpiresAt", "Namespace"}
	for index, field := range caseFoldSelfMembers() {
		t.Run("exact_duplicate/"+field.key, func(t *testing.T) {
			members := append(caseFoldSelfMembers(), field)
			if !duplicateTopLevelKey(caseFoldSelfBody(members)) {
				t.Error("exact top-level duplicate was not detected")
			}
			if _, err := parseSelfResponse(caseFoldSelfBody(members)); !errors.Is(err, ErrActivationIncomplete) {
				t.Fatalf("exact duplicate error = %v; want ErrActivationIncomplete", err)
			}
		})
		variants := []struct{ name, key string }{
			{"upper", strings.ToUpper(field.key)},
			{"lower", strings.ToLower(field.key)},
			{"mixed", mixedKeys[index]},
		}
		for _, variant := range variants {
			t.Run("single/"+field.key+"/"+variant.name, func(t *testing.T) {
				members := caseFoldSelfMembers()
				members[index].key = variant.key
				body := caseFoldSelfBody(members)
				if duplicateTopLevelKey(body) {
					t.Fatal("single field spelling was treated as a duplicate")
				}
				response, err := parseSelfResponse(body)
				if err != nil || response != caseFoldSelfExpected() {
					t.Fatalf("single field response = %+v, %v; want %+v, nil", response, err, caseFoldSelfExpected())
				}
			})
		}
	}
}

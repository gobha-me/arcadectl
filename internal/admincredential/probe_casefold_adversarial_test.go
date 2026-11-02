// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package admincredential

import (
	"errors"
	"strings"
	"testing"
)

func TestSelfResponseCaseFoldAdversarial(t *testing.T) {
	canonical := string(caseFoldSelfBody(caseFoldSelfMembers()))
	withExtra := func(extra string) string {
		return strings.TrimSuffix(canonical, "}") + "," + extra + "}"
	}
	cases := []struct {
		name          string
		body          string
		wantDuplicate bool
		wantReject    bool
	}{
		{
			name: "escaped_canonical_against_uppercase",
			body: strings.Replace(withExtra(`"credential\u0049d":"escaped-value"`),
				`"credentialId"`, `"CREDENTIALID"`, 1),
			wantDuplicate: true, wantReject: true,
		},
		{
			name:          "escaped_case_variant",
			body:          withExtra(`"credential\u0049D":"escaped-value"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name:          "fully_escaped_uppercase",
			body:          withExtra(`"\u0043\u0052\u0045\u0044\u0045\u004e\u0054\u0049\u0041\u004c\u0049\u0044":"escaped-value"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name:          "escaped_exact_duplicate_control",
			body:          withExtra(`"credential\u0049d":"escaped-value"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name: "long_s_version", body: withExtra(`"verſion":"alternate-version"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name: "long_s_expiresAt", body: withExtra(`"expireſAt":"2032-03-04T05:06:07Z"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name: "long_s_namespace", body: withExtra(`"nameſpace":"alternate-namespace"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name: "escaped_long_s", body: withExtra(`"ver\u017fion":"alternate-version"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name: "single_long_s_version_control",
			body: strings.Replace(canonical, `"version"`, `"verſion"`, 1),
		},
		{
			name: "single_long_s_expiresAt_control",
			body: strings.Replace(canonical, `"expiresAt"`, `"expireſAt"`, 1),
		},
		{
			name: "single_long_s_namespace_control",
			body: strings.Replace(canonical, `"namespace"`, `"nameſpace"`, 1),
		},
		{
			name: "single_fully_escaped_uppercase_control",
			body: strings.Replace(canonical, `"credentialId"`,
				`"\u0043\u0052\u0045\u0044\u0045\u004e\u0054\u0049\u0041\u004c\u0049\u0044"`, 1),
		},
		{
			name:          "three_case_spellings",
			body:          withExtra(`"CREDENTIALID":"second-value","CredentialId":"third-value"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name:          "three_exact_copies_control",
			body:          withExtra(`"credentialId":"second-value","credentialId":"third-value"`),
			wantDuplicate: true, wantReject: true,
		},
		// The checker only inspects top-level names. The parser still rejects
		// these bodies because Self has no object/array/unknown fields.
		{
			name: "nested_variant_after_top_level_control",
			body: withExtra(`"metadata":{"CREDENTIALID":"nested-value"}`), wantReject: true,
		},
		{
			name:       "nested_variant_before_top_level_control",
			body:       `{"metadata":{"CREDENTIALID":"nested-value"},` + strings.TrimPrefix(canonical, "{"),
			wantReject: true,
		},
		{
			name:       "nested_duplicate_pair_control",
			body:       withExtra(`"metadata":{"credentialId":"first","CREDENTIALID":"second"}`),
			wantReject: true,
		},
		{
			name: "array_nested_variant_control",
			body: withExtra(`"metadata":[{"CREDENTIALID":"nested-value"}]`), wantReject: true,
		},
		{
			name: "single_unknown_variant_control",
			body: withExtra(`"EXTRA":"unknown-value"`), wantReject: true,
		},
		// Unknown names are still subject to the checker's duplicate policy;
		// parser rejection alone cannot prove that the checker detected them.
		{
			name:          "unknown_case_pair",
			body:          withExtra(`"extra":"first","EXTRA":"second"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name:          "unknown_kelvin_pair",
			body:          withExtra(`"k":"first","K":"second"`),
			wantDuplicate: true, wantReject: true,
		},
		{
			name:          "unknown_kelvin_reverse_pair",
			body:          withExtra(`"\u212a":"first","K":"second"`),
			wantDuplicate: true, wantReject: true,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(test.body)
			if got := duplicateTopLevelKey(body); got != test.wantDuplicate {
				t.Errorf("duplicateTopLevelKey = %v; want %v", got, test.wantDuplicate)
			}
			response, err := parseSelfResponse(body)
			if test.wantReject {
				if !errors.Is(err, ErrActivationIncomplete) {
					t.Fatalf("adversarial response accepted: response=%+v, err=%v; want ErrActivationIncomplete", response, err)
				}
			} else if err != nil || response != caseFoldSelfExpected() {
				t.Fatalf("single spelling response = %+v, %v; want %+v, nil", response, err, caseFoldSelfExpected())
			}
		})
	}
}

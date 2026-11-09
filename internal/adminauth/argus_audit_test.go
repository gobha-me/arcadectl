package adminauth

import (
	"strings"
	"testing"
)

const argusDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const argusDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// ParseVerifierBundle documents that it "rejects ... duplicate keys". Go's
// encoding/json matches struct fields case-insensitively (with Unicode simple
// folding), so keys that differ only by case are duplicates of the same field.
func TestArgusVerifierBundleRejectsCaseFoldedDuplicateKeys(t *testing.T) {
	base := `{"version":"v1","credentialId":"0f8fad5b-d9cb-469f-a165-70867728950e","serial":1,"expiresAt":"2030-01-01T00:00:00Z","tokenSha256":"` + argusDigestA + `"`
	cases := map[string]string{
		"exact duplicate (control)": base + `,"tokenSha256":"` + argusDigestB + `"}`,
		"upper-case duplicate":      base + `,"TOKENSHA256":"` + argusDigestB + `"}`,
		"long-s fold of serial":     base + `,"ſerial":7}`,
		"kelvin-sign fold":          base + `,"to\u212AenSha256":"` + argusDigestB + `"}`,
	}
	for name, input := range cases {
		bundle, err := ParseVerifierBundle([]byte(input))
		if err == nil {
			t.Errorf("%s: accepted duplicate key; parsed serial=%d tokenSha256=%s…", name, bundle.Serial, bundle.TokenSHA256[:8])
		}
	}
}

func TestArgusClientCredentialRejectsCaseFoldedDuplicateKeys(t *testing.T) {
	credential, err := GenerateCredential(mustTime(t), 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateCredential(mustTime(t), 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := MarshalClientCredential(ClientCredential{Version: "v1", CredentialID: credential.Bundle.CredentialID, Serial: 1, ExpiresAt: credential.Bundle.ExpiresAt, Token: credential.Token})
	if err != nil {
		t.Fatal(err)
	}
	input := strings.TrimSuffix(string(contents), "}") + `,"Token":"` + other.Token + `"}`
	parsed, err := ParseClientCredential([]byte(input))
	if err == nil {
		t.Errorf("accepted case-folded duplicate token key; parsed token is second value: %v", parsed.Token == other.Token)
	}
}

func mustTime(t *testing.T) (now timeT) { t.Helper(); return timeNow() }

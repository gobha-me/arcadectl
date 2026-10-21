// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"fmt"
	"strings"
	"testing"
)

func TestPublicJSONMatchesBoundedJSONOracle(t *testing.T) {
	cases := []struct {
		name, body string
		valid      bool
	}{
		{"null", `null`, true},
		{"true", `true`, true},
		{"false", `false`, true},
		{"number", `-123.456e+78`, true},
		{"huge-number", `1e999999999`, true},
		{"string", `"public"`, true},
		{"empty-object", `{}`, true},
		{"empty-array", `[]`, true},
		{"trailing-space", "[{},[],null,1,true,\"x\"] \r\n\t", true},
		{"separate-objects", `[{"a":null},{"a":false}]`, true},
		{"case-distinct", `{"a":0,"A":1}`, true},
		{"normalization-distinct", `{"é":0,"e\u0301":1}`, true},
		{"unpaired-surrogate-value", `"\ud800"`, true},
		{"duplicate-null", `{"a":null,"a":1}`, false},
		{"escaped-duplicate", `{"a":1,"\u0061":2}`, false},
		{"nested-duplicate", `{"x":[{"a":1,"a":2}]}`, false},
		{"replacement-duplicate", `{"�":1,"\ud800":2}`, false},
		{"supplementary-duplicate", `{"😀":1,"\ud83d\ude00":2}`, false},
		{"escaped-quote-duplicate", `{"\"":0,"\u0022":1}`, false},
		{"escaped-backslash-duplicate", `{"\\":0,"\u005c":1}`, false},
		{"escaped-slash-duplicate", `{"/":0,"\/":1}`, false},
		{"escaped-nul-duplicate", `{"\u0000":0,"\u0000":1}`, false},
		{"repeated-unpaired-surrogates", `{"\ud800":0,"\udfff":1}`, false},
		{"unicode-line-separators", "{\"\u2028\":0,\"\u2029\":1}", true},
		{"long-escaped-value", `{"value":"` + strings.Repeat(`\u0061\\\"\/`, 1000) + `"}`, true},
		{"large-key", `{"` + strings.Repeat("public", 10000) + `":0}`, true},
		{"whitespace-heavy", strings.Repeat(" \t\r\n", 10000) + `[0]` + strings.Repeat(" ", 10000), true},
		{"empty", ``, false},
		{"space-only", " \r\n\t", false},
		{"unterminated-string", "\"" + strings.Repeat("x", 10000), false},
		{"unterminated-key", "{\"" + strings.Repeat("x", 10000), false},
		{"key-backslash-eof", "{\"key" + "\\", false},
		{"value-backslash-eof", "{\"key\":\"value" + "\\", false},
		{"missing-colon", `{"a" 0}`, false},
		{"missing-comma", `{"a":0 "b":1}`, false},
		{"bad-key-escape", `{"\x20":0}`, false},
		{"bad-key-unicode", `{"\u00xz":0}`, false},
		{"bad-key-control", "{\"a\x00b\":0}", false},
		{"bad-value-large", "{\"x\":\"" + strings.Repeat("a", 1024*1024) + `\x20"}`, false},
		{"bad-key-large", "{\"" + strings.Repeat("a", 1024*1024) + `\x20":0}`, false},
		{"bad-primitive-deep-tail", "nul" + strings.Repeat("[", 1000), false},
		{"bad-primitive-with-delimiter", `[truex,false]`, false},
		{"bad-object-root", `{]`, false},
		{"bad-array-root", `[}`, false},
		{"invalid-utf8", string([]byte{'"', 0xff, '"'}), false},
		{"invalid-key-utf8", string([]byte{'{', '"', 0xff, '"', ':', '0', '}'}), false},
		{"raw-control", "\"a\x00b\"", false},
		{"bad-escape", `"\x20"`, false},
		{"bad-unicode", `"\u00xz"`, false},
		{"bad-number", `01`, false},
		{"nonfinite", `NaN`, false},
		{"unfinished-number", `1e`, false},
		{"comment", `/*public*/{}`, false},
		{"object-comma", `{"a":1,}`, false},
		{"array-comma", `[1,]`, false},
		{"wrong-close", `{"a":1]`, false},
		{"missing-close", `{"a":1`, false},
		{"missing-value", `{"a":}`, false},
		{"numeric-key", `{1:0}`, false},
		{"documents", `{} []`, false},
		{"trailing-garbage", `{}x`, false},
		{"close-only", `]`, false},
		{"depth-64-scalar", strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64), true},
		{"depth-65-scalar", strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), false},
		{"depth-64-empty", strings.Repeat("[", 65) + strings.Repeat("]", 65), true},
		{"depth-65-empty", strings.Repeat("[", 66) + strings.Repeat("]", 66), false},
		{"nodes-exact", "[" + strings.Repeat("0,", 199998) + "0]", true},
		{"nodes-over", "[" + strings.Repeat("0,", 199999) + "0]", false},
	}
	// Keys are not values/nodes: one object plus 199999 values is accepted.
	var object strings.Builder
	object.WriteByte('{')
	for i := range 199999 {
		if i > 0 {
			object.WriteByte(',')
		}
		fmt.Fprintf(&object, `"k%d":0`, i)
	}
	object.WriteByte('}')
	cases = append(cases, struct {
		name, body string
		valid      bool
	}{"object-keys-not-nodes-exact", object.String(), true}, struct {
		name, body string
		valid      bool
	}{"object-nodes-over", strings.TrimSuffix(object.String(), "}") + `,"last":0}`, false})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, oracle := boundedJSON([]byte(tc.body))
			candidate := validatePublicJSON([]byte(tc.body))
			if (oracle == nil) != tc.valid || (candidate == nil) != tc.valid {
				t.Fatal("oracle/candidate acceptance differs from the explicit contract")
			}
			if candidate != nil && candidate != ErrRead {
				t.Fatal("candidate leaked a decoder error")
			}
		})
	}
}

func FuzzPublicJSONMatchesBoundedJSON(f *testing.F) {
	for _, body := range []string{
		`{}`, `[]`, `null`, `true`, `1e999999999`, `"\ud800"`, `{"a":null,"\u0061":false}`,
		`[{"x":[0,null,true]},{"x":{}}]`, `{"�":0,"\ud800":1}`, `{} []`,
		strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65), string([]byte{'"', 0xff, '"'}),
		`"\x20"`, `"\u00xz"`, `{"\x20":0}`, `{"a" 0}`, `{"a":0 "b":1}`,
		`{"a":}`, `[truex,false]`, `1e+`, `null[`, `{]`, `[}`, `{"a":"unfinished`,
		"{\"key" + "\\", "{\"key\":\"value" + "\\", "\"a\x00b\"",
	} {
		f.Add([]byte(body))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64*1024 {
			t.Skip()
		}
		_, oracle := boundedJSON(body)
		candidate := validatePublicJSON(body)
		if (oracle == nil) != (candidate == nil) || (candidate != nil && candidate != ErrRead) {
			t.Fatal("candidate differs from unchanged acceptance oracle")
		}
	})
}

// Synthetic but Kubernetes-shaped PUBLIC pages, not captured provider replies.
// Setup and oracle agreement are outside the timed whole-validation loop.
func publicValidationBenchBodies() map[string][]byte {
	pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"fixture","namespace":"test","uid":"public-id","resourceVersion":"123","labels":{"app":"arcadectl"},"managedFields":[{"manager":"controller","operation":"Update","apiVersion":"v1","time":"2026-01-01T00:00:00Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:labels":{".":{},"f:app":{}}},"f:spec":{"f:containers":{"k:{\"name\":\"server\"}":{".":{},"f:image":{}}}}}}]},"spec":{"containers":[{"name":"server","image":"example.invalid/server@sha256:0000000000000000000000000000000000000000000000000000000000000000","resources":{"requests":{"cpu":"100m","memory":"128Mi"}}}]},"status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}]}}`
	policy := `{"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicy","metadata":{"name":"fixture","uid":"public-policy-id","resourceVersion":"456"},"spec":{"failurePolicy":"Fail","matchConstraints":{"resourceRules":[{"apiGroups":[""],"apiVersions":["v1"],"operations":["CREATE","UPDATE"],"resources":["pods"]}]},"validations":[{"expression":"object.metadata.namespace != ''","message":"namespace required"}]},"status":{"observedGeneration":1}}`
	binding := `{"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicyBinding","metadata":{"name":"fixture","uid":"public-binding-id","resourceVersion":"789"},"spec":{"policyName":"fixture","validationActions":["Deny"],"matchResources":{"namespaceSelector":{"matchLabels":{"arcadectl.example/managed":"true"}}}}}`
	list := func(api, kind, item string, n int) []byte {
		return []byte(`{"apiVersion":"` + api + `","kind":"` + kind + `","metadata":{"resourceVersion":"123","continue":""},"items":[` + strings.Repeat(item+",", n-1) + item + `]}`)
	}
	return map[string][]byte{
		"SmallPublicGET":      []byte(`{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"fixture","namespace":"test","uid":"public-id","resourceVersion":"123"},"automountServiceAccountToken":false}`),
		"ManagedFieldsPodGET": []byte(pod),
		"PodList128":          list("v1", "PodList", pod, 128),
		"PolicyList12":        list("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyList", policy, 12),
		"BindingList12":       list("admissionregistration.k8s.io/v1", "ValidatingAdmissionPolicyBindingList", binding, 12),
	}
}

func BenchmarkPublicJSONValidation(b *testing.B) {
	bodies := publicValidationBenchBodies()
	// Fixed order, both implementations receive exactly the same prepared bytes.
	for _, name := range []string{"SmallPublicGET", "ManagedFieldsPodGET", "PodList128", "PolicyList12", "BindingList12"} {
		body := bodies[name]
		if _, err := boundedJSON(body); err != nil || validatePublicJSON(body) != nil {
			b.Fatal("benchmark fixture refused outside timing")
		}
		b.Run(name, func(b *testing.B) {
			for _, implementation := range []string{"OracleGraph", "Production"} {
				b.Run(implementation, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(body)))
					b.ResetTimer()
					for range b.N {
						if implementation == "OracleGraph" {
							if _, err := boundedJSON(body); err != nil {
								b.Fatal("oracle refused public fixture")
							}
						} else if implementation == "Production" && validatePublicJSON(body) != nil {
							b.Fatal("candidate refused public fixture")
						}
					}
				})
			}
		})
	}
}

// Measure early refusals too, not just accepted public replies. Input MB/s is
// nominal full-input size, not actual scanned bytes for early refusals.
func BenchmarkPublicJSONRejected(b *testing.B) {
	inputs := map[string][]byte{
		"Depth65LargeTail":   []byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + strings.Repeat(" ", 3*1024*1024)),
		"NodesOver":          []byte("[" + strings.Repeat("0,", 199999) + "0]"),
		"DuplicateLargeTail": []byte(`{"a":0,"a":"` + strings.Repeat("x", 3*1024*1024) + `"}`),
	}
	for _, name := range []string{"Depth65LargeTail", "NodesOver", "DuplicateLargeTail"} {
		body := inputs[name]
		if _, err := boundedJSON(body); err == nil || validatePublicJSON(body) == nil {
			b.Fatal("rejection benchmark unexpectedly accepted outside timing")
		}
		b.Run(name, func(b *testing.B) {
			for _, implementation := range []string{"OracleGraph", "Production"} {
				b.Run(implementation, func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(body)))
					b.ResetTimer()
					for range b.N {
						var err error
						switch implementation {
						case "OracleGraph":
							_, err = boundedJSON(body)
						case "Production":
							err = validatePublicJSON(body)
						}
						if err != ErrRead {
							b.Fatal("rejection candidate changed the fixed refusal")
						}
					}
				})
			}
		})
	}
}

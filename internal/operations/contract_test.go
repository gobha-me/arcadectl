// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package operations

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	arcade "github.com/gobha-me/arcadectl/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestCanonicalJSONExactValuesAndStructuralEquivalence(t *testing.T) {
	inputs := []string{`{"b":1000.0,"a":9007199254740993,"c":-0.0}`, `{ "c":0, "a":9007199254740993, "b":1e3 }`}
	var previous []byte
	for _, input := range inputs {
		value, err := CanonicalJSON([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(value, []byte("9007199254740993")) {
			t.Fatal("exact large integer rounded")
		}
		if previous != nil && !bytes.Equal(previous, value) {
			t.Fatal("equivalent JSON did not canonicalize equally")
		}
		previous = value
	}
	if string(previous) != `{"a":9007199254740993,"b":1000,"c":0}` {
		t.Fatalf("canonical result = %s", previous)
	}
}

func TestCanonicalJSONIntegerSettingsRemainTypedIntegers(t *testing.T) {
	for _, input := range []string{`{"maxPlayers":20}`, `{"maxPlayers":20.0}`, `{"maxPlayers":2e1}`} {
		value, err := CanonicalJSON([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		var typed struct {
			MaxPlayers int `json:"maxPlayers"`
		}
		if json.Unmarshal(value, &typed) != nil || typed.MaxPlayers != 20 {
			t.Fatal("canonicalization broke typed integer adapter settings")
		}
	}
}

func TestCanonicalJSONRejectsDuplicatesTrailingAndResourceAbuse(t *testing.T) {
	for _, input := range []string{`{"a":1,"a":2}`, `{"nested":{"a":1,"\u0061":2}}`, `{"a":1} {}`, `[1,]`, `01`, `1e1000000000`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34), strings.Repeat(" ", MaxJSONBytes+1)} {
		if _, err := CanonicalJSON([]byte(input)); err != ErrInvalid {
			t.Fatalf("unsafe JSON accepted or raw error returned: %v", err)
		}
	}
	if _, err := CanonicalJSON([]byte{'"', 0xff, '"'}); err != ErrInvalid {
		t.Fatal("invalid UTF-8 accepted or raw error returned")
	}
}

func TestReceiptIdentityStableAcrossCredentialRotationAndScoped(t *testing.T) {
	a, err := ReceiptName("games", "admin", "retry-key")
	if err != nil || len(a) > 63 || !strings.HasPrefix(a, "ao-") {
		t.Fatal("invalid receipt name")
	}
	b, _ := ReceiptName("games", "admin", "retry-key")
	if a != b {
		t.Fatal("stable administrator retry identity changed")
	}
	for _, input := range [][3]string{{"other", "admin", "retry-key"}, {"games", "other-admin", "retry-key"}, {"games", "admin", "different-key"}} {
		value, err := ReceiptName(input[0], input[1], input[2])
		if err != nil || value == a {
			t.Fatal("scope or key collision")
		}
	}
	for _, key := range []string{"", "credentials\ncanary", strings.Repeat("a", 129), "a,b"} {
		if _, err := ReceiptName("games", "admin", key); err != ErrInvalid {
			t.Fatal("unbounded or ambiguous key accepted")
		}
	}
}

func TestOriginalRequestDigestIgnoresOnlyServerProducedBindings(t *testing.T) {
	request := arcade.OperationRequest{ServerName: "world", Precondition: `"server:server-uid:1"`, Target: &arcade.ExactGameServerReference{ExactLocalReference: arcade.ExactLocalReference{Name: "world", UID: "server-uid"}, Generation: 1, DesiredState: arcade.DesiredStateRunning}, Image: &arcade.OperationImageInput{Version: "2.0.76", Resolution: arcade.OperationImageResolution{Digest: "sha256:" + strings.Repeat("a", 64)}}}
	original, err := RequestDigest(arcade.OperationServerUpdate, request)
	if err != nil {
		t.Fatal(err)
	}
	copy := request.DeepCopy()
	copy.Target.DesiredState = arcade.DesiredStateStopped
	copy.Target.Generation = 2
	copy.Image.Resolution.Digest = "sha256:" + strings.Repeat("b", 64)
	digest, _ := RequestDigest(arcade.OperationServerUpdate, *copy)
	if digest != original {
		t.Fatal("server-produced binding broke original retry digest")
	}
	copy.Precondition = `"server:server-uid:2"`
	digest, _ = RequestDigest(arcade.OperationServerUpdate, *copy)
	if digest == original {
		t.Fatal("different original precondition not fenced")
	}
	if request.Target.Generation != 1 || request.Target.DesiredState != arcade.DesiredStateRunning {
		t.Fatal("digest mutated its caller")
	}
	command := arcade.OperationRequest{Precondition: `"operation:parent-uid:1"`, DestroyCommand: &arcade.OperationDestroyCommand{ParentOperationRef: arcade.ExactLocalReference{Name: "parent", UID: "parent-uid"}, DestroyRef: arcade.ExactLocalReference{Name: "destroy", UID: "destroy-uid"}, Challenge: "challenge-1234567890"}}
	before, _ := RequestDigest(arcade.OperationWorldDestroyConfirm, command)
	command.DestroyCommand.ParentOperationRef.UID = "derived-parent"
	after, _ := RequestDigest(arcade.OperationWorldDestroyConfirm, command)
	if before != after {
		t.Fatal("derived parent UID changed original input")
	}
	command.DestroyCommand.DestroyRef.UID = "caller-different-child"
	after, _ = RequestDigest(arcade.OperationWorldDestroyConfirm, command)
	if before == after {
		t.Fatal("caller destroy identity omitted from original input")
	}
}

func TestPreconditionsAreStrongBoundedAndUnambiguous(t *testing.T) {
	for _, input := range []string{`"server:uid:1"`, `"operation:uid:2"`, `"retained:uid:sha256:` + strings.Repeat("a", 64) + `"`, "absent"} {
		if _, err := ParsePrecondition(input); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"*", `W/"server:uid:1"`, `"server:uid:01"`, `"server:uid:0"`, `"server:uid:1", "server:uid:2"`, `"server:uid:999999999999999999999"`, `"retained:uid:sha256:short"`} {
		if _, err := ParsePrecondition(input); err != ErrInvalid {
			t.Fatal("ambiguous precondition accepted")
		}
	}
}

func TestRequestValidationRejectsUnboundTargetAndRawReattach(t *testing.T) {
	request := arcade.OperationRequest{ServerName: "world", Precondition: `"server:server-uid:1"`, Target: &arcade.ExactGameServerReference{ExactLocalReference: arcade.ExactLocalReference{Name: "world", UID: "server-uid"}, Generation: 1, DesiredState: arcade.DesiredStateStopped}}
	if err := ValidateRequest(arcade.OperationServerStart, request); err != nil {
		t.Fatal(err)
	}
	request.Target.Generation = 2
	if ValidateRequest(arcade.OperationServerStart, request) != ErrInvalid {
		t.Fatal("unbound live target accepted")
	}
	request.Target.Generation = 1
	request.Configure = &arcade.OperationConfigureInput{Storage: &arcade.StorageSpec{Reattach: &arcade.RetainedDataReference{Identity: "caller-raw-world"}}}
	if ValidateRequest(arcade.OperationServerConfigure, request) != ErrInvalid {
		t.Fatal("raw reattach authority accepted")
	}
	if ValidateRequest("world.destroy.unsafe", request) != ErrInvalid {
		t.Fatal("unsafe receipt action accepted")
	}
}

func TestNativeSpecDigestCanonicalAndDetached(t *testing.T) {
	left := arcade.GameServerSpec{Game: "factorio", ImageDigest: "sha256:" + strings.Repeat("a", 64), DesiredState: arcade.DesiredStateStopped, Settings: runtime.RawExtension{Raw: []byte(`{"a":1,"b":2}`)}}
	right := left.DeepCopy()
	right.Settings.Raw = []byte(`{ "b":2.0, "a":1e0 }`)
	a, err := SpecDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SpecDigest(*right)
	if err != nil || a != b {
		t.Fatal("equivalent native specs had different identity")
	}
	intent, err := ServerIntent(left)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := ServerSpec(intent)
	if err != nil {
		t.Fatal(err)
	}
	restored.Settings.Raw[0] = '['
	if left.Settings.Raw[0] != '{' {
		t.Fatal("native conversion aliased original settings")
	}
}

func TestRetainedSnapshotDigestPinsOriginalIdentityAndCompleteClaims(t *testing.T) {
	target := arcade.GameDestroyTarget{GameServer: arcade.ExactLocalReference{Name: "world", UID: "original-server"}, Game: "factorio", Data: arcade.RetainedDataReference{Identity: "original-world", Claims: []arcade.RetainedDataClaimReference{{Path: "world", ClaimRef: arcade.ExactLocalReference{Name: "world-claim", UID: "world-uid"}}, {Path: "settings", ClaimRef: arcade.ExactLocalReference{Name: "settings-claim", UID: "settings-uid"}}}}}
	original, err := RetainedSnapshotDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	copy := target.DeepCopy()
	copy.Data.Claims[0], copy.Data.Claims[1] = copy.Data.Claims[1], copy.Data.Claims[0]
	reordered, err := RetainedSnapshotDigest(*copy)
	if err != nil || original != reordered {
		t.Fatal("claim ordering changed snapshot identity")
	}
	copy.GameServer.UID = "replacement-server"
	different, _ := RetainedSnapshotDigest(*copy)
	if original == different {
		t.Fatal("replacement original server was not fenced")
	}
	copy = target.DeepCopy()
	copy.Data.Claims[1].ClaimRef.UID = copy.Data.Claims[0].ClaimRef.UID
	if _, err := RetainedSnapshotDigest(*copy); err != ErrInvalid {
		t.Fatal("duplicate claim UID accepted")
	}
	copy = target.DeepCopy()
	namespace := "foreign"
	copy.Data.Claims[0].ClaimRef.Namespace = &namespace
	if _, err := RetainedSnapshotDigest(*copy); err != ErrInvalid {
		t.Fatal("cross-namespace retained authority accepted")
	}
}

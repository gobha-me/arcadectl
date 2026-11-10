// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package games_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	"github.com/gobha-me/arcadectl/internal/games/factorio"
	"github.com/gobha-me/arcadectl/internal/games/synthetic"
	"github.com/gobha-me/arcadectl/internal/platform/game"
	"github.com/gobha-me/arcadectl/internal/platform/kube"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const fuzzSettingsLimit = 64*1024 + 1

func FuzzFactorioSettingsProperties(f *testing.F) {
	f.Add(`{"name":"Factory","visibility":"private"}`)
	f.Fuzz(func(t *testing.T, raw string) { fuzzSettingsProperties(t, factorio.Definition(), raw) })
}

func FuzzSyntheticSettingsProperties(f *testing.F) {
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, raw string) { fuzzSettingsProperties(t, synthetic.Definition(), raw) })
}

// Only dependency intent is constructed here. Schema constraints are checked
// by the real planner, including its real adapter renderer, with no cluster.
func fuzzSettingsPlan(d game.Definition, raw string) error {
	_, err := kube.Build(&arcadev1alpha1.GameServer{
		ObjectMeta: metav1.ObjectMeta{Name: "fuzz-server", Namespace: "games", UID: "fuzz-uid"},
		Spec: arcadev1alpha1.GameServerSpec{
			Game: d.ID, ImageDigest: "sha256:" + strings.Repeat("a", 64), DesiredState: arcadev1alpha1.DesiredStateRunning,
			Compute: arcadev1alpha1.ComputeSpec{
				CPURequest: resource.MustParse("100m"), CPULimit: resource.MustParse("1"),
				MemoryRequest: resource.MustParse("64Mi"), MemoryLimit: resource.MustParse("128Mi"),
			},
			Storage: arcadev1alpha1.StorageSpec{Size: resource.MustParse("1Gi")}, Settings: runtime.RawExtension{Raw: []byte(raw)},
		},
	}, d)
	return err
}

// This independent JSON parse/re-encode oracle never calls a renderer/digest.
func fuzzJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing JSON")
	}
	return value, nil
}

type fuzzObservation struct {
	files  []game.ConfigurationFile
	digest string
}

func fuzzObserve(d game.Definition, raw []byte) (fuzzObservation, error) {
	files, err := d.RenderSettingsFiles(raw)
	if err != nil {
		return fuzzObservation{}, err
	}
	digest, err := d.SettingsDigest(raw)
	return fuzzObservation{files: files, digest: digest}, err
}

func fuzzSettingsProperties(t *testing.T, d game.Definition, raw string) {
	t.Helper()
	if len(raw) > fuzzSettingsLimit {
		return // Finite input budget; exact 64 KiB and one-over seeds are committed.
	}
	input, parseErr := fuzzJSON([]byte(raw))
	if parseErr != nil {
		if _, err := d.RenderSettingsFiles([]byte(raw)); err == nil {
			t.Fatal("renderer accepted malformed or trailing JSON")
		}
	}
	if err := fuzzSettingsPlan(d, raw); err != nil {
		var validation *kube.ValidationError
		if !errors.As(err, &validation) || validation.Category != kube.ValidationSettings {
			t.Fatalf("settings fixture failed outside settings admission: %v", err)
		}
		return // Renderer-only acceptance is never an admission proof.
	}
	settings, ok := input.(map[string]any)
	if parseErr != nil || !ok || settings == nil {
		t.Fatal("planner admitted non-object or malformed settings")
	}
	normalized, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := fuzzSettingsPlan(d, string(normalized)); err != nil {
		t.Fatalf("semantic equivalent refused by planner: %v", err)
	}
	first, err := fuzzObserve(d, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	second, err := fuzzObserve(d, normalized)
	if err != nil {
		t.Fatal(err)
	}
	if err := fuzzVerifyPair(d, settings, first, second); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{append(append([]byte(nil), normalized...), []byte(` {}`)...), fuzzUnknownField(t, settings)} {
		if _, err := d.RenderSettingsFiles(invalid); err == nil {
			t.Fatal("renderer accepted trailing JSON or an unknown field")
		}
	}
	// A valid change to actual rendered meaning must also change the digest.
	property, changed := "name", "fuzz-changed"
	if d.ID == "conformance-echo" {
		property, changed = "seed", "changed-seed"
	}
	if settings[property] == changed {
		changed = "other"
	}
	settings[property] = changed
	modified, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := fuzzSettingsPlan(d, string(modified)); err != nil {
		t.Fatalf("changed input is not a valid sensitivity control: %v", err)
	}
	digest, err := d.SettingsDigest(modified)
	if err != nil || digest == first.digest {
		t.Fatalf("digest failed to track changed rendered meaning: %v", err)
	}
}

func fuzzUnknownField(t *testing.T, original map[string]any) []byte {
	t.Helper()
	copy := make(map[string]any, len(original)+1)
	for k, v := range original {
		copy[k] = v
	}
	copy["__unknown_setting"] = true
	raw, err := json.Marshal(copy)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Observations are collected from production code. This explicit observation
// boundary also permits output fault injection to prove the oracle is active.
func fuzzVerifyPair(d game.Definition, input map[string]any, a, b fuzzObservation) error {
	if a.digest != b.digest || !strings.HasPrefix(a.digest, "sha256:") || len(a.digest) != 71 {
		return errors.New("semantic equivalent digest mismatch")
	}
	if !reflect.DeepEqual(a.files, b.files) {
		return errors.New("semantic equivalent file mismatch")
	}
	if len(a.files) != len(d.ConfigurationTargets) {
		return errors.New("unexpected target count")
	}
	contents := map[string][]byte{}
	total := 0
	for i, file := range a.files {
		if !utf8.Valid(file.Contents) || len(file.Contents) == 0 || bytes.IndexByte(file.Contents, 0) >= 0 {
			return errors.New("invalid rendered text")
		}
		if i > 0 && a.files[i-1].Name >= file.Name {
			return errors.New("targets not uniquely ordered")
		}
		matched := false
		for _, target := range d.ConfigurationTargets {
			if file.Name == target.Name && file.MountPath == target.MountPath {
				matched = true
			}
		}
		if !matched {
			return errors.New("undeclared target")
		}
		total += len(file.Contents)
		contents[file.Name] = file.Contents
	}
	if total > game.MaxRenderedSettingsBytes {
		return errors.New("output exceeds byte budget")
	}
	return fuzzOutputMeaning(d.ID, input, contents)
}

func fuzzOutputMeaning(id string, input map[string]any, output map[string][]byte) error {
	valueOr := func(key string, fallback any) any {
		if v, ok := input[key]; ok {
			return v
		}
		return fallback
	}
	if id == "factorio" {
		parsed, err := fuzzJSON(output["server-settings"])
		if err != nil {
			return err
		}
		expected := map[string]any{
			"name": input["name"], "description": valueOr("description", ""), "max_players": valueOr("maxPlayers", json.Number("0")),
			"visibility": map[string]any{"public": false, "lan": input["visibility"] == "lan"},
		}
		if !reflect.DeepEqual(parsed, expected) {
			return errors.New("parsed settings changed input meaning or omission semantics")
		}
		return nil
	}
	if id != "conformance-echo" {
		return errors.New("missing output meaning oracle")
	}
	expected := map[string]string{
		"echo-config": "listen=0.0.0.0:8080", "seed": valueOr("seed", "default-seed").(string),
		"motd": valueOr("motd", "Arcadectl conformance server").(string),
	}
	for name, value := range expected {
		// Independently parse the fixture's single-line artifacts, which are
		// text rather than JSON. Extra or missing newlines are significant.
		if !bytes.HasSuffix(output[name], []byte("\n")) || string(bytes.TrimSuffix(output[name], []byte("\n"))) != value {
			return fmt.Errorf("parsed %s changed input meaning", name)
		}
	}
	return nil
}

func TestFuzzSettingsNegativeControls(t *testing.T) {
	d := factorio.Definition()
	raw := []byte(`{"name":"Factory","visibility":"private"}`)
	parsed, err := fuzzJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"digest", "meaning"} {
		a, err := fuzzObserve(d, raw)
		if err != nil {
			t.Fatal(err)
		}
		b, err := fuzzObserve(d, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := fuzzVerifyPair(d, parsed.(map[string]any), a, b); err != nil {
			t.Fatal(err)
		}
		switch fault {
		case "digest":
			b.digest = "sha256:" + strings.Repeat("b", 64)
		case "meaning":
			a.files[0].Contents = bytes.ReplaceAll(a.files[0].Contents, []byte("Factory"), []byte("Changed"))
			b.files[0].Contents = append([]byte(nil), a.files[0].Contents...)
		}
		if err := fuzzVerifyPair(d, parsed.(map[string]any), a, b); err == nil {
			t.Fatalf("oracle accepted corrupted %s observation", fault)
		}
	}
}

func TestSettingsFuzzAdmissionBoundaries(t *testing.T) {
	for _, tt := range []struct {
		d     game.Definition
		raw   string
		valid bool
	}{
		{factorio.Definition(), `{"name":"x","maxPlayers":1,"visibility":"private"}`, true},
		{factorio.Definition(), `{"name":"x","maxPlayers":65535,"visibility":"private"}`, true},
		{factorio.Definition(), `{"name":"x","maxPlayers":0,"visibility":"private"}`, false},
		{factorio.Definition(), `{"name":"x","maxPlayers":65536,"visibility":"private"}`, false},
		{factorio.Definition(), `{"name":"` + strings.Repeat("x", 81) + `","visibility":"private"}`, false},
		{factorio.Definition(), `{"name":"x","description":"` + strings.Repeat("x", 201) + `","visibility":"private"}`, false},
		{synthetic.Definition(), `{}` + strings.Repeat(" ", 65534), true},
		{synthetic.Definition(), `{}` + strings.Repeat(" ", 65535), false},
		{synthetic.Definition(), `{"seed":null}`, false},
	} {
		err := fuzzSettingsPlan(tt.d, tt.raw)
		if tt.valid {
			if err != nil {
				t.Fatalf("valid boundary refused: %v", err)
			}
		} else {
			var validation *kube.ValidationError
			if !errors.As(err, &validation) || validation.Category != kube.ValidationSettings {
				t.Fatalf("schema boundary not refused as settings: %v", err)
			}
		}
	}
}

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installrender

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installpackage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Re-sign every altered payload: refusal must come from the trusted renderer,
// not a stale checksum or invalid signature. Exercise every shipped executable
// template, including the independently frozen predecessor.
func TestSignedPackageBansExecutableFragmentsAcrossEveryDeployment(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		metadata, basePayloads := fixture(t, legacy)
		profile := Profile137
		if _, err := Compile(authenticated(t, metadata, basePayloads), DefaultNamespace, profile); err != nil {
			t.Fatalf("legacy=%t unchanged signed positive control refused: %v", legacy, err)
		}
		for _, deployment := range []struct{ path, name string }{
			{installpackage.APIPath, "arcadectl-api"},
			{installpackage.ControllerPath, "arcadectl-controller"},
			{installpackage.ControllerPath, "arcadectl-destroy-controller"},
		} {
			for _, mutation := range []struct {
				name  string
				path  []string
				value any
			}{
				{"raw-pod-fragment", []string{"unsignedPodFragment"}, map[string]any{"containers": []any{map[string]any{"name": "injected"}}}},
				{"host-path", []string{"volumes"}, []any{map[string]any{"name": "host", "hostPath": map[string]any{"path": "/"}}}},
				{"host-network", []string{"hostNetwork"}, true},
				{"host-pid", []string{"hostPID"}, true},
				{"host-ipc", []string{"hostIPC"}, true},
				{"pod-privileged", []string{"securityContext", "privileged"}, true},
				{"root-user", []string{"securityContext", "runAsUser"}, int64(0)},
				{"init-container", []string{"initContainers"}, []any{map[string]any{"name": "injected", "image": "example.invalid/injected:latest", "command": []any{"sh", "-c", "true"}}}},
				{"ephemeral-container", []string{"ephemeralContainers"}, []any{map[string]any{"name": "injected", "image": "example.invalid/injected:latest"}}},
				{"container-command", []string{"containers", "command"}, []any{"sh", "-c", "true"}},
				{"container-args", []string{"containers", "args"}, []any{"--unsigned-runtime-fragment"}},
				{"container-privileged", []string{"containers", "securityContext", "privileged"}, true},
				{"privilege-escalation", []string{"containers", "securityContext", "allowPrivilegeEscalation"}, true},
				{"inline-secret", []string{"containers", "env"}, []any{map[string]any{"name": "ADMIN_TOKEN", "value": "synthetic-never-a-credential"}}},
				{"mutable-image", []string{"containers", "image"}, "example.invalid/controller:latest"},
			} {
				t.Run(fmt.Sprintf("legacy=%t/%s/%s", legacy, deployment.name, mutation.name), func(t *testing.T) {
					// Only replace the altered payload entry. Decoding constructs fresh
					// objects, and signing never modifies the shared original bytes.
					payloads := maps.Clone(basePayloads)
					original := bytes.Clone(payloads[deployment.path])
					objects, err := decodeRendered(original)
					if err != nil {
						t.Fatal(err)
					}
					changed := 0
					for _, object := range objects {
						if object.GetKind() != "Deployment" || object.GetName() != deployment.name {
							continue
						}
						changed++
						pod, found, err := unstructured.NestedMap(object.Object, "spec", "template", "spec")
						if err != nil || !found {
							t.Fatal("deployment has no pod template")
						}
						if mutation.path[0] == "containers" {
							containers, found, err := unstructured.NestedSlice(pod, "containers")
							if err != nil || !found || len(containers) != 1 {
								t.Fatal("expected one signed container")
							}
							container := containers[0].(map[string]any)
							if err := unstructured.SetNestedField(container, mutation.value, mutation.path[1:]...); err != nil {
								t.Fatal(err)
							}
							if err := unstructured.SetNestedSlice(pod, containers, "containers"); err != nil {
								t.Fatal(err)
							}
						} else if err := unstructured.SetNestedField(pod, mutation.value, mutation.path...); err != nil {
							t.Fatal(err)
						}
						if err := unstructured.SetNestedMap(object.Object, pod, "spec", "template", "spec"); err != nil {
							t.Fatal(err)
						}
					}
					if changed != 1 {
						t.Fatalf("changed %d deployments, want exactly one", changed)
					}
					payloads[deployment.path], err = encodeObjects(objects)
					if err != nil || bytes.Equal(original, payloads[deployment.path]) {
						t.Fatal("mutation did not change package bytes")
					}
					pkg := authenticated(t, metadata, payloads)
					if !pkg.IsVerified() {
						t.Fatal("altered package is not independently authenticated")
					}
					if _, err := Compile(pkg, DefaultNamespace, profile); !errors.Is(err, ErrInvalid) {
						t.Fatalf("authenticated unsafe manifest passed renderer: %v", err)
					}
				})
			}
		}
	}
}

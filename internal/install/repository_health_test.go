// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

const repositoryHealthImage = "busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"

func fixtureHealthContainer(t *testing.T) corev1.Container {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", "-ec", `source "$1"; repository_health_init_container "$2"`, "fixture-health", filepath.Join(repositoryRoot(t), "hack", "repository-health.sh"), repositoryHealthImage)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("render health container: %v", err)
	}
	var container corev1.Container
	if err := json.Unmarshal(output, &container); err != nil {
		t.Fatal(err)
	}
	return container
}

func TestRepositoryHealthGatesResticUntilServiceReachable(t *testing.T) {
	container := fixtureHealthContainer(t)
	for _, fixture := range []struct {
		name                   string
		healthyAfter, attempts int
		succeeds               bool
	}{
		{"initial-refusals", 4, 4, true}, {"exhaustion", 31, 30, false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			directory := t.TempDir()
			attemptFile, marker := filepath.Join(directory, "attempts"), filepath.Join(directory, "restic-executed")
			commands := map[string]string{
				"timeout": `test "$1" = 2 || exit 99; shift; exec "$@"`,
				"wget": `test "$*" = '-q -T 2 -O /dev/null http://minio:9000/minio/health/cluster' || exit 99
attempt=0
if [ -f "$FIXTURE_ATTEMPT_FILE" ]; then read -r attempt < "$FIXTURE_ATTEMPT_FILE"; fi
attempt=$((attempt + 1))
printf '%s\n' "$attempt" > "$FIXTURE_ATTEMPT_FILE"
test "$attempt" -ge "$FIXTURE_HEALTHY_AFTER"`,
				"sleep":          `test "$1" = 1`,
				"fixture-restic": `: > "$FIXTURE_RESTIC_MARKER"`,
			}
			for name, script := range commands {
				if err := os.WriteFile(filepath.Join(directory, name), []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "sh", "-ec", `sh -ec "$1" && fixture-restic`, "fixture-gate", container.Command[2])
			command.Env = append(os.Environ(), "PATH="+directory+":"+os.Getenv("PATH"), "FIXTURE_ATTEMPT_FILE="+attemptFile, "FIXTURE_RESTIC_MARKER="+marker, "FIXTURE_HEALTHY_AFTER="+strconv.Itoa(fixture.healthyAfter))
			output, err := command.CombinedOutput()
			if (err == nil) != fixture.succeeds {
				t.Fatalf("gate result: %v, %s", err, output)
			}
			attempts, err := os.ReadFile(attemptFile)
			if err != nil || strings.TrimSpace(string(attempts)) != strconv.Itoa(fixture.attempts) {
				t.Fatalf("attempts: %s, %v", attempts, err)
			}
			_, err = os.Stat(marker)
			if fixture.succeeds && err != nil || !fixture.succeeds && !os.IsNotExist(err) {
				t.Fatalf("Restic execution after gate: %v", err)
			}
		})
	}
}

func TestRepositoryInitJobsUseCredentialFreeBoundedHealthGate(t *testing.T) {
	want := fixtureHealthContainer(t)
	if len(want.Command) != 3 || want.Command[0] != "/bin/sh" || want.Command[1] != "-ec" || want.Image != repositoryHealthImage || len(want.Env) != 0 || len(want.EnvFrom) != 0 || len(want.VolumeMounts) != 0 || len(want.VolumeDevices) != 0 || want.Resources.Requests.Cpu().IsZero() || want.Resources.Requests.Memory().IsZero() || want.Resources.Limits.Cpu().IsZero() || want.Resources.Limits.Memory().IsZero() {
		t.Fatal("health gate is unbounded or has credential/environment/volume access")
	}
	security := want.SecurityContext
	if security == nil || security.RunAsNonRoot == nil || !*security.RunAsNonRoot || security.RunAsUser == nil || *security.RunAsUser != 65532 || security.RunAsGroup == nil || *security.RunAsGroup != 65532 || security.AllowPrivilegeEscalation == nil || *security.AllowPrivilegeEscalation || security.ReadOnlyRootFilesystem == nil || !*security.ReadOnlyRootFilesystem || security.Capabilities == nil || !reflect.DeepEqual(security.Capabilities.Drop, []corev1.Capability{"ALL"}) || security.SeccompProfile == nil || security.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatal("health gate is not restricted")
	}
	for _, mode := range []string{"synthetic", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			root := repositoryRoot(t)
			setup := `source "$repository_root/hack/repository-health.sh"
kube() { :; }
kube_bounded() { :; }
recovery_record() { :; }
namespace=fixture-test
run_id=fixture-test
run_suffix=fixture-test
repository_secret_name=fixture-test
minio_image=$controller_image
`
			var filename string
			if mode == "recovery" {
				setup += `source "$repository_root/hack/kind-recovery-scenarios.sh"
recovery_record() { :; }
recovery_install_repository
`
				filename = "recovery-restic-init.json"
			} else {
				contents := recoveryFixtureFile(t, "hack", "test-kind-lifecycle.sh")
				begin := strings.Index(string(contents), "backup_utility_image=")
				end := strings.Index(string(contents), `cat >"$workspace/restic-seed.yaml"`)
				if begin < 0 || end <= begin {
					t.Fatal("synthetic repository-init section missing")
				}
				setup += string(contents[begin:end])
				filename = "restic-init.yaml"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", "-ec", setup)
			command.Env = append(os.Environ(), "repository_root="+root, "workspace="+directory, "controller_image="+testControllerImage)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("render %s fixture: %v, %s", mode, err, output)
			}
			contents, err := os.ReadFile(filepath.Join(directory, filename))
			if err != nil {
				t.Fatal(err)
			}
			objects := decodeObjects(t, contents)
			if len(objects) != 1 {
				t.Fatal("unexpected init Job inventory")
			}
			job := &batchv1.Job{}
			convertObject(t, objects[0], job)
			if job.Kind != "Job" || job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != 120 || job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 || job.Spec.Template.Spec.RestartPolicy != corev1.RestartPolicyNever || job.Spec.Template.Spec.AutomountServiceAccountToken == nil || *job.Spec.Template.Spec.AutomountServiceAccountToken || len(job.Spec.Template.Spec.InitContainers) != 1 || !reflect.DeepEqual(job.Spec.Template.Spec.InitContainers[0], want) {
				t.Fatalf("%s Job lost its exact health gate/deadline/no-retry contract: %s", mode, fmt.Sprint(job.Spec))
			}
		})
	}
}

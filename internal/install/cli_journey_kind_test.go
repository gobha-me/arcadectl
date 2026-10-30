//go:build kindapi

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminauth"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Continue in the caller's owned Kind fixture. All ordinary lifecycle intent
// goes through the real CLI. Native access supplies observations and Kind's
// existing cloud-provider status substitute, never workload or PVC mutation.
func runKindCLIJourney(t *testing.T, f kindAPILifecycleFixture, retainedID, oldServerUID, digestA, digestB, configurationName string, assertWorld, verifyWorld func()) {
	t.Helper()
	const name = "api-factorio"
	const namespace = "arcadectl-system"
	settings := filepath.Join(f.workspace, "journey-settings.json")
	if os.WriteFile(settings, []byte(`{"name":"CLI creation proof","visibility":"private","maxPlayers":12}`), 0600) != nil {
		t.Fatal("private journey settings unavailable")
	}
	var newToken string
	runCommand := func(ctx context.Context, wantCode int, args ...string) []byte {
		t.Helper()
		safeArgs := make([]string, len(args))
		for index, argument := range args {
			safeArgs[index] = strings.ReplaceAll(strings.ReplaceAll(argument, f.workspace, "$PRIVATE_WORKSPACE"), f.apiBaseURL, "$API_URL")
		}
		t.Logf("cli-journey command: arcadectl --output json --timeout 3m %q", safeArgs)
		arguments := append([]string{"--output", "json", "--timeout", "3m"}, args...)
		command := exec.CommandContext(ctx, filepath.Join(f.workspace, "arcadectl"), arguments...)
		command.Env = []string{"XDG_CONFIG_HOME=" + filepath.Join(f.workspace, "cli-config"), "XDG_STATE_HOME=" + filepath.Join(f.workspace, "cli-state"), "GOMAXPROCS=2", "GOMEMLIMIT=1GiB"}
		stdout, stderr := &privateOutputCapture{}, &privateOutputCapture{}
		command.Stdout, command.Stderr = stdout, stderr
		err := command.Run()
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal("CLI journey process unavailable; private output withheld")
			}
			code = exit.ExitCode()
		}
		if code != wantCode || stdout.truncated || stderr.truncated {
			t.Fatalf("CLI journey exit=%d want=%d; private output withheld", code, wantCode)
		}
		for _, token := range []string{f.token, newToken} {
			if token == "" {
				continue
			}
			for _, output := range [][]byte{stdout.contents, stderr.contents} {
				if bytes.Contains(output, []byte(token)) || bytes.Contains(output, []byte(adminauth.TokenDigest(token))) {
					t.Fatal("CLI journey emitted private credential material; output withheld")
				}
			}
		}
		t.Logf("cli-journey exit=%d", code)
		return stdout.contents
	}
	cli := func(args ...string) []byte { t.Helper(); return runCommand(f.ctx, 0, args...) }
	var retained adminv1.RetainedWorld
	if json.Unmarshal(cli("retained-world", "status", retainedID), &retained) != nil || retained.OperationID != retainedID || retained.OriginalServer.UID != oldServerUID || retained.DataIdentity == "" || retained.OperationUID == "" || retained.SnapshotDigest == "" || len(retained.Claims) != 1 {
		t.Fatal("CLI retained-world discovery lost original identity")
	}
	serverUID := ""
	mutate := func(action string, args ...string) adminv1.Operation {
		t.Helper()
		started := time.Now()
		ctx, cancel := context.WithTimeout(f.ctx, 3*time.Minute)
		defer cancel()
		opCLI := func(args ...string) []byte { t.Helper(); return runCommand(ctx, 0, args...) }
		var admission struct {
			AttemptID   string            `json:"attemptID"`
			OperationID string            `json:"operationID"`
			Operation   adminv1.Operation `json:"operation"`
		}
		if json.Unmarshal(opCLI(append(args, "--no-wait")...), &admission) != nil || admission.AttemptID == "" || admission.OperationID == "" || admission.Operation.UID == "" || admission.Operation.Action != "server."+action {
			t.Fatal("CLI journey admission lost exact operation identity")
		}
		waitKindAPI(t, ctx, func() bool {
			var observed adminv1.Operation
			if json.Unmarshal(opCLI("operation", "status", admission.OperationID), &observed) != nil || observed.OperationID != admission.OperationID || observed.UID != admission.Operation.UID || observed.Action != admission.Operation.Action {
				t.Fatal("CLI journey operation identity changed")
			}
			if observed.Phase == "Failed" || observed.Phase == "Cancelled" {
				t.Fatal("CLI journey reached an unsuccessful terminal operation")
			}
			if observed.Action == "server.create" && observed.Child != nil {
				if observed.Child.Kind != "GameServer" || observed.Child.Name != name || observed.Child.UID == "" || observed.Child.UID == oldServerUID || serverUID != "" && serverUID != observed.Child.UID {
					t.Fatal("CLI reattachment did not create one distinct server identity")
				}
				serverUID = observed.Child.UID
			}
			if kindEndpointAction(observed.Action) && observed.Phase != "Succeeded" {
				ready, err := provideOwnedKindEndpoint(ctx, f.cluster.CoreV1().Services(namespace), namespace, name, types.UID(serverUID))
				if err != nil {
					t.Fatal("owned journey endpoint status unavailable")
				}
				if !ready {
					return false
				}
			}
			return observed.Phase == "Succeeded" && observed.ObservedGeneration == observed.Generation && observed.CompletedAt != ""
		})
		var completed adminv1.Operation
		if json.Unmarshal(opCLI("operation", "wait", admission.OperationID), &completed) != nil || completed.UID != admission.Operation.UID || completed.OperationID != admission.OperationID || completed.Action != admission.Operation.Action || completed.Phase != "Succeeded" || completed.ObservedGeneration != completed.Generation || completed.CompletedAt == "" {
			t.Fatal("CLI journey wait lost current terminal evidence")
		}
		assertWorld()
		t.Logf("cli-journey action=%s operation=%s uid=%s phase=%s generation=%d observed=%d started=%s completed=%s elapsed_ms=%d", completed.Action, completed.OperationID, completed.UID, completed.Phase, completed.Generation, completed.ObservedGeneration, completed.StartedAt, completed.CompletedAt, time.Since(started).Milliseconds())
		return completed
	}
	status := func(wantPhase string) adminv1.Server {
		t.Helper()
		var server adminv1.Server
		if json.Unmarshal(cli("server", "status", name), &server) != nil || server.UID != serverUID || server.Phase != wantPhase || server.Generation != server.ObservedGeneration {
			t.Fatal("CLI journey server state or retained identity changed")
		}
		conditions := map[string]bool{"SpecValid": true, "StorageReady": true, "ConfigurationReady": true, "WorkloadReady": true, "NetworkReady": true, "Ready": true}
		if len(server.Conditions) != len(conditions) {
			t.Fatal("CLI journey omitted current condition evidence")
		}
		for _, condition := range server.Conditions {
			if !conditions[condition.Type] || condition.ObservedGeneration != server.Generation || condition.Reason == "" || condition.Status != "True" && condition.Status != "False" && condition.Status != "Unknown" {
				t.Fatal("CLI journey condition identity/generation drift")
			}
			delete(conditions, condition.Type)
			if condition.Type == "Ready" && (condition.Status == "True") != (wantPhase == "Ready") {
				t.Fatal("CLI journey Ready condition disagrees with phase")
			}
			t.Logf("cli-journey condition type=%q status=%q reason=%q observed=%d", condition.Type, condition.Status, condition.Reason, condition.ObservedGeneration)
		}
		t.Logf("cli-journey server_uid=%s phase=%s generation=%d observed=%d image_digest=%s", server.UID, server.Phase, server.Generation, server.ObservedGeneration, server.ImageDigest)
		for _, selected := range retained.Claims {
			claim, err := f.cluster.CoreV1().PersistentVolumeClaims(namespace).Get(f.ctx, selected.ClaimRef.Name, metav1.GetOptions{})
			if err != nil || string(claim.UID) != selected.ClaimRef.UID || claim.Labels["arcade.gobha.me/data-identity"] != retained.DataIdentity {
				t.Fatal("CLI journey selected world identity changed")
			}
			t.Logf("cli-journey retained_claim=%s uid=%s path=%s data_identity=%s", selected.ClaimRef.Name, selected.ClaimRef.UID, selected.Path, retained.DataIdentity)
		}
		return server
	}
	gamePod := func(digest string) types.UID {
		t.Helper()
		pods, err := f.cluster.CoreV1().Pods(namespace).List(f.ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=game-server,app.kubernetes.io/instance=" + name})
		if err != nil || len(pods.Items) != 1 || pods.Items[0].UID == "" || pods.Items[0].DeletionTimestamp != nil {
			t.Fatal("CLI journey did not have one live game Pod")
		}
		pod := pods.Items[0]
		if pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != "game" || pod.Spec.Containers[0].Image != "ghcr.io/gobha-me/arcadectl-factorio@"+digest {
			t.Fatal("CLI journey runtime executable differs from selected immutable image")
		}
		ready := false
		for _, container := range pod.Status.ContainerStatuses {
			if container.Name == "game" && container.Ready && container.State.Running != nil && container.RestartCount == 0 && strings.Contains(container.ImageID, digest) {
				ready = true
			}
		}
		if !ready {
			t.Fatal("CLI journey actual runtime digest/readiness unavailable")
		}
		return pod.UID
	}
	mutate("create", "server", "create", name, "--game", "factorio", "--image-digest", digestA,
		"--cpu-request", "100m", "--cpu-limit", "2", "--memory-request", "256Mi", "--memory-limit", "2Gi",
		"--storage-size", "512Mi", "--storage-class=", "--settings-file", settings, "--retained-world", retainedID)
	status("Stopped")
	changedSettings, err := json.Marshal(map[string]any{"name": configurationName, "visibility": "private", "maxPlayers": 20})
	if err != nil || os.WriteFile(settings, changedSettings, 0600) != nil {
		t.Fatal("changed journey settings unavailable")
	}
	mutate("configure", "server", "configure", name, "--settings-file", settings)
	mutate("start", "server", "start", name)
	status("Ready")
	initialPod := gamePod(digestA)

	// This trusted-admin CLI is the documented rotation boundary. It receives
	// only this fixture's kubeconfig; the ordinary CLI never receives one.
	rotatedPath := filepath.Join(f.workspace, "journey-rotated.json")
	rotation := exec.CommandContext(f.ctx, filepath.Join(f.workspace, "credential-admin"), "rotate", "--kubeconfig", f.kubeconfig,
		"--context", "kind-"+strings.TrimSuffix(f.node, "-control-plane"), "--output", rotatedPath, "--lifetime", "30m",
		"--api-url", f.apiBaseURL+"/v1/auth/self", "--ca-file", filepath.Join(f.workspace, "api-ca.crt"),
		"--tls-server-name", "arcadectl-api.arcadectl-system.svc", "--timeout", "3m")
	rotationOut, rotationErr := &privateOutputCapture{}, &privateOutputCapture{}
	rotation.Stdout, rotation.Stderr = rotationOut, rotationErr
	if rotation.Run() != nil || rotationOut.truncated || rotationErr.truncated {
		t.Fatal("CLI journey trusted-admin rotation failed; private output withheld")
	}
	rotated := kindClientCredential(t, rotatedPath)
	newToken = rotated.Token
	for _, output := range [][]byte{rotationOut.contents, rotationErr.contents} {
		for _, token := range []string{f.token, newToken} {
			if bytes.Contains(output, []byte(token)) || bytes.Contains(output, []byte(adminauth.TokenDigest(token))) {
				t.Fatal("CLI journey rotation emitted private material; output withheld")
			}
		}
	}
	t.Log("cli-journey trusted-admin command: credential-admin rotate --kubeconfig $OWNED_KUBECONFIG --context $OWNED_KIND_CONTEXT --output $PRIVATE_WORKSPACE/journey-rotated.json --lifetime 30m --api-url $API_URL/v1/auth/self --ca-file $PRIVATE_WORKSPACE/api-ca.crt --tls-server-name arcadectl-api.arcadectl-system.svc --timeout 3m")
	refused := func(code int, args ...string) { t.Helper(); runCommand(f.ctx, code, args...) }
	refused(3, "--context", "isolated", "server", "status", name)
	cli("login", "journey", "--api", f.apiBaseURL, "--ca-file", filepath.Join(f.workspace, "api-ca.crt"), "--credential-file", rotatedPath, "--tls-server-name", "arcadectl-api.arcadectl-system.svc")
	cli("context", "use", "journey")
	status("Ready")
	if gamePod(digestA) != initialPod {
		t.Fatal("credential rotation interrupted the running game Pod")
	}
	refused(2, "server", "destroy", name)
	refused(2, "server", "destroy", name, "--unsafe-no-backup")
	assertWorld()
	mutate("restart", "server", "restart", name)
	status("Ready")
	restartedPod := gamePod(digestA)
	if restartedPod == initialPod {
		t.Fatal("CLI restart did not replace the original game Pod")
	}
	mutate("update", "server", "update", name, "--image-digest", digestB)
	if status("Ready").ImageDigest != digestB || gamePod(digestB) == restartedPod {
		t.Fatal("CLI update did not select a distinct immutable runtime")
	}
	mutate("stop", "server", "stop", name)
	status("Stopped")
	verifyWorld()
	decommission := mutate("decommission", "server", "decommission", name)
	var final adminv1.RetainedWorld
	if json.Unmarshal(cli("retained-world", "status", decommission.OperationID), &final) != nil || final.OperationUID != decommission.UID || final.OriginalServer.UID != serverUID || final.DataIdentity != retained.DataIdentity || final.SnapshotDigest == "" || len(final.Claims) != 1 || final.Claims[0] != retained.Claims[0] {
		t.Fatal("CLI decommission lost the reattached world's exact identity")
	}
	verifyWorld()
	pods, err := f.cluster.CoreV1().Pods(namespace).List(f.ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=arcadectl-api"})
	if err != nil || len(pods.Items) != 1 {
		t.Fatal("CLI journey API audit identity unavailable")
	}
	auditContext, cancelAudit := context.WithTimeout(f.ctx, 30*time.Second)
	defer cancelAudit()
	stream, err := f.cluster.CoreV1().Pods(namespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{}).Stream(auditContext)
	if err != nil {
		t.Fatal("CLI journey audit stream unavailable")
	}
	audit, readErr := io.ReadAll(io.LimitReader(stream, (1<<20)+1))
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || len(audit) > 1<<20 {
		t.Fatal("CLI journey complete bounded audit unavailable")
	}
	for _, token := range []string{f.token, newToken} {
		if bytes.Contains(audit, []byte(token)) || bytes.Contains(audit, []byte(adminauth.TokenDigest(token))) {
			t.Fatal("CLI journey credential leaked to API audit; private output withheld")
		}
	}
	t.Logf("cli-journey completed retained_world=%s data_identity=%s image_a=%s image_b=%s; install/reinstall and CLI backup/restore/interactive destroy remain separate unproved gates", final.OperationID, final.DataIdentity, digestA, digestB)
}

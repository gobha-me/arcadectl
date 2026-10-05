// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"github.com/gobha-me/arcadectl/internal/adminclient"
	"github.com/gobha-me/arcadectl/internal/cliattempt"
)

func TestOfflineHelpAndErrorsNeverEchoInput(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/unavailable/context")
	t.Setenv("XDG_STATE_HOME", "/unavailable/state")
	for _, args := range [][]string{{"--help"}, {"server", "create", "--help"}, {"completion", "bash"}} {
		var out, stderr bytes.Buffer
		if Run(context.Background(), args, Options{In: strings.NewReader(""), Out: &out, Err: &stderr}) != 0 || out.Len() == 0 || stderr.Len() != 0 {
			t.Fatal("offline help/completion failed")
		}
	}
	for _, args := range [][]string{{"SECRET-CANARY"}, {"--token", "SECRET-CANARY"}, {"--timeout", "SECRET-CANARY"}, {"--output", "json", "--challenge", "SECRET-CANARY"}, {"destroy", "confirm", "--yes", "SECRET-CANARY"}} {
		var out, stderr bytes.Buffer
		if Run(context.Background(), args, Options{In: strings.NewReader(""), Out: &out, Err: &stderr}) != 2 || strings.Contains(out.String()+stderr.String(), "SECRET-CANARY") {
			t.Fatal("invalid arguments not safely classified")
		}
	}
}

func TestOutputGoldens(t *testing.T) {
	var out bytes.Buffer
	app := application{options: Options{Out: &out}, output: "human"}
	operation := adminv1.Operation{Version: "v1", OperationID: "ao-test", UID: "receipt-uid", Generation: 1, ObservedGeneration: 1, Action: "server.stop", Phase: "Succeeded", PollURL: "/v1/operations/ao-test"}
	if app.emit(operation) != nil || out.String() != "operation ao-test server.stop Succeeded generation=1 observed=1\n" {
		t.Fatal("human operation output drift")
	}
	out.Reset()
	if writeFailure(&out, true, &cliFailure{code: "timeout", exit: 5, operationID: "ao-test", attemptID: "attempt-test"}) != nil {
		t.Fatal("JSON error output")
	}
	var result map[string]any
	if json.Unmarshal(out.Bytes(), &result) != nil || len(result) != 5 || result["version"] != "v1" || result["code"] != "timeout" || result["operationID"] != "ao-test" || result["attemptID"] != "attempt-test" || result["suggestedAction"] != guidance("timeout") {
		t.Fatal("JSON error golden drift")
	}
	out.Reset()
	app.output = "json"
	if app.emitAdmission(cliattempt.Result{AttemptID: "attempt-test", ExpectedOperationID: "ao-test", Operation: &operation}) != nil {
		t.Fatal("admission output")
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result["attemptID"] != "attempt-test" || result["operationID"] != "ao-test" || result["operation"] == nil {
		t.Fatal("admission lost resume identity")
	}
	out.Reset()
	app.output = "human"
	server := adminv1.Server{Name: "factory", UID: "server-uid", Generation: 2, ObservedGeneration: 2, Phase: "Stopped", DesiredState: "Stopped",
		Conditions: []adminv1.Condition{{Type: "Ready", Status: "False", Reason: "Stopped", ObservedGeneration: 2}},
		Endpoints:  []adminv1.Endpoint{{Name: "game", Protocol: "UDP", Address: "192.0.2.1", Port: 34197}}}
	if app.emit(server) != nil || out.String() != "server factory Stopped desired=Stopped uid=server-uid generation=2 observed=2\ncondition=Ready status=False reason=Stopped observed=2\nendpoint=game UDP 192.0.2.1:34197\n" {
		t.Fatal("human server output lost reasons or endpoints")
	}
}

func TestExitCodesAndMissingReceiptGuidance(t *testing.T) {
	for _, test := range []struct {
		err  error
		code int
	}{{&adminclient.Error{HTTPStatus: 422}, 2}, {&adminclient.Error{HTTPStatus: 401}, 3}, {&adminclient.Error{HTTPStatus: 403}, 3}, {&adminclient.Error{HTTPStatus: 409}, 4}, {&adminclient.Error{HTTPStatus: 503, Ambiguous: true}, 5}, {&adminclient.Error{HTTPStatus: 500}, 6}, {&adminclient.Error{Code: "credential_expired"}, 3}, {&adminclient.Error{Code: "tls_unavailable"}, 7}, {cliattempt.ErrReceiptMissing, 5}, {errors.New("SECRET-CANARY"), 1}, {errors.Join(cliattempt.ErrPrompt, context.DeadlineExceeded), 5}, {errors.Join(cliattempt.ErrPrompt, context.Canceled), 130}} {
		got := classify(test.err)
		if got.exit != test.code || strings.Contains(got.Error()+guidance(got.code), "SECRET-CANARY") {
			t.Fatal("exit/redaction contract drift")
		}
	}
	if strings.Contains(guidance(classify(cliattempt.ErrReceiptMissing).code), "resume") {
		t.Fatal("missing admitted receipt guidance suggested replay")
	}
}

func TestPipedInputCannotConfirmDestroy(t *testing.T) {
	var output bytes.Buffer
	app := application{options: Options{In: strings.NewReader("abcdefghijklmnop\n"), Err: &output}}
	if classify(app.prompt(context.Background(), adminv1.DestroyPreview{Challenge: "abcdefghijklmnop"})).code != "confirmation_required" || output.Len() != 0 {
		t.Fatal("pipe inherited destructive approval")
	}
}

func TestCLIBinaryCannotImportClusterMutationPackages(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(source), "..", "..")
	command := exec.Command("go", "list", "-deps", "./cmd/arcadectl")
	command.Dir = root
	command.Env = append(os.Environ(), "GOMAXPROCS=2", "GOMEMLIMIT=1GiB")
	output, err := command.Output()
	if err != nil {
		t.Fatal("dependency guard could not inspect CLI")
	}
	for _, name := range strings.Fields(string(output)) {
		for _, forbidden := range []string{"k8s.io/client-go", "sigs.k8s.io/controller-runtime", "github.com/gobha-me/arcadectl/internal/controller", "github.com/gobha-me/arcadectl/internal/platform/kube"} {
			if strings.HasPrefix(name, forbidden) {
				t.Fatal("CLI imported cluster mutation authority")
			}
		}
	}
}

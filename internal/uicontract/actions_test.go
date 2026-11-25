// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package uicontract

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
)

// This is the same checker used for the real route table and adversarial route
// fixtures. A new GET is harmless; a new mutation needs an explicit disposition.
func contractFailures(routes []adminv1.Route, actions []Action, unmapped []UnmappedRoute) []string {
	var failures []string
	ids := map[string]bool{}
	previewCount, confirmCount := 0, 0
	for _, a := range actions {
		if a.ID == "" || ids[a.ID] {
			failures = append(failures, "empty or duplicate action ID")
		}
		ids[a.ID] = true
		if strings.TrimSpace(a.Label) == "" || a.Label == a.RouteAction {
			failures = append(failures, "label is not task language")
		}
		if strings.Contains(strings.ToLower(a.ID+" "+a.Label), "unsafe") {
			failures = append(failures, "forbidden action vocabulary")
		}
		switch a.Confirm {
		case ConfirmNone, ConfirmTypedName, ConfirmPreviewThenConfirm:
		default:
			failures = append(failures, "unknown confirmation mode")
		}
		if a.SecondStepOnly && a.RouteAction != "world.destroy.confirm" && a.RouteAction != "world.destroy.cancel" {
			failures = append(failures, "unexpected second-step action")
		}
		switch a.RouteAction {
		case "world.destroy.preview":
			previewCount++
			if a.Confirm != ConfirmPreviewThenConfirm || a.SecondStepOnly {
				failures = append(failures, "destroy preview must begin the two-step flow")
			}
		case "world.destroy.confirm":
			confirmCount++
			if a.Confirm != ConfirmPreviewThenConfirm || !a.SecondStepOnly {
				failures = append(failures, "destroy confirmation must be second-step-only")
			}
		case "world.destroy.cancel":
			if !a.SecondStepOnly {
				failures = append(failures, "destroy cancellation must refer to a preview")
			}
		}
		matches := 0
		for _, route := range routes {
			if route.Method == a.Method && route.Path == a.Path && route.Action == a.RouteAction {
				matches++
			}
		}
		if matches != 1 {
			failures = append(failures, "action must match exactly one API route: "+a.ID)
		}
	}
	if previewCount != 2 || confirmCount != 1 {
		failures = append(failures, "destroy flow requires both previews and one confirmation")
	}
	exclusions := map[string]int{}
	for _, u := range unmapped {
		exclusions[u.RouteAction]++
		if u.RouteAction == "" || strings.TrimSpace(u.Reason) == "" {
			failures = append(failures, "unmapped action requires a reason")
		}
		if strings.Contains(strings.ToLower(u.Reason), "unsafe") {
			failures = append(failures, "forbidden reason vocabulary")
		}
		known := false
		for _, route := range routes {
			if route.Method != "GET" && route.Action == u.RouteAction {
				known = true
			}
		}
		if !known {
			failures = append(failures, "unmapped action must name a mutating route")
		}
	}
	for _, route := range routes {
		if route.Method == "GET" {
			continue
		}
		mapped := 0
		for _, a := range actions {
			if a.Method == route.Method && a.Path == route.Path && a.RouteAction == route.Action {
				mapped++
			}
		}
		if mapped+exclusions[route.Action] != 1 {
			failures = append(failures, "mutation requires exactly one disposition: "+route.Method+" "+route.Path)
		}
	}
	return failures
}

func TestActionsMatchAPIAndCoverEveryMutation(t *testing.T) {
	if failures := contractFailures(adminv1.Routes(), Actions(), Unmapped()); len(failures) != 0 {
		t.Fatal(failures)
	}
}

func TestContractRejectsUnclassifiedMutationsAndAllowsNewGET(t *testing.T) {
	for _, method := range []string{"POST", "PATCH", "DELETE", "PUT"} {
		routes := append(adminv1.Routes(), adminv1.Route{Method: method, Path: "/v1/new-mutation", Action: "new.mutation"})
		if failures := contractFailures(routes, Actions(), Unmapped()); !containsFailure(failures, "mutation requires exactly one disposition") {
			t.Fatalf("new %s route accepted: %v", method, failures)
		}
	}
	routes := append(adminv1.Routes(), adminv1.Route{Method: "GET", Path: "/v1/version", Action: "system.read"})
	if failures := contractFailures(routes, Actions(), Unmapped()); len(failures) != 0 {
		t.Fatalf("new GET broke the contract: %v", failures)
	}
}

func containsFailure(failures []string, text string) bool {
	for _, failure := range failures {
		if strings.Contains(failure, text) {
			return true
		}
	}
	return false
}

func TestContractRefusesBrokenActionMaps(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*[]Action, *[]UnmappedRoute)
		want   string
	}{
		{"wrong method", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].Method = "DELETE" }, "exactly one API route"},
		{"wrong path", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].Path = "/v1/fiction" }, "exactly one API route"},
		{"wrong API action", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].RouteAction = "server.fiction" }, "exactly one API route"},
		{"duplicate ID", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[1].ID = (*a)[0].ID }, "duplicate action ID"},
		{"empty label", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].Label = " " }, "task language"},
		{"raw action label", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].Label = (*a)[0].RouteAction }, "task language"},
		{"override ID", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].ID = "unsafe-create" }, "forbidden action vocabulary"},
		{"override label", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].Label = "Unsafe action" }, "forbidden action vocabulary"},
		{"override reason", func(_ *[]Action, u *[]UnmappedRoute) { (*u)[0].Reason = "unsafe" }, "forbidden reason vocabulary"},
		{"unknown confirmation", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].Confirm = "guess" }, "unknown confirmation"},
		{"unexpected second step", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[0].SecondStepOnly = true }, "unexpected second-step"},
		{"preview skips flow", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[8].Confirm = ConfirmNone }, "preview must begin"},
		{"preview second step", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[9].SecondStepOnly = true }, "preview must begin"},
		{"standalone confirm", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[10].SecondStepOnly = false }, "confirmation must be second-step-only"},
		{"confirm skips challenge", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[10].Confirm = ConfirmNone }, "confirmation must be second-step-only"},
		{"standalone cancel", func(a *[]Action, _ *[]UnmappedRoute) { (*a)[11].SecondStepOnly = false }, "cancellation must refer to a preview"},
		{"missing confirm", func(a *[]Action, _ *[]UnmappedRoute) { *a = append((*a)[:10], (*a)[11:]...) }, "both previews and one confirmation"},
		{"mapped and excluded", func(_ *[]Action, u *[]UnmappedRoute) { *u = append(*u, UnmappedRoute{"server.start", "Deferred"}) }, "exactly one disposition"},
		{"no exclusion reason", func(_ *[]Action, u *[]UnmappedRoute) { (*u)[0].Reason = "" }, "requires a reason"},
		{"unknown exclusion", func(_ *[]Action, u *[]UnmappedRoute) { *u = append(*u, UnmappedRoute{"fiction", "Deferred"}) }, "must name a mutating route"},
		{"duplicate exclusion", func(_ *[]Action, u *[]UnmappedRoute) { *u = append(*u, (*u)[0]) }, "exactly one disposition"},
		{"duplicate mapping", func(a *[]Action, _ *[]UnmappedRoute) {
			duplicate := (*a)[0]
			duplicate.ID = "other-create"
			*a = append(*a, duplicate)
		}, "exactly one disposition"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actions, unmapped := Actions(), Unmapped()
			tc.mutate(&actions, &unmapped)
			if failures := contractFailures(adminv1.Routes(), actions, unmapped); !containsFailure(failures, tc.want) {
				t.Fatalf("failures = %v, want %q", failures, tc.want)
			}
		})
	}
	duplicateRoutes := append(adminv1.Routes(), adminv1.Routes()[2])
	if failures := contractFailures(duplicateRoutes, Actions(), Unmapped()); !containsFailure(failures, "exactly one API route") {
		t.Fatalf("duplicate API route accepted: %v", failures)
	}
}

func TestActionTablesDoNotAlias(t *testing.T) {
	actions, unmapped := Actions(), Unmapped()
	originalAction, originalUnmapped := actions[0], unmapped[0]
	actions[0].Label = "changed"
	unmapped[0].Reason = "changed"
	if !reflect.DeepEqual(Actions()[0], originalAction) || !reflect.DeepEqual(Unmapped()[0], originalUnmapped) {
		t.Fatal("caller modified shared contract data")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
}

func TestUIDocumentMatchesActionMap(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join(moduleRoot(t), "docs", "UI.md"))
	if err != nil {
		t.Fatal(err)
	}
	var actions, unmapped strings.Builder
	actions.WriteString("| ID | Label | Method | Path | API action | Confirmation | Second step only |\n| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, a := range Actions() {
		fmt.Fprintf(&actions, "| %s | %s | %s | %s | %s | %s | %t |\n", a.ID, a.Label, a.Method, a.Path, a.RouteAction, a.Confirm, a.SecondStepOnly)
	}
	unmapped.WriteString("| API action | Reason |\n| --- | --- |\n")
	for _, u := range Unmapped() {
		fmt.Fprintf(&unmapped, "| %s | %s |\n", u.RouteAction, u.Reason)
	}
	for _, section := range []struct{ name, want string }{{"action-map", actions.String()}, {"unmapped", unmapped.String()}} {
		start, end := "<!-- "+section.name+":start -->\n", "<!-- "+section.name+":end -->"
		text := string(contents)
		if strings.Count(text, start) != 1 || strings.Count(text, end) != 1 {
			t.Fatalf("missing or duplicate %s doc markers", section.name)
		}
		_, tail, _ := strings.Cut(text, start)
		got, _, found := strings.Cut(tail, end)
		if !found || got != section.want {
			t.Errorf("%s docs differ from action map", section.name)
		}
	}
}

func forbiddenUIDependency(path string) bool {
	for _, prefix := range []string{"k8s.io/client-go", "sigs.k8s.io/controller-runtime", "github.com/gobha-me/arcadectl/internal/controller", "github.com/gobha-me/arcadectl/internal/platform/kube"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func TestUIContractCannotImportClusterMutationPackages(t *testing.T) {
	command := exec.Command("go", "list", "-deps", "./internal/uicontract")
	command.Dir = moduleRoot(t)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("list dependencies: %v: %s", err, output)
	}
	for _, path := range strings.Fields(string(output)) {
		if forbiddenUIDependency(path) {
			t.Errorf("UI contract imports cluster mutation package %s", path)
		}
	}
	for _, path := range []string{"k8s.io/client-go/kubernetes", "sigs.k8s.io/controller-runtime/pkg/client", "github.com/gobha-me/arcadectl/internal/controller", "github.com/gobha-me/arcadectl/internal/platform/kube"} {
		if !forbiddenUIDependency(path) {
			t.Errorf("dependency guard missed %s", path)
		}
	}
	if forbiddenUIDependency("k8s.io/client-gopher") {
		t.Error("dependency guard matched an unrelated prefix")
	}
}

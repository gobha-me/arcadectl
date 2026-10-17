// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installcontract

import (
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// These are public template/provenance-shape fixtures, not images executed from
// the genuine predecessor. Actual binary upgrade/rollback remains a runtime gate.
func TestFrozenPredecessorUpgradeAndFullTemplateRollback(t *testing.T) {
	previous := testContract(t, true)
	current := testContractVariant(t, false, installrender.DefaultNamespace, installrender.Profile137, "d", "e")
	for key := range previous.resources {
		if key.Kind == "Namespace" {
			continue
		}
		old, err := previous.Template(key, false)
		if err != nil {
			t.Fatal(err)
		}
		next, err := current.Template(key, false)
		if err != nil {
			t.Fatal(err)
		}
		oldLive := liveObject(t, old)
		upgrade, err := next.UpdateCandidate(old, oldLive, "original-uid", strings.Repeat("a", 32))
		if err != nil {
			t.Fatalf("upgrade %s: %v", key.String(), err)
		}
		if upgrade.GetUID() != oldLive.GetUID() || upgrade.GetResourceVersion() != oldLive.GetResourceVersion() {
			t.Fatal("upgrade lost original identity")
		}
		newLive := liveObject(t, next)
		rollback, err := old.UpdateCandidate(next, newLive, "original-uid", strings.Repeat("b", 32))
		if err != nil {
			t.Fatalf("rollback %s: %v", key.String(), err)
		}
		if key.Kind == "CustomResourceDefinition" && old.CheckCRD(oldLive, "original-uid", next) != nil {
			t.Fatal("unchanged genuine predecessor CRD contract refused")
		}
		if key.Kind != "Deployment" {
			continue
		}
		containers, _, _ := unstructured.NestedSlice(rollback.Object, "spec", "template", "spec", "containers")
		container := containers[0].(map[string]any)
		if key.Name == "arcadectl-api" {
			if container["image"] != previous.plan.Manifest().Images.API {
				t.Fatal("old API image not restored")
			}
			args, _ := container["args"].([]any)
			for _, arg := range args {
				if strings.HasPrefix(arg.(string), "--namespace") {
					t.Fatal("new API namespace flag survived rollback")
				}
			}
			for _, env := range container["env"].([]any) {
				if env.(map[string]any)["name"] == "POD_NAMESPACE" {
					t.Fatal("new API namespace environment survived exact old template rollback")
				}
			}
		} else {
			if container["image"] != previous.plan.Manifest().Images.Controller {
				t.Fatal("old controller image not restored")
			}
			workerImage := ""
			for _, env := range container["env"].([]any) {
				v := env.(map[string]any)
				if v["name"] == "BACKUP_WORKER_IMAGE" {
					workerImage = v["value"].(string)
				}
			}
			if workerImage != previous.plan.Manifest().Images.Controller {
				t.Fatal("worker image diverges from rolled-back controller image")
			}
		}
		// Raw rollback must have no extra pod fragments from the newer template.
		want, _, _ := unstructured.NestedMap(old.resource.Object.Object, "spec", "template")
		got, _, _ := unstructured.NestedMap(rollback.Object, "spec", "template")
		wantObject := &unstructured.Unstructured{Object: want}
		gotObject := &unstructured.Unstructured{Object: got}
		wantJSON, _ := wantObject.MarshalJSON()
		gotJSON, _ := gotObject.MarshalJSON()
		if string(wantJSON) != string(gotJSON) {
			t.Fatal("rollback did not restore complete original pod template")
		}
	}
}

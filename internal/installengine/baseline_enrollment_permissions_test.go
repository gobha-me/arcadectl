// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installbaseline"
	"github.com/gobha-me/arcadectl/internal/installstate"
)

// Pure permission derivation, not authorization, admission or enrollment proof.
func TestBaselineEnrollmentPermissionStages(t *testing.T) {
	for _, scenario := range []string{"bootstrap", "preparing", "partial", "pending", "verified", "historical", "foreign-artifact"} {
		t.Run(scenario, func(t *testing.T) {
			f := newBaselineFixture(t)
			if scenario == "verified" {
				completeBaselineFixture(t, f)
			}
			d := f.snapshot.Document()
			bootstrap := scenario == "bootstrap"
			if bootstrap {
				d = installstate.Document{Namespace: f.plan.Namespace(), ProfileID: f.plan.Profile().ID, Mode: installstate.Install, TargetPackage: f.plan.Digest(), Stage: installstate.Preparing}
			} else if scenario == "preparing" {
				d.SecurityBaseline.Stage = installstate.BaselinePreparing
			} else if scenario == "historical" {
				d.SecurityBaseline = nil
			} else if scenario == "foreign-artifact" {
				d.SecurityBaseline.ArtifactDigest = strings.Repeat("a", 64)
			}
			getNames := map[string]bool{}
			createCounts := map[string]int{"validatingadmissionpolicies": 0, "validatingadmissionpolicybindings": 0}
			for _, resource := range f.engine.baselinePlan().Resources() {
				object := resource.Object
				plural := "validatingadmissionpolicies"
				if object.GetKind() == "ValidatingAdmissionPolicyBinding" {
					plural = "validatingadmissionpolicybindings"
				}
				// A policy and its binding can share metadata.name. Their native
				// resource addresses, not bare names, are the independent keys.
				getNames[plural+"/"+object.GetName()] = true
				createCounts[plural]++
			}
			if len(getNames) != installbaseline.ResourceCount || createCounts["validatingadmissionpolicies"] != 6 || createCounts["validatingadmissionpolicybindings"] != 6 {
				t.Fatal("independent signed baseline inventory fixture incomplete")
			}
			if scenario == "partial" || scenario == "pending" {
				for _, resource := range f.engine.baselinePlan().Resources() {
					object := resource.Object
					if object.GetKind() != "ValidatingAdmissionPolicy" {
						continue
					}
					key := installstate.Key{APIVersion: object.GetAPIVersion(), Kind: object.GetKind(), Name: object.GetName()}
					if scenario == "partial" {
						d.SecurityBaseline.Resources = []installstate.BaselineResource{{Key: key, UID: "original-policy", TemplateSHA256: resource.TemplateSHA256}}
						createCounts["validatingadmissionpolicies"]--
					} else {
						d.SecurityBaseline.Pending = &installstate.Pending{Action: installstate.Create, Key: key, CreateNonce: strings.Repeat("b", 32), AfterSHA256: resource.TemplateSHA256}
					}
					break
				}
			}
			writes, updates, previews := f.access.writes, f.nsUpdates, f.access.dryRuns
			p := &ClusterPrerequisites{engine: f.engine}
			permissions, err := p.baselineEnrollmentPermissions(d, bootstrap)
			if scenario == "historical" || scenario == "foreign-artifact" {
				if err != ErrSecurityBaseline || permissions != nil {
					t.Fatal("historical/foreign record supplied baseline enrollment authority")
				}
				return
			}
			if err != nil {
				t.Fatal("eligible sealed baseline addresses refused", err)
			}
			reads, creates := map[string]int{}, map[string]int{}
			uniqueCreates := map[string]bool{}
			for _, row := range permissions {
				a := row.spec.ResourceAttributes
				if a == nil || row.spec.NonResourceAttributes != nil || a.Group != "admissionregistration.k8s.io" || a.Version != "v1" || a.Namespace != "" || a.Subresource != "" || a.Resource != "validatingadmissionpolicies" && a.Resource != "validatingadmissionpolicybindings" {
					t.Fatal("baseline enrollment permission escaped its fixed cluster-scoped APIs")
				}
				if a.Verb == "get" && getNames[a.Resource+"/"+a.Name] {
					reads[a.Resource+"/"+a.Name]++
				} else if a.Verb == "create" && a.Name == "" {
					creates[a.Resource]++
					body, err := json.Marshal(row.spec)
					if err != nil {
						t.Fatal("permission oracle encoding unavailable")
					}
					uniqueCreates[string(body)] = true
				} else {
					t.Fatal("baseline enrollment gained unbound reads, UPDATE/DELETE or named CREATE")
				}
			}
			if scenario == "verified" {
				if len(permissions) != 0 {
					t.Fatal("verified ownership reused fresh enrollment authority")
				}
			} else {
				if len(reads) != installbaseline.ResourceCount {
					t.Fatal("baseline enrollment omitted original fixed named GETs")
				}
				for name := range getNames {
					if reads[name] != 1 {
						t.Fatal("baseline named GET duplicated or omitted")
					}
				}
				if scenario == "pending" {
					if len(creates) != 0 {
						t.Fatal("pending baseline recovery gained new CREATE authority")
					}
				} else if len(uniqueCreates) != 2 || creates["validatingadmissionpolicies"] != createCounts["validatingadmissionpolicies"] || creates["validatingadmissionpolicybindings"] != createCounts["validatingadmissionpolicybindings"] {
					t.Fatal("outstanding baseline CREATE catalog differs from exact signed resources")
				}
			}
			if f.access.writes != writes || f.nsUpdates != updates || f.access.dryRuns != previews {
				t.Fatal("permission derivation performed effects")
			}
		})
	}
}

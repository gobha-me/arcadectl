// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package kube_test

// Input boundaries come from api/admin/v1/openapi.json CreateRequest/Self and
// StorageSpec; Kubernetes ResourceRequirements permits requests equal to limits.

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	arcadev1alpha1 "github.com/gobha-me/arcadectl/api/v1alpha1"
	platformkube "github.com/gobha-me/arcadectl/internal/platform/kube"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestSevenDaysPlanAddressesAtPublicNameBoundaries(t *testing.T) {
	t.Parallel()
	_, definition, template := sevenDaysAcceptanceBuild(t, sevenDaysAcceptanceSettings)
	seen := make(map[string]string)
	for _, namespaceLength := range []int{1, 63} {
		for _, nameLength := range []int{1, 2, 52, 53, 62, 63} {
			t.Run(fmt.Sprintf("namespace-%d/name-%d", namespaceLength, nameLength), func(t *testing.T) {
				server := template.DeepCopy()
				wantedName := strings.Repeat("a", nameLength)
				wantedNamespace := strings.Repeat("n", namespaceLength)
				server.Name = wantedName
				server.Namespace = wantedNamespace
				server.UID = types.UID(fmt.Sprintf("distinct-world-%d-%d", namespaceLength, nameLength))
				repeatedInput := server.DeepCopy()
				plan, err := platformkube.Build(server, definition)
				if err != nil {
					t.Fatalf("Build rejected public-schema-valid name/namespace lengths %d/%d: %v", nameLength, namespaceLength, err)
				}
				addresses := sevenDaysPropertyAddresses(t, plan, wantedNamespace)
				owner := wantedNamespace + "/" + wantedName + "/" + string(repeatedInput.UID)
				for _, address := range addresses {
					if previous, exists := seen[address]; exists {
						t.Errorf("generated address %q collides between %q and %q", address, previous, owner)
					}
					seen[address] = owner
				}
				repeated, err := platformkube.Build(repeatedInput, definition)
				if err != nil {
					t.Fatal(err)
				}
				if repeatedAddresses := sevenDaysPropertyAddresses(t, repeated, wantedNamespace); !reflect.DeepEqual(addresses, repeatedAddresses) {
					t.Errorf("same public inputs changed generated addresses: %q != %q", addresses, repeatedAddresses)
				}
			})
		}
	}
}

func TestSevenDaysPlanPreservesPositiveEquivalentResourceBounds(t *testing.T) {
	t.Parallel()
	_, definition, template := sevenDaysAcceptanceBuild(t, sevenDaysAcceptanceSettings)
	for _, quantities := range []struct {
		name, cpuRequest, cpuLimit, memoryRequest, memoryLimit string
	}{
		{"whole-and-milli", "1", "1000m", "1Gi", "1024Mi"},
		{"fractional-and-binary", "0.5", "500m", "536870912", "512Mi"},
		{"exponent-and-decimal", "1e0", "1.000", "1e9", "1000M"},
		{"positive-headroom", "250m", "1", "256Mi", "1Gi"},
	} {
		t.Run(quantities.name, func(t *testing.T) {
			server := template.DeepCopy()
			server.Spec.Compute = arcadev1alpha1.ComputeSpec{
				CPURequest: resource.MustParse(quantities.cpuRequest), CPULimit: resource.MustParse(quantities.cpuLimit),
				MemoryRequest: resource.MustParse(quantities.memoryRequest), MemoryLimit: resource.MustParse(quantities.memoryLimit),
			}
			plan, err := platformkube.Build(server, definition)
			if err != nil {
				t.Fatalf("Build rejected positive request <= limit quantities: %v", err)
			}
			container := sevenDaysAcceptanceContainer(t, plan, definition, server)
			for _, expected := range []struct {
				name    corev1.ResourceName
				request resource.Quantity
				limit   resource.Quantity
			}{
				{corev1.ResourceCPU, resource.MustParse(quantities.cpuRequest), resource.MustParse(quantities.cpuLimit)},
				{corev1.ResourceMemory, resource.MustParse(quantities.memoryRequest), resource.MustParse(quantities.memoryLimit)},
			} {
				request, requested := container.Resources.Requests[expected.name]
				limit, limited := container.Resources.Limits[expected.name]
				if !requested || !limited || request.Cmp(expected.request) != 0 || limit.Cmp(expected.limit) != 0 {
					t.Errorf("%s bounds request=%s limit=%s; want numeric values %s/%s", expected.name, request.String(), limit.String(), expected.request.String(), expected.limit.String())
				}
			}
		})
	}
}

func TestSevenDaysPlanPreservesStorageSizeAndClassSelection(t *testing.T) {
	t.Parallel()
	_, definition, template := sevenDaysAcceptanceBuild(t, sevenDaysAcceptanceSettings)
	emptyClass, namedClass := "", "fast-retained"
	for _, selection := range []struct {
		name  string
		class *string
	}{
		{"omitted", nil},
		{"explicit-empty", &emptyClass},
		{"named", &namedClass},
	} {
		for _, size := range []string{"1Gi", "1024Mi", "1.5Gi", "1536Mi"} {
			t.Run(selection.name+"/"+size, func(t *testing.T) {
				server := template.DeepCopy()
				server.Spec.Storage = arcadev1alpha1.StorageSpec{Size: resource.MustParse(size), StorageClassName: selection.class}
				wantedClass := ""
				if selection.class != nil {
					wantedClass = *selection.class
				}
				plan, err := platformkube.Build(server, definition)
				if err != nil {
					t.Fatalf("Build rejected positive storage with %s class: %v", selection.name, err)
				}
				paths := make(map[string]bool)
				for _, persistent := range definition.PersistentPaths {
					paths[persistent.Name] = false
				}
				if len(plan.DataClaims) != len(paths) || len(paths) == 0 {
					t.Fatalf("data claims=%d; want each of %d declared persistent paths", len(plan.DataClaims), len(paths))
				}
				for _, claim := range plan.DataClaims {
					if claim.Desired == nil {
						t.Fatal("plan omitted a desired data claim")
					}
					pathName := claim.Desired.Labels[platformkube.LabelDataPath]
					seen, declared := paths[pathName]
					if !declared || seen {
						t.Errorf("claim path=%q is undeclared or duplicated", pathName)
					}
					paths[pathName] = true
					request, present := claim.Desired.Spec.Resources.Requests[corev1.ResourceStorage]
					if !present || request.Cmp(resource.MustParse(size)) != 0 {
						t.Errorf("path %q storage=%s; want numeric size %s", pathName, request.String(), size)
					}
					actualClass := claim.Desired.Spec.StorageClassName
					if selection.class == nil {
						if actualClass != nil {
							t.Errorf("path %q converted omitted storage class into explicit %q", pathName, *actualClass)
						}
					} else if actualClass == nil || *actualClass != wantedClass {
						t.Errorf("path %q did not preserve explicit %s storage class", pathName, selection.name)
					}
				}
			})
		}
	}
}

func sevenDaysPropertyAddresses(t *testing.T, plan platformkube.Plan, namespace string) []string {
	t.Helper()
	if plan.Workload == nil || plan.Configuration == nil || plan.PlayerService == nil || len(plan.DataClaims) == 0 {
		t.Fatal("running plan lacks its public runtime or retained-data resources")
	}
	objects := []struct {
		kind     string
		metadata metav1.Object
	}{
		{"Deployment", plan.Workload},
		{"ConfigMap", plan.Configuration},
		{"Service", plan.PlayerService},
	}
	for _, claim := range plan.DataClaims {
		if claim.Desired == nil {
			t.Fatal("running plan contains a nil desired claim")
		}
		objects = append(objects, struct {
			kind     string
			metadata metav1.Object
		}{"PersistentVolumeClaim", claim.Desired})
	}
	var addresses []string
	for _, object := range objects {
		name := object.metadata.GetName()
		var problems []string
		if object.kind == "Service" {
			problems = validation.IsDNS1035Label(name)
		} else {
			problems = validation.IsDNS1123Subdomain(name)
		}
		if len(problems) != 0 {
			t.Errorf("generated %s name %q is invalid: %v", object.kind, name, problems)
		}
		if actualNamespace := object.metadata.GetNamespace(); actualNamespace != namespace {
			t.Errorf("generated %s namespace=%q; want exact %q", object.kind, actualNamespace, namespace)
		}
		addresses = append(addresses, object.kind+"/"+object.metadata.GetNamespace()+"/"+name)
	}
	sort.Strings(addresses)
	return addresses
}

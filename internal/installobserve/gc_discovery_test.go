// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Predicate-only catalogue tests; synthetic seals here are not observations or
// production authority. HTTP/native tests separately construct actual seals.
func TestGCDiscoveryNamespaceListCoverageIsStricterThanNativeGC(t *testing.T) {
	for _, scenario := range []string{"complete", "no-delete", "no-watch", "list-only", "create-only-virtual", "cluster-list-only", "preferred-not-gc"} {
		t.Run(scenario, func(t *testing.T) {
			catalogue := gcTestCatalogue(t)
			list := catalogue.Lists["example.test/v2"]
			extra := metav1.APIResource{Name: "extra", Kind: "Extra", Namespaced: true, Verbs: metav1.Verbs{"create", "delete", "list", "watch"}}
			switch scenario {
			case "no-delete":
				extra.Verbs = metav1.Verbs{"create", "list", "watch"}
			case "no-watch":
				extra.Verbs = metav1.Verbs{"create", "delete", "list"}
			case "list-only":
				extra.Verbs = metav1.Verbs{"list"}
			case "create-only-virtual":
				extra.Verbs = metav1.Verbs{"create"}
			case "cluster-list-only":
				extra.Namespaced = false
				extra.Verbs = metav1.Verbs{"list"}
			case "preferred-not-gc":
				list.APIResources[0].Verbs = metav1.Verbs{"get", "list"}
			}
			list.APIResources = append(list.APIResources, extra)
			catalogue.Lists["example.test/v2"] = list
			resources, err := gcResources(catalogue)
			if err != nil {
				t.Fatal("coverage fixture catalogue invalid")
			}
			discovery := &GCDiscovery{reader: &GCReader{}, journal: new(installstate.Snapshot), catalogue: catalogue, resources: resources}
			want := scenario == "complete" || scenario == "create-only-virtual" || scenario == "cluster-list-only"
			if discovery.CoversNamespaceLists() != want {
				t.Fatal("GC subset was misrepresented as complete namespace LIST coverage")
			}
		})
	}
	for _, discovery := range []*GCDiscovery{nil, {}, {reader: &GCReader{}}, {journal: new(installstate.Snapshot)}} {
		if discovery.CoversNamespaceLists() {
			t.Fatal("unsealed catalogue supplied namespace coverage")
		}
	}
}

func gcTestCatalogue(t *testing.T) gcCatalogue {
	t.Helper()
	c, err := gcGroups(metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}}, metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"}, Groups: []metav1.APIGroup{{Name: "example.test", Versions: []metav1.GroupVersionForDiscovery{{GroupVersion: "example.test/v1", Version: "v1"}, {GroupVersion: "example.test/v2", Version: "v2"}}, PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "example.test/v2", Version: "v2"}}}})
	if err != nil {
		t.Fatal(err)
	}
	r := func(name, kind string, namespace bool) metav1.APIResource {
		return metav1.APIResource{Name: name, Kind: kind, Namespaced: namespace, Verbs: metav1.Verbs{"delete", "get", "list", "watch"}}
	}
	c.Lists["v1"] = metav1.APIResourceList{GroupVersion: "v1", APIResources: []metav1.APIResource{r("secrets", "Secret", true), r("namespaces", "Namespace", false)}}
	c.Lists["example.test/v1"] = metav1.APIResourceList{GroupVersion: "example.test/v1", APIResources: []metav1.APIResource{r("widgets", "Widget", true), r("legacywidgets", "LegacyWidget", true)}}
	c.Lists["example.test/v2"] = metav1.APIResourceList{GroupVersion: "example.test/v2", APIResources: []metav1.APIResource{r("widgets", "Widget", true), {Name: "widgets/scale", Kind: "Scale", Group: "autoscaling", Version: "v1", Namespaced: true, Verbs: metav1.Verbs{"get", "update"}}}}
	return c
}

func TestGCDiscoveryPerResourcePreferenceAndConservativeDomain(t *testing.T) {
	c := gcTestCatalogue(t)
	want := []GCResource{{schema.GroupVersionResource{Version: "v1", Resource: "secrets"}, "Secret"}, {schema.GroupVersionResource{Group: "example.test", Version: "v1", Resource: "legacywidgets"}, "LegacyWidget"}, {schema.GroupVersionResource{Group: "example.test", Version: "v2", Resource: "widgets"}, "Widget"}}
	slices.SortFunc(want, func(a, b GCResource) int { return strings.Compare(a.GVR.String(), b.GVR.String()) })
	got, err := gcResources(c)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("preferred-only group selection omitted fallback or included cluster/subresource", err)
	}
	// Preferred selection happens BEFORE GC verb filtering. Do not silently
	// take an earlier version when the preferred resource is not GC-monitored.
	list := c.Lists["example.test/v2"]
	list.APIResources[0].Verbs = metav1.Verbs{"get", "list"}
	c.Lists["example.test/v2"] = list
	got, err = gcResources(c)
	if err != nil || len(got) != 2 {
		t.Fatal("preferred non-GC resource acquired fallback authority")
	}
	for _, source := range got {
		if source.GVR.Resource == "widgets" {
			t.Fatal("non-GC preferred resource selected")
		}
	}
}

func TestGCDiscoveryRefusesPartialAmbiguousAndMalformedResources(t *testing.T) {
	for label, change := range map[string]func(gcCatalogue){
		"missing-version": func(c gcCatalogue) { delete(c.Lists, "example.test/v1") },
		"extra-version":   func(c gcCatalogue) { c.Lists["foreign/v1"] = metav1.APIResourceList{GroupVersion: "foreign/v1"} },
		"wrong-version":   func(c gcCatalogue) { list := c.Lists["v1"]; list.GroupVersion = "foreign/v1"; c.Lists["v1"] = list },
		"wrong-kind":      func(c gcCatalogue) { list := c.Lists["v1"]; list.Kind = "SecretList"; c.Lists["v1"] = list },
		"duplicate-resource": func(c gcCatalogue) {
			list := c.Lists["v1"]
			list.APIResources = append(list.APIResources, list.APIResources[0])
			c.Lists["v1"] = list
		},
		"duplicate-kind": func(c gcCatalogue) {
			list := c.Lists["v1"]
			other := list.APIResources[0]
			other.Name = "othersecrets"
			list.APIResources = append(list.APIResources, other)
			c.Lists["v1"] = list
		},
		"scope-disagreement": func(c gcCatalogue) {
			list := c.Lists["example.test/v2"]
			list.APIResources[0].Namespaced = false
			c.Lists["example.test/v2"] = list
		},
		"kind-disagreement": func(c gcCatalogue) {
			list := c.Lists["example.test/v2"]
			list.APIResources[0].Kind = "ForeignWidget"
			c.Lists["example.test/v2"] = list
		},
		"cross-group": func(c gcCatalogue) {
			list := c.Lists["v1"]
			list.APIResources[0].Group = "foreign.test"
			c.Lists["v1"] = list
		},
		"cross-version": func(c gcCatalogue) { list := c.Lists["v1"]; list.APIResources[0].Version = "v2"; c.Lists["v1"] = list },
		"route": func(c gcCatalogue) {
			list := c.Lists["v1"]
			list.APIResources[0].Name = "../secrets"
			c.Lists["v1"] = list
		},
		"verb-alias": func(c gcCatalogue) {
			list := c.Lists["v1"]
			list.APIResources[0].Verbs = append(list.APIResources[0].Verbs, "list")
			c.Lists["v1"] = list
		},
		"too-many-resources": func(c gcCatalogue) {
			list := c.Lists["v1"]
			list.APIResources = make([]metav1.APIResource, 2049)
			c.Lists["v1"] = list
		},
	} {
		t.Run(label, func(t *testing.T) {
			if sources, err := gcResources(func() gcCatalogue { c := gcTestCatalogue(t); change(c); return c }()); err != ErrRead || sources != nil {
				t.Fatal("invalid catalogue supplied partial sources", err)
			}
		})
	}
}

func TestGCGroupsRejectUnknownPreferredDuplicateAndRouteAliases(t *testing.T) {
	for _, fault := range []string{"core-empty", "core-duplicate", "core-route", "core-kind", "groups-kind", "group-duplicate", "group-route", "version-duplicate", "version-route", "unknown-preferred", "too-many-versions"} {
		t.Run(fault, func(t *testing.T) {
			core := metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}}
			groups := metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList"}, Groups: []metav1.APIGroup{{Name: "example.test", Versions: []metav1.GroupVersionForDiscovery{{GroupVersion: "example.test/v1", Version: "v1"}}, PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "example.test/v1", Version: "v1"}}}}
			switch fault {
			case "core-empty":
				core.Versions = nil
			case "core-duplicate":
				core.Versions = []string{"v1", "v1"}
			case "core-route":
				core.Versions = []string{"../v1"}
			case "core-kind":
				core.Kind = "APIGroupList"
			case "groups-kind":
				groups.Kind = "APIVersions"
			case "group-duplicate":
				groups.Groups = append(groups.Groups, groups.Groups[0])
			case "group-route":
				groups.Groups[0].Name = "../example"
			case "version-duplicate":
				groups.Groups[0].Versions = append(groups.Groups[0].Versions, groups.Groups[0].Versions[0])
			case "version-route":
				groups.Groups[0].Versions[0].GroupVersion = "foreign.test/v1"
			case "unknown-preferred":
				groups.Groups[0].PreferredVersion.Version = "v2"
			case "too-many-versions":
				core.Versions = nil
				for i := 0; i < maxGCGroupVersions+1; i++ {
					core.Versions = append(core.Versions, "v"+strconv.Itoa(i+1))
				}
			}
			if _, err := gcGroups(core, groups); err != ErrRead {
				t.Fatal("malformed group discovery accepted")
			}
		})
	}
}

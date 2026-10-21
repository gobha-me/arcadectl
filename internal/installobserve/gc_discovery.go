// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/gobha-me/arcadectl/internal/installstate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
)

const maxGCGroups = 128
const maxGCGroupVersions = 512
const maxGCResources = 1024

type gcGroup struct {
	Name      string
	Versions  []metav1.GroupVersionForDiscovery
	Preferred metav1.GroupVersionForDiscovery
}

type gcCatalogue struct {
	Groups []gcGroup
	Lists  map[string]metav1.APIResourceList
}

// Typed zero values cannot prove presence: an omitted/null namespaced field
// would silently turn a namespace resource into an excluded cluster resource.
// Require explicit decision fields on the wire. Empty groups/resources/verbs
// must be explicit arrays; nullable or omitted catalogues are not completeness
// evidence, even though metav1's typed decoder accepts them.
func gcDiscoveryFields(body []byte, out any) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil {
		return ErrRead
	}
	array := func(raw json.RawMessage) ([]json.RawMessage, error) {
		if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' {
			return nil, ErrRead
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return nil, ErrRead
		}
		return values, nil
	}
	switch out.(type) {
	case *metav1.APIVersions:
		_, err := array(object["versions"])
		return err
	case *metav1.APIGroupList:
		_, err := array(object["groups"])
		return err
	case *metav1.APIResourceList:
		resources, err := array(object["resources"])
		if err != nil {
			return err
		}
		for _, raw := range resources {
			var resource map[string]json.RawMessage
			if json.Unmarshal(raw, &resource) != nil {
				return ErrRead
			}
			namespaced := bytes.TrimSpace(resource["namespaced"])
			if !bytes.Equal(namespaced, []byte("true")) && !bytes.Equal(namespaced, []byte("false")) {
				return ErrRead
			}
			if _, err := array(resource["verbs"]); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrRead
	}
}

func structuralGCKey(group, version, kind string) installstate.Key {
	return installstate.Key{APIVersion: schema.GroupVersion{Group: group, Version: version}.String(), Kind: kind, Namespace: "validation", Name: "validation"}
}

func gcGroups(core metav1.APIVersions, groups metav1.APIGroupList) (gcCatalogue, error) {
	bad := func() (gcCatalogue, error) { return gcCatalogue{}, ErrRead }
	if core.Kind != "APIVersions" || core.APIVersion != "" && core.APIVersion != "v1" || groups.Kind != "APIGroupList" || groups.APIVersion != "" && groups.APIVersion != "v1" || len(core.Versions) == 0 || len(groups.Groups) > maxGCGroups {
		return bad()
	}
	c := gcCatalogue{Groups: []gcGroup{{Name: ""}}, Lists: map[string]metav1.APIResourceList{}}
	seenGroups, seenVersions := map[string]bool{}, map[string]bool{}
	for _, version := range core.Versions {
		if len(validation.IsDNS1035Label(version)) != 0 || seenVersions[version] {
			return bad()
		}
		seenVersions[version] = true
		c.Groups[0].Versions = append(c.Groups[0].Versions, metav1.GroupVersionForDiscovery{GroupVersion: version, Version: version})
	}
	c.Groups[0].Preferred = c.Groups[0].Versions[0]
	for _, group := range groups.Groups {
		if group.Name == "" || len(validation.IsDNS1123Subdomain(group.Name)) != 0 || seenGroups[group.Name] || len(group.Versions) == 0 {
			return bad()
		}
		seenGroups[group.Name] = true
		preferred := false
		versions := []metav1.GroupVersionForDiscovery{}
		for _, version := range group.Versions {
			if len(validation.IsDNS1035Label(version.Version)) != 0 || version.GroupVersion != group.Name+"/"+version.Version || seenVersions[version.GroupVersion] {
				return bad()
			}
			seenVersions[version.GroupVersion] = true
			versions = append(versions, version)
			preferred = preferred || version == group.PreferredVersion
		}
		if !preferred {
			return bad()
		}
		c.Groups = append(c.Groups, gcGroup{group.Name, versions, group.PreferredVersion})
	}
	if len(seenVersions) > maxGCGroupVersions {
		return bad()
	}
	slices.SortFunc(c.Groups, func(a, b gcGroup) int { return strings.Compare(a.Name, b.Name) })
	return c, nil
}

// Match the pinned native GC's PER-GroupResource preferred selection, not just
// the preferred group-version: a resource may exist only in a nonpreferred
// served version. Unlike GC's partial discovery tolerance, every advertised
// version must succeed. Version order is preserved for native fallback choice.
func gcResources(c gcCatalogue) ([]GCResource, error) {
	selected := map[schema.GroupResource]GCResource{}
	shapes := map[schema.GroupResource]metav1.APIResource{}
	kinds := map[schema.GroupKind]schema.GroupResource{}
	gcEnabled := map[schema.GroupResource]bool{}
	versions := 0
	for _, group := range c.Groups {
		for _, version := range group.Versions {
			versions++
			list, exists := c.Lists[version.GroupVersion]
			if !exists || list.GroupVersion != version.GroupVersion || list.Kind != "" && list.Kind != "APIResourceList" || list.APIVersion != "" && list.APIVersion != "v1" || len(list.APIResources) > 2048 {
				return nil, ErrRead
			}
			seen := map[string]bool{}
			normal := []metav1.APIResource{}
			for _, resource := range list.APIResources {
				parts := strings.Split(resource.Name, "/")
				if len(parts) > 2 || seen[resource.Name] {
					return nil, ErrRead
				}
				seen[resource.Name] = true
				for _, part := range parts {
					if len(validation.IsDNS1035Label(part)) != 0 {
						return nil, ErrRead
					}
				}
				verbs := map[string]bool{}
				if len(resource.Verbs) > 32 {
					return nil, ErrRead
				}
				for _, verb := range resource.Verbs {
					if len(validation.IsDNS1035Label(verb)) != 0 || verbs[verb] {
						return nil, ErrRead
					}
					verbs[verb] = true
				}
				copy := *resource.DeepCopy()
				slices.Sort(copy.Verbs)
				normal = append(normal, copy)
				if len(parts) == 2 {
					continue
				} // e.g. apps deployment/scale advertises autoscaling/v1
				if resource.Group != "" && resource.Group != group.Name || resource.Version != "" && resource.Version != version.Version || !validKey(structuralGCKey(group.Name, version.Version, resource.Kind), "validation") {
					return nil, ErrRead
				}
				gr := schema.GroupResource{Group: group.Name, Resource: resource.Name}
				if prior, exists := shapes[gr]; exists && (prior.Kind != resource.Kind || prior.Namespaced != resource.Namespaced) {
					return nil, ErrRead
				}
				shapes[gr] = resource
				gk := schema.GroupKind{Group: group.Name, Kind: resource.Kind}
				if prior, exists := kinds[gk]; exists && prior != gr {
					return nil, ErrRead
				}
				kinds[gk] = gr
				if _, exists := selected[gr]; !exists || version.Version == group.Preferred.Version {
					selected[gr] = GCResource{schema.GroupVersionResource{Group: group.Name, Version: version.Version, Resource: resource.Name}, resource.Kind}
					gcEnabled[gr] = resource.Namespaced && verbs["delete"] && verbs["list"] && verbs["watch"]
				}
			}
			slices.SortFunc(normal, func(a, b metav1.APIResource) int { return strings.Compare(a.Name, b.Name) })
			list.APIResources = normal
			c.Lists[version.GroupVersion] = list
		}
	}
	if versions != len(c.Lists) {
		return nil, ErrRead
	}
	result := []GCResource{}
	for gr, resource := range selected {
		if gcEnabled[gr] {
			result = append(result, resource)
		}
	}
	if len(result) == 0 || len(result) > maxGCResources {
		return nil, ErrRead
	}
	slices.SortFunc(result, func(a, b GCResource) int { return strings.Compare(a.GVR.String(), b.GVR.String()) })
	return result, nil
}

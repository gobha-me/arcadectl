// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ServingAccess is a trusted read-only seam. Lists must be complete, unfiltered
// and uncached. It adds no Pod/ReplicaSet mutation or full-Secret fallback.
type ServingAccess interface {
	GetPod(context.Context, string, string) (*unstructured.Unstructured, error)
	GetReplicaSet(context.Context, string, string) (*unstructured.Unstructured, error)
	ListEndpointSlices(context.Context, string) (*discoveryv1.EndpointSliceList, error)
}

type servingAccess struct{ access *HTTPAccess }

func (a *HTTPAccess) Serving() ServingAccess { return servingAccess{a} }

func (s servingAccess) get(ctx context.Context, namespace, name, kind string) (*unstructured.Unstructured, error) {
	if !installrender.ValidNamespace(namespace) || !addressPart(name) {
		return nil, ErrInvalid
	}
	version, plural, prefix := "v1", "pods", "/api/v1"
	if kind == "ReplicaSet" {
		version, plural, prefix = "apps/v1", "replicasets", "/apis/apps/v1"
	} else if kind != "Pod" {
		return nil, ErrInvalid
	}
	key := installstate.Key{APIVersion: version, Kind: kind, Namespace: namespace, Name: name}
	return s.access.requestAt(ctx, http.MethodGet, key, nil, false, prefix+"/namespaces/"+namespace+"/"+plural+"/"+name, nil)
}
func (s servingAccess) GetPod(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return s.get(ctx, namespace, name, "Pod")
}
func (s servingAccess) GetReplicaSet(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return s.get(ctx, namespace, name, "ReplicaSet")
}

func (s servingAccess) ListEndpointSlices(ctx context.Context, namespace string) (*discoveryv1.EndpointSliceList, error) {
	if ctx == nil || !installrender.ValidNamespace(namespace) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	key := installstate.Key{APIVersion: "discovery.k8s.io/v1", Kind: "EndpointSliceList"}
	path := "/apis/discovery.k8s.io/v1/namespaces/" + namespace + "/endpointslices"
	result := &discoveryv1.EndpointSliceList{}
	seenTokens, seenUIDs := map[string]bool{}, map[string]bool{}
	seenNames := map[string]bool{}
	total := 0
	continuation := ""
	for page := 0; page < 32; page++ {
		query := url.Values{"limit": []string{strconv.Itoa(100)}}
		if continuation != "" {
			query.Set("continue", continuation)
		}
		obj, err := s.access.requestAt(ctx, http.MethodGet, key, nil, false, path, query)
		if err != nil {
			return nil, ErrRead
		}
		body, err := json.Marshal(obj.Object)
		total += len(body)
		if err != nil || total > 4*1024*1024 {
			return nil, ErrRead
		}
		var list discoveryv1.EndpointSliceList
		if decodeServing(obj, &list) != nil || list.ResourceVersion == "" || list.RemainingItemCount != nil && *list.RemainingItemCount < 0 || len(list.Items)+len(result.Items) > 1000 {
			return nil, ErrRead
		}
		if result.ResourceVersion == "" {
			result.TypeMeta, result.ResourceVersion = list.TypeMeta, list.ResourceVersion
		} else if list.ResourceVersion != result.ResourceVersion {
			return nil, ErrRead
		}
		for _, item := range list.Items {
			if item.Namespace != namespace || item.UID == "" || item.ResourceVersion == "" || seenUIDs[string(item.UID)] || seenNames[item.Name] {
				return nil, ErrRead
			}
			seenUIDs[string(item.UID)] = true
			seenNames[item.Name] = true
			result.Items = append(result.Items, *item.DeepCopy())
		}
		continuation = list.Continue
		if continuation == "" {
			if list.RemainingItemCount != nil && *list.RemainingItemCount != 0 {
				return nil, ErrRead
			}
			return result, nil
		}
		if len(continuation) > 2048 || seenTokens[continuation] {
			return nil, ErrRead
		}
		seenTokens[continuation] = true
	}
	return nil, ErrRead
}

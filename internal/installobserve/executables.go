// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	strictjson "sigs.k8s.io/json"
)

// ExecutableCollections are complete unfiltered namespace reads, including
// suspended, terminating and terminal workloads. They are observed dependency
// evidence only, never original ownership, coldness or mutation authority.
type ExecutableCollections struct {
	Pods                   *corev1.PodList
	Jobs                   *batchv1.JobList
	Deployments            *appsv1.DeploymentList
	ReplicaSets            *appsv1.ReplicaSetList
	StatefulSets           *appsv1.StatefulSetList
	DaemonSets             *appsv1.DaemonSetList
	ReplicationControllers *corev1.ReplicationControllerList
	CronJobs               *batchv1.CronJobList
}

func (c *ExecutableCollections) DeepCopy() *ExecutableCollections {
	if c == nil {
		return nil
	}
	return &ExecutableCollections{c.Pods.DeepCopy(), c.Jobs.DeepCopy(), c.Deployments.DeepCopy(), c.ReplicaSets.DeepCopy(), c.StatefulSets.DeepCopy(), c.DaemonSets.DeepCopy(), c.ReplicationControllers.DeepCopy(), c.CronJobs.DeepCopy()}
}

type ExecutablesObservation struct {
	journal *installstate.Snapshot
	objects *ExecutableCollections
	whole   map[installstate.Key]*unstructured.Unstructured
}

func (o *ExecutablesObservation) Journal() *installstate.Snapshot {
	if o == nil {
		return nil
	}
	return o.journal
}

func (o *ExecutablesObservation) Collections() *ExecutableCollections {
	if o == nil {
		return nil
	}
	return o.objects.DeepCopy()
}

func (o *ExecutablesObservation) Whole() map[installstate.Key]*unstructured.Unstructured {
	if o == nil || o.whole == nil {
		return nil
	}
	result := make(map[installstate.Key]*unstructured.Unstructured, len(o.whole))
	for key, object := range o.whole {
		result[key] = object.DeepCopy()
	}
	return result
}

func executableCollections(c *ExecutableCollections) []collection {
	c.Pods, c.Jobs = &corev1.PodList{}, &batchv1.JobList{}
	c.Deployments, c.ReplicaSets = &appsv1.DeploymentList{}, &appsv1.ReplicaSetList{}
	c.StatefulSets, c.DaemonSets = &appsv1.StatefulSetList{}, &appsv1.DaemonSetList{}
	c.ReplicationControllers, c.CronJobs = &corev1.ReplicationControllerList{}, &batchv1.CronJobList{}
	return []collection{
		{"v1", "Pod", "pods", true, c.Pods},
		{"batch/v1", "Job", "jobs", true, c.Jobs},
		{"apps/v1", "Deployment", "deployments", true, c.Deployments},
		{"apps/v1", "ReplicaSet", "replicasets", true, c.ReplicaSets},
		{"apps/v1", "StatefulSet", "statefulsets", true, c.StatefulSets},
		{"apps/v1", "DaemonSet", "daemonsets", true, c.DaemonSets},
		{"v1", "ReplicationController", "replicationcontrollers", true, c.ReplicationControllers},
		{"batch/v1", "CronJob", "cronjobs", true, c.CronJobs},
	}
}

// Decode the original page before the dynamic SDK's list decoder. Kubernetes
// typed LIST replies may legitimately omit BOTH item TypeMeta fields; only
// that literal omission is supported, not null/empty/partial envelopes.
func executablePageBody(body []byte, c collection) (*unstructured.UnstructuredList, error) {
	if _, err := boundedJSON(body); err != nil || strictDecode(body, c.target.DeepCopyObject()) != nil {
		return nil, ErrRead
	}
	var fields map[string]any
	strictErrors, err := strictjson.UnmarshalStrict(body, &fields)
	if err != nil || len(strictErrors) != 0 || fields["apiVersion"] != c.gv || fields["kind"] != c.kind+"List" {
		return nil, ErrRead
	}
	metadata, ok := fields["metadata"].(map[string]any)
	if !ok {
		return nil, ErrRead
	}
	if value, present := metadata["continue"]; present {
		if _, ok := value.(string); !ok {
			return nil, ErrRead
		}
	}
	if value, present := metadata["remainingItemCount"]; present && value != nil {
		if _, ok := value.(int64); !ok {
			return nil, ErrRead
		}
	}
	value, present := fields["items"]
	items, ok := value.([]any)
	if !present || !ok && value != nil {
		return nil, ErrRead
	}
	delete(fields, "items")
	page := &unstructured.UnstructuredList{Object: fields, Items: []unstructured.Unstructured{}}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, ErrRead
		}
		gv, hasGV := object["apiVersion"]
		kind, hasKind := object["kind"]
		if hasGV != hasKind || hasGV && (gv != c.gv || kind != c.kind) {
			return nil, ErrRead
		}
		page.Items = append(page.Items, unstructured.Unstructured{Object: object})
	}
	return page, nil
}

func nativeExecutablePage(ctx context.Context, client *http.Client, base *url.URL, c collection, namespace string, options metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	if ctx == nil || client == nil || base == nil {
		return nil, ErrRead
	}
	u := *base
	prefix := "/apis/" + c.gv
	if c.gv == "v1" {
		prefix = "/api/v1"
	}
	u.Path = strings.TrimRight(u.Path, "/") + prefix + "/namespaces/" + namespace + "/" + c.resource
	query := url.Values{"limit": []string{strconv.FormatInt(options.Limit, 10)}}
	if options.Continue != "" {
		query.Set("continue", options.Continue)
	}
	u.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrRead
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, ErrRead
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxResponseBytes {
		return nil, ErrRead
	}
	return executablePageBody(body, c)
}

// No Secret, domain CRD, token, owner-graph adoption, selector or cached read is
// required. All eight native kinds are mandatory, with the same bounded exact
// pagination and strict transport as ordinary observations. Raw values stay
// available for exact LIST/GET correlation; typed decoding rejects unknowns.
func (o *Observer) CollectExecutables(ctx context.Context, anchor installstate.Anchor) (*ExecutablesObservation, error) {
	if o == nil || o.journal == nil || ctx == nil || !o.plan.IsTrusted() || anchor.Namespace != o.plan.Namespace() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, observationTimeout)
	defer cancel()
	ctx = logr.NewContext(ctx, logr.Discard())
	before, err := o.journal.Load(ctx, anchor)
	if err != nil || before.Anchor() != anchor {
		return nil, ErrOwnership
	}
	d := before.Document()
	if d.ProfileID != o.plan.Profile().ID || !slices.Contains([]string{d.ActivePackage, d.TargetPackage, d.PreviousPackage}, o.plan.Digest()) {
		return nil, ErrOwnership
	}
	objects := &ExecutableCollections{}
	whole := map[installstate.Key]*unstructured.Unstructured{}
	uids := map[string]bool{}
	budget := 32 * 1024 * 1024
	for _, c := range executableCollections(objects) {
		gv, err := schema.ParseGroupVersion(c.gv)
		if err != nil {
			return nil, ErrRead
		}
		items, rv, err := boundedPages(ctx, func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
			if o.executablePage != nil {
				return o.executablePage(ctx, c, anchor.Namespace, options)
			}
			// Trusted instrumentation seam only; native New always captures
			// literal pages above, before any SDK envelope normalization.
			page, err := o.clients.Dynamic.Resource(gv.WithResource(c.resource)).Namespace(anchor.Namespace).List(ctx, options)
			if err != nil || page == nil || page.GetAPIVersion() != c.gv || page.GetKind() != c.kind+"List" {
				return nil, ErrRead
			}
			body, err := json.Marshal(page.UnstructuredContent())
			if err != nil {
				return nil, ErrRead
			}
			return executablePageBody(body, c)
		}, &budget)
		if err != nil {
			return nil, ErrRead
		}
		list := &unstructured.UnstructuredList{Object: map[string]any{"apiVersion": c.gv, "kind": c.kind + "List", "metadata": map[string]any{"resourceVersion": rv}}, Items: []unstructured.Unstructured{}}
		for _, item := range items {
			object, ok := item.(*unstructured.Unstructured)
			if !ok || object == nil || object.GetNamespace() != anchor.Namespace || object.GetName() == "" || !validIdentity(string(object.GetUID())) || !validIdentity(object.GetResourceVersion()) || uids[string(object.GetUID())] {
				return nil, ErrRead
			}
			gv, hasGV := object.Object["apiVersion"]
			kind, hasKind := object.Object["kind"]
			if hasGV != hasKind || hasGV && (gv != c.gv || kind != c.kind) {
				return nil, ErrRead
			}
			key := installstate.Key{APIVersion: c.gv, Kind: c.kind, Namespace: anchor.Namespace, Name: object.GetName()}
			if whole[key] != nil {
				return nil, ErrRead
			}
			uids[string(object.GetUID())] = true
			whole[key] = object.DeepCopy()
			typed := object.DeepCopy()
			if !hasGV {
				typed.SetAPIVersion(c.gv)
				typed.SetKind(c.kind)
			}
			list.Items = append(list.Items, *typed)
		}
		body, err := json.Marshal(list.UnstructuredContent())
		if err != nil || strictDecode(body, c.target) != nil {
			return nil, ErrRead
		}
	}
	after, err := o.journal.Load(ctx, anchor)
	if err != nil || after.Anchor() != anchor || after.ResourceVersion() != before.ResourceVersion() || !bytes.Equal(after.Bytes(), before.Bytes()) {
		return nil, ErrConcurrent
	}
	if ctx.Err() != nil {
		return nil, ErrRead
	}
	return &ExecutablesObservation{after, objects, whole}, nil
}

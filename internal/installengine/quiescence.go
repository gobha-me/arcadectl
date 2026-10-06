// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gobha-me/arcadectl/internal/installobserve"
	"github.com/gobha-me/arcadectl/internal/installsafety"
	"github.com/gobha-me/arcadectl/internal/installstate"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

var ErrQuiescence = errors.New("original installation runtime shutdown is unproved")

// ClusterQuiescence implements only APIStopped and RuntimeStopped. It does not
// stop workloads, prove cold worlds/admission behavior, or replace the complete
// LifecycleChecks provider. Every read uses the effect client's frozen cluster
// identity and original journal; callers must repeat this at mutation barriers.
type ClusterQuiescence struct{ prerequisites *ClusterPrerequisites }

func NewClusterQuiescence(p *ClusterPrerequisites) (*ClusterQuiescence, error) {
	if p == nil || p.engine == nil || p.access == nil || p.engine.access != p.access || p.access.frozen == nil {
		return nil, ErrInvalid
	}
	return &ClusterQuiescence{p}, nil
}

func (q *ClusterQuiescence) Verify(ctx context.Context, request LifecycleCheck) error {
	if q == nil || q.prerequisites == nil || ctx == nil || request.Snapshot == nil || request.Options.Now.IsZero() || (request.Checkpoint != APIStopped && request.Checkpoint != RuntimeStopped) {
		return ErrInvalid
	}
	d := request.Snapshot.Document()
	if request.Mode != d.Mode || request.Target == nil || request.Target.Digest() != d.TargetPackage {
		return ErrInvalid
	}
	if d.Pending != nil {
		// Access withdrawal may await foreground deletion/acknowledgement. Its
		// original receipt allows observation only, not pending runtime effects.
		if request.Checkpoint != RuntimeStopped || !retiringAccessDelete(d) || q.prerequisites.engine.verifyRetiredAdmission(ctx, request.Snapshot) != nil {
			return ErrInvalid
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	first, err := q.collect(ctx, request)
	if err != nil {
		return ErrQuiescence
	}
	second, err := q.collect(ctx, request)
	if err != nil || first != second || q.prerequisites.original(ctx, request.Snapshot) != nil {
		return ErrQuiescence
	}
	if d.Pending != nil && q.prerequisites.engine.verifyRetiredAdmission(ctx, request.Snapshot) != nil {
		return ErrQuiescence
	}
	return nil
}

type stoppedWitness struct {
	Deployments []appsv1.Deployment
	ReplicaSets []appsv1.ReplicaSet
	Service     *corev1.Service
	Slices      []discoveryv1.EndpointSlice
}

func (q *ClusterQuiescence) collect(ctx context.Context, request LifecycleCheck) ([32]byte, error) {
	var zero [32]byte
	p := q.prerequisites
	o, err := p.observe(ctx, request)
	if err != nil {
		return zero, ErrQuiescence
	}
	w, err := p.engine.stopped(ctx, request, o)
	if err != nil || p.original(ctx, request.Snapshot) != nil {
		return zero, ErrQuiescence
	}
	slices.SortFunc(w.Deployments, func(a, b appsv1.Deployment) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(w.ReplicaSets, func(a, b appsv1.ReplicaSet) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(w.Slices, func(a, b discoveryv1.EndpointSlice) int { return strings.Compare(a.Name, b.Name) })
	body, err := json.Marshal(w)
	if err != nil || len(body) > 32*1024*1024 {
		return zero, ErrQuiescence
	}
	return sha256.Sum256(body), nil
}

const apiFamily = "arcadectl-api"

var controllerFamilies = []string{"arcadectl-controller", "arcadectl-destroy-controller"}

func deploymentKey(namespace, name string) installstate.Key {
	return installstate.Key{APIVersion: "apps/v1", Kind: "Deployment", Namespace: namespace, Name: name}
}

// stopped accepts ONLY sealed complete observations. Inert history is evidence
// of zero executable descendants, not adoption or signed historical provenance.
// A deleted parent's sets cannot qualify as inert for full runtime shutdown;
// the API-only check can ignore independently unrelated controller history.
func (e *Engine) stopped(ctx context.Context, request LifecycleCheck, o *installobserve.Observation) (*stoppedWitness, error) {
	if o == nil || o.Snapshot() == nil || o.Runtime() == nil {
		return nil, ErrQuiescence
	}
	s, r := o.Snapshot(), o.Runtime()
	if !completeStoppedLists(s, r) {
		return nil, ErrQuiescence
	}
	d := request.Snapshot.Document()
	w := &stoppedWitness{}
	apiKey := deploymentKey(d.Namespace, apiFamily)
	if recorded, _ := e.inventory(d, apiKey); recorded != nil {
		return nil, ErrQuiescence
	}
	if _, err := e.access.Get(ctx, apiKey); !apierrors.IsNotFound(err) {
		return nil, ErrQuiescence
	}
	parents := map[string]*appsv1.Deployment{}
	{
		for _, name := range controllerFamilies {
			key := deploymentKey(d.Namespace, name)
			recorded, template := e.inventory(d, key)
			live, err := e.access.Get(ctx, key)
			if recorded == nil {
				if request.Checkpoint == RuntimeStopped && d.Mode != installstate.Uninstall || !apierrors.IsNotFound(err) {
					return nil, ErrQuiescence
				}
				continue
			}
			if template == nil || err != nil {
				return nil, ErrQuiescence
			}
			if template.MatchLive(live, recorded.UID) != nil {
				return nil, ErrQuiescence
			}
			var parent appsv1.Deployment
			if decodeServing(live, &parent) != nil {
				return nil, ErrQuiescence
			}
			if request.Checkpoint == RuntimeStopped {
				c := e.contracts[d.ActivePackage]
				if c == nil {
					return nil, ErrQuiescence
				}
				want, err := c.Template(key, true)
				if err != nil || recorded.TemplateSHA256 != want.Hash() || !stoppedDeployment(&parent) {
					return nil, ErrQuiescence
				}
			}
			if parent.Spec.Paused {
				return nil, ErrQuiescence
			}
			parents[name] = &parent
			w.Deployments = append(w.Deployments, parent)
		}
	}
	serviceKey := installstate.Key{APIVersion: "v1", Kind: "Service", Namespace: d.Namespace, Name: apiFamily}
	recorded, template := e.inventory(d, serviceKey)
	live, err := e.access.Get(ctx, serviceKey)
	if recorded == nil {
		if !apierrors.IsNotFound(err) {
			return nil, ErrQuiescence
		}
	} else {
		if template == nil || err != nil || template.MatchLive(live, recorded.UID) != nil {
			return nil, ErrQuiescence
		}
		service := &corev1.Service{}
		if decodeServing(live, service) != nil {
			return nil, ErrQuiescence
		}
		w.Service = service
	}
	hardAPI := func(meta metav1.ObjectMeta, spec *corev1.PodSpec) bool {
		return e.familyIdentitySignal(apiFamily, meta, spec)
	}
	selected := func(meta metav1.ObjectMeta, spec *corev1.PodSpec) bool {
		if e.familySignal(apiFamily, meta, spec) {
			return true
		}
		if request.Checkpoint == RuntimeStopped {
			for _, name := range controllerFamilies {
				if e.familySignal(name, meta, spec) {
					return true
				}
			}
		}
		return false
	}
	originalUIDs := map[types.UID]bool{}
	for _, parent := range parents {
		originalUIDs[parent.UID] = true
	}
	for _, resource := range d.Resources {
		if resource.Key == apiKey || request.Checkpoint == RuntimeStopped && resource.Key.Kind == "Deployment" && slices.Contains(controllerFamilies, resource.Key.Name) {
			originalUIDs[resource.UID] = true
		}
	}
	basicSelected := selected
	selected = func(meta metav1.ObjectMeta, spec *corev1.PodSpec) bool {
		if originalUIDs[meta.UID] {
			return true
		}
		for _, owner := range meta.OwnerReferences {
			if originalUIDs[owner.UID] {
				return true
			}
		}
		return basicSelected(meta, spec)
	}
	// Close all observed ownership edges before classification, rather than
	// depending on a parent ReplicaSet preceding its renamed descendants.
	for i := range r.ReplicaSets.Items {
		item := &r.ReplicaSets.Items[i]
		parentKnown := len(item.OwnerReferences) == 1 && parents[item.OwnerReferences[0].Name] != nil
		if parentKnown || selected(item.ObjectMeta, &item.Spec.Template.Spec) || selected(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			originalUIDs[item.UID] = true
		}
	}
	if closeDescendantUIDs(s, r, originalUIDs) != nil {
		return nil, ErrQuiescence
	}
	seenParents := map[string]bool{}
	for i := range r.Deployments.Items {
		item := &r.Deployments.Items[i]
		if parents[item.Name] == nil && !selected(item.ObjectMeta, &item.Spec.Template.Spec) && !selected(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			continue
		}
		parent := parents[item.Name]
		if parent == nil || !reflect.DeepEqual(item, parent) || hardAPI(item.ObjectMeta, &item.Spec.Template.Spec) || hardAPI(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			return nil, ErrQuiescence
		}
		seenParents[item.Name] = true
	}
	if len(seenParents) != len(parents) {
		return nil, ErrQuiescence
	}
	for i := range r.ReplicaSets.Items {
		item := &r.ReplicaSets.Items[i]
		var parent *appsv1.Deployment
		if len(item.OwnerReferences) == 1 {
			parent = parents[item.OwnerReferences[0].Name]
		}
		if parent == nil && !selected(item.ObjectMeta, &item.Spec.Template.Spec) && !selected(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			continue
		}
		valid := parent != nil && inertReplicaSet(item, parent)
		if request.Checkpoint == APIStopped && parent != nil {
			valid = valid || e.controllerRuntimeSet(item, parent, d)
		}
		if !valid || hardAPI(item.ObjectMeta, &item.Spec.Template.Spec) || hardAPI(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			return nil, ErrQuiescence
		}
		w.ReplicaSets = append(w.ReplicaSets, *item.DeepCopy())
		originalUIDs[item.UID] = true
	}
	for _, pod := range s.Pods.Items {
		// Shared image repositories are valid. Only the whole original signed
		// controller chain can disambiguate a repository-only API signal.
		knownController := false
		if request.Checkpoint == APIStopped && !hardAPI(pod.ObjectMeta, &pod.Spec) && len(pod.OwnerReferences) == 1 {
			owner := pod.OwnerReferences[0]
			for i := range w.ReplicaSets {
				rs := &w.ReplicaSets[i]
				parent := parents[rs.OwnerReferences[0].Name]
				if owner.UID == rs.UID && e.controllerRuntimeSet(rs, parent, d) && servingMetadata(pod.ObjectMeta, d.Namespace) && originalOwner(pod.ObjectMeta, "apps/v1", "ReplicaSet", rs.Name, rs.UID) && validOriginalPodTemplate(&pod, rs, false) {
					knownController = true
					break
				}
			}
		}
		if !knownController && selected(pod.ObjectMeta, &pod.Spec) {
			return nil, ErrQuiescence
		}
	}
	for _, job := range s.Jobs.Items {
		if selected(job.ObjectMeta, &job.Spec.Template.Spec) || selected(job.Spec.Template.ObjectMeta, &job.Spec.Template.Spec) {
			return nil, ErrQuiescence
		}
	}
	for _, item := range r.StatefulSets.Items {
		if selected(item.ObjectMeta, &item.Spec.Template.Spec) || selected(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			return nil, ErrQuiescence
		}
	}
	for _, item := range r.DaemonSets.Items {
		if selected(item.ObjectMeta, &item.Spec.Template.Spec) || selected(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			return nil, ErrQuiescence
		}
	}
	for _, item := range r.ReplicationControllers.Items {
		if selected(item.ObjectMeta, nil) || item.Spec.Template != nil && selected(item.Spec.Template.ObjectMeta, &item.Spec.Template.Spec) {
			return nil, ErrQuiescence
		}
	}
	for _, item := range r.CronJobs.Items {
		t := item.Spec.JobTemplate.Spec.Template
		if selected(item.ObjectMeta, &t.Spec) || selected(item.Spec.JobTemplate.ObjectMeta, &t.Spec) || selected(t.ObjectMeta, &t.Spec) {
			return nil, ErrQuiescence
		}
	}
	for i := range r.EndpointSlices.Items {
		item := &r.EndpointSlices.Items[i]
		related := selected(item.ObjectMeta, nil) || item.Labels[discoveryv1.LabelServiceName] == apiFamily
		for _, owner := range item.OwnerReferences {
			if w.Service != nil && owner.UID == w.Service.UID {
				related = true
			}
		}
		for _, endpoint := range item.Endpoints {
			if endpoint.TargetRef != nil && familyName(apiFamily, endpoint.TargetRef.Name) {
				related = true
			}
		}
		if !related {
			continue
		}
		if w.Service == nil || !validStoppedSlice(item, w.Service) {
			return nil, ErrQuiescence
		}
		w.Slices = append(w.Slices, *item.DeepCopy())
	}
	return w, nil
}

func validStoppedSlice(s *discoveryv1.EndpointSlice, service *corev1.Service) bool {
	if len(s.Endpoints) != 0 {
		return false
	}
	// Native endpoint reconciliation leaves a portless empty placeholder.
	// A just-drained slice can still have the original Service's HTTPS port.
	copy := s.DeepCopy()
	if len(copy.Ports) == 0 {
		copy.Ports = []discoveryv1.EndpointPort{{Name: ptr.To("https"), Protocol: ptr.To(corev1.ProtocolTCP), Port: ptr.To[int32](8443)}}
	}
	return validServingSlice(copy, service)
}

// APIStopped does not require controllers to be Ready. It does require any
// controller exception to be an original whole-template derivative of a sealed
// journal package. A failed rollout may still execute its signed predecessor;
// requiring only the new parent template would deadlock recovery before pause.
// Unreferenced packages and unknown history never authorize executable sets.
func (e *Engine) controllerRuntimeSet(rs *appsv1.ReplicaSet, d *appsv1.Deployment, journal installstate.Document) bool {
	if rs == nil || d == nil || rs.Spec.Replicas == nil || *rs.Spec.Replicas < 0 || *rs.Spec.Replicas > 1 {
		return false
	}
	copy := rs.DeepCopy()
	copy.Spec.Replicas = ptr.To[int32](0)
	copy.Status = appsv1.ReplicaSetStatus{ObservedGeneration: copy.Generation}
	if !inertReplicaSet(copy, d) {
		return false
	}
	actual := rs.Spec.Template.DeepCopy()
	delete(actual.Labels, appsv1.DefaultDeploymentUniqueLabelKey)
	if !normalizeSAAlias(&actual.Spec) {
		return false
	}
	for _, digest := range []string{journal.ActivePackage, journal.TargetPackage, journal.PreviousPackage} {
		c := e.contracts[digest]
		if c == nil {
			continue
		}
		t, err := c.Template(deploymentKey(d.Namespace, d.Name), false)
		if err != nil {
			continue
		}
		want, err := t.PodTemplate()
		if err == nil && normalizeSAAlias(&want.Spec) && apiequality.Semantic.DeepEqual(want, actual) {
			return true
		}
	}
	return false
}

func stoppedDeployment(d *appsv1.Deployment) bool {
	return d.Generation > 0 && !d.Spec.Paused && d.Spec.Replicas != nil && *d.Spec.Replicas == 0 && d.Status.ObservedGeneration == d.Generation && d.Status.Replicas == 0 && d.Status.UpdatedReplicas == 0 && d.Status.ReadyReplicas == 0 && d.Status.AvailableReplicas == 0 && d.Status.UnavailableReplicas == 0 && (d.Status.TerminatingReplicas == nil || *d.Status.TerminatingReplicas == 0)
}

// Historical templates need not belong to the bounded three-package execution
// trust set: Kubernetes retains ten revisions. They may not execute, acquire a
// new owner, or waive ColdSafety's independent worker/remount checks. On resume,
// only exact whole-template equality with the signed target authorizes a newRS.
func inertReplicaSet(rs *appsv1.ReplicaSet, d *appsv1.Deployment) bool {
	if !servingMetadata(rs.ObjectMeta, d.Namespace) || rs.Generation < 1 || !originalOwner(rs.ObjectMeta, "apps/v1", "Deployment", d.Name, d.UID) || rs.GenerateName != "" || rs.Spec.Replicas == nil || *rs.Spec.Replicas != 0 || rs.Spec.MinReadySeconds != d.Spec.MinReadySeconds || rs.Status.ObservedGeneration != rs.Generation || rs.Status.Replicas != 0 || rs.Status.FullyLabeledReplicas != 0 || rs.Status.ReadyReplicas != 0 || rs.Status.AvailableReplicas != 0 || rs.Status.TerminatingReplicas != nil && *rs.Status.TerminatingReplicas != 0 {
		return false
	}
	hash := rs.Labels[appsv1.DefaultDeploymentUniqueLabelKey]
	if hash == "" || len(hash) > 63 || len(validation.IsDNS1123Label(hash)) != 0 || rs.Name != d.Name+"-"+hash || rs.Spec.Selector == nil || d.Spec.Selector == nil || d.Spec.Selector.MatchLabels == nil {
		return false
	}
	selector := d.Spec.Selector.DeepCopy()
	selector.MatchLabels[appsv1.DefaultDeploymentUniqueLabelKey] = hash
	if !apiequality.Semantic.DeepEqual(selector, rs.Spec.Selector) || !apiequality.Semantic.DeepEqual(rs.Labels, rs.Spec.Template.Labels) {
		return false
	}
	for key, value := range selector.MatchLabels {
		if rs.Spec.Template.Labels[key] != value {
			return false
		}
	}
	meta := rs.Spec.Template.ObjectMeta.DeepCopy()
	meta.Labels, meta.Annotations = nil, nil
	if !reflect.DeepEqual(*meta, metav1.ObjectMeta{}) || len(rs.Annotations) > 5 {
		return false
	}
	revision := rs.Annotations["deployment.kubernetes.io/revision"]
	if !nativePositiveRevision(revision) {
		return false
	}
	for key, value := range rs.Annotations {
		switch key {
		case installstate.MutationAnnotation:
			if len(value) != 32 || strings.Trim(value, "0123456789abcdef") != "" {
				return false
			}
		case "deployment.kubernetes.io/revision":
		case "deployment.kubernetes.io/desired-replicas":
			if !nativeReplicaCount(value) {
				return false
			}
		case "deployment.kubernetes.io/max-replicas":
			if !nativeReplicaCount(value) {
				return false
			}
		case "deployment.kubernetes.io/revision-history":
			if !nativeRevisionHistory(value, revision) {
				return false
			}
		default:
			return false
		}
	}
	_, nonce := rs.Annotations[installstate.MutationAnnotation]
	_, desired := rs.Annotations["deployment.kubernetes.io/desired-replicas"]
	_, maximum := rs.Annotations["deployment.kubernetes.io/max-replicas"]
	return nonce && desired && maximum
}

func nativeRevisionHistory(history, revision string) bool {
	if history == "" || len(history) > 2000 {
		return false
	}
	limit, _ := strconv.ParseUint(revision, 10, 64)
	var previous uint64
	for _, part := range strings.Split(history, ",") {
		value, _ := strconv.ParseUint(part, 10, 64)
		if !nativePositiveRevision(part) || value <= previous || value >= limit {
			return false
		}
		previous = value
	}
	return true
}

func nativePositiveRevision(value string) bool {
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == value
}
func nativeReplicaCount(value string) bool {
	n, err := strconv.ParseInt(value, 10, 32)
	return err == nil && n >= 0 && strconv.FormatInt(n, 10) == value
}

func familyName(family, name string) bool {
	return name == family || strings.HasPrefix(name, family+"-")
}

// Independent redundant signals detect original descendants, orphaned/replaced
// parents, alternate builtins and renamed use of reserved identities/secrets.
// The generic part-of label is NOT enough: game workloads also carry it.
func (e *Engine) familySignal(family string, meta metav1.ObjectMeta, spec *corev1.PodSpec) bool {
	if e.familyIdentitySignal(family, meta, spec) {
		return true
	}
	if spec == nil {
		return false
	}
	imageSignal := func(image string) bool {
		for _, plan := range e.plans {
			want := plan.Manifest().Images.Controller
			if family == apiFamily {
				want = plan.Manifest().Images.API
			}
			if imageRepository(image) == imageRepository(want) {
				return true
			}
		}
		return false
	}
	for _, c := range spec.Containers {
		if imageSignal(c.Image) {
			return true
		}
	}
	for _, c := range spec.InitContainers {
		if imageSignal(c.Image) {
			return true
		}
	}
	for _, c := range spec.EphemeralContainers {
		if imageSignal(c.Image) {
			return true
		}
	}
	return false
}

func imageRepository(image string) string {
	value := strings.Split(image, "@")[0]
	if tag := strings.LastIndex(value, ":"); tag > strings.LastIndex(value, "/") {
		value = value[:tag]
	}
	return value
}

func (e *Engine) familyIdentitySignal(family string, meta metav1.ObjectMeta, spec *corev1.PodSpec) bool {
	if familyName(family, meta.Name) || familyName(family, meta.GenerateName) || meta.Labels["app.kubernetes.io/name"] == family {
		return true
	}
	for _, owner := range meta.OwnerReferences {
		if familyName(family, owner.Name) {
			return true
		}
	}
	if spec == nil {
		return false
	}
	if spec.ServiceAccountName == family || spec.DeprecatedServiceAccount == family {
		return true
	}
	secret := func(name string) bool {
		return family == apiFamily && (name == "arcadectl-api-tls" || name == "arcadectl-admin-credential")
	}
	for _, volume := range spec.Volumes {
		if volume.Secret != nil && secret(volume.Secret.SecretName) {
			return true
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil && secret(source.Secret.Name) {
					return true
				}
			}
		}
	}
	container := func(c corev1.Container) bool {
		for _, env := range c.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil && secret(env.ValueFrom.SecretKeyRef.Name) {
				return true
			}
		}
		for _, env := range c.EnvFrom {
			if env.SecretRef != nil && secret(env.SecretRef.Name) {
				return true
			}
		}
		return false
	}
	for _, c := range spec.Containers {
		if container(c) {
			return true
		}
	}
	for _, c := range spec.InitContainers {
		if container(c) {
			return true
		}
	}
	for _, c := range spec.EphemeralContainers {
		if container(corev1.Container{Image: c.Image, Env: c.Env, EnvFrom: c.EnvFrom}) {
			return true
		}
	}
	return false
}

func completeStoppedLists(s *installsafety.Snapshot, r *installsafety.RuntimeSnapshot) bool {
	// The only production input is the sealed observer, which already checks
	// object scope/UID/duplicates, exact discovery and whole pagination. Keep an
	// explicit completeness guard so no missing collection proves absence.
	if s == nil || r == nil || s.Pods == nil || s.Jobs == nil || r.Deployments == nil || r.ReplicaSets == nil || r.StatefulSets == nil || r.DaemonSets == nil || r.ReplicationControllers == nil || r.CronJobs == nil || r.EndpointSlices == nil {
		return false
	}
	for _, meta := range []metav1.ListMeta{s.Pods.ListMeta, s.Jobs.ListMeta, r.Deployments.ListMeta, r.ReplicaSets.ListMeta, r.StatefulSets.ListMeta, r.DaemonSets.ListMeta, r.ReplicationControllers.ListMeta, r.CronJobs.ListMeta, r.EndpointSlices.ListMeta} {
		if meta.ResourceVersion == "" || meta.Continue != "" || meta.RemainingItemCount != nil && *meta.RemainingItemCount != 0 {
			return false
		}
	}
	return true
}

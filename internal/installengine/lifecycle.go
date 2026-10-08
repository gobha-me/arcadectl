// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/gobha-me/arcadectl/internal/adminauth"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

var ErrLifecycle = errors.New("installation lifecycle barrier is unproved")

// Checkpoint identifies a fixed proof obligation, not an executable command or
// user-selected probe. Implementations are trusted internal instrumentation.
type Checkpoint uint8

const (
	// Prerequisites includes exact version/discovery, permissions, protected TLS
	// inputs and native-forwarding capability, before any resource effect.
	Prerequisites Checkpoint = iota + 1
	// CRDsAvailable includes establishment/storage checks AND served discovery.
	CRDsAvailable
	// AdmissionEffective requires current policy status and behavioral denials;
	// merely observing the signed policy specifications is insufficient.
	AdmissionEffective
	// ColdSafety requires complete uncached domain/worker/fence/mount and GC
	// closure observations, correlated with this exact original journal.
	ColdSafety
	// APIStopped requires complete Pod/ReplicaSet/EndpointSlice evidence, not
	// only a missing Deployment. Controllers may still be running at this point.
	APIStopped
	// RuntimeStopped additionally proves both paused controllers and absence
	// of their executable descendants; deleting/terminal Pods are not skipped.
	RuntimeStopped
	// ControllersAvailable proves actual original target controller readiness.
	ControllersAvailable
	// TargetAuthenticated uses original-Pod native forwarding and the protected
	// credential/CA files to run Activation.VerifyForwarded, not a health GET.
	TargetAuthenticated
	// AdmissionConfigured proves all original signed policies/bindings and
	// current healthy type-checking, but NOT behavior. Install may create only
	// its signed ServiceAccounts behind this barrier, providing the original
	// non-executable identity needed by native Pod behavioral probes. Signed
	// RBAC needs BootstrapAdmission; Service, new Secrets and workloads still
	// require AdmissionEffective.
	AdmissionConfigured
	// RetainedAdmission is administrator read-only verification of unchanged
	// original protections and durable pre-retirement behavioral evidence.
	// It is uninstall-only, not a substitute for live AdmissionEffective.
	RetainedAdmission
	// BootstrapAdmission proves current original protections, admin paired
	// CREATE behavior, all original signed accounts, complete namespace runtime
	// absence and cold worlds. Only Install/Applying may use it, solely to
	// create its original signed RBAC before full identity-specific proof.
	// It grants no temporary verifier permissions and never starts a workload.
	BootstrapAdmission
)

// LifecycleChecks is an internal proof-provider seam. It MUST NOT be populated
// from caller flags, callbacks in configuration, or shell exit statuses. The
// production provider must perform every obligation above; no permissive
// provider or automatic fallback is provided here. These checks are temporal
// observations, not distributed locks. They are repeated across effect edges.
type LifecycleChecks interface {
	Check(context.Context, LifecycleCheck) error
}

// LifecycleCheck keeps original sealed evidence separate from the requested
// operation. During Begin, Snapshot is the previous Complete journal, while
// Mode/Target describe the next operation and its authenticated target plan.
type LifecycleCheck struct {
	Checkpoint Checkpoint
	Snapshot   *installstate.Snapshot
	Mode       installstate.Mode
	Target     *installrender.Plan
	Options    LifecycleOptions
}

// Lifecycle coordinates the existing sealed journal, public effects and private
// Secret workflow. It does not bootstrap a namespace or load unsigned plans.
// Step performs at most one public/private effect OR one stage transition.
// Callers own a bounded context and reload after every returned step/error.
type Lifecycle struct {
	engine  *Engine
	secrets *SecretWorkflow
	checks  LifecycleChecks
}

type LifecycleOptions struct {
	Now         time.Time
	Credentials CredentialOptions
	Activation  ActivationOptions
}

func NewLifecycleWithChecks(e *Engine, secrets *SecretWorkflow, checks LifecycleChecks) (*Lifecycle, error) {
	if e == nil || secrets == nil || secrets.engine != e || nilAccess(checks) {
		return nil, ErrInvalid
	}
	return &Lifecycle{engine: e, secrets: secrets, checks: checks}, nil
}

// original also supports completed uninstall/upgrade snapshots, for which the
// mutation engine's in-flight compatibility predicate deliberately is false.
func (l *Lifecycle) original(ctx context.Context, s *installstate.Snapshot) (*installstate.Snapshot, error) {
	if l == nil || ctx == nil || s == nil {
		return nil, ErrInvalid
	}
	if err := l.engine.fixtureFence(s); err != nil {
		return nil, err
	}
	fresh, err := l.engine.journal.Load(ctx, s.Anchor())
	if err != nil {
		return nil, ErrOwnership
	}
	if fresh.ResourceVersion() != s.ResourceVersion() || !bytes.Equal(fresh.Bytes(), s.Bytes()) {
		return nil, ErrConcurrent
	}
	d := fresh.Document()
	c := l.engine.contracts[d.TargetPackage]
	if c == nil {
		return nil, ErrInvalid
	}
	t, err := c.Template(namespaceKey(d.Namespace), false)
	live, readErr := l.engine.access.Get(ctx, namespaceKey(d.Namespace))
	if err != nil || readErr != nil || t.MatchNamespace(live, fresh) != nil {
		return nil, ErrOwnership
	}
	return fresh, nil
}

// Begin starts only from Complete, preserving all original identities. It does
// not switch an interrupted operation into a rollback or rewrite its target.
// Fresh namespace bootstrap already binds an Install/Preparing journal.
func (l *Lifecycle) Begin(ctx context.Context, s *installstate.Snapshot, mode installstate.Mode, target string, opts LifecycleOptions) (*installstate.Snapshot, error) {
	fresh, err := l.original(ctx, s)
	if err != nil {
		return s, err
	}
	d := fresh.Document()
	if d.Stage != installstate.Complete || d.Pending != nil || opts.Now.IsZero() {
		return fresh, ErrInvalid
	}
	d.Mode, d.TargetPackage, d.Stage = mode, target, installstate.Preparing
	d.AdmissionRetirementRevision = 0
	if !l.engine.compatible(d) || mode == installstate.Install && d.Installed || mode != installstate.Install && !d.Installed {
		return fresh, ErrInvalid
	}
	if err := l.checkOperation(ctx, Prerequisites, fresh, mode, target, opts); err != nil {
		return fresh, err
	}
	// Current inventory must be intact before even recording a new operation.
	if err := l.inventory(ctx, fresh, true, false); err != nil {
		return fresh, err
	}
	if _, err := l.original(ctx, fresh); err != nil {
		return fresh, err
	}
	d.Revision++
	return l.engine.journal.Commit(ctx, fresh, d)
}

func (l *Lifecycle) check(ctx context.Context, kind Checkpoint, s *installstate.Snapshot, opts LifecycleOptions) error {
	d := s.Document()
	return l.checkOperation(ctx, kind, s, d.Mode, d.TargetPackage, opts)
}

func (l *Lifecycle) checkOperation(ctx context.Context, kind Checkpoint, s *installstate.Snapshot, mode installstate.Mode, target string, opts LifecycleOptions) (resultErr error) {
	traceLifecycleCheckpoint(ctx, kind, lifecycleDiagnosticEntered)
	defer func() {
		state := lifecycleDiagnosticRefused
		if resultErr == nil {
			state = lifecycleDiagnosticPassed
		}
		traceLifecycleCheckpoint(ctx, kind, state)
	}()
	plan := l.engine.plans[target]
	if plan == nil {
		return ErrInvalid
	}
	if kind == RetainedAdmission && (mode != installstate.Uninstall || l.engine.verifyRetiredAdmission(ctx, s) != nil) {
		return ErrLifecycle
	}
	var bootstrapWitness map[installstate.Key]admissionIdentity
	if kind == BootstrapAdmission {
		if mode != installstate.Install {
			return ErrLifecycle
		}
		var err error
		bootstrapWitness, err = l.engine.bootstrapAccess(ctx, s)
		if err != nil {
			return ErrLifecycle
		}
		if s.Document().ActivePackage != "" && l.secrets.VerifyRetained(ctx, s, opts.Activation.CAFile, opts.Now) != nil {
			return ErrLifecycle
		}
	}
	if err := l.checks.Check(ctx, LifecycleCheck{kind, s, mode, plan, opts}); err != nil {
		return ErrLifecycle // never expose provider/cluster/private-file details
	}
	if kind == RetainedAdmission && l.engine.verifyRetiredAdmission(ctx, s) != nil {
		return ErrLifecycle
	}
	if kind == BootstrapAdmission {
		current, err := l.engine.bootstrapAccess(ctx, s)
		if err != nil || !reflect.DeepEqual(bootstrapWitness, current) {
			return ErrLifecycle
		}
		if s.Document().ActivePackage != "" && l.secrets.VerifyRetained(ctx, s, opts.Activation.CAFile, opts.Now) != nil {
			return ErrLifecycle
		}
	}
	_, err := l.original(ctx, s)
	return err
}

func uninstallAdmissionCheckpoint(d installstate.Document) Checkpoint {
	if d.Mode == installstate.Uninstall && d.AdmissionRetirementRevision != 0 {
		return RetainedAdmission
	}
	return AdmissionEffective
}

func (l *Lifecycle) stage(ctx context.Context, s *installstate.Snapshot, stage installstate.Stage) (*installstate.Snapshot, error) {
	if _, err := l.original(ctx, s); err != nil {
		return s, err
	}
	d := s.Document()
	d.Revision++
	d.Stage = stage
	if stage == installstate.Complete {
		if d.ActivePackage != "" && d.ActivePackage != d.TargetPackage {
			d.PreviousPackage = d.ActivePackage
		}
		d.ActivePackage, d.Installed = d.TargetPackage, d.Mode != installstate.Uninstall
	}
	return l.engine.journal.Commit(ctx, s, d)
}

// inventory proves every recorded public object's original live shape. Mixed
// active/target and paused hashes are intentional during interrupted upgrades.
// complete additionally requires every target-ready hash and exact key set.
func (l *Lifecycle) inventory(ctx context.Context, s *installstate.Snapshot, crds, complete bool) error {
	d := s.Document()
	target := l.engine.contracts[d.TargetPackage]
	if target == nil {
		return ErrInvalid
	}
	for _, r := range d.Resources {
		if r.Key.Kind == "Secret" {
			continue // private workflow verifies these without public content hashes
		}
		_, t := l.engine.inventory(d, r.Key)
		want, err := target.Template(r.Key, false)
		if t == nil || err != nil || complete && r.TemplateSHA256 != want.Hash() {
			return ErrOwnership
		}
		live, err := l.engine.access.Get(ctx, r.Key)
		if err != nil {
			return ErrOwnership
		}
		if r.Key.Kind == "Namespace" {
			err = t.MatchNamespace(live, s)
		} else {
			err = t.MatchLive(live, r.UID)
		}
		if err != nil || crds && r.Key.Kind == "CustomResourceDefinition" && t.CheckCRD(live, r.UID, want) != nil {
			return ErrOwnership
		}
		if complete && r.Key.Kind == "Deployment" {
			var deployment appsv1.Deployment
			if decodeServing(live, &deployment) != nil || !availableInstallationDeployment(&deployment) {
				return ErrLifecycle
			}
		}
	}
	if complete {
		for _, r := range l.engine.plans[d.TargetPackage].Resources() {
			key := resourceKey(r)
			entry, _ := l.engine.inventory(d, key)
			if d.Mode == installstate.Uninstall && !r.Retained {
				if entry != nil {
					return ErrOwnership
				}
				if _, err := l.engine.access.Get(ctx, key); !apierrors.IsNotFound(err) {
					return ErrOwnership
				}
			} else if entry == nil {
				return ErrOwnership
			}
		}
		for _, name := range []string{adminauth.CredentialSecretName, "arcadectl-api-tls"} {
			if r, _ := l.engine.inventory(d, secretKey(d.Namespace, name)); r == nil {
				return ErrOwnership
			}
		}
	}
	_, err := l.original(ctx, s)
	return err
}

// Whole signed shape validation above already constrains each strategy. The
// controllers use reviewed RollingUpdate defaults; the API uses Recreate.
func availableInstallationDeployment(d *appsv1.Deployment) bool {
	return d.Generation > 0 && d.Spec.Replicas != nil && *d.Spec.Replicas == 1 && d.Status.ObservedGeneration == d.Generation && d.Status.Replicas == 1 && d.Status.UpdatedReplicas == 1 && d.Status.ReadyReplicas == 1 && d.Status.AvailableReplicas == 1 && d.Status.UnavailableReplicas == 0 && (d.Status.TerminatingReplicas == nil || *d.Status.TerminatingReplicas == 0)
}

func resourceKey(r installrender.Resource) installstate.Key {
	o := r.Object
	return installstate.Key{APIVersion: o.GetAPIVersion(), Kind: o.GetKind(), Namespace: o.GetNamespace(), Name: o.GetName()}
}

// ordered breaks YAML-file ordering into actual dependency barriers. In
// particular ALL policies precede ALL bindings and no Deployment can start
// while admission is still being installed.
func (l *Lifecycle) ordered(d installstate.Document) []installstate.Key {
	var keys []installstate.Key
	for _, r := range l.engine.plans[d.TargetPackage].Resources() {
		if r.Object.GetKind() != "Namespace" {
			keys = append(keys, resourceKey(r))
		}
	}
	slices.SortFunc(keys, func(a, b installstate.Key) int {
		if diff := installRank(a) - installRank(b); diff != 0 {
			return diff
		}
		if installRank(a) == 3 && (a.Kind == "ServiceAccount") != (b.Kind == "ServiceAccount") {
			if a.Kind == "ServiceAccount" {
				return -1
			}
			return 1
		}
		if a.Kind != b.Kind {
			return bytes.Compare([]byte(a.Kind), []byte(b.Kind))
		}
		return bytes.Compare([]byte(a.Name), []byte(b.Name))
	})
	return keys
}

func installRank(k installstate.Key) int {
	switch k.Kind {
	case "CustomResourceDefinition":
		return 0
	case "ValidatingAdmissionPolicy":
		return 1
	case "ValidatingAdmissionPolicyBinding":
		return 2
	case "Deployment":
		if k.Name == "arcadectl-api" {
			return 5
		}
		return 4
	default:
		return 3
	}
}

// Step never retries a pending effect, even if the desired target is missing.
// Recovery is a distinct observation-only step and does not fall through into
// another mutation. Failures leave the same stage/intent for explicit resume.
func (l *Lifecycle) Step(ctx context.Context, s *installstate.Snapshot, opts LifecycleOptions) (*installstate.Snapshot, error) {
	fresh, err := l.original(ctx, s)
	if err != nil {
		return s, err
	}
	d := fresh.Document()
	if d.Stage == installstate.Complete || opts.Now.IsZero() || !l.engine.compatible(d) {
		return fresh, ErrInvalid
	}
	if d.Pending != nil {
		if d.AdmissionRetirementRevision != 0 {
			for _, kind := range []Checkpoint{RetainedAdmission, ColdSafety, RuntimeStopped} {
				if err := l.check(ctx, kind, fresh, opts); err != nil {
					return fresh, err
				}
			}
			if err := l.secrets.VerifyRetained(ctx, fresh, opts.Activation.CAFile, opts.Now); err != nil {
				return fresh, err
			}
		}
		if d.Pending.Key.Kind != "Secret" {
			return l.engine.Recover(ctx, fresh)
		}
		c, err := l.engine.LoadCredentials(ctx, fresh, opts.Now)
		if err != nil {
			return fresh, err
		}
		return l.secrets.Recover(ctx, fresh, c, opts.Now)
	}
	// A new invocation can resume directly in Applying/Quiescing. Recheck the
	// live capabilities before every non-pending step, not only at initial start.
	if err := l.check(ctx, Prerequisites, fresh, opts); err != nil {
		return fresh, err
	}
	if err := l.inventory(ctx, fresh, d.Mode != installstate.Install, false); err != nil {
		return fresh, err
	}
	switch d.Stage {
	case installstate.Preparing, installstate.RecoveryRequired:
		if d.Mode == installstate.Install {
			if d.ActivePackage != "" {
				if err := l.secrets.VerifyRetained(ctx, fresh, opts.Activation.CAFile, opts.Now); err != nil {
					return fresh, err
				}
			}
			return l.stage(ctx, fresh, installstate.Applying)
		}
		if err := l.secrets.VerifyRetained(ctx, fresh, opts.Activation.CAFile, opts.Now); err != nil {
			return fresh, err
		}
		if err := l.check(ctx, uninstallAdmissionCheckpoint(d), fresh, opts); err != nil {
			return fresh, err
		}
		return l.stage(ctx, fresh, installstate.Quiescing)
	case installstate.Quiescing:
		return l.quiesce(ctx, fresh, opts)
	case installstate.Applying:
		if d.Mode == installstate.Uninstall {
			return l.uninstall(ctx, fresh, opts)
		}
		return l.apply(ctx, fresh, opts)
	case installstate.Verifying:
		if d.Mode == installstate.Uninstall {
			if d.AdmissionRetirementRevision == 0 {
				return fresh, ErrLifecycle
			}
			for _, kind := range []Checkpoint{RetainedAdmission, ColdSafety, RuntimeStopped} {
				if err := l.check(ctx, kind, fresh, opts); err != nil {
					return fresh, err
				}
			}
		} else {
			for _, kind := range []Checkpoint{CRDsAvailable, AdmissionEffective, ControllersAvailable, TargetAuthenticated} {
				if err := l.check(ctx, kind, fresh, opts); err != nil {
					return fresh, err
				}
			}
		}
		if err := l.inventory(ctx, fresh, true, true); err != nil {
			return fresh, err
		}
		if err := l.secrets.VerifyRetained(ctx, fresh, opts.Activation.CAFile, opts.Now); err != nil {
			return fresh, err
		}
		return l.stage(ctx, fresh, installstate.Complete)
	}
	return fresh, ErrInvalid
}

func (l *Lifecycle) quiesce(ctx context.Context, s *installstate.Snapshot, opts LifecycleOptions) (*installstate.Snapshot, error) {
	d := s.Document()
	for _, kind := range []Checkpoint{uninstallAdmissionCheckpoint(d), ColdSafety} {
		if err := l.check(ctx, kind, s, opts); err != nil {
			return s, err
		}
	}
	api := installstate.Key{APIVersion: "apps/v1", Kind: "Deployment", Namespace: d.Namespace, Name: "arcadectl-api"}
	if r, _ := l.engine.inventory(d, api); r != nil {
		return l.engine.delete(ctx, s, api, true)
	}
	if err := l.check(ctx, APIStopped, s, opts); err != nil {
		return s, err
	}
	for _, key := range l.ordered(d) {
		if key.Kind != "Deployment" || key == api {
			continue
		}
		t, err := l.engine.contracts[d.ActivePackage].Template(key, true)
		r, _ := l.engine.inventory(d, key)
		if err != nil {
			return s, ErrOwnership
		}
		if r == nil {
			// Retaining uninstall may already have foreground-deleted one or
			// both controllers before entering RecoveryRequired. Observe their
			// absence; never recreate them or adopt a same-name replacement.
			if d.Mode != installstate.Uninstall {
				return s, ErrOwnership
			}
			if _, err := l.engine.access.Get(ctx, key); !apierrors.IsNotFound(err) {
				return s, ErrOwnership
			}
			continue
		}
		if r.TemplateSHA256 != t.Hash() {
			return l.engine.Apply(ctx, s, key, d.ActivePackage, true)
		}
	}
	if err := l.check(ctx, RuntimeStopped, s, opts); err != nil {
		return s, err
	}
	if err := l.check(ctx, ColdSafety, s, opts); err != nil {
		return s, err
	}
	return l.stage(ctx, s, installstate.Applying)
}

func (l *Lifecycle) apply(ctx context.Context, s *installstate.Snapshot, opts LifecycleOptions) (*installstate.Snapshot, error) {
	d := s.Document()
	if d.Mode != installstate.Install {
		for _, kind := range []Checkpoint{AdmissionEffective, ColdSafety} {
			if err := l.check(ctx, kind, s, opts); err != nil {
				return s, err
			}
		}
		api := installstate.Key{APIVersion: "apps/v1", Kind: "Deployment", Namespace: d.Namespace, Name: "arcadectl-api"}
		if r, _ := l.engine.inventory(d, api); r == nil {
			if err := l.check(ctx, APIStopped, s, opts); err != nil {
				return s, err
			}
		}
	}
	for _, key := range l.ordered(d) {
		rank := installRank(key)
		want, err := l.engine.contracts[d.TargetPackage].Template(key, false)
		r, _ := l.engine.inventory(d, key)
		if err != nil {
			return s, ErrInvalid
		}
		if r != nil && r.TemplateSHA256 == want.Hash() {
			continue // inventory() has already checked its live original shape
		}
		if rank > 0 {
			if err := l.check(ctx, CRDsAvailable, s, opts); err != nil {
				return s, err
			}
		}
		if rank >= 3 {
			gate := AdmissionEffective
			if d.Mode == installstate.Install && key.Kind == "ServiceAccount" {
				gate = AdmissionConfigured // fresh AND retaining reinstall
			} else if d.Mode == installstate.Install && bootstrapRBACKey(key) {
				gate = BootstrapAdmission
			}
			if err := l.check(ctx, gate, s, opts); err != nil {
				return s, err
			}
		}
		if rank >= 4 {
			if next, done, err := l.ensureSecrets(ctx, s, opts); err != nil || !done {
				return next, err
			}
		}
		if rank == 5 {
			if err := l.check(ctx, ControllersAvailable, s, opts); err != nil {
				return s, err
			}
		}
		// Before the first controller restarts, require the whole cold runtime
		// proof again. Subsequent controller starts remain admission/cold gated.
		if d.Mode != installstate.Install && rank <= 4 && !l.controllersRestoring(d) {
			if err := l.check(ctx, RuntimeStopped, s, opts); err != nil {
				return s, err
			}
		}
		return l.engine.Apply(ctx, s, key, d.TargetPackage, false)
	}
	return l.stage(ctx, s, installstate.Verifying)
}

func (l *Lifecycle) controllersRestoring(d installstate.Document) bool {
	for _, key := range l.ordered(d) {
		if installRank(key) != 4 {
			continue
		}
		t, err := l.engine.contracts[d.TargetPackage].Template(key, false)
		r, _ := l.engine.inventory(d, key)
		if err == nil && r != nil && r.TemplateSHA256 == t.Hash() {
			return true
		}
	}
	return false
}

func (l *Lifecycle) ensureSecrets(ctx context.Context, s *installstate.Snapshot, opts LifecycleOptions) (*installstate.Snapshot, bool, error) {
	d := s.Document()
	names := []string{adminauth.CredentialSecretName, "arcadectl-api-tls"}
	var missing []string
	for _, name := range names {
		if r, _ := l.engine.inventory(d, secretKey(d.Namespace, name)); r == nil {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		err := l.secrets.VerifyRetained(ctx, s, opts.Activation.CAFile, opts.Now)
		return s, true, err
	}
	if d.Mode != installstate.Install || d.ActivePackage != "" {
		return s, false, ErrOwnership // never regenerate retained credentials
	}
	c, err := l.engine.LoadCredentials(ctx, s, opts.Now)
	if err != nil {
		// Only proven private NotFound, with neither Secret recorded, permits
		// initial generation. Corrupt/expired/replaced files are not absence.
		_, _, readErr := l.engine.files.Read(credentialName(s.Anchor()), 65536)
		if len(missing) != 2 || !errors.Is(readErr, privatefs.ErrNotFound) {
			return s, false, ErrCredentials
		}
		credentialOpts := opts.Credentials
		credentialOpts.Now = opts.Now
		c, err = l.engine.PrepareCredentials(ctx, s, credentialOpts)
		if err != nil {
			return s, false, err
		}
	}
	next, err := l.secrets.Create(ctx, s, c, missing[0], opts.Now)
	return next, false, err
}

func deleteRank(k installstate.Key) int {
	switch k.Kind {
	case "Deployment":
		return 0
	case "Service":
		return 1
	case "RoleBinding", "ClusterRoleBinding":
		return 2
	case "Role", "ClusterRole":
		return 3
	case "ServiceAccount":
		return 4
	}
	return 5
}

func (l *Lifecycle) uninstall(ctx context.Context, s *installstate.Snapshot, opts LifecycleOptions) (*installstate.Snapshot, error) {
	for _, kind := range []Checkpoint{uninstallAdmissionCheckpoint(s.Document()), ColdSafety, RuntimeStopped} {
		if err := l.check(ctx, kind, s, opts); err != nil {
			return s, err
		}
	}
	if err := l.secrets.VerifyRetained(ctx, s, opts.Activation.CAFile, opts.Now); err != nil {
		return s, err
	}
	var runtime []installstate.Resource
	for _, r := range s.Document().Resources {
		if !r.Retained {
			runtime = append(runtime, r)
		}
	}
	slices.SortFunc(runtime, func(a, b installstate.Resource) int {
		if diff := deleteRank(a.Key) - deleteRank(b.Key); diff != 0 {
			return diff
		}
		if a.Key.Kind != b.Key.Kind {
			return bytes.Compare([]byte(a.Key.Kind), []byte(b.Key.Kind))
		}
		return bytes.Compare([]byte(a.Key.Name), []byte(b.Key.Name))
	})
	if len(runtime) == 0 {
		if s.Document().AdmissionRetirementRevision == 0 {
			return s, ErrLifecycle
		}
		return l.stage(ctx, s, installstate.Verifying)
	}
	if accessRetirementKey(runtime[0].Key) && s.Document().AdmissionRetirementRevision == 0 {
		return l.retireAdmission(ctx, s, opts)
	}
	return l.engine.delete(ctx, s, runtime[0].Key, true)
}

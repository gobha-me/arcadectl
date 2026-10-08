// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/gobha-me/arcadectl/internal/installengine"
	"github.com/gobha-me/arcadectl/internal/installfiles"
	"github.com/gobha-me/arcadectl/internal/installrender"
	"github.com/gobha-me/arcadectl/internal/installstate"
	"github.com/gobha-me/arcadectl/internal/privatefs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func validMutationOptions(o options) bool {
	if !absolutePath(o.apiCA) || o.clientCredential != "" && !absolutePath(o.clientCredential) {
		return false
	}
	if o.command == "install" {
		if !absolutePath(o.apiCertificate) || !absolutePath(o.apiKey) {
			return false
		}
	} else if o.apiCertificate != "" || o.apiKey != "" {
		// Explicit resume may need original initial TLS inputs before a private
		// candidate exists; it never regenerates a missing used candidate.
		if o.command != "resume" || !absolutePath(o.apiCertificate) || !absolutePath(o.apiKey) {
			return false
		}
	}
	if o.command == "install" || o.command == "upgrade" || o.command == "rollback" {
		if !absolutePath(o.targetPackage) {
			return false
		}
		found := false
		for _, path := range o.packages {
			found = found || path == o.targetPackage
		}
		return found
	}
	return o.targetPackage == "" // resume/uninstall cannot retarget the journal
}

type mutationInstallation struct {
	files               *privatefs.Store
	access              *installengine.HTTPAccess
	engine              *installengine.Engine
	journal             *installstate.Store
	lifecycle           *installengine.Lifecycle
	original            *installrender.Plan
	target              *installrender.Plan
	bootstrapRegistered bool
	registeredBootstrap *installrender.Plan
}

// All plans are independently signed/trusted. NewClusterLifecycle supplies the
// closed production checks; this boundary accepts no provider/callback/URL.
func loadMutationInstallation(o options) (*mutationInstallation, error) {
	trust, err := installfiles.ReadTrustKey(o.trustKey)
	if err != nil {
		return nil, errInputs
	}
	bootstrap, err := installfiles.Load(o.bootstrapPackage, trust)
	if err != nil {
		return nil, errInputs
	}
	original, err := installrender.Compile(bootstrap, o.namespace, o.profile)
	if err != nil {
		return nil, errInputs
	}
	plans := []*installrender.Plan{}
	var target *installrender.Plan
	bootstrapRegistered := false
	var registeredBootstrap *installrender.Plan
	for _, path := range o.packages {
		pkg, err := installfiles.Load(path, trust)
		if err != nil {
			return nil, errInputs
		}
		plan, err := installrender.Compile(pkg, o.namespace, o.profile)
		if err != nil {
			return nil, errInputs
		}
		plans = append(plans, plan)
		bootstrapRegistered = bootstrapRegistered || plan.Digest() == original.Digest()
		if plan.Digest() == original.Digest() {
			registeredBootstrap = plan
		}
		if path == o.targetPackage {
			target = plan
		}
	}
	configuration, err := loadStaticConfig(o)
	if err != nil {
		return nil, errInputs
	}
	access, err := installengine.NewDirectHTTPAccess(configuration)
	if err != nil {
		return nil, errInputs
	}
	files, err := privatefs.Open(o.stateDir, false)
	if err != nil {
		return nil, errInputs
	}
	fail := func() (*mutationInstallation, error) {
		_ = files.Close()
		return nil, errInputs
	}
	journal, err := installstate.New(access.Namespaces(), plans...)
	if err != nil {
		return fail()
	}
	engine, err := installengine.NewWithAccess(access, journal, files, plans...)
	if err != nil {
		return fail()
	}
	lifecycle, err := installengine.NewClusterLifecycle(engine, access)
	if err != nil {
		return fail()
	}
	return &mutationInstallation{files: files, access: access, engine: engine, journal: journal, lifecycle: lifecycle, original: original, target: target, bootstrapRegistered: bootstrapRegistered, registeredBootstrap: registeredBootstrap}, nil
}

func mutationLifecycleOptions(o options, s *installstate.Snapshot) installengine.LifecycleOptions {
	client := o.clientCredential
	if client == "" && s != nil {
		client = filepath.Join(o.stateDir, "admin-client-"+s.Anchor().InstallationID+".json")
	}
	now := time.Now().UTC()
	return installengine.LifecycleOptions{Now: now,
		Credentials: installengine.CredentialOptions{Now: now, AdminLifetime: 24 * time.Hour, CertificateFile: o.apiCertificate, KeyFile: o.apiKey, CAFile: o.apiCA},
		Activation:  installengine.ActivationOptions{CredentialFile: client, CAFile: o.apiCA},
	}
}

func (x *mutationInstallation) start(ctx context.Context, o options) (*installstate.Snapshot, error) {
	_, _, readErr := x.files.Read(o.receipt, installstate.MaxBytes)
	if errors.Is(readErr, privatefs.ErrNotFound) {
		if o.command != "install" || x.target == nil || x.target.Digest() != x.original.Digest() || o.clientCredential != "" {
			return nil, installengine.ErrInvalid
		}
		prerequisites, err := installengine.NewClusterPrerequisites(x.engine, x.access)
		if err != nil || prerequisites.VerifyBootstrap(ctx, x.target, mutationLifecycleOptions(o, nil)) != nil {
			return nil, installengine.ErrPrerequisites
		}
		receipt, err := installstate.PrepareBootstrap(x.files, o.receipt, x.original)
		if err != nil {
			return nil, err
		}
		return receipt.EnsureNamespace(ctx, x.access.Namespaces())
	}
	if readErr != nil {
		return nil, installengine.ErrRecovery
	}
	receipt, err := installstate.LoadBootstrap(x.files, o.receipt, x.original)
	if err != nil {
		return nil, err
	}
	anchor, err := receipt.PinnedAnchor(ctx)
	if err != nil {
		// Only the original bootstrap method can settle its own saved intent.
		// It does not replay unknown CREATE or adopt matching names/nonces.
		if o.command != "resume" || !x.bootstrapRegistered || o.clientCredential != "" {
			return nil, installengine.ErrRecovery
		}
		prerequisites, err := installengine.NewClusterPrerequisites(x.engine, x.access)
		if err != nil || prerequisites.VerifyBootstrap(ctx, x.registeredBootstrap, mutationLifecycleOptions(o, nil)) != nil {
			return nil, installengine.ErrPrerequisites
		}
		return receipt.EnsureNamespace(ctx, x.access.Namespaces())
	}
	s, err := x.journal.Load(ctx, anchor)
	if err != nil {
		// Only an original ACK-pinned namespace with NO journal can finish
		// bootstrap binding. Never call the one-plan helper on an upgraded,
		// malformed or foreign existing journal.
		if o.command == "resume" && x.bootstrapRegistered {
			live, readErr := x.access.Namespaces().Get(ctx, anchor.Namespace, metav1.GetOptions{})
			if readErr == nil && live.UID == anchor.UID && live.Annotations[installstate.Annotation] == "" {
				return receipt.EnsureNamespace(ctx, x.access.Namespaces())
			}
		}
		return nil, err
	}
	d := s.Document()
	if o.command == "resume" {
		if d.Stage == installstate.Complete {
			return nil, installengine.ErrInvalid
		}
		return s, nil
	}
	if d.Stage != installstate.Complete {
		return nil, installengine.ErrInvalid // never retarget an interrupted run
	}
	mode := installstate.Uninstall
	target := d.TargetPackage
	if o.command != "uninstall" {
		if x.target == nil {
			return nil, installengine.ErrInvalid
		}
		target = x.target.Digest()
		switch o.command {
		case "install":
			mode = installstate.Install
		case "upgrade":
			mode = installstate.Upgrade
		case "rollback":
			mode = installstate.Rollback
		default:
			return nil, installengine.ErrInvalid
		}
	}
	return x.lifecycle.Begin(ctx, s, mode, target, mutationLifecycleOptions(o, s))
}

func runMutation(ctx context.Context, o options, stdout, stderr io.Writer) int {
	x, err := loadMutationInstallation(o)
	if err != nil {
		_, _ = io.WriteString(stderr, errInputs.Error()+"\n")
		return 3
	}
	defer x.files.Close()
	s, err := x.start(ctx, o)
	if err != nil {
		_, _ = io.WriteString(stderr, "installation start refused; inspect protected original evidence before resume\n")
		return 4
	}
	if o.command == "resume" && x.lifecycle.ResumeFixtures(ctx, s, mutationLifecycleOptions(o, s)) != nil {
		_, _ = io.WriteString(stderr, "original fixture recovery refused; inspect protected evidence; no uncertain effect was replayed\n")
		return 4
	}
	// Finite steps plus a bounded outer context. A failed Step is NEVER retried
	// here: uncertain effects require explicit observation-only recovery/resume.
	for step := 0; step < 512 && ctx.Err() == nil; step++ {
		if s.Document().Stage == installstate.Complete {
			message := "installation lifecycle complete; protected client credentials remain in the state directory\n"
			if s.Document().Mode == installstate.Uninstall {
				message = "installation removed; namespace, world claims, credentials and protections retained; use inspect for recovery guidance; destroy is a separate operation\n"
			}
			if n, err := io.WriteString(stdout, message); err != nil || n != len(message) {
				return 1
			}
			return 0
		}
		if _, err := fmt.Fprintf(stdout, "installation stage %s revision %d\n", s.Document().Stage, s.Document().Revision); err != nil {
			return 1
		}
		s, err = x.lifecycle.Step(ctx, s, mutationLifecycleOptions(o, s))
		if err != nil || s == nil {
			_, _ = io.WriteString(stderr, "installation stopped at a protected checkpoint; inspect before explicit resume; no failed effect was retried\n")
			return 4
		}
	}
	_, _ = io.WriteString(stderr, "installation operation bound reached; inspect before explicit resume\n")
	return 4
}

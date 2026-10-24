// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"sync"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type baselineProbeSuiteKey struct{}

// Private authority for nonpersistent probes inside ONE behavioral proof,
// never an effect permit or reusable successful baseline. The invocation owns
// the fresh global opening/closing witnesses. Each probe still reviews its
// exact operation and both complete containment catalogs, without caching.
type baselineProbeSuite struct {
	mu       sync.Mutex
	actors   *baselineActors
	baseline *ClusterSecurityBaseline
	snapshot *installstate.Snapshot
	root     context.Context
	cancel   context.CancelFunc
	busy     chan struct{}
	closed   bool
	poisoned bool
}

// Called only by prove after its successful full opening verification. A new
// child context and private value prevent transfer to another invocation.
func newBaselineProbeSuite(ctx context.Context, actors *baselineActors) (context.Context, *baselineProbeSuite, error) {
	if ctx == nil || ctx.Err() != nil || ctx.Value(baselineProbeSuiteKey{}) != nil || actors == nil || actors.baseline == nil || actors.snapshot == nil {
		return nil, nil, ErrSecurityBaseline
	}
	root, cancel := context.WithCancel(ctx)
	suite := &baselineProbeSuite{actors: actors, baseline: actors.baseline, snapshot: actors.snapshot, root: root, cancel: cancel}
	return context.WithValue(root, baselineProbeSuiteKey{}, suite), suite, nil
}

func (s *baselineProbeSuite) bound(ctx context.Context, actors *baselineActors) bool {
	return ctx != nil && ctx.Err() == nil && ctx.Value(baselineProbeSuiteKey{}) == s && s.root != nil && s.root.Err() == nil &&
		actors != nil && actors == s.actors && actors.baseline == s.baseline && actors.snapshot == s.snapshot
}

func (s *baselineProbeSuite) begin(ctx context.Context, actors *baselineActors) error {
	if s == nil {
		return ErrSecurityBaseline
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Entry belongs to the invocation's own cancellation channel, not a
	// transplanted private value or WithoutCancel context. The probe creates
	// its narrower deadline only AFTER this lease is acquired.
	if s.closed || s.poisoned || s.busy != nil || !s.bound(ctx, actors) || ctx.Done() != s.root.Done() {
		s.closed, s.poisoned = true, true
		if s.cancel != nil {
			s.cancel()
		}
		return ErrSecurityBaseline
	}
	s.busy = make(chan struct{})
	return nil
}

func (s *baselineProbeSuite) current(ctx context.Context, actors *baselineActors) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.poisoned && s.busy != nil && s.bound(ctx, actors)
}

func (s *baselineProbeSuite) finish(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || s.closed || s.poisoned || s.root.Err() != nil || s.busy == nil {
		s.closed, s.poisoned = true, true
		s.cancel()
	}
	if s.busy != nil {
		close(s.busy)
		s.busy = nil
	}
	if s.poisoned {
		return ErrSecurityBaseline
	}
	return nil
}

// Revoke before the complete closing proof, cancel in-flight work, and JOIN
// its deferred finish. A concurrent/refused/canceled probe cannot close cleanly.
func (s *baselineProbeSuite) close() error {
	if s == nil {
		return ErrSecurityBaseline
	}
	s.mu.Lock()
	if !s.closed && (s.busy != nil || s.root == nil || s.root.Err() != nil) {
		s.poisoned = true
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	done := s.busy
	s.mu.Unlock()
	if done != nil {
		<-done
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return ErrSecurityBaseline
	}
	return nil
}

// Only the behavioral driver uses the narrow path. Standalone actors.probe,
// full actors.verify and denied compositions ignore this capability entirely.
func (b *baselineBehavior) probe(ctx context.Context, actor admissionActor, operation admissionProbeOperation, object *unstructured.Unstructured, policy, binding, message string) (*unstructured.Unstructured, error) {
	if b == nil || b.actors == nil || ctx == nil {
		return nil, ErrSecurityBaseline
	}
	suite, ok := ctx.Value(baselineProbeSuiteKey{}).(*baselineProbeSuite)
	if !ok || suite == nil {
		return nil, ErrSecurityBaseline
	}
	return b.actors.probeWithSuite(ctx, actor, operation, object, policy, binding, message, suite)
}

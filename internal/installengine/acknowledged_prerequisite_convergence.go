// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"reflect"
	"time"

	"github.com/gobha-me/arcadectl/internal/installstate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
)

// A native CRD CREATE ACK may precede asynchronous establishment/status writes.
// Prepare whole-object quietness BEFORE the complete prerequisite proof, never
// by retrying a refused proof or dropping its exact resource-version witnesses.
// Only the original successful ACK enters here. Explicit Recover and uncertain
// responses remain observation-only recovery without this preparation path.
// The caller owns the same protected receipt through preparation, proof and CAS.
// This helper grants no effect or settlement authority and writes nothing.
func (e *Engine) prepareAcknowledgedPrerequisite(ctx context.Context, s *installstate.Snapshot, ack *unstructured.Unstructured, operation *baselinePrerequisite, receipt *prerequisiteReceiptWitness) error {
	if e == nil || e.baseline == nil || ctx == nil || ctx.Err() != nil || s == nil || ack == nil || operation == nil || receipt == nil || receipt.uid == "" || receipt.uid != ack.GetUID() {
		return ErrOutcomeUnknown
	}
	d := s.Document()
	p := d.Pending
	if p == nil || p.Action != installstate.Create || p.Key != operation.key || p.Key.APIVersion != "apiextensions.k8s.io/v1" || p.Key.Kind != "CustomResourceDefinition" || p.Key.Namespace != "" || d.ActivePackage != "" && operation.secrets == nil {
		return ErrOutcomeUnknown
	}
	template, err := e.prerequisiteContext(s, operation)
	if err != nil || !effectMatches(template, p, ack) || e.confirmPrerequisiteReceipt(s, operation, receipt) != nil {
		return ErrOutcomeUnknown
	}
	var previous *unstructured.Unstructured
	var quiet time.Time
	err = wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 90*time.Second, true, func(ctx context.Context) (bool, error) {
		if _, err := e.currentOriginal(ctx, s); err != nil || e.confirmPrerequisiteReceipt(s, operation, receipt) != nil {
			return false, ErrOutcomeUnknown
		}
		live, readErr := e.access.Get(ctx, p.Key)
		if readErr != nil || live == nil || live.GetUID() != receipt.uid || live.GetGeneration() != ack.GetGeneration() || !effectMatches(template, p, live) {
			return false, ErrOutcomeUnknown
		}
		if _, err := e.currentOriginal(ctx, s); err != nil || e.confirmPrerequisiteReceipt(s, operation, receipt) != nil || ctx.Err() != nil {
			return false, ErrOutcomeUnknown
		}
		// Preserve every whole observed field, including RV and status. A change
		// restarts quietness; it is not ignored by the proof that follows.
		if previous == nil || !reflect.DeepEqual(previous.Object, live.Object) {
			previous, quiet = live.DeepCopy(), time.Now()
		}
		return time.Since(quiet) >= time.Second, nil
	})
	if err != nil || ctx.Err() != nil || e.confirmPrerequisiteReceipt(s, operation, receipt) != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

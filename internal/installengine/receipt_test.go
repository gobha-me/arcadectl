// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gobha-me/arcadectl/internal/canonicaljson"
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestReceiptBindingRefusesForeignOrMalformedEvidence(t *testing.T) {
	for _, scenario := range []string{"anchor", "key", "nonce", "hash", "target", "duplicate", "trailing"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t, false)
			f.nsUpdate = func(_ *corev1.Namespace) error {
				if f.nsUpdates == 2 {
					return ErrRead
				}
				return nil
			}
			s, err := f.engine.Apply(context.Background(), f.snapshot, f.key, f.plan.Digest(), false)
			if !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatal(err)
			}
			name := "create-" + s.Document().Pending.CreateNonce + ".json"
			body, id, err := f.engine.files.Read(name, 4096)
			if err != nil {
				t.Fatal(err)
			}
			var r createReceipt
			if json.Unmarshal(body, &r) != nil {
				t.Fatal("receipt")
			}
			switch scenario {
			case "anchor":
				r.Anchor.UID = "foreign-namespace"
			case "key":
				r.Pending.Key.Name = "foreign"
			case "nonce":
				r.Pending.CreateNonce = "foreign"
			case "hash":
				r.Pending.AfterSHA256 = "foreign"
			case "target":
				r.TargetPackage = "foreign"
			}
			if scenario == "duplicate" {
				body = append([]byte(`{"version":"v1",`), body[1:]...)
			} else if scenario == "trailing" {
				body = append(body, []byte(` {}`)...)
			} else {
				body, _ = json.Marshal(r)
				body, err = canonicaljson.CanonicalJSON(body)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.engine.files.AtomicWrite(name, body, &id); err != nil {
				t.Fatal(err)
			}
			if _, err := f.engine.Recover(context.Background(), s); !errors.Is(err, ErrOutcomeUnknown) || f.access.writes != 1 {
				t.Fatal("foreign receipt granted ownership")
			}
		})
	}
}

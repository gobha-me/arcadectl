//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"
)

type kindCPUPilotFake struct {
	state       kindNodeCPUObservation
	calls       [][]string
	updates     []int
	inspect     int
	raw         []byte
	unapplied   bool
	updateError bool
	after       func(*kindNodeCPUObservation)
	wantContext context.Context
}

func newKindCPUPilotFake() (*gcOwnedKindNode, *kindCPUPilotFake) {
	f := &kindCPUPilotFake{state: kindNodeCPUObservation{ID: "owned-native-id", Cluster: "owned-native", NanoCPUs: 2_000_000_000, Memory: 3 << 30, Swap: 3 << 30, PIDs: 2048}}
	n := &gcOwnedKindNode{name: "owned-native-control-plane", id: f.state.ID, cluster: f.state.Cluster, pilotCommand: f.run}
	return n, f
}

func (f *kindCPUPilotFake) run(ctx context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if ctx.Err() != nil || f.wantContext != nil && ctx != f.wantContext {
		return nil, errors.New("closed fake context refused")
	}
	if reflect.DeepEqual(args, []string{"docker", "inspect", "--format", kindNodeCPUInspect, "owned-native-control-plane"}) {
		f.inspect++
		if f.raw != nil {
			return f.raw, nil
		}
		state := f.state
		if f.after != nil && len(f.updates) != 0 {
			f.after(&state)
		}
		return json.Marshal(state)
	}
	if len(args) != 5 || args[0] != "docker" || args[1] != "update" || args[2] != "--cpus" || args[4] != "owned-native-id" {
		return nil, errors.New("unexpected fake command")
	}
	cpus, err := strconv.Atoi(args[3])
	if err != nil || cpus != 2 && cpus != 3 {
		return nil, errors.New("unexpected fake quota")
	}
	f.updates = append(f.updates, cpus)
	if !f.unapplied {
		f.state.NanoCPUs = int64(cpus) * 1_000_000_000
	}
	if f.updateError {
		return nil, errors.New("PRIVATE-CANARY")
	}
	return nil, nil
}

func TestKindNodeCPUPilotOwnershipAndQuota(t *testing.T) {
	t.Run("exact-owned-bracket", func(t *testing.T) {
		n, f := newKindCPUPilotFake()
		for _, quota := range []int{2, 3, 3, 2} {
			if n.setPilotCPUs(t.Context(), quota) != nil {
				t.Fatal("exact owned quota refused")
			}
		}
		if !reflect.DeepEqual(f.updates, []int{2, 3, 3, 2}) || f.inspect != 8 || len(f.calls) != 12 || !n.pilotRestore || n.pilotLimits != (kindNodeCPULimits{Memory: 3 << 30, Swap: 3 << 30, PIDs: 2048}) {
			t.Fatal("owned quota changed command census or fixed limits")
		}
	})
	for _, quota := range []int{-1, 0, 1, 4} {
		t.Run("invalid-quota-"+strconv.Itoa(quota), func(t *testing.T) {
			n, f := newKindCPUPilotFake()
			if n.setPilotCPUs(t.Context(), quota) != ErrInvalid || len(f.calls) != 0 || n.pilotRestore {
				t.Fatal("invalid quota reached Docker or armed restoration")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*gcOwnedKindNode, *kindCPUPilotFake)
		calls  int
	}{
		{"missing-captured-id", func(n *gcOwnedKindNode, _ *kindCPUPilotFake) { n.id = "" }, 0},
		{"wrong-node-name", func(n *gcOwnedKindNode, _ *kindCPUPilotFake) { n.name = "foreign" }, 0},
		{"replaced-id", func(_ *gcOwnedKindNode, f *kindCPUPilotFake) { f.state.ID = "replacement" }, 1},
		{"foreign-label", func(_ *gcOwnedKindNode, f *kindCPUPilotFake) { f.state.Cluster = "foreign" }, 1},
		{"memory", func(_ *gcOwnedKindNode, f *kindCPUPilotFake) { f.state.Memory++ }, 1},
		{"swap", func(_ *gcOwnedKindNode, f *kindCPUPilotFake) { f.state.Swap++ }, 1},
		{"pids", func(_ *gcOwnedKindNode, f *kindCPUPilotFake) { f.state.PIDs++ }, 1},
		{"unknown-cpu", func(_ *gcOwnedKindNode, f *kindCPUPilotFake) { f.state.NanoCPUs = 0 }, 1},
		{"malformed", func(_ *gcOwnedKindNode, f *kindCPUPilotFake) { f.raw = []byte(`{"id":`) }, 1},
		{"duplicate", func(_ *gcOwnedKindNode, f *kindCPUPilotFake) {
			f.raw = []byte(`{"id":"owned-native-id","id":"owned-native-id","cluster":"owned-native","nanoCPUs":2000000000,"memory":3221225472,"swap":3221225472,"pids":2048}`)
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, f := newKindCPUPilotFake()
			tc.change(n, f)
			if n.setPilotCPUs(t.Context(), 3) == nil || len(f.calls) != tc.calls || len(f.updates) != 0 || n.pilotRestore {
				t.Fatal("unproved ownership or changed bounds reached update")
			}
		})
	}
	for _, field := range []string{"id", "label", "memory", "swap", "pids"} {
		t.Run("post-update-"+field, func(t *testing.T) {
			n, f := newKindCPUPilotFake()
			f.after = func(s *kindNodeCPUObservation) {
				switch field {
				case "id":
					s.ID = "replacement"
				case "label":
					s.Cluster = "foreign"
				case "memory":
					s.Memory++
				case "swap":
					s.Swap++
				case "pids":
					s.PIDs++
				}
			}
			if n.setPilotCPUs(t.Context(), 3) == nil || !n.pilotRestore || !reflect.DeepEqual(f.updates, []int{3}) {
				t.Fatal("post-update drift was accepted or restoration was not armed")
			}
		})
	}
	t.Run("unapplied-quota", func(t *testing.T) {
		n, f := newKindCPUPilotFake()
		f.unapplied = true
		if n.setPilotCPUs(t.Context(), 3) == nil || !n.pilotRestore || f.inspect != 2 {
			t.Fatal("unapplied quota was accepted")
		}
	})
	t.Run("expired-context", func(t *testing.T) {
		n, f := newKindCPUPilotFake()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if n.setPilotCPUs(ctx, 3) == nil || len(f.calls) != 0 || n.pilotRestore {
			t.Fatal("expired context reached update")
		}
	})
}

func TestKindNodeCPUPilotCleanupAndBracket(t *testing.T) {
	for _, restoreFails := range []bool{false, true} {
		t.Run("uncertain-update-restore-error-"+strconv.FormatBool(restoreFails), func(t *testing.T) {
			n, f := newKindCPUPilotFake()
			f.updateError = true
			if n.setPilotCPUs(t.Context(), 3) == nil || !n.pilotRestore || f.state.NanoCPUs != 3_000_000_000 {
				t.Fatal("uncertain update lost restoration intent")
			}
			f.updateError = restoreFails
			fixtureCtx, fixtureCancel := context.WithCancel(t.Context())
			fixtureCancel()
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			f.wantContext = cleanupCtx
			reported, cleaned := 0, false
			finishKindPilotCleanup(cleanupCtx, n, func() { reported++ }, func() {
				if fixtureCtx.Err() == nil || !reflect.DeepEqual(f.updates, []int{3, 2}) {
					t.Error("cleanup ran before independent restoration attempt")
				}
				cleaned = true
			})
			if !cleaned || reported != map[bool]int{false: 0, true: 1}[restoreFails] {
				t.Fatal("restoration failure skipped cleanup or was hidden")
			}
		})
	}
	t.Run("ordinary-fixture-zero-extra-commands", func(t *testing.T) {
		n, f := newKindCPUPilotFake()
		cleaned := false
		finishKindPilotCleanup(t.Context(), n, func() { t.Error("unarmed restore failed") }, func() { cleaned = true })
		if !cleaned || len(f.calls) != 0 {
			t.Fatal("ordinary fixture acquired pilot commands")
		}
	})
	t.Run("restore-refuses-replacement-and-still-cleans", func(t *testing.T) {
		n, f := newKindCPUPilotFake()
		if n.setPilotCPUs(t.Context(), 3) != nil {
			t.Fatal("setup failed")
		}
		f.state.ID = "replacement"
		reported, cleaned := false, false
		finishKindPilotCleanup(t.Context(), n, func() { reported = true }, func() { cleaned = true })
		if !reported || !cleaned || !reflect.DeepEqual(f.updates, []int{3}) {
			t.Fatal("replacement was updated or prevented remaining cleanup")
		}
	})
	for fail := -1; fail < 4; fail++ {
		t.Run("bracket-stop-"+strconv.Itoa(fail), func(t *testing.T) {
			var quotas []int
			elapsed, err := runKindNodeCPUBracket(t.Context(), func(index, cpus int) (time.Duration, error) {
				quotas = append(quotas, cpus)
				if index == fail {
					return time.Second, ErrFixtures
				}
				return time.Second, nil
			})
			want := []int{2, 3, 3, 2}
			if fail >= 0 {
				want = want[:fail+1]
			}
			if !reflect.DeepEqual(quotas, want) || (err == nil) != (fail < 0) {
				t.Fatal("bracket retried, continued after refusal or omitted a sample")
			}
			if fail < 0 && elapsed != [4]time.Duration{time.Second, time.Second, time.Second, time.Second} {
				t.Fatal("bracket timing changed")
			}
		})
	}
	t.Run("bracket-expiry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		count := 0
		_, err := runKindNodeCPUBracket(ctx, func(int, int) (time.Duration, error) { count++; cancel(); return time.Second, nil })
		if err == nil || count != 1 {
			t.Fatal("expired aggregate budget advanced the bracket")
		}
	})
	t.Run("screen-is-not-adoption", func(t *testing.T) {
		for _, tc := range []struct {
			d      [4]time.Duration
			useful bool
		}{
			{[4]time.Duration{100, 85, 85, 120}, true},
			{[4]time.Duration{100, 86, 80, 120}, false},
			{[4]time.Duration{100, 70, 70, 80}, false},
			{[4]time.Duration{100, 0, 80, 120}, false},
		} {
			if kindNodeCPUPilotUseful(tc.d) != tc.useful {
				t.Fatal("screen ignored faster control, both candidates or completeness")
			}
		}
		if !kindNodeCPUPilotOptIn("1", "true", "true") || kindNodeCPUPilotOptIn("", "true", "true") || kindNodeCPUPilotOptIn("1", "false", "true") || kindNodeCPUPilotOptIn("1", "true", "false") {
			t.Fatal("pilot opt-in escaped closed CI selection")
		}
	})
}

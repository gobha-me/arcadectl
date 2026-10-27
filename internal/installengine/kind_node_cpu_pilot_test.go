//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"strconv"
	"time"

	strictjson "sigs.k8s.io/json"
)

// Only the disposable native fixture supplies this private command capability.
// It retains that fixture's Docker configuration and bounded, silent output.
type kindNodePilotCommand func(context.Context, ...string) ([]byte, error)

type kindNodeCPULimits struct {
	Memory int64 `json:"memory"`
	Swap   int64 `json:"swap"`
	PIDs   int64 `json:"pids"`
}

type kindNodeCPUObservation struct {
	ID       string `json:"id"`
	Cluster  string `json:"cluster"`
	NanoCPUs int64  `json:"nanoCPUs"`
	Memory   int64  `json:"memory"`
	Swap     int64  `json:"swap"`
	PIDs     int64  `json:"pids"`
}

const kindNodeCPUInspect = `{"id":{{json .Id}},"cluster":{{json (index .Config.Labels "io.x-k8s.kind.cluster")}},"nanoCPUs":{{.HostConfig.NanoCpus}},"memory":{{.HostConfig.Memory}},"swap":{{.HostConfig.MemorySwap}},"pids":{{json .HostConfig.PidsLimit}}}`

func (n *gcOwnedKindNode) inspectPilotCPUs(ctx context.Context) (kindNodeCPUObservation, error) {
	var state kindNodeCPUObservation
	if n == nil || ctx == nil || ctx.Err() != nil || n.pilotCommand == nil || n.id == "" || n.cluster == "" || n.name != n.cluster+"-control-plane" {
		return state, ErrOutcomeUnknown
	}
	body, err := n.pilotCommand(ctx, "docker", "inspect", "--format", kindNodeCPUInspect, n.name)
	if err != nil || len(body) == 0 || len(body) > 1<<20 {
		return state, ErrOutcomeUnknown
	}
	invalid, err := strictjson.UnmarshalStrict(body, &state)
	if err != nil || len(invalid) != 0 || state.ID != n.id || state.Cluster != n.cluster || state.NanoCPUs != 2_000_000_000 && state.NanoCPUs != 3_000_000_000 || state.Memory != 3<<30 || state.Swap != 3<<30 || state.PIDs != 2048 {
		return kindNodeCPUObservation{}, ErrOutcomeUnknown
	}
	return state, nil
}

func (n *gcOwnedKindNode) setPilotCPUs(ctx context.Context, cpus int) error {
	if cpus != 2 && cpus != 3 {
		return ErrInvalid
	}
	before, err := n.inspectPilotCPUs(ctx)
	if err != nil {
		return err
	}
	limits := kindNodeCPULimits{Memory: before.Memory, Swap: before.Swap, PIDs: before.PIDs}
	if n.pilotRestore && n.pilotLimits != limits {
		return ErrOutcomeUnknown
	}
	n.pilotLimits = limits
	// Arm BEFORE sending: an errored update can still have changed the quota.
	n.pilotRestore = true
	if _, err := n.pilotCommand(ctx, "docker", "update", "--cpus", strconv.Itoa(cpus), n.id); err != nil {
		return ErrOutcomeUnknown
	}
	after, err := n.inspectPilotCPUs(ctx)
	if err != nil || after.NanoCPUs != int64(cpus)*1_000_000_000 || (kindNodeCPULimits{Memory: after.Memory, Swap: after.Swap, PIDs: after.PIDs}) != limits {
		return ErrOutcomeUnknown
	}
	return nil
}

// Called INSIDE the existing independent three-minute cleanup context. Ordinary
// fixtures are unarmed, so execute exactly their original cleanup commands.
func finishKindPilotCleanup(ctx context.Context, n *gcOwnedKindNode, reportRestoreFailure, cleanup func()) {
	if n != nil && n.pilotRestore && n.setPilotCPUs(ctx, 2) != nil {
		reportRestoreFailure()
	}
	cleanup()
}

// Four samples only; the caller owns the one aggregate fixture deadline.
// A refusal never advances the bracket or retries a partial proof.
func runKindNodeCPUBracket(ctx context.Context, sample func(int, int) (time.Duration, error)) ([4]time.Duration, error) {
	var elapsed [4]time.Duration
	for index, cpus := range [4]int{2, 3, 3, 2} {
		if ctx == nil || ctx.Err() != nil || sample == nil {
			return elapsed, ErrInvalid
		}
		var err error
		elapsed[index], err = sample(index, cpus)
		if err != nil || elapsed[index] <= 0 || ctx.Err() != nil {
			return elapsed, ErrFixtures
		}
	}
	return elapsed, nil
}

func kindNodeCPUPilotOptIn(flag, ci, actions string) bool {
	return flag == "1" && ci == "true" && actions == "true"
}

func kindNodeCPUPilotUseful(elapsed [4]time.Duration) bool {
	for _, value := range elapsed {
		if value <= 0 {
			return false
		}
	}
	control := elapsed[0]
	if elapsed[3] < control {
		control = elapsed[3]
	}
	// Avoid duration multiplication overflow; all fixture spans are <=40m.
	return float64(elapsed[1]) <= float64(control)*0.85 && float64(elapsed[2]) <= float64(control)*0.85
}

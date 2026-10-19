//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const installerBinaryPipelineLineLimit = 16*1024 + 128

// Independently freeze the consumer's v1 row. A future producer field must not
// silently extend what this private-text forwarding boundary permits.
type installerBinaryPipelineRow struct {
	Scope                    string `json:"scope"`
	Kind                     string `json:"kind"`
	Calls                    uint64 `json:"calls"`
	Returned                 uint64 `json:"returned"`
	InclusiveWallNanoseconds uint64 `json:"inclusiveWallNanoseconds"`
}

type installerBinaryPipelineCosts struct {
	final  bool
	values [48 * 3]uint64
}

// A separate closed v1 channel, not an extension or reinterpretation of the
// frozen numeric cost channel. Canonical JSON, literal enum census and bounded
// unsigned counters prevent private text from becoming live progress output.
func installerBinaryPipelineLine(line string) (installerBinaryPipelineCosts, bool) {
	var result installerBinaryPipelineCosts
	if len(line) > installerBinaryPipelineLineLimit {
		return result, false
	}
	body, ok := strings.CutPrefix(line, "installation diagnostic step-request-pipeline ")
	if !ok {
		body, ok = strings.CutPrefix(line, "installation diagnostic command-request-pipeline ")
		result.final = true
	}
	if !ok || len(body) > 16384 {
		return installerBinaryPipelineCosts{}, false
	}
	var record struct {
		Format     string                       `json:"format"`
		Accounting string                       `json:"accounting"`
		Rows       []installerBinaryPipelineRow `json:"rows"`
	}
	if json.Unmarshal([]byte(body), &record) != nil || record.Format != "installer-request-pipeline-v1" || record.Accounting != "direct-http-inclusive-overlapping-not-sdk-or-cpu" || len(record.Rows) != 48 {
		return installerBinaryPipelineCosts{}, false
	}
	canonical, err := json.Marshal(record)
	if err != nil || string(canonical) != body {
		return installerBinaryPipelineCosts{}, false // also rejects duplicate/unknown fields and numeric aliases
	}
	for scope, label := range []string{"baseline-discovery", "baseline-opening", "baseline-dry-run", "baseline-closing", "public-inventory", "other"} {
		for kind, name := range []string{"client-do", "roundtrip-to-headers", "guarded-post-headers", "outer-body-read", "post-body-validation", "public-inventory", "contract-check", "phase-row"} {
			index := scope*8 + kind
			row := record.Rows[index]
			if row.Scope != label || row.Kind != name || row.Returned > row.Calls {
				return installerBinaryPipelineCosts{}, false
			}
			result.values[index*3], result.values[index*3+1], result.values[index*3+2] = row.Calls, row.Returned, row.InclusiveWallNanoseconds
		}
	}
	return result, true
}

// Diagnostics are checked only after the actual current command succeeded.
// Children killed/refused earlier may lack a final record, never a success.
func installerBinaryCompletedPipelineCosts(output []byte, maxSteps int) bool {
	var previous [48 * 3]uint64
	steps, stages, final := 0, 0, false
	lines := bytes.Split(output, []byte{'\n'})
	for index, line := range lines {
		s := string(line)
		if installerBinaryProgressLine(s) {
			if index == len(lines)-1 {
				return false
			}
			stages++
		}
		if !strings.HasPrefix(s, "installation diagnostic step-request-pipeline") && !strings.HasPrefix(s, "installation diagnostic command-request-pipeline") {
			continue
		}
		current, ok := installerBinaryPipelineLine(s)
		if !ok || final || index == len(lines)-1 {
			return false
		}
		if current.final {
			if steps == 0 || current.values != previous {
				return false
			}
			final = true
		} else {
			steps++
			if steps > maxSteps {
				return false
			}
			for index, value := range current.values {
				if value < previous[index] {
					return false
				}
			}
			previous = current.values
		}
	}
	return final && stages == steps
}

func TestInstallerBinaryRequestPipelineCapture(t *testing.T) {
	testInstallerBinaryRequestPipelineCapture(t)
}

func testInstallerBinaryRequestPipelineCapture(t *testing.T) {
	t.Helper()
	var costs *requestPipelineCosts
	step := "installation diagnostic step-request-pipeline " + costs.snapshot()
	final := "installation diagnostic command-request-pipeline " + costs.snapshot()
	if parsed, ok := installerBinaryPipelineLine(step); !ok || parsed.final {
		t.Fatal("closed pipeline producer and consumer disagree")
	}
	for _, bad := range []string{
		" " + step, step + " ", step + "PRIVATE-CANARY", strings.Replace(step, "baseline-opening", "PRIVATE-CANARY", 1),
		strings.Replace(step, `"format":`, `"extra":"PRIVATE-CANARY","format":`, 1),
		strings.Replace(step, `"format":`, `"format":"installer-request-pipeline-v1","format":`, 1),
		strings.Replace(step, `"scope":`, `"extra":"PRIVATE-CANARY","scope":`, 1),
		strings.Replace(step, `"scope":`, `"scope":"baseline-discovery","scope":`, 1),
		strings.Replace(step, `"calls":0`, `"calls":0e0`, 1), strings.Replace(step, `"calls":0`, `"calls":-1`, 1),
		strings.Replace(step, `"calls":0`, `"calls":18446744073709551616`, 1),
		strings.Replace(step, `"inclusiveWallNanoseconds":0`, `"inclusiveWallNanoseconds":18446744073709551616`, 1),
		strings.Replace(step, `"returned":0`, `"returned":1`, 1), strings.Replace(step, `"rows":[{`, `"rows":[null,{`, 1),
		strings.Repeat("x", installerBinaryPipelineLineLimit+1),
	} {
		if _, ok := installerBinaryPipelineLine(bad); ok {
			t.Fatal("unclosed pipeline text escaped its separate live channel")
		}
	}
	maxStep := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(step, `"calls":0`, `"calls":18446744073709551615`), `"returned":0`, `"returned":18446744073709551615`), `"inclusiveWallNanoseconds":0`, `"inclusiveWallNanoseconds":18446744073709551615`)
	if parsed, ok := installerBinaryPipelineLine(maxStep); !ok || parsed.values[0] != ^uint64(0) || parsed.values[len(parsed.values)-1] != ^uint64(0) {
		t.Fatal("canonical uint64 pipeline counters lost precision")
	}
	valid := "installation stage complete revision 7\n" + step + "\n" + final + "\n"
	if !installerBinaryCompletedPipelineCosts([]byte(valid), 1) {
		t.Fatal("joined successful pipeline record refused")
	}
	for _, bad := range []string{step + "\n" + final + "\n", valid + final + "\n", strings.TrimSuffix(valid, "\n"), strings.Replace(valid, final, step, 1), strings.Replace(valid, step, strings.Replace(step, `"calls":0`, `"calls":1`, 1), 1), step + "\n" + final + "\ninstallation stage complete revision 7"} {
		if installerBinaryCompletedPipelineCosts([]byte(bad), 1) {
			t.Fatal("incomplete, regressing or duplicate pipeline records certified")
		}
	}
	regression := "installation stage complete revision 7\n" + maxStep + "\ninstallation stage complete revision 8\n" + step + "\n" + final + "\n"
	if installerBinaryCompletedPipelineCosts([]byte(regression), 2) {
		t.Fatal("regressing step counters with a matching final record certified")
	}
	emitted := []string{}
	capture := &installerBinaryProgressCapture{log: func(line string) { emitted = append(emitted, line) }}
	// Chunked forwarding remains newline-only. Raw combined bytes are unchanged.
	input := "PRIVATE-CANARY\n" + step + "\n" + final + "\n" + step
	for _, b := range []byte(input) {
		capture.Write([]byte{b})
	}
	if len(emitted) != 2 || emitted[0] != step || emitted[1] != final || string(capture.output()) != input {
		t.Fatal("pipeline forwarding leaked private/incomplete text or changed capture")
	}
	for i := 0; i < 520; i++ {
		capture.Write([]byte("\n" + step))
	}
	if capture.pipelineEmitted != 513 {
		t.Fatal("pipeline live-channel bound drifted")
	}
}

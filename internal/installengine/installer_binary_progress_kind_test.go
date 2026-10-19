//go:build kindinstall

// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test-harness observation only: never evidence or authority for a lifecycle
// effect. Retain every byte for the existing completion/failure assertions, but
// emit only complete bounded fixed stage/revision or numeric cost lines. The
// two channels have independent limits. No EOF suffix flush.
type installerBinaryProgressCapture struct {
	mu          sync.Mutex
	capture     bytes.Buffer
	line        []byte
	discard     bool
	emitted     int
	costEmitted int
	log         func(string)
}

func (c *installerBinaryProgressCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = c.capture.Write(p)
	for _, b := range p {
		if b == '\n' {
			if !c.discard && c.log != nil {
				line := string(c.line)
				if c.emitted < 512 && installerBinaryProgressLine(line) {
					c.emitted++
					c.log(line) // synchronous; callback must not reenter c
				} else if _, ok := installerBinaryCostLine(line); ok && c.costEmitted < 513 {
					c.costEmitted++
					c.log(line)
				}
			}
			c.line, c.discard = c.line[:0], false
		} else if !c.discard {
			if len(c.line) == 2048 {
				c.line, c.discard = c.line[:0], true
			} else {
				c.line = append(c.line, b)
			}
		}
	}
	return len(p), nil
}

func (c *installerBinaryProgressCapture) output() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.capture.Bytes())
}

func installerBinaryProgressLine(line string) bool {
	if len(line) > 128 {
		return false
	}
	var rest string
	var baseline bool
	if strings.HasPrefix(line, "installation stage ") {
		rest = strings.TrimPrefix(line, "installation stage ")
	} else if strings.HasPrefix(line, "security baseline stage ") {
		rest, baseline = strings.TrimPrefix(line, "security baseline stage "), true
	} else {
		return false
	}
	stage, revision, found := strings.Cut(rest, " revision ")
	if !found {
		return false
	}
	valid := stage == "preparing" || stage == "applying" || stage == "recovery-required"
	if baseline {
		valid = valid || stage == "verified"
	} else {
		valid = valid || stage == "quiescing" || stage == "verifying" || stage == "complete"
	}
	n, err := strconv.ParseUint(revision, 10, 64)
	return valid && err == nil && n != 0 && strconv.FormatUint(n, 10) == revision
}

type installerBinaryCosts struct {
	final  bool
	values [3 * costKinds]uint64
}

// Only the exact production counter schema may leave the combined output live.
// Fixed names/order, canonical integers and a finite byte bound; no raw suffixes
// or flexible whitespace. These diagnostics never grant lifecycle authority.
func installerBinaryCostLine(line string) (installerBinaryCosts, bool) {
	var result installerBinaryCosts
	if len(line) > 2048 {
		return result, false
	}
	rest, ok := strings.CutPrefix(line, "installation diagnostic step-cost ")
	if !ok {
		rest, ok = strings.CutPrefix(line, "installation diagnostic command-cost ")
		result.final = true
	}
	if !ok {
		return installerBinaryCosts{}, false
	}
	fields := strings.Split(rest, " ")
	if len(fields) != len(result.values) {
		return installerBinaryCosts{}, false
	}
	for index, field := range fields {
		label := lifecycleCostLabels[index/3] + []string{"-calls=", "-returned=", "-inclusive-wall-ns="}[index%3]
		number, found := strings.CutPrefix(field, label)
		n, err := strconv.ParseUint(number, 10, 64)
		if !found || err != nil || strconv.FormatUint(n, 10) != number {
			return installerBinaryCosts{}, false
		}
		result.values[index] = n
	}
	return result, true
}

// This checks diagnostic completeness only AFTER an actual successful current
// child exits. Existing independent whole-lifecycle assertions are still needed.
// A killed or refused child may legitimately lack its final diagnostic record.
func installerBinaryCompletedCosts(output []byte, maxSteps int) bool {
	var previous [3 * costKinds]uint64
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
		if !strings.HasPrefix(s, "installation diagnostic step-cost") && !strings.HasPrefix(s, "installation diagnostic command-cost") {
			continue
		}
		current, ok := installerBinaryCostLine(s)
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

func TestInstallerBinaryProgressCapture(t *testing.T) {
	testInstallerBinaryProgressCapture(t)
	testInstallerBinaryCostCapture(t)
	testInstallerBinaryProgressSubprocess(t)
	testHistoricalInstallerFailureObservation(t)
}

// A local inert shell, not an installer or cluster probe. Its stdin handshake
// makes live emission before exit observable without timing sleeps. Verify Run
// still reports both nonzero exits and cancellation; no failed process is retried.
func testInstallerBinaryProgressSubprocess(t *testing.T) {
	t.Helper()
	var empty *LifecycleCosts
	costLine := "installation diagnostic step-cost " + empty.Snapshot()
	for _, mode := range []string{"ok", "failure", "cancel"} {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", "-c", "printf '%s\\n' SECRET-CANARY >&2; printf '%s\\n' 'installation stage applying revision 7'; printf '%s\\n' \"$1\" >&2; read -r decision; case \"$decision\" in ok) exit 0;; *) exit 7;; esac", "cost-capture", costLine)
			progress := make(chan string, 2)
			capture := &installerBinaryProgressCapture{log: func(line string) { progress <- line }}
			cmd.Stdout, cmd.Stderr = capture, capture
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal("inert subprocess input unavailable")
			}
			defer stdin.Close()
			if cmd.Start() != nil {
				t.Fatal("inert subprocess unavailable")
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			for _, want := range []string{"installation stage applying revision 7", costLine} {
				select {
				case line := <-progress:
					if line != want {
						cancel()
						<-done
						t.Fatal("subprocess private output escaped live filter")
					}
				case <-ctx.Done():
					<-done
					t.Fatal("subprocess progress or costs were buffered until exit")
				}
			}
			select {
			case <-done:
				t.Fatal("inert subprocess exited before release")
			default:
			}
			if mode == "cancel" {
				cancel()
			} else if _, err := io.WriteString(stdin, mode+"\n"); err != nil {
				cancel()
				<-done
				t.Fatal("inert subprocess release failed")
			}
			err = <-done
			var exit *exec.ExitError
			if mode == "ok" && err != nil || mode == "failure" && (!errors.As(err, &exit) || exit.ExitCode() != 7) || mode == "cancel" && (err == nil || !errors.Is(ctx.Err(), context.Canceled)) {
				t.Fatal("capture masked subprocess exit or cancellation")
			}
			if string(capture.output()) != "SECRET-CANARY\ninstallation stage applying revision 7\n"+costLine+"\n" {
				t.Fatal("capture changed original combined subprocess output")
			}
		}()
	}
}

// Run these pure controls before the native fixture too: profile/mode selectors
// must not silently omit the capture contract. No cluster setup is used here.
func testInstallerBinaryProgressCapture(t *testing.T) {
	t.Helper()
	t.Run("parent-context-diagnostic", testInstallerBinaryParentContext)
	valid := []string{}
	for _, stage := range []string{"preparing", "quiescing", "applying", "verifying", "complete", "recovery-required"} {
		valid = append(valid, "installation stage "+stage+" revision 18446744073709551615")
	}
	for _, stage := range []string{"preparing", "applying", "verified", "recovery-required"} {
		valid = append(valid, "security baseline stage "+stage+" revision 1")
	}
	for _, line := range valid {
		for split := 0; split <= len(line); split++ {
			var logs []string
			c := &installerBinaryProgressCapture{log: func(s string) { logs = append(logs, s) }}
			_, _ = c.Write([]byte(line[:split]))
			_, _ = c.Write([]byte(line[split:]))
			if len(logs) != 0 {
				t.Fatal("progress emitted before complete newline")
			}
			_, _ = c.Write([]byte("\n"))
			if len(logs) != 1 || logs[0] != line || string(c.output()) != line+"\n" {
				t.Fatal("fragmented approved progress or original capture changed")
			}
		}
	}
	bad := []string{
		"SECRET-CANARY", " installation stage applying revision 1",
		"installation stage SECRET-CANARY revision 1", "installation stage verified revision 1",
		"security baseline stage complete revision 1", "installation stage applying revision 0",
		"installation stage applying revision 01", "installation stage applying revision +1",
		"installation stage applying revision -1", "installation stage applying revision 18446744073709551616",
		"installation stage applying revision 1 SECRET-CANARY", "installation stage applying revision 1\r",
		"installation stage applying revision 1\x00", "\x1b[0minstallation stage applying revision 1",
		"installation stage applying revision 1\x1b[0m", "installation stage applying revision 1\t",
		strings.Repeat("x", 129) + "installation stage applying revision 1",
	}
	var logs []string
	c := &installerBinaryProgressCapture{log: func(s string) { logs = append(logs, s) }}
	wire := strings.Join(bad, "\n") + "\n" + valid[0] + "\n" + valid[1]
	for _, b := range []byte(wire) {
		if n, err := c.Write([]byte{b}); n != 1 || err != nil {
			t.Fatal("capture changed subprocess write semantics")
		}
	}
	if len(logs) != 1 || logs[0] != valid[0] || string(c.output()) != wire {
		t.Fatal("unsafe/overlong/unterminated progress escaped or original capture changed")
	}
	logs = nil
	c = &installerBinaryProgressCapture{log: func(s string) { logs = append(logs, s) }}
	var writers sync.WaitGroup
	for range 16 {
		writers.Go(func() { _, _ = c.Write([]byte(valid[0] + "\n")) })
	}
	writers.Wait()
	if len(logs) != 16 || string(c.output()) != strings.Repeat(valid[0]+"\n", 16) {
		t.Fatal("shared stream capture or progress ordering raced")
	}
	logs = nil
	c = &installerBinaryProgressCapture{log: func(s string) { logs = append(logs, s) }}
	wire = strings.Repeat(valid[0]+"\n", 513)
	_, _ = c.Write([]byte(wire))
	if len(logs) != 512 || string(c.output()) != wire {
		t.Fatal("live progress bound changed complete capture")
	}
}

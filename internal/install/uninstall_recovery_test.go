// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControllerUninstallPrintsActionableRecoveryOnlyAfterRemoval(t *testing.T) {
	for _, refuseDelete := range []bool{false, true} {
		name := "removed"
		if refuseDelete {
			name = "delete-refused"
		}
		t.Run(name, func(t *testing.T) {
			fakeKubectl, logPath := writeFakeKubectl(t)
			wrapper := filepath.Join(filepath.Dir(fakeKubectl), "kubectl-boundary")
			body := "#!/bin/sh\nset -eu\nif [ \"$1\" = delete ] && [ \"$REFUSE_DELETE\" = true ]; then exit 52; fi\nexec \"$FAKE_KUBECTL\" \"$@\"\n"
			if err := os.WriteFile(wrapper, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "bash", filepath.Join(repositoryRoot(t), "hack", "uninstall.sh"))
			refusal := "false"
			if refuseDelete {
				refusal = "true"
			}
			command.Env = append(os.Environ(), "KUBECTL="+wrapper, "FAKE_KUBECTL="+fakeKubectl,
				"KUBECTL_LOG="+logPath, "REFUSE_DELETE="+refusal,
				"KUBECTL_SERVERS=factory\tStopped\tStopped\t2\t2\t\n")
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("uninstall exceeded test deadline")
			}
			if refuseDelete {
				if err == nil || strings.Contains(string(output), "Recovery:") || strings.Contains(string(output), "controller removed;") {
					t.Fatalf("failed deletion reported recovery success: error=%v output=%s", err, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("uninstall failed: %v\n%s", err, output)
			}
			for _, guidance := range []string{"Recovery:", "keep the arcadectl-system namespace", "Deleting the namespace", "hack/install.sh", "digest-pinned image", "names and UIDs", "reattach every adapter path", "docs/LIFECYCLE.md", "separate backup-gated destroy"} {
				if !strings.Contains(string(output), guidance) {
					t.Errorf("successful uninstall omitted %q: %s", guidance, output)
				}
			}
			commands, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			deletes := 0
			for line := range strings.SplitSeq(string(commands), "\n") {
				if strings.HasPrefix(line, "delete ") {
					deletes++
					want := "delete --filename " + filepath.Join(repositoryRoot(t), "config/install/uninstall.yaml") + " --ignore-not-found=true"
					if line != want {
						t.Errorf("unexpected deletion: %s", line)
					}
				}
			}
			if deletes != 1 {
				t.Fatalf("got %d removal commands, want exactly one", deletes)
			}
		})
	}
}

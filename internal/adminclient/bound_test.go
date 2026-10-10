// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package adminclient

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"net"
	"os"
	"sync/atomic"
	"testing"

	"github.com/gobha-me/arcadectl/internal/privatefs"
)

func TestBoundLoaderPinsCapturedCredentialAndCABytes(t *testing.T) {
	for _, change := range []string{"credential", "ca", "nil-dial", "none"} {
		t.Run(change, func(t *testing.T) {
			config, _, requests := clientFixture(t, nil)
			credential, credentialID, err := privatefs.ReadAbsolute(config.CredentialFile, 16384, privatefs.Private)
			if err != nil {
				t.Fatal(err)
			}
			ca, caID, err := privatefs.ReadAbsolute(config.CAFile, 1024*1024, privatefs.TrustedPublic)
			if err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int32
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			// Valid JSON/PEM with different captured bytes, same path and inode.
			switch change {
			case "credential":
				if os.WriteFile(config.CredentialFile, append(credential, '\n'), 0600) != nil {
					t.Fatal("fixture change")
				}
			case "ca":
				if os.WriteFile(config.CAFile, append(ca, '\n'), 0600) != nil {
					t.Fatal("fixture change")
				}
			case "nil-dial":
				dial = nil
			}
			block, _ := pem.Decode(ca)
			if block == nil {
				t.Fatal("fixture leaf")
			}
			client, err := LoadBoundWithDialer(config, credentialID, caID, sha256.Sum256(block.Bytes), dial)
			// Restore A before any later outer check. A constructor which captured
			// B cannot be made safe by observing A at the subsequent dial barrier.
			if os.WriteFile(config.CredentialFile, credential, 0600) != nil || os.WriteFile(config.CAFile, ca, 0600) != nil {
				t.Fatal("fixture restore")
			}
			if change != "none" {
				if err == nil || client != nil || requests.Load() != 0 || dials.Load() != 0 {
					t.Fatal("unbound captured bytes accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.Verify(context.Background()); err != nil || requests.Load() != 1 || dials.Load() != 1 {
				t.Fatal("bound custom route did not authenticate", err)
			}
		})
	}
}

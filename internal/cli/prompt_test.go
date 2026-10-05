// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	adminv1 "github.com/gobha-me/arcadectl/api/admin/v1"
	"golang.org/x/sys/unix"
)

func promptTerminal(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("test terminal unavailable")
	}
	master := os.NewFile(uintptr(fd), "test-terminal")
	t.Cleanup(func() { _ = master.Close() })
	if unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0) != nil {
		t.Fatal("test terminal unlock failed")
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal("test terminal identity unavailable")
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal("test terminal slave unavailable")
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func TestTerminalConfirmationExactInputAndDeadline(t *testing.T) {
	for _, test := range []struct {
		name, input string
		deadline    bool
		want        string
	}{
		{name: "exact", input: "abcdefghijklmnop\n"},
		{name: "wrong", input: "other\n", want: "confirmation_required"},
		{name: "space", input: "abcdefghijklmnop \n", want: "confirmation_required"},
		{name: "deadline", deadline: true, want: "timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			master, slave := promptTerminal(t)
			app := application{options: Options{In: slave, Err: slave}}
			preview := adminv1.DestroyPreview{Challenge: "abcdefghijklmnop", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if test.deadline {
				preview.ExpiresAt = time.Now().Add(250 * time.Millisecond).UTC().Format(time.RFC3339Nano)
			}
			done := make(chan error, 1)
			go func() { done <- app.prompt(ctx, preview) }()
			if !test.deadline {
				var display bytes.Buffer
				for !bytes.Contains(display.Bytes(), []byte("Type exactly abcdefghijklmnop: ")) {
					if ctx.Err() != nil {
						t.Fatal("fresh inventory did not appear")
					}
					fds := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
					n, err := unix.Poll(fds, 50)
					if err == unix.EINTR {
						continue
					}
					if err != nil {
						t.Fatal("fresh inventory polling failed")
					}
					if n == 0 {
						continue
					}
					var chunk [2048]byte
					read, err := unix.Read(int(master.Fd()), chunk[:])
					if err != nil {
						t.Fatal("fresh inventory read failed")
					}
					display.Write(chunk[:read])
				}
				if _, err := master.Write([]byte(test.input)); err != nil {
					t.Fatal("fresh test input unavailable")
				}
			}
			err := <-done
			if test.want == "" {
				if err != nil {
					t.Fatal("exact typed challenge refused")
				}
			} else if err == nil || classify(err).code != test.want {
				t.Fatalf("prompt result: got %v, expected %s", err, test.want)
			}
		})
	}
}

func TestTerminalConfirmationDoesNotInheritQueuedInput(t *testing.T) {
	master, slave := promptTerminal(t)
	if _, err := master.Write([]byte("abcdefghijklmnop\n")); err != nil {
		t.Fatal(err)
	}
	fds := []unix.PollFd{{Fd: int32(slave.Fd()), Events: unix.POLLIN}}
	if n, err := unix.Poll(fds, 1000); err != nil || n == 0 || fds[0].Revents&unix.POLLIN == 0 {
		t.Fatal("prior challenge did not reach terminal input queue")
	}
	app := application{options: Options{In: slave, Err: slave}}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	preview := adminv1.DestroyPreview{Challenge: "abcdefghijklmnop", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	if err := app.prompt(ctx, preview); err == nil || classify(err).code != "timeout" {
		t.Fatal("old queued input inherited destructive approval")
	}
}

func TestTerminalConfirmationRequiresDisplayedTerminal(t *testing.T) {
	_, slave := promptTerminal(t)
	app := application{options: Options{In: slave, Err: os.Stderr}}
	// Use a regular file explicitly, independent of the runner's stderr topology.
	output, err := os.CreateTemp(t.TempDir(), "not-a-terminal")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	app.options.Err = output
	if err := app.prompt(context.Background(), adminv1.DestroyPreview{}); err == nil || classify(err).code != "confirmation_required" {
		t.Fatal("hidden inventory could authorize destruction")
	}
}

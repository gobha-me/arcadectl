// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package installengine

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sync/atomic"
	"testing"
)

// ProxyFromEnvironment caches process environment. A fresh test-binary child
// proves actual non-loopback observer routing, independent of suite ordering.
func directObserverChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv("ARCADECTL_DIRECT_OBSERVER_TEST") == t.Name() {
		return true
	}
	command := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.timeout=1m")
	command.Env = append(os.Environ(), "ARCADECTL_DIRECT_OBSERVER_TEST="+t.Name(), "HTTPS_PROXY=http://127.0.0.1:1", "HTTP_PROXY=http://127.0.0.1:1", "ALL_PROXY=http://127.0.0.1:1", "NO_PROXY=", "no_proxy=")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("direct observer routing regression: %v\n%s", err, output)
	}
	return false
}

// Test-only frozen-reader instrumentation: direct construction has already
// rejected routing callbacks. Resolve only our fake non-loopback fixture host
// to the exact owned TLS server, without DNS or shared hosts-file changes.
// Journal/effect reads continue through the unchanged original HTTPAccess.
func instrumentDirectObserver(t *testing.T, access *HTTPAccess) *atomic.Int32 {
	t.Helper()
	u, err := url.Parse(access.frozen.Host)
	if err != nil || !access.direct {
		t.Fatal("invalid direct fixture")
	}
	original := u.Host
	host, port, err := net.SplitHostPort(original)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = net.JoinHostPort("observer.test", port)
	access.frozen.Host, access.frozen.ServerName = u.String(), host
	calls := &atomic.Int32{}
	access.frozen.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != u.Host {
			return nil, errors.New("test observer routed through environment proxy")
		}
		calls.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, original)
	}
	return calls
}

func TestDirectSafetyObserverIgnoresEnvironmentProxy(t *testing.T) {
	if directObserverChild(t) {
		testSafetyObservation(t, true)
	}
}

func TestDirectRecoveryObserverIgnoresEnvironmentProxy(t *testing.T) {
	if !directObserverChild(t) {
		return
	}
	x := newRecoveryFixtureRouting(t, true)
	calls := instrumentDirectObserver(t, x.reporter.access)
	if _, err := x.reporter.Collect(context.Background(), x.receipt); err != nil || calls.Load() == 0 || x.lists != 2 {
		t.Fatal("direct recovery observer failed or skipped read", err)
	}
}

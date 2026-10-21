// Copyright 2026 gobha-me
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const kindRuntimeLogLimit = 64 * 1024

// Test-only failure evidence. No raw output, container IDs, arbitrary native
// messages, URLs or errors escape the reader. A signature is an observation,
// not an exhaustive classification or a demonstrated root cause.
func kindRuntimeLogSignature(body []byte) string {
	if len(body) > kindRuntimeLogLimit {
		return "truncated"
	}
	// Verified against the checksum-pinned upstream entrypoint documented in
	// images/factorio/README.md. Do not guess Factorio binary failure messages.
	const signature = "If $GENERATE_NEW_SAVE is true, you must specify $SAVE_NAME"
	lines := bytes.Split(body, []byte{'\n'})
	for _, line := range lines[:len(lines)-1] { // incomplete trailing lines are unknown
		if string(bytes.TrimSuffix(line, []byte{'\r'})) == signature {
			return "save-name-required"
		}
	}
	return "unknown"
}

// Install this BELOW client-go's debug/logging transport, not after DoRaw or
// Stream. The raw body is consumed here and replaced by a fixed category, and
// arbitrary upstream errors/headers/status strings never reach instrumentation.
type kindRuntimeLogTransport struct {
	next       http.RoundTripper
	host, path string
}

func (r kindRuntimeLogTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet || request.URL.Host != r.host || request.URL.Path != r.path || request.URL.RawPath != "" || request.URL.User != nil || request.URL.Fragment != "" {
		return nil, errors.New("runtime diagnostic unavailable")
	}
	query := request.URL.Query()
	previous := query.Get("previous")
	if (previous != "true" && previous != "false") || request.URL.RawQuery != (url.Values{"container": {"game"}, "previous": {previous}, "limitBytes": {"65536"}, "timestamps": {"false"}}).Encode() {
		return nil, errors.New("runtime diagnostic unavailable")
	}
	category := "unavailable"
	response, err := r.next.RoundTrip(request)
	if response != nil && response.Body != nil {
		if err == nil && response.StatusCode == http.StatusOK {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, kindRuntimeLogLimit+1))
			if readErr == nil {
				// Hitting the server-side limit is ambiguous: it may have clipped
				// a larger log. Never classify a possibly truncated signature.
				if len(body) >= kindRuntimeLogLimit {
					category = "truncated"
				} else {
					category = kindRuntimeLogSignature(body)
				}
			}
		}
		if response.Body.Close() != nil {
			category = "unavailable"
		}
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader(category)), ContentLength: int64(len(category)), Request: request}, nil
}

func kindRuntimeLogClient(config *rest.Config, namespace, name string) (*http.Client, *url.URL, error) {
	if config == nil || config.WrapTransport != nil || config.Transport != nil || config.ExecProvider != nil || config.AuthProvider != nil || config.Dial != nil || config.Proxy != nil || len(validation.IsDNS1123Label(namespace)) != 0 || len(validation.IsDNS1123Subdomain(name)) != 0 {
		return nil, nil, errors.New("runtime diagnostic unavailable")
	}
	base, err := url.Parse(config.Host)
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Path != "" && base.Path != "/" || base.Scheme != "https" && base.Scheme != "http" {
		return nil, nil, errors.New("runtime diagnostic unavailable")
	}
	base.Path = "/api/v1/namespaces/" + namespace + "/pods/" + name + "/log"
	frozen := rest.CopyConfig(config)
	frozen.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return kindRuntimeLogTransport{next, base.Host, base.Path}
	}
	client, err := rest.HTTPClientFor(frozen)
	if err != nil {
		return nil, nil, errors.New("runtime diagnostic unavailable")
	}
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("runtime diagnostic unavailable") }
	return client, base, nil
}

func kindRuntimeGameStatus(pod *corev1.Pod, image string) (corev1.ContainerStatus, bool) {
	var result corev1.ContainerStatus
	if pod == nil || pod.UID == "" || pod.DeletionTimestamp != nil || image == "" {
		return result, false
	}
	containers, statuses := 0, 0
	for _, container := range pod.Spec.Containers {
		if container.Name == "game" {
			if container.Image != image {
				return result, false
			}
			containers++
		}
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "game" {
			result = status
			statuses++
		}
	}
	_, digest, found := strings.Cut(image, "@sha256:")
	return result, containers == 1 && statuses == 1 && found && len(digest) == 64 && strings.Trim(digest, "0123456789abcdef") == "" && result.ContainerID != "" && strings.HasSuffix(result.ImageID, "sha256:"+digest)
}

func kindRuntimeSameSample(original, fresh *corev1.Pod, image string) bool {
	a, okA := kindRuntimeGameStatus(original, image)
	b, okB := kindRuntimeGameStatus(fresh, image)
	return okA && okB && original.UID == fresh.UID && original.Namespace == fresh.Namespace && original.Name == fresh.Name && original.Spec.NodeName == fresh.Spec.NodeName && original.CreationTimestamp.Equal(&fresh.CreationTimestamp) && apiequality.Semantic.DeepEqual(a, b)
}

// The original failing Pod is bracketed by independently fetched samples.
// Replacement, image drift, another restart or changed termination evidence
// makes attribution unknown. This does not retry a workload or change any gate.
func kindRuntimeLogDiagnostic(ctx context.Context, config *rest.Config, original *corev1.Pod, image string, get func(context.Context) (*corev1.Pod, error)) string {
	const unavailable = " logs=[current=unavailable previous=unavailable]"
	if ctx == nil || original == nil || get == nil {
		return unavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// SDK GETs log whole Pod bodies at high verbosity, including arbitrary
	// termination messages/container IDs. Silence these specific diagnostic
	// reads too, and refuse if contextual logging was globally disabled rather
	// than silently falling back to the process logger.
	ctx = klog.NewContext(ctx, logr.Discard())
	if klog.FromContext(ctx).Enabled() {
		return unavailable
	}
	client, endpoint, err := kindRuntimeLogClient(config, original.Namespace, original.Name)
	if err != nil {
		return unavailable
	}
	before, err := get(ctx)
	if err != nil || !kindRuntimeSameSample(original, before, image) {
		return unavailable
	}
	read := func(previous bool) string {
		if previous {
			status, ok := kindRuntimeGameStatus(before, image)
			if !ok || status.RestartCount < 1 || status.LastTerminationState.Terminated == nil {
				return "unavailable"
			}
		}
		u := *endpoint
		value := "false"
		if previous {
			value = "true"
		}
		u.RawQuery = (url.Values{"container": {"game"}, "previous": {value}, "limitBytes": {"65536"}, "timestamps": {"false"}}).Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "unavailable"
		}
		response, err := client.Do(request)
		if err != nil {
			return "unavailable"
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 64))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil {
			return "unavailable"
		}
		switch string(body) {
		case "unknown", "unavailable", "truncated", "save-name-required":
			return string(body)
		default:
			return "unavailable"
		}
	}
	current, previous := read(false), read(true)
	after, err := get(ctx)
	if err != nil || !kindRuntimeSameSample(before, after, image) {
		return " logs=[current=uncorrelated previous=uncorrelated]"
	}
	return " logs=[current=" + current + " previous=" + previous + "]"
}

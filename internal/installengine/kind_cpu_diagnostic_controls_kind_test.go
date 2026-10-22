//go:build kindinstall

package installengine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type kindCPUFakeTransport func(*http.Request) (*http.Response, error)

func (f kindCPUFakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type kindCPUClosedBody struct {
	io.Reader
	closed *int
}

type kindCPUFailedReader struct{}

func (kindCPUFailedReader) Read([]byte) (int, error) {
	return 0, errors.New("private-provider-read /var/run/private")
}

func (b kindCPUClosedBody) Close() error {
	(*b.closed)++
	return nil
}

const kindCPUControlID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const kindCPUControlCluster = "arcadectl-install-auth-0123456789ab"

func kindCPUControlInspect() string {
	return `{"Id":"` + kindCPUControlID + `","Name":"/` + kindCPUControlCluster + `-control-plane","Config":{"Labels":{"io.x-k8s.kind.cluster":"` + kindCPUControlCluster + `"}},"State":{"Running":true,"StartedAt":"2026-10-22T00:00:00Z"},"RestartCount":0,"HostConfig":{"NanoCpus":2000000000,"Memory":3221225472,"MemorySwap":3221225472,"PidsLimit":2048},"UnknownPublicField":"private-provider-canary"}`
}

func kindCPUControlStats() string {
	return `{"id":"` + kindCPUControlID + `","read":"2026-10-22T00:00:01Z","cpu_stats":{"online_cpus":8,"cpu_usage":{"total_usage":100},"throttling_data":{"periods":10,"throttled_periods":3,"throttled_time":50}}}`
}

func kindCPUControlClient(t *testing.T, inspect, stats string, status int, closing ...string) (*http.Client, *int, *int) {
	t.Helper()
	calls, closed := 0, 0
	client := &http.Client{Transport: kindCPUFakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodGet || r.URL.Scheme != "http" || r.URL.Host != "docker" || r.Header.Get("Authorization") != "" || r.Body != nil {
			t.Fatal("diagnostic request escaped its closed read-only contract")
		}
		if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > 5*time.Second || time.Until(deadline) <= 0 {
			t.Fatal("diagnostic request has no bounded live context")
		}
		body := inspect
		expectedPath := "/v1.47/containers/" + kindCPUControlID + "/json"
		if calls%3 == 2 {
			expectedPath = "/v1.47/containers/" + kindCPUControlID + "/stats"
		} else if calls%3 == 0 && len(closing) == 1 {
			body = closing[0]
		}
		if r.URL.Path != expectedPath {
			t.Fatal("stats were not bracketed by inspect")
		}
		switch r.URL.Path {
		case "/v1.47/containers/" + kindCPUControlID + "/json":
			if r.URL.RawQuery != "" {
				t.Fatal("inspect query changed")
			}
		case "/v1.47/containers/" + kindCPUControlID + "/stats":
			if r.URL.RawQuery != "stream=false&one-shot=false" {
				t.Fatal("stats query changed")
			}
			body = stats
		default:
			t.Fatal("diagnostic request escaped exact owned identity")
		}
		return &http.Response{StatusCode: status, Body: kindCPUClosedBody{Reader: strings.NewReader(body), closed: &closed}}, nil
	})}
	return client, &calls, &closed
}

func kindCPUControlHost() ([8]uint64, int, error) { return [8]uint64{10, 2, 3, 40, 5, 6, 7, 8}, 8, nil }

func TestKindCPUResourceDiagnosticActivation(t *testing.T) {
	for _, row := range []struct {
		value                     string
		present, enabled, refused bool
	}{
		{"", false, false, false}, {"1", true, true, false}, {"", true, false, true}, {"0", true, false, true}, {"true", true, false, true},
	} {
		enabled, err := kindCPUEnabled(row.value, row.present)
		if enabled != row.enabled || (err != nil) != row.refused {
			t.Fatal("activation contract changed")
		}
		if err != nil {
			kindCPUControlRefusal(t, err, kindCPUActivation, 0)
		}
	}
	// Calls no diagnostic I/O even when identity would be invalid if activated.
	t.Setenv("ARCADECTL_KIND_CPU_DIAGNOSTICS", "restore-at-cleanup")
	if os.Unsetenv("ARCADECTL_KIND_CPU_DIAGNOSTICS") != nil {
		t.Fatal("control environment unavailable")
	}
	observeKindCPUFixture(t, "invalid", "invalid", 2000000000)
}

func TestKindCPUResourceDiagnosticOwnedReadBounds(t *testing.T) {
	client, calls, closed := kindCPUControlClient(t, kindCPUControlInspect(), kindCPUControlStats(), http.StatusOK)
	for i := 0; i < 2; i++ {
		s, err := kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, 2000000000, kindCPUControlHost)
		if err != nil || s.online != 8 || s.counters.UsageNS != 100 || s.cores != 8 {
			t.Fatal("owned numeric snapshot refused")
		}
	}
	if *calls != 6 || *closed != 6 {
		t.Fatal("two snapshots must join exactly six closed GETs")
	}
}

func TestKindCPUResourceDiagnosticOwnershipAndNumericRefusals(t *testing.T) {
	inspect, stats := kindCPUControlInspect(), kindCPUControlStats()
	rows := []struct{ name, inspect, stats string }{
		{"id", strings.Replace(inspect, kindCPUControlID, "foreign-private-id", 1), stats},
		{"name", strings.Replace(inspect, "-control-plane", "-foreign", 1), stats},
		{"label", strings.Replace(inspect, `"io.x-k8s.kind.cluster":"`+kindCPUControlCluster+`"`, `"io.x-k8s.kind.cluster":"foreign-private-label"`, 1), stats},
		{"running", strings.Replace(inspect, `"Running":true`, `"Running":false`, 1), stats},
		{"epoch", strings.Replace(inspect, "2026-10-22T00:00:00Z", "bad-private-epoch", 1), stats},
		{"stats-id", inspect, strings.Replace(stats, kindCPUControlID, "foreign-private-id", 1)},
		{"stats-id-omitted", inspect, strings.Replace(stats, `"id":"`+kindCPUControlID+`",`, "", 1)},
		{"read", inspect, strings.Replace(stats, "2026-10-22T00:00:01Z", "bad-private-read", 1)},
		{"duplicate", inspect, strings.Replace(stats, `"online_cpus":8`, `"online_cpus":8,"online_cpus":8`, 1)},
		{"malformed", inspect, `{`},
		{"utf8", inspect, "{\"id\":\"\xff\"}"},
		{"body-limit", inspect, strings.Repeat(" ", kindCPUBodyLimit+1)},
	}
	for _, field := range []string{"NanoCpus", "Memory", "MemorySwap", "PidsLimit"} {
		var object map[string]any
		if json.Unmarshal([]byte(inspect), &object) != nil {
			t.Fatal("control fixture invalid")
		}
		object["HostConfig"].(map[string]any)[field] = 1
		body, _ := json.Marshal(object)
		rows = append(rows, struct{ name, inspect, stats string }{field, string(body), stats})
	}
	for _, field := range []struct{ key, value string }{{"total_usage", "100"}, {"periods", "10"}, {"throttled_periods", "3"}, {"throttled_time", "50"}} {
		for _, bad := range []string{`null`, `"100"`, `100.5`, `-1`, `9223372036854775808`, `1e100`} {
			rows = append(rows, struct{ name, inspect, stats string }{field.key + "-" + bad, inspect, strings.Replace(stats, `"`+field.key+`":`+field.value, `"`+field.key+`":`+bad, 1)})
		}
	}
	for _, bad := range []string{`4294967296`, `null`, `"0"`, `-1`, `0.5`} {
		rows = append(rows, struct{ name, inspect, stats string }{"online-" + bad, inspect, strings.Replace(stats, `"online_cpus":8`, `"online_cpus":`+bad, 1)})
	}
	rows = append(rows, struct{ name, inspect, stats string }{"periods", inspect, strings.Replace(stats, `"throttled_periods":3`, `"throttled_periods":11`, 1)})
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			client, calls, closed := kindCPUControlClient(t, row.inspect, row.stats, http.StatusOK)
			_, err := kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, 2000000000, kindCPUControlHost)
			if !errors.Is(err, errKindCPU) {
				t.Fatal("invalid observation accepted or provider error exposed")
			}
			expected := kindCPUStatsNumbers
			if row.name == "stats-id-omitted" {
				expected = kindCPUStatsID
			}
			if stage, ok := map[string]uint16{"id": kindCPUIdentity, "name": kindCPUIdentity, "label": kindCPUIdentity, "running": kindCPUIdentity, "epoch": kindCPUEpoch, "stats-id": kindCPUStatsID, "read": kindCPUStatsRead, "duplicate": kindCPUJSONFailure, "malformed": kindCPUJSONFailure, "utf8": kindCPUJSONFailure, "body-limit": kindCPUSize, "NanoCpus": kindCPUNanoLimit, "Memory": kindCPUMemoryLimit, "MemorySwap": kindCPUSwapLimit, "PidsLimit": kindCPUPIDsLimit}[row.name]; ok {
				expected = stage
			}
			kindCPUControlRefusal(t, err, expected, 0)
			if *calls != *closed || *calls < 1 || *calls > 3 {
				t.Fatal("refusal leaked a response or made extra calls")
			}
		})
	}
}

func TestKindCPUResourceDiagnosticClosingInspectRefusals(t *testing.T) {
	opening, stats := kindCPUControlInspect(), kindCPUControlStats()
	// Larger post-restart counters must not conceal a changed incarnation.
	stats = strings.Replace(stats, `"total_usage":100`, `"total_usage":1000000`, 1)
	for _, row := range []struct{ name, closing string }{
		{"restart-count", strings.Replace(opening, `"RestartCount":0`, `"RestartCount":1`, 1)},
		{"restart-epoch", strings.Replace(opening, "2026-10-22T00:00:00Z", "2026-10-22T00:00:00.5Z", 1)},
		{"id", strings.Replace(opening, kindCPUControlID, "foreign-private-id", 1)},
		{"name", strings.Replace(opening, "-control-plane", "-foreign", 1)},
		{"label", strings.Replace(opening, `"io.x-k8s.kind.cluster":"`+kindCPUControlCluster+`"`, `"io.x-k8s.kind.cluster":"foreign-private-label"`, 1)},
		{"running", strings.Replace(opening, `"Running":true`, `"Running":false`, 1)},
		{"cpu", strings.Replace(opening, `"NanoCpus":2000000000`, `"NanoCpus":4000000000`, 1)},
		{"memory", strings.Replace(opening, `"Memory":3221225472`, `"Memory":6442450944`, 1)},
		{"swap", strings.Replace(opening, `"MemorySwap":3221225472`, `"MemorySwap":6442450944`, 1)},
		{"pids", strings.Replace(opening, `"PidsLimit":2048`, `"PidsLimit":4096`, 1)},
	} {
		t.Run(row.name, func(t *testing.T) {
			client, calls, closed := kindCPUControlClient(t, opening, stats, http.StatusOK, row.closing)
			original := client.Transport
			var snapshotContext context.Context
			client.Transport = kindCPUFakeTransport(func(r *http.Request) (*http.Response, error) {
				if snapshotContext == nil {
					snapshotContext = r.Context()
				} else if snapshotContext != r.Context() {
					t.Fatal("snapshot reads did not share their bounded context")
				}
				return original.RoundTrip(r)
			})
			hostRead := false
			_, err := kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, 2000000000, func() ([8]uint64, int, error) {
				hostRead = true
				return kindCPUControlHost()
			})
			if !errors.Is(err, errKindCPU) || *calls != 3 || *closed != 3 || hostRead {
				t.Fatal("closing identity/caps change accepted or snapshot not joined")
			}
			expected := kindCPUIdentity
			if stage, ok := map[string]uint16{"restart-count": kindCPUClosingDrift, "restart-epoch": kindCPUClosingDrift, "cpu": kindCPUNanoLimit, "memory": kindCPUMemoryLimit, "swap": kindCPUSwapLimit, "pids": kindCPUPIDsLimit}[row.name]; ok {
				expected = stage
			}
			kindCPUControlRefusal(t, err, expected, 0)
		})
	}
}

func TestKindCPUResourceDiagnosticHTTPRefusals(t *testing.T) {
	client, calls, closed := kindCPUControlClient(t, "private-provider-error", "", http.StatusForbidden)
	_, err := kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, 2000000000, kindCPUControlHost)
	if !errors.Is(err, errKindCPU) || *calls != 1 || *closed != 1 {
		t.Fatal("HTTP refusal not bounded and sanitized")
	}
	kindCPUControlRefusal(t, err, kindCPUHTTPStatus, 403)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client = &http.Client{Transport: kindCPUFakeTransport(func(r *http.Request) (*http.Response, error) {
		if r.Context().Err() == nil {
			t.Fatal("cancellation was not propagated")
		}
		return nil, errKindCPU
	})}
	if _, err := kindCPUJSON(ctx, client, kindCPUControlID+"/json"); !errors.Is(err, errKindCPU) {
		t.Fatal("canceled request accepted")
	}
}

func kindCPUControlPair() (kindCPUSnapshot, kindCPUSnapshot) {
	start := time.Now()
	a := kindCPUSnapshot{start: start, end: start.Add(time.Millisecond), read: start, epoch: "private-epoch", online: 8, cores: 8, nanoCPUs: 2000000000,
		counters: kindCPUCounters{UsageNS: 100, Periods: 10, ThrottledPeriods: 3, ThrottledNS: 50}, host: [8]uint64{10, 2, 3, 40, 5, 6, 7, 8}}
	b := a
	b.start, b.end, b.read = start.Add(time.Second), start.Add(time.Second+time.Millisecond), start.Add(time.Second)
	b.counters = kindCPUCounters{UsageNS: 120, Periods: 12, ThrottledPeriods: 4, ThrottledNS: 2000000050}
	for i := range b.host {
		b.host[i]++
	}
	return a, b
}

func TestKindCPUResourceDiagnosticMonotonicityAndPrivacy(t *testing.T) {
	a, b := kindCPUControlPair()
	result, err := kindCPUCompare(a, b)
	if err != nil || result.Status != "observed" || result.Delta.UsageNS != 20 || result.Delta.ThrottledNS != 2000000000 || result.HostTotalDeltaTicks != 8 || result.HostIdleDeltaTicks != 1 || result.HostIOWaitDeltaTicks != 1 || result.ParentElapsedLowerNS != int64(time.Second-time.Millisecond) || result.ParentElapsedUpperNS != int64(time.Second+time.Millisecond) {
		t.Fatal("numeric summary changed or throttle time improperly clamped to wall")
	}
	encoded, _ := json.Marshal(result)
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		t.Fatal("summary not JSON")
	}
	keys := []string{"status", "refusal_stage", "http_status", "nano_cpus", "memory_bytes", "memory_swap_total_bytes", "pids", "docker_online_cpus", "host_runtime_cpus_not_available_capacity", "parent_sampling_elapsed_lower_ns", "parent_sampling_elapsed_upper_ns", "docker_read_timestamp_delta_ns_clock_dependent", "before", "after", "delta", "host_total_delta_ticks", "host_idle_delta_ticks", "host_iowait_delta_ticks"}
	if len(fields) != len(keys) {
		t.Fatal("summary vocabulary widened")
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			t.Fatal("summary vocabulary changed")
		}
	}
	for _, private := range []string{kindCPUControlID, kindCPUControlCluster, "private-epoch", "/proc", "private-provider"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("summary exposed provider data")
		}
	}
	for name, mutate := range map[string]func(*kindCPUSnapshot){
		"cpu-decrease":             func(s *kindCPUSnapshot) { s.counters.UsageNS = 99 },
		"period-decrease":          func(s *kindCPUSnapshot) { s.counters.Periods = 9 },
		"throttle-period-decrease": func(s *kindCPUSnapshot) { s.counters.ThrottledPeriods = 2 },
		"throttle-time-decrease":   func(s *kindCPUSnapshot) { s.counters.ThrottledNS = 49 },
		"throttle-delta":           func(s *kindCPUSnapshot) { s.counters.ThrottledPeriods = 6 },
		"host-decrease":            func(s *kindCPUSnapshot) { s.host[4] = 4 },
		"host-overflow":            func(s *kindCPUSnapshot) { s.host[0], s.host[1] = math.MaxUint64, math.MaxUint64 },
		"restart":                  func(s *kindCPUSnapshot) { s.restarts++ },
		"epoch":                    func(s *kindCPUSnapshot) { s.epoch = "foreign-private-epoch" },
		"online":                   func(s *kindCPUSnapshot) { s.online++ },
		"cores":                    func(s *kindCPUSnapshot) { s.cores++ },
		"read-clock":               func(s *kindCPUSnapshot) { s.read = a.read },
		"overlap":                  func(s *kindCPUSnapshot) { s.start = a.end },
		"snapshot-bound":           func(s *kindCPUSnapshot) { s.end = s.start.Add(6 * time.Second) },
		"end-before-start":         func(s *kindCPUSnapshot) { s.end = s.start.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := b
			mutate(&changed)
			refused, err := kindCPUCompare(a, changed)
			if !errors.Is(err, errKindCPU) || refused != (kindCPUSummary{Status: "refused", RefusalStage: kindCPUComparison}) {
				t.Fatal("invalid sample became partial positive evidence")
			}
		})
	}
}

func TestKindCPUResourceDiagnosticHostProcBounds(t *testing.T) {
	for _, input := range []string{"cpu 1 2 3 4 5 6 7 8 1000 2000\n", "cpu 1 2 3 4 5 6 7 8\n"} {
		ticks, err := kindCPUProc(input)
		if err != nil || ticks != ([8]uint64{1, 2, 3, 4, 5, 6, 7, 8}) {
			t.Fatal("guest double counting or aggregate parser changed")
		}
	}
	for _, input := range []string{"cpu0 1 2 3 4 5 6 7 8", "cpu 1 2 3", "cpu -1 2 3 4 5 6 7 8", "cpu +1 2 3 4 5 6 7 8", "cpu 1.0 2 3 4 5 6 7 8", "cpu 18446744073709551615 2 3 4 5 6 7 8", strings.Repeat(" ", 4097)} {
		_, err := kindCPUProc(input)
		if !errors.Is(err, errKindCPU) {
			t.Fatal("malformed or overflowing host statistic accepted")
		}
		kindCPUControlRefusal(t, err, kindCPUHostFailure, 0)
	}
}

func kindCPUControlRefusal(t *testing.T, err error, stage, status uint16) {
	t.Helper()
	if !errors.Is(err, errKindCPU) || err.Error() != "Kind CPU diagnostic unavailable" {
		t.Fatal("refusal error contract widened")
	}
	result := kindCPURefused(err)
	if result != (kindCPUSummary{Status: "refused", RefusalStage: stage, HTTPStatus: status}) {
		t.Fatal("refusal code changed or numeric evidence leaked")
	}
	encoded, _ := json.Marshal(result)
	for _, forbidden := range []string{kindCPUControlID, kindCPUControlCluster, "private-provider", "/containers", "/var/run"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatal("refusal exposed private data")
		}
	}
}

func TestKindCPUResourceDiagnosticRefusalStages(t *testing.T) {
	stages := []uint16{kindCPUActivation, kindCPUDaemon, kindCPUTransport, kindCPUHTTPStatus, kindCPURead, kindCPUSize, kindCPUJSONFailure, kindCPUIdentity, kindCPUNanoLimit, kindCPUMemoryLimit, kindCPUSwapLimit, kindCPUPIDsLimit, kindCPUEpoch, kindCPUStatsID, kindCPUStatsRead, kindCPUStatsNumbers, kindCPUClosingDrift, kindCPUHostFailure, kindCPUComparison}
	for index, stage := range stages {
		if stage != uint16(index+1) {
			t.Fatal("closed refusal stage numbering changed")
		}
		kindCPUControlRefusal(t, kindCPUFailure(stage), stage, 0)
	}
	for _, row := range []struct{ stage, status, expectedStage, expectedStatus uint16 }{
		{0, 500, 19, 0}, {20, 500, 19, 0}, {4, 99, 4, 0}, {4, 100, 4, 100}, {4, 599, 4, 599}, {4, 600, 4, 0}, {8, 403, 8, 0},
	} {
		kindCPUControlRefusal(t, kindCPURefusal{stage: row.stage, status: row.status}, row.expectedStage, row.expectedStatus)
	}
	// Even an unclassified provider error cannot enter the closed output.
	if kindCPURefused(errors.New("private-provider-id /var/run/private")) != (kindCPUSummary{Status: "refused", RefusalStage: 19}) {
		t.Fatal("unclassified error leaked")
	}
	client := &http.Client{Transport: kindCPUFakeTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("private-provider-id /var/run/private")
	})}
	_, err := kindCPUJSON(context.Background(), client, kindCPUControlID+"/json")
	kindCPUControlRefusal(t, err, kindCPUTransport, 0)
	closed := 0
	client.Transport = kindCPUFakeTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: kindCPUClosedBody{Reader: kindCPUFailedReader{}, closed: &closed}}, nil
	})
	_, err = kindCPUJSON(context.Background(), client, kindCPUControlID+"/json")
	kindCPUControlRefusal(t, err, kindCPURead, 0)
	if closed != 1 {
		t.Fatal("read refusal did not close response")
	}
	client, calls, bodies := kindCPUControlClient(t, kindCPUControlInspect(), kindCPUControlStats(), http.StatusOK)
	_, err = kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, 2000000000, func() ([8]uint64, int, error) {
		return [8]uint64{}, 0, errors.New("private-provider-host /proc/private")
	})
	kindCPUControlRefusal(t, err, kindCPUHostFailure, 0)
	if *calls != 3 || *bodies != 3 {
		t.Fatal("host refusal did not join snapshot")
	}
}

func TestKindCPUResourceDiagnosticOptionalOnlineCPU(t *testing.T) {
	for _, row := range []struct{ name, stats string }{
		{"omitted", strings.Replace(kindCPUControlStats(), `"online_cpus":8,`, "", 1)},
		{"zero", strings.Replace(kindCPUControlStats(), `"online_cpus":8`, `"online_cpus":0`, 1)},
	} {
		t.Run(row.name, func(t *testing.T) {
			client, calls, closed := kindCPUControlClient(t, kindCPUControlInspect(), row.stats, http.StatusOK)
			for i := 0; i < 2; i++ {
				snapshot, err := kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, 2000000000, kindCPUControlHost)
				if err != nil || snapshot.online != 0 || snapshot.counters.UsageNS != 100 {
					t.Fatal("valid unavailable online CPU observation refused")
				}
			}
			if *calls != 6 || *closed != 6 {
				t.Fatal("optional field changed snapshot request bounds")
			}
			a, b := kindCPUControlPair()
			a.online, b.online = 0, 0
			result, err := kindCPUCompare(a, b)
			if err != nil || result.Status != "observed" || result.OnlineCPUs != 0 {
				t.Fatal("unavailable online CPUs substituted or refused")
			}
			b.online = 8
			_, err = kindCPUCompare(a, b)
			kindCPUControlRefusal(t, err, kindCPUComparison, 0)
		})
	}
}

func TestKindCPUResourceDiagnosticQuota(t *testing.T) {
	for _, row := range []struct {
		value             string
		present           bool
		diagnostic        string
		diagnosticPresent bool
		quota             string
		nanoCPUs          uint64
	}{
		{"", false, "", false, "2", 2000000000},
		{"", false, "1", true, "2", 2000000000},
		{"2", true, "1", true, "2", 2000000000},
		{"3", true, "1", true, "3", 3000000000},
	} {
		quota, nanoCPUs, err := kindCPUQuota(row.value, row.present, row.diagnostic, row.diagnosticPresent)
		if err != nil || quota != row.quota || nanoCPUs != row.nanoCPUs {
			t.Fatal("closed quota selection changed")
		}
	}
	for _, value := range []string{"", "1", "4", "02", "+2", "2.0", " 2", "3 ", "-1", "max"} {
		quota, nanoCPUs, err := kindCPUQuota(value, true, "1", true)
		kindCPUControlRefusal(t, err, kindCPUActivation, 0)
		if quota != "" || nanoCPUs != 0 {
			t.Fatal("invalid quota returned a resource override")
		}
	}
	for _, row := range []struct {
		value   string
		present bool
	}{{"", false}, {"", true}, {"0", true}, {"true", true}} {
		_, _, err := kindCPUQuota("3", true, row.value, row.present)
		kindCPUControlRefusal(t, err, kindCPUActivation, 0)
	}
	for _, row := range []struct {
		quota    string
		nanoCPUs uint64
	}{{"2", 2000000000}, {"3", 3000000000}} {
		t.Run(row.quota, func(t *testing.T) {
			t.Setenv("ARCADECTL_KIND_CPU_DIAGNOSTICS", "1")
			t.Setenv("ARCADECTL_KIND_CPU_QUOTA", row.quota)
			quota, nanoCPUs := kindCPUFixtureQuota(t)
			if quota != row.quota || nanoCPUs != row.nanoCPUs {
				t.Fatal("fixture quota did not preserve immutable selection")
			}
			inspect := strings.Replace(kindCPUControlInspect(), `"NanoCpus":2000000000`, `"NanoCpus":`+row.quota+`000000000`, 1)
			client, calls, closed := kindCPUControlClient(t, inspect, kindCPUControlStats(), http.StatusOK)
			for i := 0; i < 2; i++ {
				snapshot, err := kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, nanoCPUs, kindCPUControlHost)
				if err != nil || snapshot.nanoCPUs != nanoCPUs {
					t.Fatal("matching selected quota refused or replaced")
				}
			}
			if *calls != 6 || *closed != 6 {
				t.Fatal("quota changed snapshot read bounds")
			}
			a, b := kindCPUControlPair()
			a.nanoCPUs, b.nanoCPUs = nanoCPUs, nanoCPUs
			result, err := kindCPUCompare(a, b)
			if err != nil || result.NanoCPUs != nanoCPUs {
				t.Fatal("summary did not emit validated selected quota")
			}
			b.nanoCPUs = 5000000000 - nanoCPUs
			_, err = kindCPUCompare(a, b)
			kindCPUControlRefusal(t, err, kindCPUComparison, 0)
			otherQuota := uint64(5000000000) - nanoCPUs
			client, calls, closed = kindCPUControlClient(t, inspect, kindCPUControlStats(), http.StatusOK)
			_, err = kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, otherQuota, kindCPUControlHost)
			kindCPUControlRefusal(t, err, kindCPUNanoLimit, 0)
			if *calls != 1 || *closed != 1 {
				t.Fatal("mismatched quota made extra reads")
			}
		})
	}
	// A forged expectation cannot expand the closed two/three-CPU experiment.
	client, calls, closed := kindCPUControlClient(t, kindCPUControlInspect(), kindCPUControlStats(), http.StatusOK)
	_, err := kindCPUObserve(client, kindCPUControlID, kindCPUControlCluster, 4000000000, kindCPUControlHost)
	kindCPUControlRefusal(t, err, kindCPUNanoLimit, 0)
	if *calls != 0 || *closed != 0 {
		t.Fatal("invalid expectation reached Docker")
	}
}

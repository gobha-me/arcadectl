//go:build kindinstall

package installengine

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	strictjson "sigs.k8s.io/json"
)

const kindCPUBodyLimit = 64 << 10

var errKindCPU = errors.New("Kind CPU diagnostic unavailable")

// Closed refusal vocabulary; never include a provider error or response text.
const (
	kindCPUActivation uint16 = iota + 1
	kindCPUDaemon
	kindCPUTransport
	kindCPUHTTPStatus
	kindCPURead
	kindCPUSize
	kindCPUJSONFailure
	kindCPUIdentity
	kindCPUNanoLimit
	kindCPUMemoryLimit
	kindCPUSwapLimit
	kindCPUPIDsLimit
	kindCPUEpoch
	kindCPUStatsID
	kindCPUStatsRead
	kindCPUStatsNumbers
	kindCPUClosingDrift
	kindCPUHostFailure
	kindCPUComparison
)

type kindCPURefusal struct{ stage, status uint16 }

func (kindCPURefusal) Error() string    { return errKindCPU.Error() }
func (kindCPURefusal) Unwrap() error    { return errKindCPU }
func kindCPUFailure(stage uint16) error { return kindCPURefusal{stage: stage} }

func kindCPURefused(err error) kindCPUSummary {
	reason := kindCPURefusal{stage: kindCPUComparison}
	var classified kindCPURefusal
	if errors.As(err, &classified) && classified.stage >= kindCPUActivation && classified.stage <= kindCPUComparison {
		reason = classified
	}
	if reason.stage != kindCPUHTTPStatus || reason.status < 100 || reason.status > 599 {
		reason.status = 0
	}
	return kindCPUSummary{Status: "refused", RefusalStage: reason.stage, HTTPStatus: reason.status}
}

// API v1.47: NanoCpus is 1e-9 CPUs; memory/swap are bytes. Linux CPU
// total_usage and aggregate throttled_time are nanoseconds, NOT lost wall time.
// https://github.com/moby/moby/blob/v27.5.1/api/types/container/stats.go
// https://github.com/moby/moby/blob/v27.5.1/api/swagger.yaml
type kindCPUCounters struct {
	UsageNS          uint64 `json:"usage_ns"`
	Periods          uint64 `json:"periods"`
	ThrottledPeriods uint64 `json:"throttled_periods"`
	ThrottledNS      uint64 `json:"throttled_ns"`
}

type kindCPUSnapshot struct {
	start, end time.Time
	read       time.Time
	epoch      string
	restarts   uint64
	online     uint64
	counters   kindCPUCounters
	host       [8]uint64
	cores      int
}

// Closed output: no provider-controlled strings, identifiers, labels or paths.
// Parent sampling bounds are NOT atomic Docker/host observation bounds.
type kindCPUSummary struct {
	Status               string          `json:"status"`
	RefusalStage         uint16          `json:"refusal_stage"`
	HTTPStatus           uint16          `json:"http_status"`
	NanoCPUs             uint64          `json:"nano_cpus"`
	MemoryBytes          uint64          `json:"memory_bytes"`
	MemorySwapTotalBytes uint64          `json:"memory_swap_total_bytes"`
	PIDs                 uint64          `json:"pids"`
	OnlineCPUs           uint64          `json:"docker_online_cpus"` // 0 = unavailable, never host capacity.
	RuntimeCPUs          int             `json:"host_runtime_cpus_not_available_capacity"`
	ParentElapsedLowerNS int64           `json:"parent_sampling_elapsed_lower_ns"`
	ParentElapsedUpperNS int64           `json:"parent_sampling_elapsed_upper_ns"`
	DockerReadDeltaNS    int64           `json:"docker_read_timestamp_delta_ns_clock_dependent"`
	Before               kindCPUCounters `json:"before"`
	After                kindCPUCounters `json:"after"`
	Delta                kindCPUCounters `json:"delta"`
	HostTotalDeltaTicks  uint64          `json:"host_total_delta_ticks"`
	HostIdleDeltaTicks   uint64          `json:"host_idle_delta_ticks"`
	HostIOWaitDeltaTicks uint64          `json:"host_iowait_delta_ticks"`
}

func kindCPUEnabled(value string, present bool) (bool, error) {
	if !present {
		return false, nil
	}
	if value != "1" {
		return false, kindCPUFailure(kindCPUActivation)
	}
	return true, nil
}

func observeKindCPUFixture(t *testing.T, id, cluster string) {
	t.Helper()
	enabled, err := kindCPUEnabled(os.LookupEnv("ARCADECTL_KIND_CPU_DIAGNOSTICS"))
	if !enabled && err == nil {
		return // Inactive means no extra socket, filesystem, or API reads.
	}
	emit := func(s kindCPUSummary, failure error) {
		if failure != nil {
			s = kindCPURefused(failure)
		}
		encoded, _ := json.Marshal(s)
		t.Logf("Kind CPU diagnostic: %s", encoded)
		if failure != nil {
			t.Error(errKindCPU.Error())
		}
	}
	if err != nil {
		emit(kindCPUSummary{}, err)
		t.FailNow()
		return
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) || !regexp.MustCompile(`^arcadectl-install-auth-[a-f0-9]{12}$`).MatchString(cluster) {
		emit(kindCPUSummary{}, kindCPUFailure(kindCPUIdentity))
		t.FailNow()
		return
	}
	// Never silently select another daemon, TLS endpoint, proxy, or context.
	for _, key := range []string{"DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"} {
		if os.Getenv(key) != "" {
			emit(kindCPUSummary{}, kindCPUFailure(kindCPUDaemon))
			t.FailNow()
			return
		}
	}
	if host := os.Getenv("DOCKER_HOST"); host != "" && host != "unix:///var/run/docker.sock" {
		emit(kindCPUSummary{}, kindCPUFailure(kindCPUDaemon))
		t.FailNow()
		return
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/var/run/docker.sock")
	}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errKindCPU }}
	before, err := kindCPUObserve(client, id, cluster, kindCPUHost)
	if err != nil {
		transport.CloseIdleConnections()
		emit(kindCPUSummary{}, err)
		t.FailNow()
		return
	}
	// Registered after the limits and existing teardown, so this executes first.
	// The fixture's test context may already be canceled during Cleanup.
	t.Cleanup(func() {
		defer transport.CloseIdleConnections()
		after, failure := kindCPUObserve(client, id, cluster, kindCPUHost)
		result := kindCPUSummary{Status: "refused"}
		if failure == nil {
			result, failure = kindCPUCompare(before, after)
		}
		emit(result, failure)
	})
}

func kindCPUJSON(ctx context.Context, client *http.Client, path string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.47/containers/"+path, nil)
	if err != nil {
		return nil, kindCPUFailure(kindCPUTransport)
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, kindCPUFailure(kindCPUTransport)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, kindCPUBodyLimit+1))
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusOK {
		status := uint16(0)
		if response.StatusCode >= 100 && response.StatusCode <= 599 {
			status = uint16(response.StatusCode)
		}
		return nil, kindCPURefusal{stage: kindCPUHTTPStatus, status: status}
	}
	if readErr != nil || closeErr != nil || ctx.Err() != nil {
		return nil, kindCPUFailure(kindCPURead)
	}
	if response.ContentLength > kindCPUBodyLimit || len(body) > kindCPUBodyLimit {
		return nil, kindCPUFailure(kindCPUSize)
	}
	if !utf8.Valid(body) {
		return nil, kindCPUFailure(kindCPUJSONFailure)
	}
	var fields map[string]any
	strict, err := strictjson.UnmarshalStrict(body, &fields)
	if err != nil || len(strict) != 0 || fields == nil {
		return nil, kindCPUFailure(kindCPUJSONFailure)
	}
	return fields, nil
}

func kindCPUField(fields map[string]any, keys ...string) any {
	var value any = fields
	for _, key := range keys {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[key]
	}
	return value
}

func kindCPUNumber(value any) (uint64, bool) {
	n, ok := value.(int64) // Reject floats, strings, negatives and >MaxInt64.
	return uint64(n), ok && n >= 0
}

func kindCPUInspect(ctx context.Context, client *http.Client, id, cluster string) (string, uint64, error) {
	inspect, err := kindCPUJSON(ctx, client, id+"/json")
	if err != nil {
		return "", 0, err
	}
	if kindCPUField(inspect, "Id") != id || kindCPUField(inspect, "Name") != "/"+cluster+"-control-plane" || kindCPUField(inspect, "Config", "Labels", "io.x-k8s.kind.cluster") != cluster || kindCPUField(inspect, "State", "Running") != true {
		return "", 0, kindCPUFailure(kindCPUIdentity)
	}
	for _, cap := range []struct {
		key      string
		expected uint64
		stage    uint16
	}{
		{"NanoCpus", 2000000000, kindCPUNanoLimit}, {"Memory", 3221225472, kindCPUMemoryLimit}, {"MemorySwap", 3221225472, kindCPUSwapLimit}, {"PidsLimit", 2048, kindCPUPIDsLimit},
	} {
		if value, ok := kindCPUNumber(kindCPUField(inspect, "HostConfig", cap.key)); !ok || value != cap.expected {
			return "", 0, kindCPUFailure(cap.stage)
		}
	}
	epoch, _ := kindCPUField(inspect, "State", "StartedAt").(string)
	started, err := time.Parse(time.RFC3339Nano, epoch)
	restarts, ok := kindCPUNumber(inspect["RestartCount"])
	if err != nil || started.IsZero() || !ok {
		return "", 0, kindCPUFailure(kindCPUEpoch)
	}
	return epoch, restarts, nil
}

func kindCPUObserve(client *http.Client, id, cluster string, host func() ([8]uint64, int, error)) (kindCPUSnapshot, error) {
	s := kindCPUSnapshot{start: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	s.epoch, s.restarts, err = kindCPUInspect(ctx, client, id, cluster)
	if err != nil {
		return s, err
	}
	epoch, _ := time.Parse(time.RFC3339Nano, s.epoch)
	// The non-stream sampler attaches the container ID; Moby's one-shot
	// branch can omit it. Keep mandatory response identity, not a looser check.
	// https://github.com/moby/moby/blob/v27.5.1/daemon/stats.go
	stats, err := kindCPUJSON(ctx, client, id+"/stats?stream=false&one-shot=false")
	if err != nil {
		return s, err
	}
	if stats["id"] != id {
		return s, kindCPUFailure(kindCPUStatsID)
	}
	read, _ := stats["read"].(string)
	s.read, err = time.Parse(time.RFC3339Nano, read)
	if err != nil || s.read.Year() < 1970 || s.read.Year() > 2200 || s.read.Before(epoch) {
		return s, kindCPUFailure(kindCPUStatsRead)
	}
	// The API declares this field optional. Only absence or literal integer
	// zero means unavailable; null is invalid, and host capacity is not inferred.
	if cpu, ok := stats["cpu_stats"].(map[string]any); ok {
		if value, present := cpu["online_cpus"]; present {
			var valid bool
			s.online, valid = kindCPUNumber(value)
			if !valid || s.online > math.MaxUint32 {
				return s, kindCPUFailure(kindCPUStatsNumbers)
			}
		}
	}
	for _, entry := range []struct {
		out *uint64
		key []string
	}{
		{&s.counters.UsageNS, []string{"cpu_stats", "cpu_usage", "total_usage"}},
		{&s.counters.Periods, []string{"cpu_stats", "throttling_data", "periods"}},
		{&s.counters.ThrottledPeriods, []string{"cpu_stats", "throttling_data", "throttled_periods"}},
		{&s.counters.ThrottledNS, []string{"cpu_stats", "throttling_data", "throttled_time"}},
	} {
		value, ok := kindCPUNumber(kindCPUField(stats, entry.key...))
		if !ok {
			return s, kindCPUFailure(kindCPUStatsNumbers)
		}
		*entry.out = value
	}
	if s.counters.ThrottledPeriods > s.counters.Periods {
		return s, kindCPUFailure(kindCPUStatsNumbers)
	}
	// A restart or resource/ownership change during stats must not turn a newer
	// counter value into evidence for the opening incarnation or resource caps.
	closingEpoch, closingRestarts, err := kindCPUInspect(ctx, client, id, cluster)
	if err != nil {
		return s, err
	}
	if closingEpoch != s.epoch || closingRestarts != s.restarts {
		return s, kindCPUFailure(kindCPUClosingDrift)
	}
	s.host, s.cores, err = host()
	s.end = time.Now()
	if err != nil || s.cores <= 0 || ctx.Err() != nil || s.end.Sub(s.start) > 5*time.Second {
		return s, kindCPUFailure(kindCPUHostFailure)
	}
	return s, nil
}

// Linux aggregate USER_HZ ticks: first eight fields only, excluding guest
// double counting. Iowait can decrease; such samples are refused, not clamped.
// https://docs.kernel.org/filesystems/proc.html
func kindCPUProc(line string) ([8]uint64, error) {
	var ticks [8]uint64
	fields := strings.Fields(line)
	if len(line) > 4096 || len(fields) < 9 || fields[0] != "cpu" {
		return ticks, kindCPUFailure(kindCPUHostFailure)
	}
	var total uint64
	for i := range ticks {
		value, err := strconv.ParseUint(fields[i+1], 10, 64)
		if err != nil || strings.HasPrefix(fields[i+1], "+") || math.MaxUint64-total < value {
			return [8]uint64{}, kindCPUFailure(kindCPUHostFailure)
		}
		ticks[i], total = value, total+value
	}
	return ticks, nil
}

func kindCPUHost() ([8]uint64, int, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return [8]uint64{}, 0, kindCPUFailure(kindCPUHostFailure)
	}
	line, readErr := bufio.NewReader(io.LimitReader(file, 4097)).ReadString('\n')
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return [8]uint64{}, 0, kindCPUFailure(kindCPUHostFailure)
	}
	ticks, err := kindCPUProc(line)
	return ticks, runtime.NumCPU(), err
}

func kindCPUCompare(a, b kindCPUSnapshot) (kindCPUSummary, error) {
	failure := kindCPUFailure(kindCPUComparison)
	refused := kindCPURefused(failure)
	lower, upper := b.start.Sub(a.end), b.end.Sub(a.start)
	readDelta := b.read.Sub(a.read)
	if a.start.After(a.end) || b.start.After(b.end) || a.end.Sub(a.start) > 5*time.Second || b.end.Sub(b.start) > 5*time.Second || lower <= 0 || upper < lower || upper == time.Duration(math.MaxInt64) || readDelta <= 0 || readDelta == time.Duration(math.MaxInt64) || a.epoch == "" || a.epoch != b.epoch || a.restarts != b.restarts || a.online != b.online || a.cores <= 0 || a.cores != b.cores {
		return refused, failure
	}
	delta := kindCPUCounters{}
	for _, entry := range []struct {
		before, after uint64
		out           *uint64
	}{
		{a.counters.UsageNS, b.counters.UsageNS, &delta.UsageNS},
		{a.counters.Periods, b.counters.Periods, &delta.Periods},
		{a.counters.ThrottledPeriods, b.counters.ThrottledPeriods, &delta.ThrottledPeriods},
		{a.counters.ThrottledNS, b.counters.ThrottledNS, &delta.ThrottledNS},
	} {
		if entry.after < entry.before {
			return refused, failure
		}
		*entry.out = entry.after - entry.before
	}
	if a.counters.ThrottledPeriods > a.counters.Periods || b.counters.ThrottledPeriods > b.counters.Periods || delta.ThrottledPeriods > delta.Periods {
		return refused, failure
	}
	var hostTotal uint64
	for i := range a.host {
		if b.host[i] < a.host[i] || math.MaxUint64-hostTotal < b.host[i]-a.host[i] {
			return refused, failure
		}
		hostTotal += b.host[i] - a.host[i]
	}
	if hostTotal == 0 {
		return refused, failure
	}
	return kindCPUSummary{Status: "observed", NanoCPUs: 2000000000, MemoryBytes: 3221225472, MemorySwapTotalBytes: 3221225472, PIDs: 2048,
		OnlineCPUs: a.online, RuntimeCPUs: a.cores, ParentElapsedLowerNS: int64(lower), ParentElapsedUpperNS: int64(upper), DockerReadDeltaNS: int64(readDelta), Before: a.counters, After: b.counters, Delta: delta,
		HostTotalDeltaTicks: hostTotal, HostIdleDeltaTicks: b.host[3] - a.host[3], HostIOWaitDeltaTicks: b.host[4] - a.host[4]}, nil
}

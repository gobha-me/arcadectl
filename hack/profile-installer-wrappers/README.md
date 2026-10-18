# Installer wrapper cost screen

## Opt-in native component diagnostic

`go run -p 1 ./hack/profile-installer-wrappers native-component FULL_SOURCE_SHA`
compiles the tagged test binary and runs exactly one fresh
`TestKindAdmissionEffectiveV3WithBaseline/kubernetes-1.37.0/warm` proof. It uses
the test package working directory and retains the existing 40-minute fixture
and 45-minute Go-test limits, all 55 cases, original/closing checks, fixture
retirement, journal/baseline assertions and owned cleanup. The new diagnostic
launcher has a separate finite compile/capture/analysis envelope; it does not
change a production, full-transition or ordinary component deadline.

`native-component-v2 FULL_SOURCE_SHA` runs the SAME proof and budgets but emits
explicit `arcadectl-native-component-screen-v2` (or v2 refusal) records using
50 exact symbols, adding collection and defensive-copy attribution. The original
`native-component` mode and its 36-symbol v1 records remain unchanged. Both
versions' cumulative rows overlap; nested collection/copy rows are not additive.

CPU and allocation profiles from that ONE execution supply four synchronous
views: complete driver, phase observation, engine request and observer transport.
The native catalogue freezes the previous v3 exact symbols plus the complete
driver symbol; default synthetic v1 output and catalogue stay unchanged. Raw
profiles/transcripts remain bounded RAM-only and are wiped, with the existing
sealed-memfd and joined-child protections. Refusals never export provider text.

This is real Kind **Install-mode component** work with directly prepared journal
stages and separately installed baseline policies. It is NOT an actual CLI
Upgrade, historical enrollment, identical first-upgrade state, transition
completion, RKE2 or release certification. It cannot discharge the unfinished
full transition/uninstall gate. Root views omit async/remote CPU and waits;
sampled allocations and rounded overlapping cumulative rows are not exclusive
wall time, a proven bottleneck or a performance cure.

The temporary diagnostic workflow additionally compares a TEST-ONLY public JSON
validation-without-graph candidate against the unchanged production parser, with
explicit depth/node/decoded-key/UTF8/EOF cases, a bounded differential fuzz run,
and paired whole-validation benchmarks over synthetic public Kubernetes pages.
Neither production transport nor metadata envelope/redaction is changed. Parser
microbenchmarks do not establish a native lifecycle or transition speedup.

Linux-only, opt-in CI diagnostic. From the clean repository root:

```sh
GOMAXPROCS=2 GOMEMLIMIT=1GiB go run -p 1 ./hack/profile-installer-wrappers "$(git rev-parse HEAD)"
```

Compilation, the two existing test roots (16 fresh executions each), and profile
analysis run sequentially. The original behavioral/request/no-effect/WAL/read
oracles remain unchanged. This does not replace any race or native lifecycle
proof, nor certify release or cluster compatibility. Do not run in a constrained
shared pod without the approved build headroom.

CPU and sampled allocation profiles stream through bounded pipes into RAM.
Analysis uses a sealed anonymous memfd, not a persistent raw profile, HTTP
endpoint, or a pipe that pprof's format probe could partially consume. All child
stdout/stderr is bounded and private. Only source/binary/profile hashes, byte
counts, fixed function IDs and numerical measurements are printed. Temporary
compiled binaries are removed from the exact owned directory on exit.

Failure output is a separate closed refusal record: fixed stage/target/metric,
child exit/deadline/cancellation classification, bounded capture hashes/lengths,
truncation and Go-test timeout flags, and fixed-root RUN/PASS occurrence counts.
When truncated, capture hashes describe only the retained prefix, not the full
discarded stream. No raw capture is replayed after refusal.
No underlying error text is included. These counters diagnose incomplete runs;
they do not replace the complete successful transcript/oracle check. A refused
screen must not be treated as a zero-cost result or a lifecycle pass.

The pprof table reader treats only the first five fields as numeric columns;
the complete remaining function name may contain spaces (for example Go generic
shapes). Full-name matching prevents a name with an allowlisted prefix from
being exported as that function. Projection refusals name only the closed
numeric/header/type/duplicate/root category, never the rejected row.

Each metric focuses on synchronous stacks containing its production root:
`ClusterSecurityBaseline.Verify` or `fixtureWire.observePhaseLocked`. Unmatched
flat values are reported separately; missing rows mean unsampled/absent, not
zero. Values are pprof's formatted/rounded numbers, not lossless integer
accounting. Cumulative values overlap and must not be added. Allocation weights are
sampling estimates at rate 8192, not exact allocation counts. Profiling itself
perturbs CPU. Setup, asynchronous descendants, synthetic server goroutines,
remote work and wall-clock waiting are outside this focused accounting. Wall
duration covers the repeated test process, including setup and profiling.

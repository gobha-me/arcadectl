# Installer wrapper cost screen

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

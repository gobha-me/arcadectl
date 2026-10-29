# Health signals and observability scope

Tracking: [#38](https://github.com/gobha-me/arcadectl/issues/38).

Controller `/healthz` reports process liveness. `/readyz` requires the informer
families watched by that controller mode to synchronize. The watch families are
registered before the manager starts, so an empty cache cannot satisfy the
readiness check before controller sources are registered. Normal and destroy
controllers retain their separate watch sets and Kubernetes authorities.

Each readiness request has a one-second cache wait and ends when its request or
manager lifecycle ends. Failures return a fixed message, without API errors,
object names, or credential material. Readiness does not assert that every game
world is healthy, that a backup is verified, or that this replica is the elected
leader. Native installer proofs still verify the exact original controllers,
leaders, workloads and admission behavior independently.

The API retains its separate `/livez` and `/readyz` checks. API readiness requires
its authentication dependencies; a process responding to liveness alone is not
ready for administration. The private health ports are not player endpoints or
public Service ports.

Both controller modes and the API have a startup probe against their process
liveness endpoint, with 30 attempts at two-second intervals and a one-second
per-request timeout. This lets the process start before ordinary liveness and
readiness probing begins. Failure to synchronize caches keeps readiness false;
it does not convert a dependency failure into a process-liveness failure.

Initial operator signals:

| Signal | Interpretation / action |
| --- | --- |
| Liveness unavailable during startup | Inspect bounded startup progress and container termination state. |
| Liveness available, readiness false | Inspect CRD availability, namespace RBAC, API connectivity and informer synchronization. Preserve worlds; do not treat this as destroy authorization. |
| Controller ready, one GameServer condition false | Use that condition's stable reason and recovery guidance. Controller readiness is not game readiness. |
| API ready, an operation fails | Inspect the exact operation receipt and native child; request timeout does not cancel admitted work. |

## Bounded lifecycle metrics

The existing private controller metrics endpoint also exports these families:

| Family | Labels | Meaning |
| --- | --- | --- |
| `arcadectl_operation_completions_total` | `kind`, `action`, `result` | First locally observed successful status write from nonterminal to terminal. |
| `arcadectl_operation_duration_seconds` | `kind`, `action`, `result` | Persisted start-to-completion duration; absent/zero/reversed timestamps omit the duration sample. |
| `arcadectl_server_condition_transitions_total` | `condition`, `status`, `class` | Successfully persisted changes in a current server condition's status or reason. |

`kind` is `receipt`, `backup`, `restore`, or `destroy`. Receipt actions are the
twelve stable ordinary lifecycle actions plus `unknown`; native kinds each use
one fixed action. Results are `succeeded`, `failed`, or `cancelled`. Receipt and
native-child samples describe different boundaries and must not be added to
estimate a number of user intents or combined into one latency distribution.

Condition labels use only the six canonical GameServer condition types, three
statuses (`true`, `false`, `unknown`), and fixed diagnostic classes:
`validation`, `dependency`, `storage`, `retained-data`, `configuration`,
`workload`, `network`, `collision`, `progress`, `healthy`, or `unknown`.
Unrecognized reason text maps to `unknown`; arbitrary condition types and
statuses are omitted. Object names, namespace names, UIDs, adapter IDs, error
messages and credentials are never labels. Identical status/reason rechecks do
not increment the transition counter. A condition carrying an older generation
is not presented as a current transition.

Operation durations use buckets at 1, 5, 15, 30, 60, 120, 300, 900, 1800, 3600,
21600 and 86400 seconds, plus infinity. These are observation buckets, not
completion deadlines or promises. Failed Kubernetes status writes produce no
success/transition samples. Existing lifecycle validation, data guards,
authorization, retries and deadlines remain authoritative.

These process-local metrics reset on restart and can undercount across crashes,
ambiguous committed writes or scrape loss. They are not a durable audit log,
an exhaustive fleet inventory, a ready-server gauge, or release evidence.
Readiness endpoints and exact persisted operation receipts retain their own
semantics. No extra Kubernetes authority, event writer, Secret read, log
collection or public metrics exposure is added.

## Initial indicators and alert guidance

Track receipt success/failure rates separately from deliberate cancellations:

```promql
sum(rate(arcadectl_operation_completions_total{kind="receipt",result="failed"}[30m]))
/
clamp_min(sum(rate(arcadectl_operation_completions_total{kind="receipt",result=~"succeeded|failed"}[30m])), 1e-9)
```

Inspect latency by action and boundary, rather than aggregating backup time
with quick state changes:

```promql
histogram_quantile(0.95, sum by (le, action) (rate(arcadectl_operation_duration_seconds_bucket{kind="receipt",result="succeeded"}[1h])))
```

An increase in `arcadectl_server_condition_transitions_total{class="collision"}`
calls for ownership inspection, never automatic adoption or deletion. Storage,
network, workload and retained-data class increases guide triage; pair them
with current CLI conditions and observed generations before acting. These
counters do not report the number of currently broken servers. Require enough
samples and an environment-specific baseline before selecting numerical alert
thresholds. No production availability SLO is established by these metrics.

Metric names, label keys and finite vocabularies form the initial schema.
Adding a family or a fixed class is additive; removing/renaming one or changing
its counting boundary requires dashboard/alert migration and a documented
compatibility decision. Never add object identifiers or raw reason strings as
labels to improve drill-down.

The #38 structured event/log correlation schema, API authorization metrics, and
integration with the complete redacted diagnostics bundle remain acceptance
work. Health and lifecycle telemetry alone do not complete that issue.

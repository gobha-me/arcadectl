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

## Structured lifecycle log schema

Successfully persisted operation completions and current server condition
changes also emit structured Info records through a dedicated `lifecycle`
process logger. The logger deliberately does not inherit per-request object
names, namespace names or arbitrary context fields. Records contain no raw
errors, condition messages, annotations, settings, Secret data or credentials.

All records use `schema: arcadectl.lifecycle-log/v1`. The `operation_completed`
event includes fixed `kind`, `action` and `result` vocabularies matching the
metrics. The `server_condition_changed` event includes a canonical `condition`,
fixed `status`, diagnostic `class`, generation and a closed reason code.
Unrecognized reason text becomes `Unknown`. Only successfully persisted
transitions emit records; unchanged or stale observations do not become events.

The `correlation` field is the first 32 lowercase hexadecimal characters of
SHA-256 over the object's UTF-8 UID, or `unknown` for an absent UID. Compute the
same value from a server/operation/native-child UID returned by the CLI/API to
find its records. Receipt and child UIDs identify different boundaries; follow
the exact child reference rather than assuming their correlation fields match.
Correlation is a diagnostic key, not an authorization token or proof of object
ownership. Hashing also prevents a malformed input UID from becoming raw log
text. No UID, correlation or object name is a metric label.

Process timestamps and logger framing are outside this event schema. Event
fields and counting boundaries have the same migration expectations as metric
labels. Log delivery is best effort and can be lost after a committed status
write; the durable object status and API audit remain authoritative. No
Kubernetes Event object or additional Kubernetes permission is created.

## Private API request metrics

The API's existing private health listener also serves `GET /metrics` (and
`HEAD`). It has no public Service route. Keep this port in the administrative
network boundary; do not expose it as a player or public endpoint. Scrapes
require no administrator token and cannot invoke API operations. The ordinary
TLS API listener retains authentication and never serves the scrape handler.

| Family | Labels | Meaning |
| --- | --- | --- |
| `arcadectl_api_requests_total` | `action`, `result`, `audit` | Requests reaching the guarded handler's outcome boundary. |
| `arcadectl_api_request_duration_seconds` | `action`, `result`, `audit` | Handler time including the bounded outcome-audit wait. |

Actions are the enumerated API actions, or `unmatched` before an authenticated
route is selected. Authentication failures cannot disclose which resource or
action the caller requested. Results are `unauthenticated`, `unavailable`,
`forbidden`, `succeeded`, `rejected`, `internal`, or the defensive `unknown`.
The audit label is `acknowledged` or `unavailable`, describing the outcome
record's acknowledgement separately from the response already sent. A failed
outcome audit after an applied mutation therefore retains `succeeded` alongside
`audit="unavailable"`; it does not imply that the mutation can be replayed.
Subsequent requests remain fenced by the existing audit guard.

No URL, method, principal, credential ID, namespace, object name, request ID,
body, token, error text or arbitrary route pattern becomes a label. Each API
boundary has an isolated registry containing only these two families, without
Go/process collectors or custom caller-provided collectors. Scrapes are not
counted as API requests. Process restarts reset counters. Failure to obtain the
initial random request ID occurs before this outcome boundary and is not
counted. Missing scrapes and crashes can lose observations.

Duration buckets are 0.005, 0.025, 0.1, 0.5, 1, 2, 5 and 15 seconds, plus
infinity. This is HTTP handler latency, not the duration or success of an
asynchronous admitted operation. Use operation receipts and the separate
lifecycle metric families for completion evidence. Authentication rejections,
authorization rejections and unavailable dependencies remain distinguishable;
an increase warrants private audit/health inspection, never weaker checks.
Audit acknowledgement is not durable external audit storage. The metric schema
and migration rules above apply to these families as well.

The #38 Kubernetes Events and integration with the complete redacted diagnostics
bundle remain acceptance work. Health and telemetry alone do not complete that
issue.

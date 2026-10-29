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

The larger #38 metrics, event/log compatibility schema, low-cardinality SLI and
alert guidance, and integration with the complete redacted diagnostics bundle
remain separate acceptance work. This initial health change does not establish
production-grade telemetry or an availability SLO.

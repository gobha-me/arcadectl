# Legacy salvage ledger

The private Gitea repository is evidence, not the v2 source tree. No file is
copied merely because it existed before.

## Reuse as behavior or reference

| Legacy concept | v2 disposition | Required proof |
|---|---|---|
| Kubernetes reconciliation | Reuse the controller-runtime pattern | Idempotent envtest and isolated-cluster lifecycle tests |
| Desired and observed conditions | Reuse the concept | Stable reasons, actionable messages, observed generation |
| Pure resource builders | Reuse the approach | Table tests and deterministic output |
| Definition-owned image, ports, probes, and settings | Narrow and reuse | Shared adapter conformance suite |
| Port allocation validation | Retain as deferred reference | Required only when a Traefik provider is designed |

## Rewrite

| Surface | Reason |
|---|---|
| Custom resources | Existing fields encode one UDP game port, one TCP RCON port, and unsafe reset semantics |
| Reconciler lifecycle | Existing deletion finalizer deletes world PVCs |
| API | Legacy gateway does not compile and does not enforce caller ownership |
| Authentication | UI-local JWT and SQLite are not the cluster mutation boundary |
| Networking | Existing IngressRoute path hard-codes Factorio ports and endpoint roles |
| Backup and restore | No proven recoverable backup lifecycle exists |
| Packaging and CI | Legacy repository has no current hosted validation workflow |

## Discard from slice one

- The legacy API gateway and UI backend.
- The React UI.
- User-supplied raw pod fragments and shell hooks in game templates.
- Factorio-specific behavior in generic builders or controllers.
- Destructive `saveFile.reset` behavior.
- Seven Days to Die support claims.
- Traefik allocation, billing, quotas, and multi-user SaaS behavior.
- Historical completion and production-readiness claims without current proof.

## Provenance rule

If implementation is later ported from the legacy repository, the pull request
must name the source commit and paths, explain why reuse is safer than rewrite,
and add tests for the retained behavior. Credentials, deployment identities,
private endpoints, and unreviewed assets are never copied.

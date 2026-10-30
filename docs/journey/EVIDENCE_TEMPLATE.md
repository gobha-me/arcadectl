# Single-admin journey record

Copy this template for a reviewed exact-candidate CI run. Use `unknown` where
not measured; explain the check used. An empty cell or unrun stage never means
pass. Exclude credentials, verifier digests, kubeconfig and private file data.

- Candidate full SHA / clean checkout: unknown (check `git rev-parse HEAD` and `git status --porcelain`).
- PR / CI run / job / sanitized artifact URLs: unknown.
- Go, kind, Kubernetes, package and renderer versions: unknown (record actual tool output and signed metadata).
- Controller, API, game A/B, worker and repository image digests: unknown.
- Signed package and security-baseline digests / declared profile: unknown.
- Storage class and CSI driver / networking prerequisite evidence: unknown.
- Overall start/end UTC, elapsed, exit status: unknown.
- Evidence retention expiry and durable reviewed archive: unknown.

| Stage | Exact command with private paths replaced | Elapsed / bound | Operation ID + UID | Phase / current generations / conditions | World identity / marker | Result + CI evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Install and prerequisite checks | unknown | unknown | unknown | unknown | unknown | unrun |
| Credential obtain/login | unknown | unknown | n/a | unknown | unknown | unrun |
| Create/configure/start/inspect | unknown | unknown | unknown | unknown | unknown | unrun |
| Rotate and old-auth refusal | unknown | unknown | n/a | unknown | unchanged game Pod UID | unrun |
| Stop/start/restart/update | unknown | unknown | unknown | unknown | exact PVC/PV and Pod UIDs | unrun |
| Backup and repository verify | unknown | unknown | unknown | unknown | backup UID/artifact digest | unrun |
| Isolated restore | unknown | unknown | unknown | unknown | previous/candidate CSI IDs + markers | unrun |
| Decommission | unknown | unknown | unknown | unknown | retained data identity + all claim UIDs | unrun |
| Uninstall/reinstall/reattach | unknown | unknown | unknown | unknown | same exact retained identities | unrun |
| Unsafe-destroy refusal | unknown | unknown | unknown | unknown | unchanged claims/markers | unrun |
| Backup-gated interactive destroy | unknown | unknown | unknown | unknown | exact selected claim absence | unrun |
| Exact owned-resource cleanup | unknown | unknown | n/a | unknown | unrelated sentinel unchanged | unrun |

Record each failed/timeout operation's fixed CLI reason, saved attempt ID, exact
receipt identity, recovery command and observed outcome. Do not automatically
reissue an uncertain mutation. State explicitly which observations used only
read access and which fixture-only setup supplied storage or endpoint status.

Acceptance verdict: **incomplete** until every required row has actual
exact-source hosted evidence. List missing cases and concrete blockers here.

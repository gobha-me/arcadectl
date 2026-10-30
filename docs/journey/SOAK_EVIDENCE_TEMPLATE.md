# Lifecycle reliability run record

- Exact candidate SHA and clean/unchanged-source checks: unknown.
- Mode, exact command, start/end UTC, elapsed, child/outer bounds, exit status: unknown.
- CI run/job and sanitized artifact URLs, retention expiry, reviewed archive: unknown.
- Actual Go/kind/Kubernetes/package/renderer versions and all image/package digests: unknown.
- Declared profile, storage CSI driver/class/handles and networking prerequisite: unknown.
- Continuous-world run or fresh-world-per-round run: unknown; never conflate them.
- Readiness sampling period, sample count, missing samples, observed overlap: unknown.
- Original server/PVC/PV/data identities and marker/save digests: unknown.
- Unrelated sentinel identity and cleanup evidence: unknown.

Check actual outputs to replace `unknown`; do not infer missing versions or
measurements from a neighboring run. Keep credentials, verifier digests,
kubeconfig and private contents out of this record.

| Round / fault | Exact injection command and original UID | Operation/receipt ID + UID | Bound | Actual recovery / readiness / reconcile latency | Current generations / conditions / fixed reason | World/marker and overlap evidence | Result / link |
| --- | --- | --- | --- | --- | --- | --- | --- |
| start/stop/restart/update | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| sustained running | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| controller restart | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| API restart | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| node drain | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| transient API errors | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| image-pull failure | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| Service delay | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| storage reattachment delay | unknown | unknown | unknown | unknown | unknown | unknown | unrun |
| signed upgrade/rollback with a physical world | unknown | unknown | unknown | unknown | unknown | unknown | unrun |

For every failure, record whether it converged or reached a stable actionable
failure, exact original identities, preserved saved attempt, and the separately
reviewed recovery command. Never erase a failed round by retrying it in place.

Verdict: **incomplete** until every required fault and continuous-world duration
has actual exact-candidate evidence. List blockers and distinguish nonbinding
claim retention from physical-world continuity.

# Single-admin CLI journey evidence

Issue #29 requires one complete journey on the exact candidate. This directory
records the acceptance contract and remaining gaps; it is not release evidence.

Inspect the runner without any cluster or Go execution:

```sh
bash hack/test-kind-journey.sh --plan
```

On a disposable **CI runner only**, with the prerequisites in
[TESTING.md](../TESTING.md), run:

```sh
CI=true bash hack/test-kind-journey.sh
```

The runner accepts no cluster, context or kubeconfig argument. The underlying
`TestKindAuthenticatedAdmin` creates a unique owned kind cluster and registry,
checks identities before cleanup, and gives the ordinary CLI only private
context/credential paths. Its setup uses trusted administrator authority to
provision test infrastructure. It never adopts an ambient cluster. The shell
limit is 35 minutes, Go is limited to 33 minutes, the existing fixture to
28 minutes, and each CLI command/operation observation to three minutes.
Existing fixture deadlines remain unchanged. A failure exits nonzero and must
retain the original saved attempt for inspection; the runner does not retry it.

The existing required `Kind authenticated admin API` job runs this same Go test,
including the additional CLI journey. No workflow change is needed to execute
it. Hosted success must be verified for the exact PR head, not inferred from
a compile-only local check. Local kind execution is not part of this change.

The added stage runs discovery, exact retained-world reattachment as Stopped,
configure, start, status, trusted-admin credential rotation, old-context auth
refusal, new-context login, restart, digest update, stop and decommission. Every
ordinary lifecycle mutation is issued by the real CLI. Exact operation UID,
current generation and completed time are checked, runtime Pod replacements
are required, and PVC/PV identity plus the on-volume marker and real save are
rechecked. Rotation must leave the running game Pod unchanged. CLI stdout and
stderr and bounded API audit bytes are scanned for the fixture credentials.
Missing-backup and unsupported unsafe-destroy input must exit 2 with world
identity unchanged. These are input-refusal tests, not proof of interactive
backup-gated destruction.

Commands and operation IDs, UIDs, phases, generations and elapsed milliseconds
are logged without credential contents. Private file roots and the local API
address are replaced with placeholders in command logs. Use the
[evidence template](EVIDENCE_TEMPLATE.md) to retain sanitized exact-head CI
links and actual results. Do not copy kubeconfig, Secrets, client JSON, settings
contents, raw logs or private working directories into an artifact.

## Remaining acceptance gates

This extends a controller/API fixture; it does not start with the signed
installer or certify a released package. Installer uninstall/reinstall plus
CLI reattachment in the same journey remain outstanding. The CLI has no
standalone `preflight` command; login and typed operation validation are not
substitutes for the documented installation prerequisite checks. The current
fixture's prebound Retain hostPath PV cannot certify CSI-isolated restore.
CLI backup, restore, interactive confirmed destroy and their repository/CSI
fixtures remain required. The independent native recovery harness proves a
controller path, not those CLI operations. Do not close #29 from this partial
journey, or describe kind's test-only LoadBalancer status as a cloud-provider
proof.

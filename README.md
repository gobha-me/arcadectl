# Arcadectl

Arcadectl is a Kubernetes-native game-server platform. It turns a certified
game definition and an administrator's intent into a safe, durable, operable
game service.

Factorio is the first certified adapter and reference implementation. It is
not the platform's domain model.

## Status

Arcadectl v2 is under active development and is not deployable yet. The first
milestone proves one complete Factorio lifecycle: create, configure, start,
stop, restart, update, and decommission without data loss. Backup, restore, and
deliberate destruction are separately gated follow-on milestones.

The current foundation includes generated `GameServer`, `GameBackup`, and
`GameRestore` CRDs, a pure,
game-neutral Kubernetes resource planner, typed adapter settings rendering, and
an idempotent controller. The controller starts and stops runtime resources
while retaining storage, refuses to adopt conflicting resources, and cannot
delete persistent claims under its generated RBAC policy. A digest-rendered,
namespace-scoped controller install is available for isolated evaluation;
the certified Factorio lifecycle is exercised in a disposable-cluster proof.
Retained worlds carry a durable data identity, and a replacement server must
explicitly reattach every adapter path by exact local PVC name and UID; a
same-name resource is never authority to adopt an old world.
Backup and restore requests now have immutable, retry-safe API contracts, but
their workers are not implemented. Explicit destruction and production
deployment also remain unimplemented.

A structurally different synthetic adapter participates in conformance tests
from the beginning. Adding another game must not require changes to the core
lifecycle controller.

## Safety contract

- Ordinary lifecycle operations retain world data.
- Removing compute resources does not remove persistent data.
- Destruction is a separate, explicitly confirmed operation.
- Backup and restore are proven before destructive reset is enabled.
- Cluster mutations are authorized and validated at the server boundary.
- Secrets are referenced; they are never embedded in custom resources,
  status, logs, examples, or backups.

See [the architecture](docs/ARCHITECTURE.md), [the lifecycle contract](docs/LIFECYCLE.md),
[the backup and restore contract](docs/BACKUP_RESTORE.md),
[isolated lifecycle testing](docs/TESTING.md), [install and uninstall](docs/INSTALL.md),
[the salvage ledger](docs/SALVAGE_LEDGER.md), and [the security policy](SECURITY.md).

## Development

Requires the Go version declared in `go.mod` (currently Go 1.26).

```sh
go mod verify
test -z "$(gofmt -l .)"
make verify-generated
make verify-runtime-assets
go vet ./...
go test -race ./...
```

The disposable-cluster lifecycle proof has additional Linux and Docker
requirements documented in [docs/TESTING.md](docs/TESTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

# Arcadectl

Arcadectl is a Kubernetes-native game-server platform. It turns a certified
game definition and an administrator's intent into a safe, durable, operable
game service.

Factorio is the first certified adapter and reference implementation. It is
not the platform's domain model.

## Status

Arcadectl v2 is under active development and is not deployable yet. The first
milestone proves one complete Factorio lifecycle: create, configure, start,
stop, restart, update, back up, restore, decommission without data loss, and
deliberately destroy.

The current foundation includes a generated `GameServer` CRD, a pure,
game-neutral Kubernetes resource planner, and an idempotent controller. The
controller starts and stops runtime resources while retaining storage, refuses
to adopt conflicting resources, and cannot delete persistent claims under its
generated RBAC policy. Packaging and isolated-cluster validation remain before
the project is deployable.

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
[the salvage ledger](docs/SALVAGE_LEDGER.md), and [the security policy](SECURITY.md).

## Development

Requires Go 1.24 or the toolchain declared in `go.mod`.

```sh
go mod verify
test -z "$(gofmt -l .)"
make verify-generated
go vet ./...
go test -race ./...
```

## License

Apache License 2.0. See [LICENSE](LICENSE).

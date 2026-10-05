# Single-admin CLI

`arcadectl` is the ordinary administrator client for the authenticated v1 API.
It does not read kubeconfig or mutate Kubernetes directly. Factorio is the first
certified adapter; lifecycle and recovery commands use game-neutral API intent.
The initial supported CLI platform is Linux. Integrated installation, upgrade,
and release packaging remain separate roadmap work.

Build with the Go version in `go.mod`:

```sh
GOMAXPROCS=2 GOMEMLIMIT=1GiB go build -p=1 -o bin/arcadectl ./cmd/arcadectl
./bin/arcadectl --help
./bin/arcadectl completion bash
```

Help and completions work offline, without opening credentials or creating
state. [Generated command reference](generated/cli/commands.md) and completion
files are committed; `make generate-cli` updates them and `make verify-cli`
checks drift.

## Credentials and contexts

First obtain a private client credential using the separate trusted Kubernetes
administrator workflow in [ADMIN_API.md](ADMIN_API.md). The ordinary CLI cannot
bootstrap or rotate server credentials. Do not paste a token into a command,
environment variable, shell history, settings file, or repository.

```sh
arcadectl login evaluation --api https://api.example:8443 \
  --ca-file /absolute/private/ca.pem \
  --credential-file /absolute/private/admin.json
arcadectl context list
arcadectl context use evaluation
arcadectl --context evaluation server status
```

Login verifies HTTPS and `/v1/auth/self`. Context metadata pins the API origin,
CA content hash, stable principal, and installation namespace; it stores paths,
not bearer tokens or verifier digests. Each command verifies that identity before
use. A rotated credential at the same private path preserves the stable principal
and namespace, so pending requests can still be recovered. A changed origin, CA,
principal, or namespace requires deliberate login and cannot resume old attempts.

The credential file must be owner-only, regular, singly linked, and mode `0600`.
Private context and attempt directories are `0700`. Symlink or untrusted writable
path components are rejected. On Linux, descriptor-anchored filesystem access,
locks, atomic replacement, and file/directory sync protect journal transitions.
HTTPS uses explicit CA trust, no environment proxy, no redirects, and bounded
responses. Each request has a 30-second transport deadline; `--timeout` (default
30 minutes, maximum 24 hours) also bounds server/operation requests, attempt-lock
waits, confirmation, and observation. It does not cancel admitted work.

Contexts live under `$XDG_CONFIG_HOME/arcadectl` (otherwise the user configuration
directory), and saved attempts under `$XDG_STATE_HOME/arcadectl` (otherwise
`$HOME/.local/state/arcadectl`). These are private user-local state, not project
files. Attempts may contain settings, exact world identities, and confirmation
challenges; protect them even though they never contain bearer tokens. Context
removal does not delete the credential file, CA file, or server-side resources.

## Lifecycle and retained worlds

Creation requires explicit game, immutable image selection, compute limits,
and storage size. It defaults to `Stopped`; start is a separate intent. Settings
come from a bounded JSON object file. Configure replaces supplied groups rather
than guessing partial resource values; all four compute fields form one group.

```sh
arcadectl server create factory --game factorio --image-version 2.0.76 \
  --cpu-request 100m --cpu-limit 1 --memory-request 256Mi --memory-limit 1Gi \
  --storage-size 1Gi --settings-file ./factorio-settings.json
arcadectl server start factory
arcadectl server status factory
arcadectl server stop factory
arcadectl server restart factory
arcadectl server update factory --image-version 2.0.76
arcadectl server backup factory --repository-secret world-backups
```

Use only versions admitted by the installed adapter; the example is not a
promise of an available release. Backup and restore leave the world stopped
unless resumption is explicitly requested. Secret names are references, never
secret contents. Restore requires a successful, current backup with exact UID
evidence and writes to isolated candidate claims; see the generated help and
[backup/restore contract](BACKUP_RESTORE.md).

`server decommission NAME` removes the GameServer while retaining the world.
Its successful receipt is durable authority for `retained-world status ID`,
deliberate `server create ... --retained-world ID`, or
`retained-world destroy ID --backup NAME`. Ordinary stop, restart, update, and
decommission never delete world PVCs.

## Waiting, retry, and recovery

Commands wait for current-generation terminal evidence by default. `--no-wait`
returns admission only, with an operation ID and local attempt ID. `--output json`
writes result DTOs to stdout and structured errors to stderr; progress goes to
stderr in human mode. An observation timeout or interrupt does not cancel an
admitted operation or authorize a new mutation.

Before sending a mutation, the CLI durably records its random idempotency key,
canonical body, original ETag, identity binding, and expected receipt ID. It never
implicitly retries an uncertain POST or refreshes its body/ETag. Repeating the
same unresolved command looks up that exact receipt; a different intent in the
same scope is fenced. Use the emitted IDs:

```sh
arcadectl operation status OPERATION_ID
arcadectl operation wait OPERATION_ID --timeout 5m
arcadectl operation resume ATTEMPT_ID
arcadectl operation resolve ATTEMPT_ID
```

Explicit resume discovers an admitted receipt first. Only a genuinely absent
receipt for an uncertain attempt permits replay of the exact saved bytes/key.
A previously admitted receipt that disappears is **never replayed**. Same-name
receipt or child UID replacement, stale terminal status, missing evidence, and
identity drift remain fenced. Explicit resolve releases a local scope only after
definitive rejection or exact, current terminal evidence; it does not POST or
cancel work. A successful or failed terminal command can then create a new intent.

## Deliberate destruction

`server destroy NAME --backup NAME` (or the retained-world counterpart) only
prepares a repository-reverified, cold, backup-gated preview. It cannot delete
claims by itself. `destroy confirm PARENT_OPERATION_ID` displays the namespace,
original server UID, data identity, every claim name/UID/path, backup UID,
expiry, and restoration guidance. Both input and displayed inventory must be
real terminals. Type the exact challenge; there is no `--yes`, token/challenge
flag, environment approval, pipe support, or controlling-terminal fallback.
Queued input from an earlier command is flushed before the fresh inventory is
displayed, so a previous response cannot silently authorize confirmation.

Confirmation cross-checks both parent receipt and native destroy operation before
and after the prompt. Explicit replay requires a fresh terminal review of the
same unexpired preview; it cannot substitute a new challenge, target, or ETag.
The prompt is bounded by command timeout and preview expiry. Unsafe no-backup
overrides remain outside this CLI and the ordinary HTTP API.

`destroy cancel PARENT_OPERATION_ID` requests cancellation; accepting that request
is not rollback. The CLI waits on the original exact parent and child. A parent
that already succeeded reports `too_late` and exits nonzero, never a false
cancellation success. See [DESTROY.md](DESTROY.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Successful result; with `--no-wait`, admission only |
| 1 | Local credential, filesystem, state, or output failure |
| 2 | Invalid input or required interactive confirmation |
| 3 | Authentication/authorization or credential expiry |
| 4 | Conflict, identity/preview drift, or unresolved different intent |
| 5 | Timeout or uncertain outcome; preserve and inspect the saved attempt |
| 6 | API/server failure, failed operation, or cancellation too late |
| 7 | TLS, transport, or response protocol failure |
| 130 | Interrupted; admitted work may still be running |

Errors and progress use fixed guidance/reason codes, not raw transport errors,
request bodies, server diagnostics, tokens, or verifier digests.

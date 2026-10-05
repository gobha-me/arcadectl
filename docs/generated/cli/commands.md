# Arcadectl command reference

Generated from the offline command tree. Do not edit manually.

## arcadectl

Safely operate game servers through the authenticated Arcadectl API

```text
Usage:
  arcadectl [command]

Available Commands:
  completion     Generate the autocompletion script for the specified shell
  context        Manage saved endpoint metadata without storing bearer tokens
  destroy        Exactly confirm or cancel a prepared backup-gated destroy
  help           Help about any command
  login          Verify HTTPS identity and save paths to an owner-only credential and CA file
  operation      Inspect, wait on, or explicitly resume durable operations
  retained-world Inspect or deliberately destroy worlds after server-object removal
  server         Create, configure, inspect, and operate servers; ordinary removal retains worlds

Flags:
      --context string     Use a saved administrator context
  -h, --help               help for arcadectl
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)

Use "arcadectl [command] --help" for more information about a command.
```

## arcadectl completion

Generate the autocompletion script for the specified shell

```text
Usage:
  arcadectl completion [command]

Available Commands:
  bash        Generate the autocompletion script for bash
  fish        Generate the autocompletion script for fish
  powershell  Generate the autocompletion script for powershell
  zsh         Generate the autocompletion script for zsh

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)

Use "arcadectl completion [command] --help" for more information about a command.
```

## arcadectl completion bash

Generate the autocompletion script for bash

```text
Usage:
  arcadectl completion bash

Flags:
      --no-descriptions   disable completion descriptions

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl completion fish

Generate the autocompletion script for fish

```text
Usage:
  arcadectl completion fish [flags]

Flags:
      --no-descriptions   disable completion descriptions

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl completion powershell

Generate the autocompletion script for powershell

```text
Usage:
  arcadectl completion powershell [flags]

Flags:
      --no-descriptions   disable completion descriptions

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl completion zsh

Generate the autocompletion script for zsh

```text
Usage:
  arcadectl completion zsh [flags]

Flags:
      --no-descriptions   disable completion descriptions

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl context

Manage saved endpoint metadata without storing bearer tokens

```text
Usage:
  arcadectl context [command]

Available Commands:
  current     Show the selected context
  list        List saved contexts
  remove      Remove metadata only; retain credential and CA files
  use         Select a saved context

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)

Use "arcadectl context [command] --help" for more information about a command.
```

## arcadectl context current

Show the selected context

```text
Usage:
  arcadectl context current [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl context list

List saved contexts

```text
Usage:
  arcadectl context list [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl context remove

Remove metadata only; retain credential and CA files

```text
Usage:
  arcadectl context remove CONTEXT [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl context use

Select a saved context

```text
Usage:
  arcadectl context use CONTEXT [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl destroy

Exactly confirm or cancel a prepared backup-gated destroy

```text
Usage:
  arcadectl destroy [command]

Available Commands:
  cancel      Request cancellation; admission is not rollback and deletion may already be too late
  confirm     Show exact world inventory and type its challenge on a real terminal

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)

Use "arcadectl destroy [command] --help" for more information about a command.
```

## arcadectl destroy cancel

Request cancellation; admission is not rollback and deletion may already be too late

```text
Usage:
  arcadectl destroy cancel PARENT_OPERATION_ID [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl destroy confirm

Show exact world inventory and type its challenge on a real terminal

```text
Usage:
  arcadectl destroy confirm PARENT_OPERATION_ID [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl help

Help about any command

```text
Usage:
  arcadectl help [command] [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl login

Verify HTTPS identity and save paths to an owner-only credential and CA file

```text
Usage:
  arcadectl login CONTEXT [flags]

Flags:
      --api string               Trusted HTTPS API origin (no path, query, or user information)
      --ca-file string           Absolute trusted CA bundle path
      --credential-file string   Absolute owner-only 0600 administrator credential path
      --tls-server-name string   Explicit verified TLS server name, if different from origin host

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl operation

Inspect, wait on, or explicitly resume durable operations

```text
Usage:
  arcadectl operation [command]

Available Commands:
  list        List operation receipts
  resolve     Release a local attempt only after definitive rejection or exact terminal evidence
  resume      Recover the exact saved request; destructive replay requires fresh terminal confirmation
  status      Inspect one receipt
  wait        Wait without cancelling admitted work

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)

Use "arcadectl operation [command] --help" for more information about a command.
```

## arcadectl operation list

List operation receipts

```text
Usage:
  arcadectl operation list [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl operation resolve

Release a local attempt only after definitive rejection or exact terminal evidence

```text
Usage:
  arcadectl operation resolve ATTEMPT_ID [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl operation resume

Recover the exact saved request; destructive replay requires fresh terminal confirmation

```text
Usage:
  arcadectl operation resume ATTEMPT_ID [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl operation status

Inspect one receipt

```text
Usage:
  arcadectl operation status OPERATION_ID [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl operation wait

Wait without cancelling admitted work

```text
Usage:
  arcadectl operation wait OPERATION_ID [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl retained-world

Inspect or deliberately destroy worlds after server-object removal

```text
Usage:
  arcadectl retained-world [command]

Available Commands:
  destroy     Prepare a backup-gated destroy preview; this command never confirms deletion
  status      Read durable original server and claim identity evidence

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)

Use "arcadectl retained-world [command] --help" for more information about a command.
```

## arcadectl retained-world destroy

Prepare a backup-gated destroy preview; this command never confirms deletion

```text
Usage:
  arcadectl retained-world destroy DECOMMISSION_OPERATION_ID [flags]

Flags:
      --backup string   Exact successful native backup name (not its operation receipt)

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl retained-world status

Read durable original server and claim identity evidence

```text
Usage:
  arcadectl retained-world status DECOMMISSION_OPERATION_ID [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server

Create, configure, inspect, and operate servers; ordinary removal retains worlds

```text
Usage:
  arcadectl server [command]

Available Commands:
  backup       Make a verified cold backup; leave stopped by default
  configure    Replace supplied settings or resource groups
  create       Create a server stopped by default
  decommission Remove the server object while retaining its exact world identities
  destroy      Prepare a backup-gated destroy preview; this command never confirms deletion
  restart      Restart without overlapping workloads
  restore      Restore to new claims; leave stopped by default
  start        Start without resetting a world
  status       Inspect a server or list servers
  stop         Stop and retain a world
  update       Update an immutable image

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)

Use "arcadectl server [command] --help" for more information about a command.
```

## arcadectl server backup

Make a verified cold backup; leave stopped by default

```text
Usage:
  arcadectl server backup NAME [flags]

Flags:
      --repository-secret string   Existing repository credential Secret name only
      --restart-policy string      LeaveStopped or explicit RestorePreviousState (default "LeaveStopped")

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server configure

Replace supplied settings or resource groups

```text
Usage:
  arcadectl server configure NAME [flags]

Flags:
      --cpu-limit string        CPU limit
      --cpu-request string      CPU request; all four compute fields form one replacement group
      --memory-limit string     Memory limit
      --memory-request string   Memory request
      --settings-file string    Bounded JSON settings file; supplied object replaces settings
      --storage-class string    Storage class; explicitly empty selects no class
      --storage-size string     World storage capacity request

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server create

Create a server stopped by default

```text
Usage:
  arcadectl server create NAME [flags]

Flags:
      --cpu-limit string        CPU limit
      --cpu-request string      CPU request; all four compute fields form one replacement group
      --desired-state string    Initial state: Stopped or explicitly Running (default "Stopped")
      --game string             Certified game adapter
      --image-digest string     Immutable adapter image digest
      --image-version string    Curated adapter image version; mutually exclusive with digest
      --memory-limit string     Memory limit
      --memory-request string   Memory request
      --retained-world string   Exact successful decommission receipt for deliberate reattachment
      --settings-file string    Bounded JSON settings file; supplied object replaces settings
      --storage-class string    Storage class; explicitly empty selects no class
      --storage-size string     World storage capacity request

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server decommission

Remove the server object while retaining its exact world identities

```text
Usage:
  arcadectl server decommission NAME [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server destroy

Prepare a backup-gated destroy preview; this command never confirms deletion

```text
Usage:
  arcadectl server destroy NAME [flags]

Flags:
      --backup string   Exact successful native backup name (not its operation receipt)

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server restart

Restart without overlapping workloads

```text
Usage:
  arcadectl server restart NAME [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server restore

Restore to new claims; leave stopped by default

```text
Usage:
  arcadectl server restore NAME [flags]

Flags:
      --backup string           Exact successful native backup name (not its operation receipt)
      --restart-policy string   LeaveStopped or explicit RestorePreviousState (default "LeaveStopped")

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server start

Start without resetting a world

```text
Usage:
  arcadectl server start NAME [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server status

Inspect a server or list servers

```text
Usage:
  arcadectl server status [NAME] [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server stop

Stop and retain a world

```text
Usage:
  arcadectl server stop NAME [flags]

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

## arcadectl server update

Update an immutable image

```text
Usage:
  arcadectl server update NAME [flags]

Flags:
      --image-digest string    Immutable adapter image digest
      --image-version string   Curated adapter image version; mutually exclusive with digest

Global Flags:
      --context string     Use a saved administrator context
      --no-wait            Return after receipt admission without waiting for completion
      --output string      Output format: human or json (default "human")
      --timeout duration   Bounded request, lock, confirmation, and observation timeout; does not cancel admitted work (default 30m0s)
```

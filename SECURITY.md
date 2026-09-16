# Security policy

Arcadectl is pre-release software. Do not deploy it with valuable worlds or
production credentials until a release explicitly says that the relevant
lifecycle is supported.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting when available. Do not open a
public issue containing an exploit, secret, credential, private endpoint, or
other sensitive material.

## Security boundaries

- The API authenticates callers and authorizes every requested mutation.
- The API service account may mutate Arcadectl resources, not workloads.
- The controller is the sole normal workload, network, and storage mutator.
- Game definitions are curated platform inputs, not tenant-supplied pod specs.
- Secret values stay in Kubernetes Secrets and are never copied into API
  resources or observable status.
- Destructive operations fail closed and require exact confirmation.

The legacy Gitea repository is not part of this public project. It remains
private because its history contains credential-like material and unreviewed
assets.

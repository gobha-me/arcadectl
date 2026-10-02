# Authenticated administration boundary

Arcadectl is a game-server platform; authentication belongs to the platform,
not the Factorio adapter. This foundation adds `arcadectl-api`, one generated
administrator credential, typed server-side authorization, structured audit,
and separate API RBAC. It is not a hosted or multi-user service.

The only domain HTTP route in this foundation is `GET /v1/auth/self`. It returns
`version`, `principalId`, `credentialId`, and `expiresAt`; never a token, verifier,
role list, or Kubernetes credential. Lifecycle endpoints and durable operation
receipts are the next API issue. There is no generic Kubernetes proxy.

## Identity, trust, and exposure

The stable principal is `admin`; each rotation gets a new opaque credential ID.
The opaque bearer contains 256 random bits and expires after 30 days by default.
Only a single Authorization header using the Bearer scheme is accepted. Query
parameters and cookies are not credentials. Expired/incorrect/malformed tokens
receive 401 before any handler reads a body or performs a mutation.
The transport accepts bounded RFC 6750 bearer syntax; the credential verifier
enforces the generated token format. A future JWT/OIDC authenticator does not
require changes to transport encoding, adapters, or reconcilers.

The managed Secret is `arcadectl-system/arcadectl-admin-credential`, type
`arcade.gobha.me/admin-credential`. It contains the private `token` and the
versioned `auth.json` SHA-256 verifier bundle. **Only `auth.json` is projected
into the API pod.** The API service account cannot get, list, watch, or mutate
Secrets. Protect the Secret, client credential file, Kubernetes administrator
kubeconfig, and TLS private key as credentials. Kubernetes Secret encryption at
rest and administrator access control remain cluster-operator responsibilities.

The server accepts HTTPS only, with TLS 1.2 or newer, on port 8443. Its ClusterIP
Service exposes only HTTPS port 443. There is no Ingress, external IP, NodePort,
LoadBalancer, CORS policy, HTTP fallback, or insecure client option. Public
exposure and certificate issuance are not configured by this slice. The cluster
network is not an authorization boundary: every API request still authenticates.
Liveness/readiness use a separate port 8081 which is not exposed by the Service.
Readiness also checks the loaded TLS certificate validity interval continuously; an
expired or not-yet-valid certificate is unready without a liveness restart loop.
No arbitrary request inputs are included in health responses.

A trusted administrator must provide `arcadectl-system/arcadectl-api-tls` with
`tls.crt` and `tls.key`, issued for the actual API hostname. The certificate is
loaded at startup; changing TLS material requires an API restart. Clients must
verify the CA and hostname. `--tls-server-name` on the credential utility permits
a verified hostname when using a local port-forward; it does not bypass TLS.
Protect any ingress, tunneling, or log-collection infrastructure you add.

## Trusted administrator bootstrap and rotation

Build the Linux administrator utility from the checkout:

```sh
go build -o ./arcadectl-admin-credential ./cmd/arcadectl-admin-credential
```

Create an owner-only private output directory. Supply an absolute, new output
filename in that directory and a trusted cluster-admin kubeconfig/context:

```sh
./arcadectl-admin-credential init \
  --kubeconfig /absolute/private/admin.kubeconfig --context evaluation \
  --output /absolute/private/credentials/initial.json
```

The utility writes a versioned client credential file using exclusive creation,
mode 0600, and file/directory fsync **before** attempting to create the Secret.
It does not print the token or export an existing credential. Initialization
does not claim the API is activated; the TLS Secret and API deployment may not
exist yet. Concurrent initialization cannot overwrite the winning Secret.
All created candidate files are retained, including definite conflicts; a
conflicting candidate is explicitly inactive. This avoids unsafe path-based
cleanup and preserves evidence without implying that every saved file is active.

Install the API separately after its namespace, credential, TLS, and admission
prerequisites exist. A released API image is not yet available; use an actual
digest from an isolated evaluation build, never the all-zero controller fixture:

```sh
make render-api API_IMAGE=registry.example/arcadectl-api@sha256:ACTUAL_DIGEST
```

Rendering is deterministic and read-only. It does not create either Secret and
does not install the controller, CRDs, or admission policies. Apply the resulting
manifest only to the intended evaluation cluster. Existing controller install
and safe uninstall workflows are unchanged; integrated packaging belongs to the
installation milestone. Remove the API Deployment/Service/RoleBinding/Role/SA
explicitly when ending an isolated evaluation, retaining administrator-owned
credentials/TLS material unless their deletion is separately intended.

Rotate through the trusted Kubernetes administrator, not through a bearer-only
endpoint:

```sh
./arcadectl-admin-credential rotate \
  --kubeconfig /absolute/private/admin.kubeconfig --context evaluation \
  --output /absolute/private/credentials/rotated.json \
  --api-url https://api.example/v1/auth/self \
  --ca-file /absolute/private/api-ca.crt
```

The utility validates the exact managed Secret and changes it using its current
UID/resourceVersion and an incremented serial. A conflicting rotation is never
automatically retried against the winner. The output contains the new token,
new ID/serial/expiry, and prior Secret UID/resourceVersion; it never stores the
previous raw token. The default operation deadline is five minutes.

The API reopens the projected file every second, including Kubernetes atomic
symlink updates. The complete verifier bundle replaces the old one atomically:
there is no old-token grace period once the new bundle is observed. Kubernetes
projection propagation is asynchronous, so a successful Secret update alone
does not prove revocation. The utility waits for the single serving API instance
to accept the new credential and reject the old one over trusted HTTPS. It
disables redirects and environment-configured proxies. The shipped Deployment
is one replica with `Recreate`; multiple or changing serving identities cannot
produce a successful rotation proof. An expired old credential can be rotated
by the trusted Kubernetes administrator even while the API is unready.

Invalid/missing verifier content or a serial rollback makes protected requests
503 and readiness false, without a last-good verifier fallback. Expiry makes
readiness false but requests with expired credentials remain 401. Liveness
stays healthy so restarting does not masquerade as credential recovery.

If a create/update times out, it may have committed. The utility retains the
fsynced private output and reports an unconfirmed outcome unless exact candidate
readback confirms it. An activation timeout also retains the committed Secret
and output. Do not delete the file, blindly retry initialization, or assume the
old token is still valid. Use trusted administrator readback to establish current
identity, preserve the candidate, and, when needed, deliberately rotate the
current Secret into another new private file. There is no automatic rollback or
crash-resume mutation loop. A nonzero exit is not proof of zero cluster writes.

## Authorization and auditing

The API role can read and mutate only the four main Arcadectl custom resources
in `arcadectl-system`. It has no status-subresource authority, workload, Service,
ConfigMap, Secret, PVC/PV, Lease, RBAC, or cluster-scoped authority. Reconcilers
continue to own actual Kubernetes workload/data changes. Direct custom-resource
access remains cluster-administrator access, not an alternative tenant API.

Every mutation route must register a recognized action through the guarded
router. The server authenticates and authorizes before exposing the sealed
mutation capability or entering the handler. The authorizer refuses unknown
actions. Authentication/authorization interfaces can be replaced for OIDC later
without changing game adapters or reconciliation logic.

There is deliberately **no unsafe-no-backup HTTP action**. The existing
fail-closed `arcadectl-destroy-unsafe-admin` admission policy and binding must
remain installed. Even with ordinary CR write RBAC, the API service account is
not the distinct `arcadectl-destroy-admin` identity and cannot forge its unsafe
override. Ordinary destroy remains repository-reverified, cold, and explicitly
confirmed, including retained worlds with original-identity evidence.

Audit emits JSON lines to stdout with generated request IDs, stable principal
and non-secret credential IDs, fixed action/method/route-template/namespace,
intent/outcome, status, and duration. It does not include caller request IDs,
headers, query, bodies, raw paths, raw errors, tokens, or verifiers. A mutation
requires its audit intent to be accepted synchronously before its handler runs.
Audit acknowledgment is bounded to one second. A stalled sink occupies at most
one outstanding call and causes the same unhealthy fence as a failed write;
there is no unbounded queue or retry. Controlled mutation execution accepts
only a live capability from this server; captured capabilities stop working
when the handler returns. Read handlers receive no API-owned mutation client.
This is a boundary for trusted compiled API code, not a sandbox for arbitrary
plugins constructing their own Kubernetes clients.
An audit-write failure latches unhealthy and rejects future protected requests.
If an outcome write fails after a mutation applied, its truthful HTTP response
is preserved; reporting a fictional failure could provoke unsafe retries.
Already admitted concurrent requests are not rolled back by another request's
later audit failure. Restart only after repairing the audit output destination.

Accepted stdout writes do not prove durable collection. Configure access-controlled
durable log collection and Kubernetes API-server audit retention before real-world
administrative use; both are explicit operator prerequisites. This foundation
does not silently claim hosted-service compliance or production readiness.

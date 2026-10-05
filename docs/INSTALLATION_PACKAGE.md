# Signed installation package development

The offline package command builds and verifies versioned installation bytes.
The integrated installer, upgrade/rollback runtime certification, and package
lifecycle CI remain in development under issue #27. This is not a released
package or a declaration of production-supported Kubernetes profiles.

```sh
GOMAXPROCS=2 GOMEMLIMIT=1GiB go build -p 1 ./cmd/arcadectl-package
./arcadectl-package --help
```

`build` requires explicit version, full source commit, source timestamp,
controller/API image digests, and external signing and trust keys. It never
generates keys, discovers trust, connects to Kubernetes, or publishes a release.
Supply a PKCS#8 Ed25519 private-key PEM and the independently trusted matching
PKIX Ed25519 public-key PEM. The private key must have mode 0600 under a
current-user-owned 0700 directory. Public trust keys must not be group/other
writable. Paths must be clean and absolute, without symlinks or hardlinked keys.

After assigning the explicit public metadata and private key paths locally:

```sh
./arcadectl-package build \
  --version 0.1.0-rc.1 \
  --source-sha "$PACKAGE_SOURCE_SHA" \
  --source-epoch "$PACKAGE_SOURCE_EPOCH" \
  --controller-image "$PACKAGE_CONTROLLER_IMAGE" \
  --api-image "$PACKAGE_API_IMAGE" \
  --signing-key "$PACKAGE_SIGNING_KEY_PATH" \
  --trust-key "$PACKAGE_TRUST_KEY_PATH" \
  --output /absolute/private/packages/candidate

./arcadectl-package verify \
  --package /absolute/private/packages/candidate \
  --trust-key "$PACKAGE_TRUST_KEY_PATH"
```

Images require actual nonzero SHA-256 digests. The timestamp is explicit, not
the current time. Identical metadata, renderer inputs, and signing identity
produce identical contents: `manifest.json`, `signature.json`, and exactly
`manifests/{anchors,api,controller}.yaml`.

Output must be a new directory beneath an existing current-user-owned 0700
directory. Its basename starts with a letter/digit, contains only letters,
digits, `.`, `_`, or `-`, and has at most 128 characters. Private staging,
exclusive creation, fsync, and atomic no-replace publication prevent overwriting
an existing output. Final contents are authenticated again after publication.
An unconfirmed publication/durability error means output or staging may remain:
preserve them and verify the requested output before further action. It does
not mean nothing changed. A stdout failure also leaves published output intact.

The detached signature authenticates canonical metadata and exact payload
checksums using the supplied trust key; a bundled key cannot establish trust.
Verification also requires byte-exact reviewed renderer outputs. Validly signed
arbitrary manifests are not authorized. Packages contain no inline credentials,
private TLS keys, arbitrary pod fragments, host paths, or privileged modes.

Signatures do not prove image/source provenance, reproducible image builds, or
runtime certification. The current Kubernetes 1.35.8/1.37.0 declarations still
need package-lifecycle evidence. TLS, restricted Pod security, admission policy
support, CSI storage, game networking, image-registry access, and Restic/S3
readiness are separate prerequisites; the installer does not provision a storage
driver, LoadBalancer, or backup repository.

## Exact predecessor fixtures

`--legacy-source` accepts only frozen source
`7dcbad6497782c198c7b142a6a8b902dead4b79e`, its original templates, the default
namespace, and the Kubernetes 1.37.0 declaration. Supply images actually built
from that source; relabeling current binaries does not prove upgrade/rollback.

Current packages can declare `--predecessor /absolute/package/path` and
`--predecessor-id ID`. The predecessor is externally verified and checked
against the frozen renderer. Metadata binds its exact canonical manifest digest,
source, images, namespace, and profile. This does not authorize adopting an
unsigned or unowned installation. CRD compatibility and rollback to complete
prior templates remain installer checks, not an image-tag change alone.

## Ownership and interruption contract

The bounded journal uses a Namespace annotation, not a ConfigMap or an expiring
Lease. Controllers can write ConfigMaps but cannot write Namespace objects.
Only public original identities, reviewed resource addresses, package digests,
and mutation intent belong in the journal—not tokens, verifier bundles, TLS
keys, or private filesystem paths.

A private durable receipt records installation identity and the create attempt
before namespace creation. Only its exact nonce and reviewed namespace metadata
can confirm a genuinely lost response only during the original invocation. An
attempted unconfirmed creation is never replayed, even if a read currently
returns NotFound. Restart without a durably pinned original UID remains
unresolved even when a later same-named object has a copied nonce. Known Create
acknowledgement UIDs are pinned before shape acceptance and before binding the
cluster journal. Namespace replacement, ownership drift,
weakened Pod security, or a concurrent revision causes refusal.

Journal updates use one original-UID/resource-version-controlled write. A lost
response is success only after exact candidate readback on the same UID. Pending
intent cannot be overwritten or settled by changing unrelated inventory, and
retained objects cannot be journaled for deletion. This machinery does not prove
live workload safety: the engine must still quiesce admission/controllers,
repeat complete safety observations, prove actual policy denials, and preserve
retained worlds and recovery credentials.

## Authoritative retaining-uninstall observations

The internal observer reads all pages of five domain-record collections, Jobs,
Pods, Leases, PVCs, Secret metadata, and admission policies/bindings without
selectors or cache-only resource versions. Every collection needs a nonempty,
consistent resource version and a final page; an expired/failed page, repeated
continuation token, or malformed response discards the whole observation.

Secret and recursive-owner reads negotiate only Kubernetes partial metadata.
The transport rejects full-object fallback responses before client-go decoding,
then strips annotations, labels, managed fields, and other unnecessary metadata
before response logging. Private last-applied Secret annotations do not become
safety evidence. Server errors and warnings are not reflected into diagnostics.

Recursive owners are resolved through uncached exact-version discovery, with
known resource names/scopes checked independently. Original inventoried UIDs
are required for cluster-scoped retained anchors; unknown, replaced, deleting,
cyclic, contradictory, or out-of-scope owners are refused. The original
Namespace identity, journal document, and resource version must be unchanged
before and after all reads.

Bounds include a five-minute observation deadline, 30-second HTTP request
timeouts, 4 MiB per response, 8 MiB per collection, 32 MiB aggregate list bytes,
32 MiB recursive evidence, 256 pages per collection, 10,000 objects/nodes,
128 owner references per object, and 64 owner edges per path. Exceeding a bound
requires explicit administrator investigation; it is not empty/safe evidence.

The collection/aggregate byte budgets count serialized retained evidence after
transport metadata sanitation, not cumulative network traffic. Object-count,
page-count, per-response, recursive-evidence, and deadline bounds also apply.

These unit and TLS HTTP tests do not certify a live cluster package lifecycle.
The observation is not atomic across Kubernetes collections, an admission
denial proof, or a lock. The unfinished engine must still prove runtime-owned
templates, stop API admission and controller Pods, repeat the safety barrier,
and preserve worlds and recovery credentials through upgrade/rollback/uninstall.

## Signed live-resource contracts

The internal mutation contract checks whole objects against sealed package
templates plus narrowly reviewed Kubernetes defaults. Unknown fields are refused
before typed conversion; nested CRD schema shape is also compared without
discarding unknown keys. Typed quantities compare by numeric value. RBAC rules,
subjects and role references, API Service routing, Deployment containers,
worker images, and admission specifications remain part of the signed contract.
Matching dry-run and live webhook output does not authorize an unsigned change.

Only original UID/resource-version inventory can authorize an update. Candidates
copy no arbitrary live fields: they preserve validated single-family Service
allocations and bounded Deployment revision bookkeeping. Paused variants exist
only for the two controller Deployments, not as a substitute for deleting API
admission and proving that its actual Pods and endpoints are gone. Namespace
dynamic annotations must equal the exact sealed public journal observation.

Before upgrade/rollback, each CRD must have the unchanged signed schema and
None conversion, one served/storage `v1alpha1`, exactly that stored version,
accepted original names, and healthy nonduplicated establishment conditions.
Any present aggregate/condition observed generation must be current; an absent
feature-gated observed-generation field does not invalidate older profiles.
Deleting/migrating/nonstructural CRDs and healthy-object metadata finalizers
are refused. This first supported transition performs no schema conversion or
storage migration; future such transitions need an explicit reviewed plan.

The isolated Kubernetes 1.37 API-server gate independently checks all 38 public
resources through create, dry-run update, original UID/RV update and readback,
including the durable Namespace bootstrap. The normal envtest CI target includes
this gate. Synthetic predecessor/current/rollback tests restore complete prior
Pod templates, including API namespace configuration removal and paired
controller/worker image rollback. These are not genuine predecessor-binary or
full package-lifecycle certification; Kubernetes 1.35.8 runtime proof remains
pending. Original serving-identity checks and direct HTTPS activation are
implemented below; full runtime activation, admission behavior, quiescence and
lifecycle CI remain engine responsibilities.

## Journal-before-effect resource writes

The internal administrator effect layer now executes signed public-resource
creates/updates and original-UID/RV foreground deletes. It confirms the exact
Namespace journal and full signed Namespace shape, independently checks dry-run
admission, saves the public intent, then sends at most one real mutation request.
It never adopts an existing object by name or labels. Updates preserve original
UID/RV and only the reviewed server assignments. Namespace bootstrap and journal
CAS use the same single-attempt HTTP provider, rather than the typed client's
internal Retry-After retry behavior.

The provider uses verified HTTPS, HTTP/1.1, non-replayable JSON write bodies and
an inner per-request attempt guard. Redirects, raw server errors/warnings and
unknown resource mappings are refused. Responses are bounded to 1 MiB,
64 JSON nesting levels and 200,000 tokens; duplicates are rejected and integers
are preserved. Writes request strict field validation. External auth plugins and
custom base transports are unsupported. File-backed certificate/key/CA/token
inputs are read as bounded protected snapshots; no background credential-file
rotation can reflect private reload errors. The source kubeconfig is not changed.

Every Create also prepares a protected, durable local receipt before the effect,
then pins its acknowledged original UID before readback/settlement. The original
call may pin a lost response's immediately correlated signed readback instead.
Explicit recovery requires the exact receipt bound to Namespace UID,
installation ID, object address, package, template hash and saved nonce. A copied
nonce on a replacement UID cannot authorize adoption. An interrupted Create
whose UID was never durably pinned remains unresolved, even if a later object
looks correct: manual original-identity investigation is required. Keep these
receipts with the protected bootstrap evidence; never regenerate them on resume.
Definitively rejected Creates cannot establish ownership from a later matching
readback. Fixed, sanitized HTTP rejection classifications remain distinct from
genuinely ambiguous transport/response loss for public resources, bootstrap and
private Secrets; a raced object with copied nonce/shape is not adopted.

Recovery observes and settles only; it does not repeat dry-run or real writes.
Accepted foreground deletion is not absence. Deleting objects, replacements,
unchanged before-state, unreadable evidence and journal races retain pending
intent. Recovery also enforces the original stage/package/action contract:
quiescence may delete API admission and pause the original controllers;
application installs the target's ready templates; uninstall only deletes
non-retained runtime inventory. Namespace, CRDs, admission policies, credentials
and world claims are not deleted by this primitive.

Unit and TLS HTTP tests count mutation attempts under Retry-After and a retrying
wrapper, exercise lost acknowledgements/readbacks/settlement, and refuse UID,
nonce, shape, receipt and journal substitution. The isolated Kubernetes 1.37
API-server gate covers all 38 public-resource journaled creates plus two private
Secret creates, a genuinely lost Create acknowledgement, unavailable-readback recovery, and original-UID/RV
update through the production provider. The gate also manually creates a
ReplicaSet and Pod with ServiceAccount admission enabled to check native Pod
defaults and token projection. No kubelet or workload binary runs; this does
not prove a full installation, upgrade, rollback or retaining uninstall.

This is not a user-facing installer or permission/safety proof. Lifecycle
orchestration must still establish prerequisites, CRD status/discovery,
behavioral admission denials, owner/GC retention closure, real API/controller
quiescence, credential/TLS activation, repeated safety barriers and recovery
guidance before issuing effects. Full binary lifecycle CI remains unfinished.

## Private administrator and TLS candidates

The internal fresh-install Secret workflow prepares one protected canonical
candidate envelope before any Secret effect. It binds the original Namespace
UID, installation ID, target package and two distinct saved create nonces.
The administrator candidate uses the existing credential format, principal,
serial and verifier rules. Resume reloads that exact candidate; it never
regenerates a token, overwrites foreign output or adopts an existing Secret.
TLS remains an explicit prerequisite supplied through bounded protected files,
not inline package values or automatic CA provisioning. The pair must match,
chain to the supplied CA, be currently valid for server authentication and name
`arcadectl-api.<installation-namespace>.svc`.

Private client JSON and CA outputs are saved before the real effect. A separate
bounded, redacted HTTPS path permits only the two reviewed Secret names and
supports GET and Create, not replacement, rotation or deletion. Independent
dry-run admission must preserve complete metadata, type and private contents.
The Namespace intent/inventory records only original Secret UIDs and public
nonces; Secret template hashes remain empty. Tokens, token digests and TLS keys
never enter this public journal. Diagnostic formatting of candidate envelopes
is redacted for pointer/value forms and every formatting verb.

The same single-attempt, acknowledged-UID receipt and no-replay recovery rules
apply to private Creates. Resume also reconfirms exact protected inode/content,
file fsync and directory fsync before trusting visible candidate files, existing
exports or original-UID receipts. Visibility after uncertain publication is not
proof of durability. Changed private contents, replaced files, weakened directory
protection or unconfirmed persistence refuse further authority.

Retained-credential verification reads the original inventoried Secret UIDs
without rewriting them. It permits valid administrator rotation in the existing
format; it does not require the expired initial candidate to remain usable.
The Kubernetes 1.37 API-server gate now creates all 40 resources, recovers a
private unavailable readback without replay, correlates a genuinely lost private
Create acknowledgement, checks retained Secret identity and verifies absence of
private material in the journal. Native admission checks create a Pod object,
but execute no workload binary: genuine predecessor-binary upgrade/rollback
and retaining-uninstall lifecycle certification are still pending. This
internal workflow is not a released installer CLI or an authorization/safety
proof for those operations.

## Original serving identity and direct authenticated activation

The internal read-only serving observer binds the original inventoried Service,
API Deployment and ServiceAccount to their signed target contracts. Complete,
unfiltered EndpointSlice pagination must have one consistent list version and
no repeated names, UIDs or continuation tokens. Reads are limited to 32 pages,
1,000 objects, 4 MiB aggregate and one minute; individual responses retain the
provider's strict 1 MiB JSON budget. There is no general Pod/ReplicaSet mutation
mapping or metadata-to-full-Secret fallback.

The sole ready endpoint must refer to the exact original Pod UID. Its sole
controller owner must be the original ReplicaSet owned by the inventoried API
Deployment. ReplicaSet selectors and templates, Pod metadata and the full
admitted PodSpec must match the signed workload. Only reviewed native fields
are normalized: scheduler node assignment, default service links, consistent
deprecated ServiceAccount alias, default priority/preemption, two default
NoExecute tolerations and the exact standard projected ServiceAccount token
volume/mount. Additional containers, environment, security settings, projection
sources, annotations or altered owners are refused. Readiness and observed
generations must be current. Original Namespace/journal barriers surround the
reads; these observations are not a distributed lock or atomic cluster snapshot.

Direct activation derives its HTTPS destination only from this proved Pod IP
and fixed port 8443. It uses the fixed service DNS SAN, validates current
administrator/TLS bytes from the same original-UID Secret reads, and binds the
client constructor's protected credential/CA snapshot reads to exact file
identities. In addition to normal CA/SAN validation, the TLS handshake pins
the peer leaf to the validated original TLS Secret before HTTP authorization.
An A-to-B-to-A file rewrite or a stale same-CA/SAN certificate cannot launder
unbound authentication material through outer before/after checks.

The actual HTTPS `/v1/auth/self` response must identify the stable administrator
and original installation namespace. Full route and file/Secret identities are
reobserved after dialing, before TLS/bearer transmission, and after successful
authentication. Activation writes or rotates nothing and does not mark an
installation installed. Changed ownership, readiness, workload shape, resource
versions, protected files or peer certificate leave activation unproved with
fixed, redacted errors.

Tests use the real API boundary, file-backed verifier, TLS server and client
with fake keys and private test files. They prove authentication and refusal
behavior over a package-private owned test connection; Kubernetes topology is
fixture evidence, not a running Pod. The separate isolated Kubernetes 1.37 gate
proves native admitted Pod defaults, not workload execution. Direct activation
requires Pod-network reachability. A safe original-Pod outside-cluster forwarding
route, installer CLI, behavioral admission/quiescence barriers and full fresh,
supported-predecessor upgrade/rollback/retain-uninstall binary CI remain pending.

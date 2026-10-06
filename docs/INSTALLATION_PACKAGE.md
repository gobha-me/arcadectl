# Signed installation package development

The offline package command builds and verifies versioned installation bytes.
The integrated installer, upgrade/rollback runtime certification, and package
lifecycle CI remain in development under issue #27. This is not a released
package or a declaration of production-supported Kubernetes profiles.

## Read-only retained-world recovery reporting

The internal closed `RecoveryReporter` reads only the original Namespace and
its sealed installation journal, plus **all** current namespace PVCs. Reporting
works after a completed retaining uninstall without surviving workloads,
ServiceAccounts, admission fixtures, domain CRDs, or Secret reads. It includes
unlabeled and unrelated claims, even when their former owner no longer exists;
membership grants no ownership, adoption or permission to delete.

The reporter requires the unchanged, durable original bootstrap receipt and
independently trusted current signed packages. The original bootstrap package
can predate all three currently registered packages and must be verified
separately, not retied to the newest package or regenerated. `PinnedAnchor`
does not bootstrap a Namespace, repair local state, bind a journal or create a
lock file. A receipt's acknowledged UID alone does not prove Namespace shape;
the reporter independently checks its exact current signed shape and journal.

Two complete, bounded, unfiltered PVC enumerations must have identical sorted
whole claim items (including each UID, resource version and shape), bracketed
by unchanged original Namespace/journal checks and a final receipt check. Each
enumeration has a coherent list revision, but unrelated storage churn may
advance that revision between reads. Its second revision is report metadata,
not a namespace identity or a cold-world lock.

Output is bounded, JSON-escaped and allowlisted: original installation identity,
profile, journal revision/mode/stage, known package digests, public pending
action/address/original UID, and current PVC name/UID/resource version/PV name/
phase/deletion flag. It never dumps objects, labels, annotations, owner
references, arbitrary status text, credentials, private paths or raw errors.
Fixed guidance requires preserving original signed packages, protected receipts
and client/CA files; it forbids deleting the Namespace/PVCs or replaying an
uncertain effect with a fresh candidate. This is observation and recovery
guidance, **not** backup, coldness, detach, deletion or full lifecycle proof.
The separate administrator boundary now exposes only read-only inspection:

```sh
GOMAXPROCS=2 GOMEMLIMIT=1GiB go build -p 1 ./cmd/arcadectl-installer
./arcadectl-installer inspect \
  --namespace "$INSTALL_NAMESPACE" --profile "$INSTALL_PROFILE" \
  --bootstrap-package "$ORIGINAL_BOOTSTRAP_PACKAGE_PATH" \
  --package "$CURRENT_PACKAGE_PATH" --trust-key "$INSTALL_TRUST_KEY_PATH" \
  --state-dir "$EXISTING_PRIVATE_STATE_PATH" --bootstrap-receipt bootstrap.json \
  --kubeconfig "$EXPLICIT_PRIVATE_KUBECONFIG_PATH" --context "$EXPLICIT_CONTEXT"
```

Repeat `--package` for one to three independently trusted current/target/previous
packages. All paths are explicit, clean and absolute; the existing receipts
directory is euid-owned mode 0700 and the kubeconfig is a protected mode-0600
regular file. No state directory, receipt, Namespace, journal or credential is
created or repaired. The default five-minute timeout may be lowered but not
raised; cancellation and incomplete observations fail without partial output.

Kubeconfig input must contain exactly one complete, typed-strict v1 Config
document. The explicit context must select existing cluster/user entries, and
any nonempty context namespace must match `--namespace`. It requires an explicit
CA and exactly one static credential mode: bearer, a complete client certificate/
key pair, or complete basic credentials. Conflicting inline/file sources,
relative references, anonymous authentication, exec/auth-provider plugins,
impersonation, insecure TLS, configured proxies and URL queries/fragments/non-root paths
are refused. Selected references are frozen by protected bounded reads before
HTTP transport creation. It does not use SDK loaders/conversion, default context,
in-cluster credentials, system/default CA selection, environment kubeconfig
merges/proxy routing, credential refresh or persistence. A stdout failure is an
error and never leads to a mutation or retry. This command is not an API-client
fallback; the ordinary CLI remains API-only and the package command offline.
Lifecycle mutation commands and integrated runtime certification remain in
development.

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
requires Pod-network reachability. The internal native forwarding route below
does not require that reachability. Installer CLI, behavioral admission/quiescence
barriers and full fresh, supported-predecessor upgrade/rollback/retain-uninstall
binary CI remain pending.

## Bounded original-Pod native forwarding

Forwarded activation uses the same serving, credential-file, retained-Secret,
peer-certificate and authenticated-response barriers as direct activation. It
opens only the fixed original Pod's `portforward` subresource and port 8443,
after an additional uncached original-UID Pod read. Kubernetes offers no UID
precondition on this subresource: whole serving identity is reobserved after
opening, before inner TLS/bearer transmission, and after authentication. There
is no local listener, arbitrary caller URL/port, reconnect, Pod replacement
fallback or direct-route fallback.

The cluster connection uses frozen static bearer, basic or client-certificate
authentication with verified HTTPS and HTTP/1.1. Configured impersonation,
custom transports/wrappers/dialers and explicit proxies are unsupported on
this native route; it fails before forwarding rather than dropping their
authority or routing behavior. The raw connection is direct, not an
environment-proxy route. The installer must check this capability before any
installation effects. There is one POST upgrade attempt, no redirects or
retrying transport. Upgrade-header parsing has an 8 KiB pre-parser budget and
30-second/context deadline. Exact native protocol, upgrade headers and no HTTP
body framing are required. Rejected bodies are never consumed or reflected.
Prefetched frame bytes remain in the same bounded header reader.

Only the pinned SPDY frame codec is used, not its connection/queue/debug manager.
Before decoder allocation, a wire guard limits DATA payloads to 64 KiB, controls
to 4 KiB, the incoming session to 256 frames/1 MiB, and outgoing wire bytes to
1 MiB. It permits only the two locally opened streams: error ID 1 and data ID 3.
Their sole acknowledgements have empty headers; decoded header count/fields
are additionally capped at 8/256 bytes. Unsolicited streams, extra headers,
duplicate/unopened acknowledgements, nonempty error-stream data, invalid
flags/lengths, resets and GOAWAY terminate with a fixed redacted failure.
Bounded native PINGs are echoed; bounded settings/window controls do not create
streams or queues. This is the reviewed Kubernetes native profile, not a
general-purpose SPDY implementation.

One reader and one fixed 32 KiB writer bridge an internal `net.Pipe`; blocking
provides backpressure without DATA queues. Acknowledgement waits are at most
five seconds and cancellation-aware. The connection lives only for the bounded
activation context. Abort first hard-closes the actual socket (including beneath
TLS), then closes both pipe ends; callers join all owned workers. No protocol
cleanup write, TLS close-notify or SDK acknowledgement waiter can hold abort.

Tests interoperate with the stock native server connection and a real
authenticated HTTPS API over an owned test route, proving both TLS layers and
static auth modes. Negative tests cover original-Pod replacement, malformed
upgrade headers, redirects/errors, resource drift, frame/header amplification,
wire/sequence limits, stalled headers, missing acknowledgements, established
blocked pumps and blocked protocol writes, with joined-worker evidence. A
bounded single-worker fuzz target exercises the pre-parser guard. These are
protocol/activation proofs with fixture Kubernetes topology, not real-kubelet
forwarding or full installer lifecycle certification. The separate closed
target-authentication gate below covers actual kubelet forwarding; the full
isolated binary lifecycle gate remains required before issue #27 is complete.

### Closed authenticated-target checkpoint

`ClusterTargetAuthenticated` implements only `TargetAuthenticated`. Its
constructor binds the engine to its same frozen, native-capable `HTTPAccess`;
callers cannot substitute serving, Secret, URL, dial, port or reconnect providers.
It requires a settled Verifying journal, the exact registered target plan and
operation mode, and repeats original Namespace/journal barriers around forwarded
activation. Success is read-only authenticated identity evidence, not a completed
installation or a claim that the other lifecycle checkpoints passed.

Current retained Secret UIDs, resource versions, protected client/CA files and
TLS leaf identity remain authoritative. A valid same-Secret-UID administrator
rotation and a supported changed-package upgrade/rollback do not reload the
original bootstrap candidate. Stale client files and replacement Secrets fail
before forwarding. Private typed Secret decoding is case-sensitive and rejects
unknown fields and differently cased aliases, including nested metadata fields.

`make test-kind-install-auth` runs both exact checksum-pinned supported patches,
1.35.8 then 1.37.0, in disposable clusters. Signed test-package effects and the
private credential workflow establish original resource identities; real
controller-manager/kubelet observations supply Deployment, ReplicaSet, Pod and
EndpointSlice readiness. The gate then uses the closed provider's fixed original
Pod port-forward and real authenticated HTTPS, not a kubectl forward or injected
dial. Public journal bytes and resource version must remain unchanged.

The fixture deliberately constructs lifecycle stages and omits controller
Deployments. Its package signing key is test-only. This proves the authentication
component against actual kubelets, **not** a fresh installer CLI journey, genuine
predecessor binary upgrade/rollback, controller reconciliation, admission fixture
bootstrap, or retaining uninstall. Those full lifecycle gates remain mandatory.
Only test-owned node/registry containers and image tags are removed, with exact
identity/label checks and verified absence. Private output is not an artifact.
Profiles are serialized; Go children use two processors and a 1 GiB soft heap
limit, the owned Kind node is limited to 3 GiB/two CPUs, and its registry to
128 MiB/half a CPU. These do not hard-limit the shared Docker daemon or BuildKit;
shared-pod runs still require memory monitoring and no concurrent builds.

## Ordered, resumable lifecycle coordinator

The internal coordinator now connects sealed journal transitions to the actual
public effect and private Secret workflows. Each `Step` performs at most one
resource effect or one stage transition. A pending step performs observation-only
recovery and returns without falling through into the next mutation. Missing
original create-UID evidence never permits replay or name/nonce-only adoption.

Fresh install orders all five CRDs, all six policies, all six bindings,
non-workload identities/RBAC/Service, protected credential exports and the two
private Secrets, then both controllers and the API last. Existing target-ready
entries are skipped only after their original live shapes have been checked.
The coordinator does not infer dependency ordering from YAML file order.

Upgrade/rollback/uninstall preserve the active package while quiescing: remove
original API admission first, prove API descendants/endpoints absent, pause
both original controllers, then prove complete runtime absence and cold-data/GC
safety. Upgrade and rollback restore complete target templates and recreate
the API with a new durable original UID. Retaining uninstall removes runtime
Deployments/Service, bindings before roles, and service accounts last; it never
deletes a PVC, retained CRD, policy/binding, Namespace or Secret. Recovery after
settled controller removal proves authoritative absence rather than recreating
or adopting a controller. Same-package reinstall keeps retained credential UIDs
and never generates replacement tokens.

Uninstall proves live runtime-identity admission behavior before withdrawing
the first original RoleBinding or ClusterRoleBinding. After executable runtime
and Services are gone, it fsyncs a protected receipt containing the exact
pre-removal journal and all twelve original policy/binding UID, resource-version
and template-hash witnesses. An observation-only journal CAS latches that
receipt's original revision. Accounts and permissions are not retained merely
to run tests. Later removal, pending-delete recovery and final verification use
the distinct administrator read-only `RetainedAdmission` checkpoint, alongside
fresh cold-data, runtime-absence and retained-credential observations.

Missing/corrupt receipts, changed or unhealthy protections, substituted
inventory, and recreation of removed access objects fail closed. This proves
removal of the installation's own runtime access, not global revocation of
independent administrator grants. The marker cannot be replaced or cleared
mid-operation; it resets only when a completed operation begins its successor.
Monotonic revisions prevent reusing earlier uninstall evidence after reinstall.
No additional signed resources, retention flags, grants or counts are introduced.
Legacy journals omit the new optional marker and retain their canonical bytes;
an already partially withdrawn legacy uninstall without pre-removal evidence
is not retrospectively certified. Older binaries that do not understand the
new marker reject such journals; downgrade compatibility is not implied.

Completion rechecks CRD availability, admission effectiveness, controller
evidence, authenticated target activation, every target-ready inventory hash
and live shape, current CRD storage/conditions and original private Secret UIDs.
Uninstall instead proves exact retained inventory and absence of all runtime
addresses. Prerequisites are checked before every non-pending step so direct
resume does not bypass preflight. The old sealed snapshot and requested new
mode/verified target plan are explicitly separate during operation preflight.
An interrupted operation cannot silently change mode/target or automatically
roll back: supported rollback begins only from a completed installation.

The coordinator currently requires a trusted internal proof-provider seam for
permissions/prerequisites, behavioral admission, full quiescence/cold-safety,
controller descendant evidence and forwarded authentication. There is no
permissive production provider, shell-status fallback or user-configurable
callback. The closed production provider, administrator installer command,
retained-claim recovery output and full isolated package/binary lifecycle CI
are still required; this coordinator is not a usable certified installer yet.

Tests exercise the real journal CAS/effect/private-file/Secret machinery with
fixture Kubernetes/proof providers. They cover ordered install, retaining
uninstall/reinstall, exact signed predecessor upgrade/whole-template rollback,
proof failures and redaction, fresh completion barriers, no-replay recovery,
recovery after one/both controller removals and retained-only verification,
and same-name replacement refusal. These fixtures do not certify real admission
behavior, kubelet forwarding, preservation of running world bytes or executed
predecessor images. Those remain mandatory runtime gates for issue #27.

## Closed cluster prerequisite proof

The production prerequisite foundation uses fixed, bounded version, discovery
and SelfSubjectAccessReview routes over the frozen administrator HTTPS identity.
It requires the exact declared Kubernetes patch and effective version, literal
discovery scope, resource kind/verbs and the exact requested authorization spec.
Only explicit `allowed: true` with no denial/evaluation error proves permission.
Native discovery may omit `apiVersion`; a present version must be literal `v1`.
Nonpersistent authorization responses may include only strictly checked inert
managed-field bookkeeping for the fixed installer manager and exact submitted
spec fieldset. Generic HTTP error codes, metadata and policy-looking messages
are not authorization evidence. Responses are bounded, duplicate/unknown keys
are rejected, error bodies are discarded, and POSTs never retry or redirect.

Permissions are derived from the requested operation and remaining original
inventory, not merely the previous completed mode. Collection CREATE has no
resource-name restriction. Bound lifecycle proof never requests Namespace
CREATE/DELETE, Secret UPDATE/DELETE or PVC DELETE. Retaining reinstall does not
request retained-resource creates; uninstall does not require native forwarding
or already-settled runtime mutations. Closed nonpersistent admission probes
still require Pod/PVC/GameDestroy CREATE authorization; these permissions are
not an authorization to perform persistent probe writes.

`VerifyBootstrap` checks the sealed fresh target, protected TLS/issuance inputs,
native-route capability, exact cluster contract and all fixed public addresses
before the namespace's first write. Every address must be authoritatively absent;
there is no existing-resource adoption. The durable bootstrap receipt remains
the definitive original-UID/no-replay barrier; preflight is not a lock. Bound
resume rechecks the original journal before and after its observations. A saved
durable credential candidate replaces the need to reopen original issuance
certificate/key files, but its CA must still match the protected activation CA.
A missing candidate already used by an inventoried Secret is never regenerated.

Serial isolated API-server tests cover both exact declared patches, native
discovery/authorization response shapes and portforward kind, restricted RBAC
refusal before namespace creation, fresh pre-CRD proof, candidate-backed resume,
CA mismatch and loss of a used candidate. The Linux amd64 1.35.8 fixture uses
checksum-pinned upstream 1.35.8 kube-apiserver with checksum-pinned 1.35.0 envtest
etcd/kubectl, because the reviewed envtest index has no 1.35.8 bundle. It does not
substitute a nearby API-server patch. All fixtures are disposable and downloads
stream to bounded task-owned files instead of allocating archive-sized buffers.

This is not a complete `LifecycleChecks` provider or runtime certification.
Behavioral admission, complete cold/quiescence evidence, actual controller
readiness, integration of all closed checkpoints, administrator installer command,
recovery output and fresh/upgrade/rollback/uninstall binary CI remain required.
Native Pod behavioral probes also require an existing original ServiceAccount.
Fresh install and retaining reinstall now put the signed ServiceAccounts first
within the non-executable dependency rank, behind `AdmissionConfigured` (every
original signed policy/binding and current healthy type-checking). Its original
signed RBAC then uses a separate, non-executable `BootstrapAdmission` gate:
administrator CREATE pairs, all original accounts, cold worlds and complete
namespace workload absence. Services, new credentials and workloads remain
behind full behavioral admission effectiveness. Resuming after one account or
one RBAC resource does not bypass the corresponding repeated barrier.
CREATE probe coverage does not certify DELETE/UPDATE branches;
real lifecycle CI and any applicable live-claim proof must cover those explicitly
without adding PVC deletion authority to ordinary retaining uninstall.

## Closed native CREATE admission proof

`ClusterAdmission.VerifyConfigured` observes all twelve original policies and
bindings against their recorded signed templates, including mixed active/target
inventory during a transition. It requires current policy generation/type-check
status without warnings and refuses missing, replaced, drifted or unhealthy
objects. Configuration alone does not prove behavioral enforcement.

`VerifyCreateProbes` surrounds six fixed positive/negative dry-run CREATE pairs
with repeated original configuration and journal checks. It requires the
inventoried `arcadectl-controller` ServiceAccount's original UID/signed shape
and unchanged resource version before and after the probes; a default, foreign,
missing or recreated account is not substituted. Probe names use fresh bounded
random nonces. Positive worker Pods have one scheduling gate, no authorization
marker or owner, no credential volume/environment, no token automount and the
signed digest-pinned controller image. PVC probes explicitly use an empty
storage class so they cannot request provisioning. Fictional GameDestroy
references have no confirmation and all requests are `dryRun=All`.

Positive responses must preserve the entire independently specified object,
including native initial status, generated metadata, the exact installer field
ownership tree and profile-certified defaults. Sidecars, node assignment,
volumes, annotations, spec/status drift and null-versus-absent structural changes
are refused. Returned metadata is never ownership or desired-shape authority.
Negative responses count only when the inner transport sees the exact native
422 Status for the fixed policy, binding, resource/name and signed validation.
It classifies before stripping raw errors below SDK wrappers. Generic denial,
another cause, an unexpected acceptance, duplicate/malformed/unbounded JSON,
redirect or retry is not evidence. All public errors remain fixed and redacted.

Both exact Kubernetes profiles run the six native pairs with ServiceAccount
admission enabled and verify zero persistent Pod, PVC or GameDestroy effects.
Fixture integration and fault-injection tests exercise original identity/race
barriers, full accepted-shape refusal, no replay and raw-error redaction. These
API-server fixtures have no kubelet or policy-status controller and are not
full runtime lifecycle certification. The partial CREATE proof is deliberately
not a complete `LifecycleChecks.AdmissionEffective` implementation.

## Closed non-executable RBAC bootstrap

Identity-specific admission proof cannot run before an actor has its signed
runtime permissions. `ClusterAdmission.VerifyBootstrap` breaks that dependency
only for original signed Role/ClusterRole/RoleBinding/ClusterRoleBinding effects.
It is a distinct checkpoint, not a weaker meaning of `AdmissionEffective`.
The coordinator enforces Install/Applying, not installed, no pending intent or
access-retirement marker, and either a fresh package or a same-package retaining
reinstall. Upgrade and rollback keep their existing full behavioral barriers.

Every signed ServiceAccount must already have its original journal UID and
exact target shape. Existing signed RBAC must also remain original and exact.
The package's named Services and Deployments must be absent both from inventory
and exact live GETs; a replacement or failed read is not absence. This Service
predicate concerns installation Services, not a claim that every namespace
Service was listed. The sealed observer separately proves complete absence of
all namespace Pods, Jobs, Deployments, ReplicaSets, StatefulSets, DaemonSets,
ReplicationControllers, CronJobs and EndpointSlices, including suspended,
terminal and deleting objects. Cold-world/worker/fence/mount/GC evidence remains
mandatory. No absence is inferred from incomplete or missing collections.

The provider brackets the six administrator CREATE pairs with that complete
absence/cold proof, unchanged world identities, original account versions and
all twelve original healthy protection objects. Fresh bootstrap requires its
managed credential Secrets absent; retaining reinstall preserves only its
inventoried originals, with private SecretWorkflow verification repeated by the
coordinator. It never regenerates retained credentials. Pending RBAC recovery
stays observation-only, after which the next effect repeats the bootstrap gate.

No temporary verifier roles, TokenRequest/impersonation privileges, extra human
Kubernetes accounts or runtime permission expansions are introduced. Full actor
UPDATE/DELETE/subresource proof still gates Services, new Secrets, workloads and
completion. Fixed HTTPS fixtures test the production observer/provider and
fault barriers; they do not certify native policy evaluation, real storage,
kubelet behavior or a complete binary installation lifecycle.

### Closed original software actor access

The private admission factory consumes an explicitly selected existing-admin-
impersonation mode. There is no default mode, TokenRequest, credential fallback,
new permission grant or additional human Kubernetes account. The factory checks
the exact namespace/journal, registered package, all original signed accounts
and RBAC objects, and all twelve original healthy policies/bindings before and
after constructing its three fixed software clients. Missing, replaced or
drifted access is not adopted. Mixed-package access uses the original recorded
signed templates. The admin's existing impersonation right is reviewed against
each exact namespace/account name; it is not guessed from discovery verbs.

Actor credentials and TLS come only from the administrator's already-frozen
configuration. `NewDirectHTTPAccess` explicitly selects direct routing, rejects
caller proxy/dial callbacks and bypasses environment proxies. Observer clients
inherit that same explicit routing; callback-free frozen source configuration
is not passed directly to an environment-proxy-defaulting observer. The CLI's
read-only inspection uses this direct constructor. Actor derivation refuses
pre-existing impersonation, transport/routing wrappers or credential plugins.

Only ordinary-controller Pod/PVC UPDATE and PVC CREATE, destroy-controller Pod/
GameDestroy UPDATE and PVC DELETE, and destroy-admin GameDestroy CREATE/UPDATE
are exposed. Each operation first requires the actor's own exact operation SSAR,
not administrator permission. Pod subresources remain administrator probes:
the runtime actors do not gain those privileges. The factory repeats original
access/policy/journal witnesses around authorization and dry-run requests.
Negative policy/binding/message triples must belong to the witnessed signed
protection set. RBAC 403, a foreign policy or unsigned message is not evidence.

The inner actor wire guard pins the administrator authentication and the exact
single service-account impersonation header, method, URL and body. Groups,
UID/extra impersonation headers, aliases/duplicates, authentication replacement,
context loss and operation/body changes are refused before transmission.
Generic persistent Access methods and general read/discovery requests cannot
use these actor clients. All errors remain fixed and redacted.

HTTPS fixtures cover the complete factory's original-identity/permission/race
barriers and malicious wrappers. Fresh-process non-loopback proxy tests cover
both sealed safety and recovery observer reads. Isolated native API-server
tests use the same closed actor transport and actual operation authorization
on both declared profiles, but do not manufacture policy status or claim the
full factory/provider is certified there. The durable state/fence and native
storage-candidate evidence below are additional foundations; production fixture
effects, whole named accepted shapes, cleanup/recovery and complete lifecycle
checkpoint composition remain separate unfinished requirements.

### Durable inert-fixture intent and installer fence

A private fixed-catalog WAL binds its exact original sealed namespace journal
and resource version to one random run and ten reviewed recipe slots: three
suspended Jobs and their gated worker Pods, one plain gated Pod, retained/plain
synthetic PVCs and an already-cancelled GameDestroy. This is identity/state
bookkeeping, **not permission, fixture construction or native effect proof**.
No raw objects, credentials, private paths or caller-selected recipes are stored.
Fixtures are not inserted into ordinary installation inventory or its pending
effect; those remain restricted to signed package resources.

Protected exclusive creation, fsynced compare-and-swap updates, file-identity
checks and one cooperative WAL lock enforce the state sequence. A CREATE-attempt
intent must be durable before a future persistent request. Its acknowledgement
UID may be pinned only by the same in-process attempt capability, never by
resuming an unknown attempt or finding a matching name/nonce. Acknowledged UIDs
cannot be replaced. Cleanup records the observed canonical positive resource
version, cannot reset for replay and requires worker Pod absence before Job
deletion. Strict canonical decoding and original-journal resume comparison also
reject contradictory owner states, UID gaps/duplicates, foreign journal/package/
namespace data and extras.

Any active WAL fences ordinary public/private effects, lifecycle transitions
and pending installer recovery before even an injected proof provider runs.
Malformed, unreadable and terminal-but-unretired files also block. The future
closed provider must independently observe original identity, whole allowed
shape and actual absence, archive evidence and retire the exact active file.
The private transport below supplies once-only fixture effects, but no public
provider or retirement path exists; a terminal WAL alone cannot bypass those
missing proofs. Cooperative local locking and these
temporal checks are not an atomic cluster lock or fresh behavioral evidence.

### Closed inert-fixture recipes

A separate private pure constructor derives every object from that canonical
WAL, its registered signed target plan and a fixed slot. It accepts no caller
objects, images, account names, fragments or addresses. Returned objects are
defensive constructions, not configuration stored for later effects. Worker
Pods reuse the restricted signed-image defaults with one scheduling gate, no
token automount, mounts, environment, sidecars or node assignment. Their Job
UID must already be durably acknowledged; a missing or unknown create outcome
cannot supply an owner by matching a live name.

Jobs have both suspension and zero parallelism, with an explicit manual selector
matching only their unique template label. Separately created probe Pods omit
that label and have a **non-controlling** original Job UID owner reference.
Matching controlling children can be deleted during suspension; mismatching
controlling children can have ownership released. The pinned
[1.35.8 Job controller](https://github.com/kubernetes/kubernetes/blob/v1.35.8/pkg/controller/job/job_controller.go)
and [1.37.0 Job controller](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/controller/job/job_controller.go)
must instead leave this recipe intact. The disposable native test requires
real controller-observed suspension and unchanged manual Pod ownership/specs
through a thirty-second window, no node assignment or extra probe Pods, and
both dry-run/persistent specs equal to the closed constructor. A plain Pod has
a separate gate and no worker label or owner. PVCs use the non-binding synthetic
recipe described below.

The GameDestroy fixture is born `cancelRequested: true`, has the original
destroy-admin audit annotation and entirely fictional run-derived target
references/data identity, distinct from the retained fixture. It has no
confirmation, backup/repository references, status or deletion journal. That
object alone cannot establish changed-spec unsafe UPDATE behavior: cancellation
cannot be cleared, and the other target/mode/reference fields are immutable.
A private pure recipe and separate whole-result validator now describe only
the original slot's `Cancelled` status with its run-derived challenge, fixed
already-expired preview and fixture-only guidance. The ordinary validator still
rejects every GameDestroy status. This pure component permits no status write
and never persists a confirmation; the separately guarded private transport is
described below. Its exact status fieldset is schema-derived and must pass both
native profiles rather than merely typed/schema validation. The destroy controller must remain
independently cold: terminal cancellation alone does not prevent finalizer or
worker/lease cleanup effects.

An optional protected receipt preserves exact canonical legacy v1 bytes when
absent. Seed intent requires all ten native original acknowledgements; while
attempted, every entry transition, including cleanup, is blocked. Separate
instance-local send/ACK capabilities cannot revive on reload, and ACK requires
consumed send capability plus a distinct canonical result RV. Receipt changes
cannot accompany entry changes or reset/reseed; an acknowledged receipt remains
immutable throughout otherwise-valid original UID/RV cleanup. Document/body
drift and protected-file replacement also fail closed. These are state-machine
primitives, not reliable native ACK, recovery settlement or
cleanup authorization. The active WAL fence remains in effect.

The private status transport derives only the original slot9 named `/status`
PUT from the closed constructor, original UID and intent RV. It independently
requires that exact named status UPDATE discovery/SSAR for the frozen original
install administrator; missing rights refuse, with no new grant, token or
impersonation fallback. The wire first proves the actual absent-status original
whole body at the intent RV. Shared-ledger serialization, single-send capability
consumption before any possible request, fixed manager/Strict validation and
below-wrapper request guards prevent generic mutation or replay.

A bounded strict native response with the original UID and distinct canonical RV
is durably acknowledged before any post-request witness, wrapper error or whole-
shape refusal. An unknown response remains attempted and fenced; later GET,
client reconstruction, reload and guessed acknowledgement cannot repair or
resend it. Successful return additionally requires the exact complete seeded
shape and unchanged original witnesses. No CREATE UID capability is supplied.
This component does not itself establish coldness or cleanup authority.

The disposable native proof separately requires absent application controllers
and only the exact synthetic GameDestroy among domain objects, with no leases.
After seeding, only a dry-run main-resource UPDATE adds the run challenge while
retaining cancellation, fictional target, audit identity and exact status.
A separate pure whole validator permits only that confirmed-spec/fieldset and
generation delta; it checks main/status managed-field roles and native ordering
for same-second or later-second timestamps before private normalization.
The native proof deliberately crosses a whole-second boundary, pairs distinct-
admin acceptance with exact original unsafe-policy/controller denial, and
uncached-observes the entire unchanged persistent original after every dry-run.
No confirmation is persisted. These controls must pass both exact native
profiles; CRD/CEL, RBAC or status-subresource acceptance alone is not evidence
for the signed unsafe admission policy, which matches the main resource rather
than `/status`. Fresh test-cluster cold scans are not a production cold provider.
Both exact supported profiles exercise this sequence in the native authentication
gate, including original UID/RV cleanup and actual absence. This is native
component evidence, not signed-binary install/upgrade/rollback/uninstall acceptance.

The disposable native test now uses the same engine's original direct transport,
sealed actor/policy witnesses and private ledger-bound wire for whole-validated
dry-run CREATE and persistent CREATE/GET/DELETE on both exact profiles. The
normal SDK supplies only limited test-owned descendant observations. These tests are
not production fixture permission, observation-only recovery or WAL retirement.
The private whole-result validator below checks dry-run, ACK and stable bodies.
Test cleanup enumerates durable
acknowledgements even after post-ACK refusal, uses original UID/fresh RV
preconditions and requires actual absence. Unknown CREATE blocks cleanup
transitions and no Job is removed before its worker's absence is proved;
exact owned-cluster teardown remains an independent fallback.
Unknown status seeding also blocks every cleanup transition. A seeded original
requires its complete exact seeded shape and acknowledged RV before test
cleanup; seed ACK alone is not inertness proof or permission to delete.
The already-cancelled synthetic leaf uses background deletion only within that
fresh exclusively owned cluster, with no finalizers/owners or observed
application/runtime descendants and no deployed application controller.
Those limited collection checks are not universal GC closure or production
cleanup authorization. The observed foreground deletion timeout is not treated
as proof of a specific discovery or permission failure.
The active test WAL remains fenced even after test cleanup. No ordinary effect
or cold/runtime proof ignores its fixtures or considers this run complete.

### Private ledger-bound transport checkpoint

The private fixture transport consumes an instance-local, once-only send
capability after a durable CREATE/DELETE intent. All clients sharing the ledger
serialize wire operations; the closed provider still owns WAL transitions and
close serially. Loading a ledger or rebuilding a client cannot recreate a send
capability. GET observes the fixed address without adopting unknown CREATE UIDs,
resetting attempts or converting DELETE acknowledgements into absence.

The closed preview operation derives the next Planned recipe and original
CREATE actor, checks original witnesses/discovery/exact CREATE SSAR, and sends
one guarded POST with exactly `dryRun=All`, the fixed installer field manager
and Strict validation. It refuses pending effects, cleanup, skipped slots and
leftover ACK/send capabilities. A complete strict reply must pass whole dry-run
shape validation and unchanged original witnesses before a copy is returned.
Preview UIDs never become acknowledgements; neither acceptance nor refusal
changes the protected WAL, restores a capability or authorizes persistent
CREATE. Native tests observe exact-address absence before and after preview.

Routes, objects and software actors are derived from the ten fixed slots.
The original administrator creates ordinary inert fixtures; the original
destroy-admin creates the born-cancelled GameDestroy; retained synthetic PVC
cleanup selects the original destroy-controller. These use the original frozen
admin transport and already-held impersonation rights, not new tokens/grants.
Discovery, exact-operation SSARs, unchanged original journal/account/RBAC/policy
witnesses and protected WAL bytes surround every operation. Private clients
reject general Access use, arbitrary methods, changed routes/bodies/identities,
replay-enabling headers, retries and redirects.

Bounded strict native JSON with the exact CREATE status/address and canonical
nonzero native UID supplies a reliable acknowledgement. That UID is fsynced
before post-request witness/refusal checks, including an outer transport error.
Malformed identity remains unknown; later GET cannot repair it. All native
response bodies, headers and trailers are captured/sanitized below wrappers.
DELETE derives original UID and journaled fresh RV preconditions, leaves the
attempt unresolved until independently observed actual absence, and never
resends after a lost response, post-witness refusal, client rebuild or restart.

This is a private transport component with fake-credential HTTPS regression
tests, **not a production permission boundary or full provider**. No public
entrypoint invokes it. Complete cold/runtime absence, integration of whole-
result/descendant checks before effects, observation-only
recovery and WAL retirement remain necessary. Native recipe evidence above
certifies this private transport in an exclusively owned test cluster, not
those missing production checks or the complete installation lifecycle.

A test-only, off-by-default diagnostic can privately capture the fixed synthetic
fixtures' native metadata/status after original UID and desired-shape checks.
It requires an existing protected directory, creates private files without
overwrite and excludes executable specs, credentials and general observations.
The captures are not uploaded as CI artifacts, are not fixture authority and
do not substitute for whole-result validation or complete provider authority.

### Closed whole-fixture result validation

A private pure validator derives desired configuration only from the fixed-slot
recipe and registered signed plan. Dry-run bodies require a Planned slot, a
native generated UUID and no RV; that UUID never supplies durable ownership.
ACK and stable-live bodies require an Original slot, its durably acknowledged
UUID and canonical positive RV. Pending effects cannot be repaired by a body.

Strict typed decoding plus exact raw top-level/spec/metadata/status equality
reject extra/null/zero fields, altered owners/gates, execution and volume binding.
Only fixed installer fieldsets and status-correlated native controller
bookkeeping are allowed. Job ACK status is empty; stable status is suspended-
only with zero ready/terminating counts and no terminated Pod UIDs. Synthetic
PVC status is initially Pending and stably Lost, with the exact protection
finalizer. Pods remain gated Pending/BestEffort. GameDestroy has **absent**
status only at this application-controller-cold checkpoint, not an arbitrary
Cancelled runtime status.

Timestamps require canonical UTC seconds, bounded nonzero RFC3339 years and
the observation ceiling. Old original times remain valid after protected
ledger reload. Manager strings and canonical RVs are shape bookkeeping, not
actor identity or freshness. The provider must separately prove uncached wire
observations, current original journal/access/policy/cold barriers and complete
descendants. This validator changes no WAL, restores no send capability and
retires no fence; it grants no cleanup or complete-provider authority.

The native test applies these checks before CREATE, after durable ACK, throughout
bounded convergence/stability and before original UID/RV cleanup intent. Ordinary
race regressions cover both profiles/all slots/phases, mutated fields and times,
replacement rejection, absent-vs-null status, pending deletion and protected
reload without capability revival.

Private opt-in activation diagnostics record only the first fixed refusal stage
of the SAME attempt: serving reads versus fingerprint drift and credential-
binding reads versus drift. No errors/bodies/identities/credentials are retained.
Public errors and TLS/bearer/fingerprint/connection guards remain unchanged; no
authentication retry is added. These diagnostics cannot retroactively explain
an earlier refusal without captured stage evidence.

### Native non-binding storage-candidate evidence

The existing isolated native-authentication Kind test additionally checks a
synthetic storage recipe on both exact declared Kubernetes profiles. It never
reads an external kubeconfig or uses real worlds/shared storage. An empty
storage class alone prevents dynamic default-class provisioning, **not static
or prebound volume binding**; selectors alone do not close prebinding either.

The candidate explicitly sets `pv.kubernetes.io/bind-completed: yes`, leaves
`spec.volumeName` empty and fixes the empty storage class. The pinned
[1.35.8 PV controller](https://github.com/kubernetes/kubernetes/blob/v1.35.8/pkg/controller/volume/persistentvolume/pv_controller.go)
and [1.37.0 PV controller](https://github.com/kubernetes/kubernetes/blob/v1.37.0/pkg/controller/volume/persistentvolume/pv_controller.go)
route that synthetic shape to `ClaimLost` without binding or provisioning.
**Never set this annotation on a real claim or treat it as ownership evidence.**

Actual running controllers must bind a separate positive-control claim while
plain/retained inert claims converge to `Lost`. Matching available/prebound
static PVs exist before those claims. Explicit PVC/PV update events and a
40-second observation window exercise both controller directions and more than
two declared-profile default binder sync periods. Throughout, original claim
UIDs, desired specs and retained labels stay fixed; available/prebound PV specs
stay unchanged and the complete owned-cluster PV set gains no unexpected PV.
The retained `Lost` claim must still yield the exact signed administrator DELETE
denial and an unchanged whole raw reread. Exact acknowledged-UID/fresh-RV cleanup
uses the original dedicated destroy account for the retained synthetic claim,
then waits for actual claim/PV absence. Test PVs use `Retain`; no fixture Pod
mounts their host paths or creates/writes those paths.

This certifies a test-owned candidate on these two standard controller profiles,
not arbitrary external provisioners, production fixture adoption/cleanup,
physical CSI behavior or complete installer lifecycle. Production fixture
transport and whole-result checking must use the durable original-identity
provider; the native test does not bypass that requirement.

### Named dry-run transport and native operation evidence

The private admission transport also has a closed operation set: named PUT for
Pod/PVC/GameDestroy, PUT for Pod `ephemeralcontainers` and `resize`, and named
PVC DELETE. Named operations require the original nonempty UID and canonical
positive-decimal uint64 resource version used by both exact native profiles.
Zero (including zero-padded forms) is refused before the wire: it selects an
unconditional native UPDATE, not a pinned old object. Native conflict tests use
a different positive version and independently require HTTP 409, rather than
counting a changed result version as precondition enforcement.
The operations accept only native HTTP 200 and the same resource identity, never
201/202, a generic Success Status, 404/409, another policy denial or a retry.
The transport validates identity, not the complete accepted defaulted shape;
a future production provider must independently certify that shape and bracket
all probes with original-object, policy, account and journal barriers.

DELETE constructs a fixed `DeleteOptions` body containing `dryRun: [All]` and
both original UID/resource-version preconditions. Kubernetes does not decode
query options when this body is present, so a URL-only dry-run is insufficient.
No propagation, grace, orphan or unsafe-delete option is exposed. Before the
wire, the inner transport checks the entire fixed method, URL/Host, query,
body and JSON headers against the request-bound witness. Context loss, operation
substitution, wrapper mutation and replay are refused. Native errors are
classified privately, then their body, status text, trailers and header
parameters are sanitized before outer SDK wrappers can observe them.

Both exact profiles certify unchanged named UPDATE acceptance, worker image,
gate and authorization-marker denials, worker subresource denials paired with
non-worker subresource acceptance, retained-PVC label/marker-change/marker-removal/DELETE denials,
non-world PVC DELETE acceptance, and unsafe-destroy spec/audit-identity denials.
Every operation rereads and compares the entire unchanged persistent fixture.
Worker Pods have actual original Job owners, one scheduling gate and no token
automount. Their test-owned Jobs are suspended with parallelism zero; PVCs use
an empty storage class. The same closed actor wire transport additionally
certifies correct/wrong-actor worker gate authorization, ordinary-controller
restore-candidate CREATE and cold-marker change/removal, dedicated-controller
retained-PVC dry-run DELETE, and distinct-admin unsafe CREATE/UPDATE with paired
audit/spec denials. Unsafe CREATE has an independently closed native fieldset
for its exact audit annotation and no backup/repository references. Setup remains
test-owned; no fixture is a real world or evidence of production cleanup.

This is API-server transport evidence, not an installer fixture lifecycle or
complete `AdmissionEffective` implementation. Production temporary-fixture
ownership/recovery/cleanup and whole named-result validation remain required.
The private factory's operation-specific authorization and unchanged original
policy/account/journal witnesses do not substitute for that fixture lifecycle.
The prerequisite contract does not silently gain administrator PVC DELETE,
additional UPDATE or Pod subresource privileges. No scheduler, kubelet, real
world destruction or binary installation lifecycle is certified here.

Final uninstall uses the approved pre-removal behavior/durable-evidence and
post-removal administrator-observation split described above. It does not run
live actor probes after their permissions/accounts are removed. Original
accounts are never silently retained, recreated or adopted. Fresh-bootstrap
behavioral authorization, production fixture lifecycle and the complete closed
lifecycle-provider composition remain separate unfinished obligations; this
retirement checkpoint is not full install/upgrade/rollback/uninstall acceptance.

## Original CRD discovery and bound safety reads

`ClusterPrerequisites.VerifyCRDs` combines every original inventoried CRD's
recorded signed template with its original UID, native establishment/storage
state and identical signed target conversion/schema contract. It requires all
five retained CRDs and actual exact-version custom-resource discovery for every
derived operation permission, including all five collection reads and the
GameDestroy CREATE probe. Another pass requires unchanged original CRD UIDs,
resource versions and template hashes across discovery. Original Namespace and
sealed journal checks bracket the gate. Discovery alone cannot adopt CRDs or
replace the signed storage/conversion checks; this is not an atomic cluster lock.

The private observer bridge derives read clients from the mutation access's
frozen cluster/static credential identity, not a separately reopened kubeconfig.
Caller changes to TLS bytes, impersonation groups/extras, token files or host
configuration do not redirect or refresh that identity. Complete unfiltered
reads and metadata-only recursive owner evidence must retain the supplied
sealed original journal's exact anchor, resource version and bytes. Changed,
replaced or stale journal/Namespace observations are discarded in full.

Metadata sanitation and raw error suppression occur below supplied wrappers
and SDK logging. Public response syntax rejects duplicate keys, invalid UTF-8,
trailing JSON and excessive depth/node counts before SDK decoding; conversion
to typed safety objects and metadata uses case-sensitive strict decoding.
Unknown fields or capitalization aliases cannot silently become safety state.
Only fixed JSON content type/status and no raw headers/trailers reach wrappers.

Native API-server fixtures on both declared profiles cover CRD establishment,
served discovery and the same-cluster read bridge, including populated gated
Pod and no-provisioning PVC reads. They do not provide a kubelet or physical
storage. Neither the bridge nor an empty/settled observation proves coldness:
exact current claim identity/binding, detached storage, workload templates that
could remount claims, API/controller descendants and endpoints, actual runtime
readiness and full lifecycle CI remain separate required obligations.

### Bound current-world and cold-storage checkpoint

The separate `ClusterCold` checkpoint now combines the sealed same-identity
observer with pure cold-data validation. The observer also reads complete
namespace Deployment, ReplicaSet, StatefulSet, DaemonSet, ReplicationController
and CronJob lists, plus the complete cluster VolumeAttachment list. Failure of
any of these reads discards the entire observation; copies do not alias callers.

Every live namespace PVC is retained, including unlabeled claims outside domain
history. A current stopped GameServer must resolve the complete selected adapter
path set through the platform planner, with exact claim UIDs, durable identity
labels and bound-world observations. Status-only active-data switches do not
escape validation just because the GameServer generation stayed unchanged.
Only never-observed generated Pending data can lack a bound-world receipt;
explicit selections and previously observed worlds cannot use that exception.
Historical operation references may outlive their PVCs, but remain conservative
future-mount signals rather than authority to adopt replacements.

Bound claims require exact UID-to-PV binding, nondeleting ownerless backing
PVs, matching class/mode, covering access modes and positive observed capacity.
An increased capacity request is not mistaken for new data identity or loss of
coldness while the stopped world's older capacity remains bound. Named PV GETs
are derived from namespace claims and global attachment sources, individually
discovery/SSAR-authorized and bounded. No PV LIST, wildcard read or PVC/PV delete
authority is introduced. The declared CSI storage prerequisite supplies exact
physical `(driver, volumeHandle)` identity: a differently named PV or translated
inline attachment cannot hide an alias. Matching attachment intent is refused
until absent, including pending, false-attached, deleting and error states.
Well-formed distinct CSI sources remain unrelated; missing, ambiguous or
uncomparable source evidence fails closed.

Pods and every collected builtin workload template are checked for retained
mounts and broad data-worker signals, regardless of completion, suspension,
termination or zero replicas. StatefulSet claim-template names and generic
ephemeral claim names are included. The checkpoint repeats complete observations
and protected server/claim/PV identity, bracketing them with the original signed
policy UID/spec/resource-version evidence and original namespace journal.
Harmless leader renewals and independently proved unrelated attachment changes
are not protected world identity.

This is read-only cold-data evidence, not a cluster lock, storage provisioner,
admission-behavior receipt, runtime-stop fallback or full `LifecycleChecks`
provider. Unit/HTTPS fixtures do not certify physical CSI detachment, real
kubelet operation or full binary install/upgrade/rollback/uninstall. Complete
API/controller quiescence, the remaining admission branches, retained recovery
guidance and actual isolated lifecycle CI remain required before issue #27 can
be delivered.

### Bound API/controller shutdown checkpoint

The separate read-only `ClusterQuiescence` implements `APIStopped` and
`RuntimeStopped`, not controller availability or the full lifecycle provider.
The sealed observer now also collects the complete unfiltered namespace
EndpointSlice list, within the existing whole-observation byte/pagination and
original-journal barriers. An unavailable page or case-aliased/unknown typed
field cannot become absence evidence.

API shutdown requires both an absent settled API Deployment inventory entry
and an exact-name NotFound read, plus complete absence of its executable
descendants and alternate builtin workload templates. Original API Service
UID/spec evidence binds any surviving empty EndpointSlices. Native portless
placeholders and just-drained original HTTPS slices are allowed; unready,
terminating or otherwise nonempty slices are not absence. Service replacement,
malformed original-UID ownership and stale descendants fail closed.

Full runtime shutdown additionally requires both original signed zero-replica
controller Deployments, their current observed generation and zero counters,
and no related Pods, including terminal or deleting Pods. Missing controllers
are allowed only after settled retaining-uninstall removal, never recreated or
adopted. Reserved names, owner UIDs/names, family labels, ServiceAccount aliases,
image repositories and API Secret references are independent refusal signals.
Shared and tagged image repositories remain supported: the API-only checkpoint
can distinguish an original whole signed controller Pod/RS/Deployment chain,
including an unscheduled Pending Pod, from a repository-only orphan signal.
The authenticated serving path still requires a scheduled original Pod.

Kubernetes retains ten ReplicaSet revisions while executable package trust is
bounded to three packages. Historical zero sets can therefore be certified as
inert without claiming unavailable historical signatures: exact original live
parent UID/owner/selector/hash derivatives, bounded native-shaped annotations,
current zero status and complete related-Pod absence are required. A deleted
parent's sets cannot qualify as inert and always block full runtime shutdown.
The API-only checkpoint may ignore independently unrelated controller history.
Historical payloads cannot authorize execution or
adoption; only exact whole signed controller-template equality can authorize a
controller exception from the journal's active/target/previous package set.
This lets recovery pause a signed predecessor still running after a failed
target rollout, without admitting unknown or unreferenced historical execution.
Target readiness remains a separate exact-target obligation.
Independent ColdSafety still scans every old
template for workers and remounts, regardless of zero replicas.

Ownership closure is precomputed over the complete observed metadata graph
before runtime classification. Object UIDs and every owner reference count,
independently of list order or owner flags/kind. A renamed nested set or an
indirect descendant through a Job or recursively observed metadata owner cannot
hide ahead of its parent in a list.

Repeated whole observations and original runtime identity/read-shape witnesses
surround the check. This is not a cluster lock or an effect. HTTPS fixtures cover
race/refusal boundaries; exact 1.35.8/1.37.0 isolated API-server fixtures cover
native zero-state objects, portless placeholders and genuinely admitted Pending
controller Pods with ServiceAccount admission enabled. Seeded fixture status is
not controller-manager/kubelet shutdown evidence. Actual target availability,
all admission branches, complete binary lifecycle/recovery output and isolated
fresh/predecessor upgrade/rollback/uninstall CI remain delivery requirements.

### Bound target-controller availability checkpoint

The separate read-only `ClusterControllers` implements only
`ControllersAvailable`, in Applying and Verifying. Both original ServiceAccounts
and Deployments must match the exact signed target package and their original
inventory UIDs. During rollback the target is the older approved package, not
the still-active newer package; neither the active package nor shutdown's
signed-predecessor exception can substitute for target readiness.

Complete unfiltered workload observations establish the actual
Pod-to-ReplicaSet-to-original-Deployment chains. Native selection chooses the
oldest whole-template-matching set, with name tie-breaking; matching ignores
only the hash label and the reviewed ServiceAccount alias normalization.
The selected set must have current one-replica readiness counters, original
owner/selector/hash derivatives and native controller desired/max annotations
of `1/2`. Every other related set, including older matching revisions, must be
inert with no related Pods. Exactly one scheduled Running, Ready,
whole-template-derived Pod is required for each selected set. Extra, orphaned,
terminal, deleting, altered or stale descendants are refused.

Classification follows original and derivative UIDs, all owner references,
reserved family names/labels/selectors and both ServiceAccount aliases, across
outer and nested workload metadata/specs. Transitive UID closure is independent
of list order and includes recursively observed metadata owners. Any related
alternate builtin workload is refused, including zero/suspended templates.
Repository equality alone is deliberately not controller identity: an active
API or domain worker can share the repository without becoming a controller
descendant. Availability neither authorizes those siblings nor certifies their
shape. It does not replace ColdSafety's broader no-worker/remount obligation,
prove namespace-wide runtime absence or exclusive credential authority.

Two complete observations and unchanged relevant account/controller/set/Pod
witnesses are bracketed by the original Namespace/journal barriers. Unrelated
runtime and leader-lease churn is not target controller identity. These are
temporal reads, not an atomic lock. Exact 1.35.8/1.37.0 API-server fixtures admit
the scheduled controller Pod shapes and distinguish unready/old executable
sets from seeded target-ready topology; scheduling and Ready counters are
explicit test-admin inputs. They do not certify a real scheduler, kubelet,
controller-manager, leader acquisition or successful reconciliation. The
complete provider, remaining admission branches, authenticated-target integration,
installer/recovery command and actual binary lifecycle CI remain required.

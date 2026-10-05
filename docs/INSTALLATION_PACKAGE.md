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
can confirm a lost response. An attempted unconfirmed creation is never replayed,
even if a read currently returns NotFound. Its original UID is durably pinned
before binding the cluster journal. Namespace replacement, ownership drift,
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

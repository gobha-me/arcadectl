# Exact-source CLI artifacts

The local artifact builder is a component of supply-chain work (#39). It builds
unsigned Linux amd64/arm64 CLI archives from one clean tracked Git commit. It
does not publish, sign, tag, certify a platform, or approve a release. In
particular, an arm64 cross-build is not arm64 runtime certification.

From a clean checkout, select the exact Go patch in `go.mod` and a new output
directory whose parent already exists:

```sh
GOTOOLCHAIN=go1.26.10 make build-cli-artifacts ARTIFACT_DIR=/tmp/arcadectl-build-one
GOTOOLCHAIN=go1.26.10 make build-cli-artifacts ARTIFACT_DIR=/tmp/arcadectl-build-two
diff -qr /tmp/arcadectl-build-one /tmp/arcadectl-build-two
cd /tmp/arcadectl-build-one
sha256sum --check --strict SHA256SUMS
tar -xzf arcadectl-linux-amd64.tar.gz
./arcadectl version --output json
```

Run a binary only on its matching platform. `version` works offline and requires
no credential, saved context, API connection, or cluster access. Development
builds report unknown source identity. Embedded version information is a build
claim; authenticating an artifact requires a separately trusted signed digest.

The builder refuses tracked modifications, the wrong Go patch, and an existing
output path. It exports the exact commit with `git archive`; untracked files and
ignored build outputs cannot enter the source snapshot. It pins build target
features, disables CGO, uses module read-only mode, trims paths, clears the build
ID, and embeds the exact source SHA and commit epoch. Packaging fixes archive
order, ownership, modes, timestamps, and gzip headers. `SOURCE_DATE_EPOCH` from
the caller does not override the commit epoch. No signing credential is read.

`manifest.json` binds every archive to its SHA-256, size, target, exact source,
commit epoch, Go patch, Python and zlib versions. It explicitly records
`signed: false`, `certified: false`, and per-target `not-evaluated` certification.
`SHA256SUMS` covers the manifest, archives and dependency inventories. A failed
write may leave an incomplete directory; a successful build and complete
checksum verification are both required before consuming these local files.

The per-target `.modules.json` inventories come from the actual built binaries,
including Go module checksums and build settings. They are not SPDX/CycloneDX
SBOMs, a license audit, a provenance attestation, or signatures. The archive
includes project LICENSE/NOTICE; a complete dependency license disposition
remains a release prerequisite. Compression reproducibility is bounded to the
recorded Python/zlib versions and matching source/toolchain/build inputs.

Publication remains blocked on protected-ref build automation, exact-main full
CI, vulnerability/image/manifest/license policy, complete SBOMs, trusted
provenance and signing, image multi-architecture evidence, adapter compatibility
certification, and independent review. Pull-request code must never receive
release signing or publication credentials. Neither these unsigned local
artifacts nor a successful checksum check bypass those gates.

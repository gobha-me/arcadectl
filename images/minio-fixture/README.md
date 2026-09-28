# Isolated MinIO fixture

This image is test-only, never part of the Arcadectl production controller or
published to the project registry. The harness builds it serially, pushes it
only to its disposable local registry, and runs the resolved immutable digest.

The original upstream container pin became unavailable. We instead build
unmodified official MinIO release `RELEASE.2025-10-15T17-29-55Z` from commit
`9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a`. Docker verifies the source archive
SHA-256 `45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841`
before extraction. The recipe supplies fixed upstream version metadata, uses
the upstream `kqueue` build tag, disables VCS discovery for the archive, and
bounds Go build concurrency and memory pressure. The `DEVELOPMENT` release tag
identifies our source build instead of impersonating an upstream binary.

MinIO is separately licensed under AGPL-3.0; this build does not add MinIO code
to Arcadectl's Go module. The image includes the unmodified source archive,
upstream `LICENSE` and dependency `CREDITS`, and the complete Docker build recipe
under `/licenses`. Do not strip them when distributing this fixture.

The harness runs numeric UID/GID 65532, with only private `/data` and `/tmp`
volumes writable, and probes `/minio/health/cluster` to wait for S3 write quorum.
No source-world claims or Kubernetes API token are mounted into MinIO.

Sources: [official release](https://github.com/minio/minio/releases/tag/RELEASE.2025-10-15T17-29-55Z),
[exact source archive](https://codeload.github.com/minio/minio/tar.gz/9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a),
[build metadata generator](https://github.com/minio/minio/blob/9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a/buildscripts/gen-ldflags.go),
[health checks](https://github.com/minio/minio/blob/9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a/cmd/healthcheck-handler.go).

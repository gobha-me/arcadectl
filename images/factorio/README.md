# Certified Factorio runtime

Arcadectl uses a thin image derived from the pinned `factoriotools/factorio`
image. It adds an entrypoint wrapper that keeps the upstream Bash trace stream
out of container logs and a silent `/arcadectl/readiness` helper that checks
the loopback RCON listener without putting its administrator port or diagnostic
output in the Pod spec or kubelet Events. The wrapper is required because the
upstream entrypoint expands its generated RCON password while tracing commands.

The pinned base manifest contains the upstream entrypoint from commit
`0099d8864f6fc7a4ffbf72439990eb8df6751a67`, with SHA-256
`d6ee01961cedb2542fd875d8b2ad5a0f4b3d22eb7a591851c297fed1802b1233`.
The Docker build verifies that hash before adding the wrapper and fixed helper.

The adapter accepts only digests from
`ghcr.io/gobha-me/arcadectl-factorio`. Updating Factorio therefore requires an
explicit base-image digest change here, a rebuilt derived image, and the
isolated lifecycle evidence required by the Factorio adapter.

The public image is not published by this slice. Publication remains gated on
the release supply-chain work, including provenance, SBOM, vulnerability and
license review. Local isolated-cluster validation may build this Dockerfile
without pushing it.

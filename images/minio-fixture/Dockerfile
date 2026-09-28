# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0
# Build recipe only. Unmodified MinIO is a separate AGPL-3.0 test fixture.

FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV GOTOOLCHAIN=local GOMAXPROCS=2 GOMEMLIMIT=1GiB GOFLAGS="-mod=readonly -p=1"
WORKDIR /src
ADD --checksum=sha256:45521908307306e925c98d629e1c17d78c8b72b6ee242b1bfb1409f7d8ee5841 \
    https://codeload.github.com/minio/minio/tar.gz/9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a /tmp/minio-source.tar.gz
RUN tar -xzf /tmp/minio-source.tar.gz --strip-components=1 \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -tags kqueue -trimpath -buildvcs=false \
       -ldflags='-s -w -buildid= -X github.com/minio/minio/cmd.Version=2025-10-15T17:29:55Z -X github.com/minio/minio/cmd.CopyrightYear=2025 -X github.com/minio/minio/cmd.ReleaseTag=DEVELOPMENT.2025-10-15T17-29-55Z -X github.com/minio/minio/cmd.CommitID=9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a -X github.com/minio/minio/cmd.ShortCommitID=9e49d5e7a648f -X github.com/minio/minio/cmd.GOPATH=/go -X github.com/minio/minio/cmd.GOROOT=/usr/local/go' \
       -o /out/minio . \
    && mkdir -p /out/licenses \
    && cp LICENSE CREDITS /out/licenses/ \
    && cp /tmp/minio-source.tar.gz /out/licenses/ \
    && chmod 0755 /out/minio \
    && chmod 0644 /out/licenses/*
COPY Dockerfile /out/licenses/build-recipe.Dockerfile
RUN mkdir -p /out/etc/ssl/certs \
    && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt \
    && chmod 0644 /out/etc/ssl/certs/ca-certificates.crt \
    && find /out -exec touch -d '@1760549395' {} +

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/minio/minio" \
      org.opencontainers.image.revision="9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      arcade.gobha.me/purpose="isolated-lifecycle-test-fixture"
COPY --from=build /out/ /
ENV HOME=/tmp MINIO_BROWSER=off MINIO_UPDATE=off
USER 65532:65532
ENTRYPOINT ["/minio"]

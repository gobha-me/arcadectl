# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

ARG SOURCE_DATE_EPOCH
FROM restic/restic@sha256:39d9072fb5651c80d75c7a811612eb60b4c06b32ffe87c2e9f3c7222e1797e76 AS restic

FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VCS_REF
ARG SOURCE_DATE_EPOCH
ARG LIFECYCLE_TEST=false
ARG SOURCE_DIRTY=false
ENV GOTOOLCHAIN=local GOMAXPROCS=2 GOFLAGS="-mod=readonly -p=2"

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
COPY LICENSE NOTICE ./
COPY licenses ./licenses
COPY --from=restic /usr/bin/restic /rootfs/restic
COPY --from=restic /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt
RUN case "$VCS_REF" in ""|*[!0-9a-f]*) echo "VCS_REF must be a full lowercase Git SHA" >&2; exit 1 ;; esac \
    && test "${#VCS_REF}" -eq 40 \
    && case "$SOURCE_DATE_EPOCH" in ""|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be a Unix timestamp" >&2; exit 1 ;; esac \
    && case "$LIFECYCLE_TEST" in false) set -- ;; true) set -- -tags=lifecycletest ;; *) echo "LIFECYCLE_TEST must be true or false" >&2; exit 1 ;; esac \
    && case "$SOURCE_DIRTY" in true|false) ;; *) echo "SOURCE_DIRTY must be true or false" >&2; exit 1 ;; esac \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build "$@" -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-controller ./cmd/arcadectl-controller \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-backup-worker ./cmd/arcadectl-backup-worker \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-restore-worker ./cmd/arcadectl-restore-worker \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-backup-authorizer ./cmd/arcadectl-backup-authorizer \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-restore-authorizer ./cmd/arcadectl-restore-authorizer \
    && mkdir -p /rootfs/licenses \
    && cp /out/arcadectl-controller /rootfs/arcadectl-controller \
    && cp /out/arcadectl-backup-worker /rootfs/arcadectl-backup-worker \
    && cp /out/arcadectl-restore-worker /rootfs/arcadectl-restore-worker \
    && cp /out/arcadectl-backup-authorizer /rootfs/arcadectl-backup-authorizer \
    && cp /out/arcadectl-restore-authorizer /rootfs/arcadectl-restore-authorizer \
    && cp LICENSE NOTICE /rootfs/licenses/ \
    && cp licenses/restic-LICENSE /rootfs/licenses/restic-LICENSE \
    && chmod 0755 /rootfs/arcadectl-controller /rootfs/arcadectl-backup-worker /rootfs/arcadectl-restore-worker /rootfs/arcadectl-backup-authorizer /rootfs/arcadectl-restore-authorizer /rootfs/restic \
    && chmod 0644 /rootfs/licenses/LICENSE /rootfs/licenses/NOTICE /rootfs/licenses/restic-LICENSE /rootfs/etc/ssl/certs/ca-certificates.crt \
    && chown 65532:65532 /rootfs/arcadectl-controller /rootfs/arcadectl-backup-worker /rootfs/arcadectl-restore-worker /rootfs/arcadectl-backup-authorizer /rootfs/arcadectl-restore-authorizer \
    && find /rootfs -exec touch -d "@$SOURCE_DATE_EPOCH" {} +

FROM scratch

ARG VCS_REF
ARG SOURCE_DIRTY=false
LABEL org.opencontainers.image.source="https://github.com/gobha-me/arcadectl" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.licenses="Apache-2.0" \
      arcade.gobha.me/source-dirty="$SOURCE_DIRTY"

COPY --from=build /rootfs /

USER 65532:65532
ENTRYPOINT ["/arcadectl-controller"]

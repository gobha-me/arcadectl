# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

ARG SOURCE_DATE_EPOCH
FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VCS_REF
ARG SOURCE_DATE_EPOCH
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY cmd ./cmd
COPY internal ./internal
COPY LICENSE NOTICE ./
RUN case "$VCS_REF" in ""|*[!0-9a-f]*) echo "VCS_REF must be a full lowercase Git SHA" >&2; exit 1 ;; esac \
    && test "${#VCS_REF}" -eq 40 \
    && case "$SOURCE_DATE_EPOCH" in ""|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be a Unix timestamp" >&2; exit 1 ;; esac \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -trimpath -ldflags="-s -w -buildid=" -o /out/arcadectl-controller ./cmd/arcadectl-controller \
    && mkdir -p /rootfs/licenses \
    && cp /out/arcadectl-controller /rootfs/arcadectl-controller \
    && cp LICENSE NOTICE /rootfs/licenses/ \
    && chmod 0755 /rootfs/arcadectl-controller \
    && chmod 0644 /rootfs/licenses/LICENSE /rootfs/licenses/NOTICE \
    && chown 65532:65532 /rootfs/arcadectl-controller \
    && find /rootfs -exec touch -d "@$SOURCE_DATE_EPOCH" {} +

FROM scratch

ARG VCS_REF
LABEL org.opencontainers.image.source="https://github.com/gobha-me/arcadectl" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /rootfs /

USER 65532:65532
ENTRYPOINT ["/arcadectl-controller"]

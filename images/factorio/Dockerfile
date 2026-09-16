# syntax=docker/dockerfile:1.8
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

FROM factoriotools/factorio@sha256:4ec5fea2e06bd78ec84f7d1820ab9dbfc50cb1e19f0c7a1fb316dec1d7e5f5ca

RUN echo "d6ee01961cedb2542fd875d8b2ad5a0f4b3d22eb7a591851c297fed1802b1233  /docker-entrypoint.sh" | sha256sum -c -

COPY --chmod=0555 secure-entrypoint.sh /arcadectl/secure-entrypoint.sh

ENTRYPOINT ["/arcadectl/secure-entrypoint.sh"]

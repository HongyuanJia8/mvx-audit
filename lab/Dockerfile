FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

ARG CHROMIUM_VERSION=150.0.7871.181-1~deb12u1

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium="${CHROMIUM_VERSION}" ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin analyst
WORKDIR /opt/mvx-lab
COPY --chown=root:root runner.mjs ./runner.mjs
USER analyst

ENV HOME=/tmp \
    MVX_LAB_CONTAINER=1
ENTRYPOINT ["node", "/opt/mvx-lab/runner.mjs"]

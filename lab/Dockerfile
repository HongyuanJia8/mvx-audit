FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin analyst
WORKDIR /opt/mvx-lab
COPY --chown=root:root runner.mjs ./runner.mjs
USER analyst

ENV MVX_LAB_CONTAINER=1
ENTRYPOINT ["node", "/opt/mvx-lab/runner.mjs"]

# Base image for probe containers — the ones that run third-party code.
#
# Carries node and python because the sampling frame is npm and PyPI packages,
# and one image for both keeps exactly one containment story to verify rather
# than two. Nothing MCPWatch-specific is baked in: the probe driver is copied in
# at run time, and the image itself holds no corpus path, no credentials, and no
# knowledge of the host.
#
# The unprivileged user is created here rather than relied upon from the base
# image so that `--user` in the runner names something that certainly exists.
FROM node:22-bookworm-slim

# strace is WP9's primary instrument: it sees a syscall whether or not it
# succeeded, which is what makes a connection refused by the sinkhole still
# count as a tool reaching for the network.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates strace \
 && rm -rf /var/lib/apt/lists/*

# uid 10001 is arbitrary but fixed: the runner passes --user 10001:10001, and a
# drifting uid would silently turn into a root probe.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin prober \
 && mkdir -p /srv/probe /srv/server \
 && chown -R prober:prober /srv

COPY --chown=prober:prober driver.py /srv/probe/driver.py
# WP9's exerciser. Present in the image but never invoked by the WP8 probe path,
# which runs driver.py alone — the nightly collection cycle has no way to reach
# a tools/call.
COPY --chown=prober:prober exercise.py /srv/probe/exercise.py

USER prober
WORKDIR /srv/server

# npm's own network calls should never be attempted from a launched server, and
# a cache write outside the writable volume would fail confusingly.
ENV npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

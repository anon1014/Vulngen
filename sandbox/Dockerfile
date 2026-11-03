# Sandbox image for verifying generated cases.
# Containers from this image are always started with --network none,
# a read-only root filesystem, no capabilities, and resource limits
# (see vulngen/verify.py).
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user by default.
USER 65534:65534
WORKDIR /tmp

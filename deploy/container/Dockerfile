# deid-serve, containerised. Read docs/DEPLOY-SERVER.md first.
#
# Build from the REPOSITORY ROOT, because the build needs the whole workspace:
#   docker build -f deploy/container/Dockerfile -t deid-tr/deid-serve:local .
#
# What this image does NOT contain:
#   * Model weights. There are none to contain -- L2 has no trained model in this
#     build, so this image masks ZERO NAMES. Baking weights into an image would
#     also mean shipping a multi-gigabyte artifact whose provenance nobody checks.
#   * Any network call at build time other than the dependency fetch below.
#     No curl-to-bash, no fetching a script from a URL, no model download.

# ---------------------------------------------------------------------------
# Stage 1: build.
# ---------------------------------------------------------------------------
FROM rust:1-slim-trixie AS build
WORKDIR /src

# The whole workspace, because deid-tr-service depends on deid-tr-core by path
# and core embeds eval/schema.yaml with include_str!.
COPY . .

# The ONE network operation in this file, and it is a dependency fetch. Split
# from the build so that a build cannot quietly acquire anything else: the build
# step below runs --offline and fails if it wants a crate this line did not get.
RUN cargo fetch --locked

RUN cargo build --release --offline --locked -p deid-tr-service --bin deid-serve

# ---------------------------------------------------------------------------
# Stage 2: runtime. Nothing from stage 1 comes across except the binary.
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

# curl is here for exactly one reason: HEALTHCHECK needs an HTTP client and the
# service binary is not one. It is the only package added, and it is added in the
# runtime stage rather than being inherited from a fatter base.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# A DEDICATED UNPRIVILEGED USER. The container's root is still root in the
# kernel's eyes for anything that escapes the namespace, and this process holds
# session span maps -- the table from each surrogate back to the real identifier.
RUN groupadd --system --gid 10001 deid \
    && useradd --system --uid 10001 --gid deid --no-create-home --shell /usr/sbin/nologin deid

COPY --from=build /src/target/release/deid-serve /usr/local/bin/deid-serve
COPY deploy/container/entrypoint.sh /usr/local/bin/deid-entrypoint
RUN chmod 0755 /usr/local/bin/deid-entrypoint

USER deid:deid
WORKDIR /var/empty

# The default binds the CONTAINER'S LOOPBACK, and that is deliberate even though
# it makes a bare `docker run -p 8787:8787` reach nothing at all.
#
# Under bridge networking, Docker's published port forwards to the container's
# bridge address, not to its loopback, so this default FAILS CLOSED: the operator
# gets a connection refused rather than a de-identification endpoint they did not
# mean to publish. The two ways to actually reach it are in compose.yaml, and both
# of them are decisions someone has to make on purpose.
#
# THE COMMENT THIS FILE EXISTS FOR: publishing on all host interfaces -- `-p
# 8787:8787` with no address, which is what a shipped compose file does when
# nobody thought about it -- is the incumbent's documented default. Their prose is
# careful and their compose file is not, and the operator gets the compose file.
# That specific bug is the one this project does not ship: `deid-serve` refuses an
# all-interfaces bind unconditionally, and every publish example we write names
# 127.0.0.1 on the host side.
CMD ["/usr/local/bin/deid-serve", "--port", "8787"]

EXPOSE 8787

# /health is unauthenticated by design so a supervisor can check liveness without
# holding a credential, and it returns no document text -- version, tier, and
# which layers are live. The probe runs INSIDE the container and tries loopback
# first, then this container's own address, because those are the only two things
# the process is ever bound to and the script must not need to be told which.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/deid-entrypoint", "health"]

ENTRYPOINT []

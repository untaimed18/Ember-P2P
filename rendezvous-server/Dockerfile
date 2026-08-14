# Base images are pinned by digest so rebuilding a commit produces the same
# server. Bump the digest with the tag when taking base image security updates:
#   docker buildx imagetools inspect rust:1.94-slim
FROM rust:1.94-slim@sha256:cf09adf8c3ebaba10779e5c23ff7fe4df4cccdab8a91f199b0c142c53fef3e1a AS builder
WORKDIR /app
# No glob on the lockfile and --locked on the build: a missing or stale
# Cargo.lock must fail here, not silently resolve newer transitive crates than
# the ones committed and ship them to an internet-facing service.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/* \
    && groupadd -r ember && useradd -r -g ember ember
COPY --from=builder /app/target/release/ember-rendezvous /usr/local/bin/
EXPOSE 8080
ENV PORT=8080
USER ember
CMD ["ember-rendezvous"]

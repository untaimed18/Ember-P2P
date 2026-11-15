# emberd, Ember without a window, as a container. Build from the repository
# root:
#
#   docker build -f packaging/emberd/Dockerfile -t emberd .
#   docker run -d --name emberd -p 4711:4711 -p 4662:4662/tcp -p 4662:4662/udp \
#     -p 4672:4672/udp -v emberd-data:/data -v /srv/downloads:/downloads emberd
#   docker logs emberd          (the setup code for the first visit is here)
#
# Then open http://<this host>:4711. The web interface listens on every
# address in here so the port can be published; over plain HTTP its password
# travels unencrypted, so publish it only to a network you trust, or put it
# behind a reverse proxy with HTTPS. To share folders, mount them and name
# them: -v /srv/music:/shared/music:ro -e EMBERD_SHARED_DIRS=/shared/music.

FROM node:24-bookworm AS web
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build:web

FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --locked --release --manifest-path src-tauri/Cargo.toml \
      --no-default-features --features server --bin emberd

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1000 --create-home --home-dir /home/emberd --shell /usr/sbin/nologin emberd \
 && mkdir -p /data /downloads \
 && chown emberd:emberd /data /downloads
COPY --from=build /src/src-tauri/target/release/emberd /opt/emberd/emberd
COPY --from=web /src/build-web /opt/emberd/web
COPY src-tauri/resources/dbip-country-lite.mmdb /opt/emberd/resources/dbip-country-lite.mmdb
ENV EMBER_DATA_DIR=/data \
    EMBERD_DOWNLOAD_DIR=/downloads \
    EMBERD_LISTEN=0.0.0.0:4711 \
    HOME=/home/emberd
VOLUME ["/data", "/downloads"]
# The web interface; eD2K and the Ember overlay (TCP, and QUIC on UDP); Kad.
EXPOSE 4711/tcp 4662/tcp 4662/udp 4672/udp
USER emberd
# tini passes `docker stop`'s signal on, so Ember saves and stops cleanly.
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/emberd/emberd"]
STOPSIGNAL SIGTERM

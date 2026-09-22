# Build stage: compile the client and daemon.
FROM rust:1.97-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p keepstone-cli -p keepstone-daemon

# Runtime stage.
FROM debian:bookworm-slim
RUN useradd --create-home --uid 10001 keepstone
COPY --from=builder /src/target/release/keepstone /usr/local/bin/keepstone
COPY --from=builder /src/target/release/keepstone-daemon /usr/local/bin/keepstone-daemon
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
    && mkdir -p /data \
    && chown keepstone:keepstone /data
USER keepstone
WORKDIR /home/keepstone
ENV KEEPSTONE_DATA=/data
VOLUME /data
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["keepstone", "--help"]

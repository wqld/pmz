FROM rust:1 AS builder

COPY . .

RUN apt-get update && apt-get install musl-tools -y
RUN rustup target add $(uname -m)-unknown-linux-musl
RUN cargo build --target $(uname -m)-unknown-linux-musl --release
RUN mv /target/$(uname -m)-unknown-linux-musl/release/agent /target/pmz-agent

FROM alpine:3.18 AS runtime

COPY --from=builder --chown=root:root /target/pmz-agent /app/

ENV RUST_LOG=info
EXPOSE 8100

CMD ["/app/pmz-agent"]

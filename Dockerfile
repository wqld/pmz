FROM --platform=$BUILDPLATFORM rust:1 AS builder

# export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
# export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
# cargo build --release --target aarch64-unknown-linux-musl -p agent
# cargo build --release --target x86_64-unknown-linux-musl -p agent
# docker build --push --platform linux/amd64,linux/arm64 -t ghcr.io/wqld/pmz-agent:0.1.0 .

ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM"
RUN case "$TARGETPLATFORM" in \
    "linux/arm64") echo aarch64-unknown-linux-musl > /rust_target.txt ;; \
    "linux/amd64") echo x86_64-unknown-linux-musl > /rust_target.txt ;; \
    *) exit 1 ;; \
    esac

COPY . .

RUN cp target/$(cat /rust_target.txt)/release/agent target/pmz-agent

FROM alpine:3.18 AS runtime

COPY --from=builder --chown=root:root /target/pmz-agent /app/

ENV RUST_LOG=info
EXPOSE 8100

CMD ["/app/pmz-agent"]

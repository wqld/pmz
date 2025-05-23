agent-tag := '0.1.0'
cni-tag := '0.1.0'
target := arch() + '-unknown-linux-musl'

alias latk := load-agent-to-kind
@load-agent-to-kind TAG=agent-tag TARGET=target:
    cargo build --release --target {{TARGET}} -p agent
    docker build -t ghcr.io/wqld/pmz-agent:{{TAG}} .
    kind load docker-image ghcr.io/wqld/pmz-agent:{{TAG}}
    @# all done!

alias lctk := load-cni-to-kind
@load-cni-to-kind TAG=cni-tag TARGET=target:
    cargo build --release --target {{TARGET}} -p cni
    docker build -f Dockerfile.cni -t ghcr.io/wqld/pmz-cni:{{TAG}} .
    kind load docker-image ghcr.io/wqld/pmz-cni:{{TAG}}
    @# all done!

alias patg := publish-agent-to-ghrc
@publish-agent-to-ghrc TAG=agent-tag:
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc
    cargo build --release --target aarch64-unknown-linux-musl -p agent
    cargo build --release --target x86_64-unknown-linux-musl -p agent
    docker build --push --platform linux/amd64,linux/arm64 -t ghcr.io/wqld/pmz-agent:{{TAG}} .

@package-daemon:
    @# TODO

@install-crd:
    cargo run -p agent --bin crdgen | kubectl apply -f -

@build-proto:
    cargo clean -p proto
    cargo build -p proto

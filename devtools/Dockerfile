FROM ubuntu:20.04

# Adding rust binaries to PATH.
ENV PATH="$PATH:/root/.cargo/bin"
ENV CC=clang
ENV AR=llvm-ar

# Install all required packages in one go to optimize the image
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# DEBIAN_FRONTEND is set for tzdata.
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    build-essential ca-certificates curl gcc git libssl-dev pkg-config ssh \
    clang llvm nasm \
    # cleanup
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rustup and a fixed version of Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2021-08-20
RUN rustup toolchain install 1.58.1
RUN rustup component add rust-src
COPY cargo_config /root/.cargo/config
RUN cargo install cargo-xbuild

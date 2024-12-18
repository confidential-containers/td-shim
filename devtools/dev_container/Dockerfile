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
    screen expect \
    # cleanup
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rustup and a fixed version of Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.83.0
RUN rustup component add rust-src
RUN rustup component add llvm-tools-preview
COPY cargo_config /root/.cargo/config
RUN cargo install cargo-xbuild

# Install fuzzing tools
# For more information, please see doc/fuzzing.md.
RUN cargo install cargo-afl
RUN cargo install cargo-fuzz --version 0.12.0

# Install rudra
RUN rustup component add rustc-dev
RUN cargo install sccache
RUN set -eux; \
    git clone https://github.com/sslab-gatech/Rudra.git; \
    cd Rudra; \
    ./install-release.sh;

RUN git clone https://github.com/confidential-containers/td-shim.git

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
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2023-12-31
RUN rustup toolchain install 1.75.0
RUN rustup component add rust-src
RUN rustup component add llvm-tools-preview
COPY cargo_config /root/.cargo/config
RUN cargo install cargo-xbuild

# Install fuzzing tools
# The rust version used now is nightly-2021-08-20, the latest cargo-fuzz needs to be upgraded to the rust version, and nightly-2021-08-20 can use cargo-fuzz 0.10.2 . 
# For more information, please see doc/fuzzing.md.
RUN cargo install cargo-afl
RUN cargo install cargo-fuzz --version 0.10.2

# Install rudra
RUN rustup component add rustc-dev
RUN cargo install sccache
RUN set -eux; \
    git clone https://github.com/sslab-gatech/Rudra.git; \
    cd Rudra; \
    ./install-release.sh;

RUN git clone https://github.com/confidential-containers/td-shim.git

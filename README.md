[![Main](https://github.com/confidential-containers/td-shim/actions/workflows/main.yml/badge.svg)](https://github.com/confidential-containers/td-shim/actions/workflows/main.yml)
[![Libray Crates](https://github.com/confidential-containers/td-shim/actions/workflows/library.yml/badge.svg)](https://github.com/confidential-containers/td-shim/actions/workflows/library.yml)
[![Cargo Deny](https://github.com/confidential-containers/td-shim/actions/workflows/deny.yml/badge.svg)](https://github.com/confidential-containers/td-shim/actions/workflows/deny.yml)
[![Cargo Fmt & Clippy](https://github.com/confidential-containers/td-shim/actions/workflows/format.yml/badge.svg)](https://github.com/confidential-containers/td-shim/actions/workflows/format.yml)
[![Integration Test](https://github.com/confidential-containers/td-shim/actions/workflows/integration.yml/badge.svg)](https://github.com/confidential-containers/td-shim/actions/workflows/integration.yml)
[![TDX Integration Test](https://github.com/confidential-containers/td-shim/actions/workflows/integration-tdx.yml/badge.svg)](https://github.com/confidential-containers/td-shim/actions/workflows/integration-tdx.yml)
[![Fuzzing Test](https://github.com/confidential-containers/td-shim/actions/workflows/fuzz.yml/badge.svg)](https://github.com/confidential-containers/td-shim/actions/workflows/fuzz.yml)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim?ref=badge_shield)
# TD-shim - Confidential Containers Shim Firmware

Hardware virtualization-based containers are designed to launch and run
containerized applications in hardware virtualized environments. While
containers usually run directly as bare-metal applications, using TD or VT as an
isolation layer from the host OS is used as a secure and efficient way of
building multi-tenant Cloud-native infrastructures (e.g. Kubernetes).

In order to match the short start-up time and resource consumption overhead of
bare-metal containers, runtime architectures for TD- and VT-based containers put
a strong focus on minimizing boot time. They must also launch the container
payload as quickly as possible. Hardware virtualization-based containers
typically run on top of simplified and customized Linux kernels to minimize the
overall guest boot time.

Simplified kernels typically have no UEFI dependencies and no ACPI ASL
support. This allows guests to boot without firmware dependencies. Current
VT-based container runtimes rely on VMMs that are capable of directly booting
into the guest kernel without loading firmware.

TD Shim is a simplified [TDX virtual firmware](doc/tdshim_spec.md#vfw) for the
simplified kernel for TD container. This document describes a lightweight
interface between the TD Shim and TD VMM and between the TD Shim and the
simplified kernel.

![Overview](doc/td-shim-diagram.png)

## Documents

* [TD-Shim specification](doc/tdshim_spec.md)

* Introduction [PDF](doc/td-shim-introduction.pdf) and [conference talk](https://fosdem.org/2023/schedule/event/cc_online_rust/)

## Feature Introduction

This is a Shim Firmware to support [Intel TDX](https://software.intel.com/content/www/us/en/develop/articles/intel-trust-domain-extensions.html).

The API specification is at [td-shim specification](doc/tdshim_spec.md).

The secure boot specification for td-shim is at [secure boot specification](doc/secure_boot.md)

The design is at [td-shim design](doc/design.md).

The threat model analysis is at [td-shim threat model](doc/threat_model.md).

## How to build

### Tools

1. Install [RUST](https://www.rust-lang.org/)

please use 1.83.0.

```
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.83.0
rustup target add x86_64-unknown-none
```

2. Install [NASM](https://www.nasm.us/)

Please make sure nasm can be found in PATH.

3. Install LLVM

Please make sure clang can be found in PATH.

Set env:

```
export CC=clang
export AR=llvm-ar

export CC_x86_64_unknown_none=clang
export AR_x86_64_unknown_none=llvm-ar
```

### Secure boot support

Please follow [Secure Boot Guide](doc/secure_boot_guide.md)

### Before build
```
git submodule update --init --recursive
./sh_script/preparation.sh
```
### Use xtask to build TdShim image

Build TdShim image to launch a payload support Linux Boot Protocol

```
cargo image --release

```
Build TdShim image to launch an executable payload

```
cargo image -t executable -p /path/to/payload_binary --release
```

Build TdShim image to launch the example payload

```
cargo image --example-payload --release
```

### Build TdShim manually

Build TdShim to launch a payload support Linux Boot Protocol

```
cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx
cargo run -p td-shim-tools --bin td-shim-ld --features=linker -- target/x86_64-unknown-none/release/ResetVector.bin target/x86_64-unknown-none/release/td-shim -o target/release/final.bin
```

Build TdShim to launch a executable payload

```
cargo build -p td-shim --target x86_64-unknown-none --release --features=main,tdx --no-default-features
```

Build Elf format payload

```
cargo build -p td-payload --target x86_64-unknown-none --release --bin example --features=tdx,start,cet-shstk,stack-guard
cargo run -p td-shim-tools --bin td-shim-ld -- target/x86_64-unknown-none/release/ResetVector.bin target/x86_64-unknown-none/release/td-shim -t executable -p target/x86_64-unknown-none/release/example -o target/release/final-elf.bin
```

To build the debug TdShim, please use `dev-opt` profile to build `td-shim` binary. For example:

```
cargo build -p td-shim --target x86_64-unknown-none --profile dev-opt --features=main,tdx
cargo run -p td-shim-tools --bin td-shim-ld --features=linker -- target/x86_64-unknown-none/dev-opt/ResetVector.bin target/x86_64-unknown-none/dev-opt/td-shim -o target/debug/final.bin
```

## Run
REF: https://github.com/tianocore/edk2-staging/tree/TDVF

```
./launch-rust-td.sh
```

## Reproducible Build
Reproducible build of td-shim binary requires same system user and
source code path (see https://github.com/confidential-containers/td-shim/issues/604).

The [Dockerfile](./Dockerfile) is provided to build the docker image with
the `td-shim` compilation environment for reproducible build. You can use
the [docker.sh](./sh_script/docker.sh) to build and run the docker container:

```
./sh_script/docker.sh -f devtools/dev_container
```

## Code Contributions

1.  install [pre-commit](https://pre-commit.com/#install)
2.  run ```pre-commit install```
3.  when you run ```git commit```, pre-commit will do check-code things.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fconfidential-containers%2Ftd-shim?ref=badge_large)

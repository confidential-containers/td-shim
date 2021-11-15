# td-shim
Confidential Containers Shim Firmware

## Feature Introduction

This is a Shim Firmware to support [Intel TDX](https://software.intel.com/content/www/us/en/develop/articles/intel-trust-domain-extensions.html).

The API specification is at [td-shim specification](https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md).

The design is at [td-shim design](https://github.com/confidential-containers/td-shim/blob/main/doc/design.md).

The threat model analysis is at [td-shim threat model](https://github.com/confidential-containers/td-shim/blob/main/doc/threat_model.md).

## How to build

### Tools

1. Install [RUST](https://www.rust-lang.org/)

please use nightly-2021-08-20.

NOTE: We need install nightly version because we use cargo-xbuild.

The version nightly-2021-08-20 is chosen because we run [rudra](https://github.com/bjorn3/Rudra.git) tool, which depends upon this version.

1.1. Install xbuild

```
cargo install cargo-xbuild
```

Please reinstall cargo-xbuild, after you update the rust toolchain.

2. Install [NASM](https://www.nasm.us/)

Please make sure nasm can be found in PATH.

3. Install LLVM

Please make sure clang can be found in PATH.

Set env:

```
set CC=clang
set AR=llvm-ar
```

### Build TdShim
```
cargo xbuild -p rust-tdshim --target x86_64-unknown-uefi --release
```

### Build PE format payload
```
pushd rust-td-payload
cargo xbuild --target x86_64-unknown-uefi --release
popd
cargo run -p rust-td-tool -- target/x86_64-unknown-uefi/release/ResetVector.bin target/x86_64-unknown-uefi/release/rust-tdshim.efi target/x86_64-unknown-uefi/release/rust-td-payload.efi target/x86_64-unknown-uefi/release/final.bin
```

### Build Elf format payload
```
pushd rust-td-payload
cargo xbuild --target target.json --release
popd
cargo run -p rust-td-tool -- target/x86_64-unknown-uefi/release/ResetVector.bin target/x86_64-unknown-uefi/release/rust-tdshim.efi target/target//release/rust-td-payload target/x86_64-unknown-uefi/release/final.bin
```

## Run
REF: https://github.com/tianocore/edk2-staging/tree/TDVF

```
./launch-rust-td.sh
```

## Code Contributions

1.  install [pre-commit](https://pre-commit.com/#install)
2.  run ```pre-commit install```
3.  when you run ```git commit```, pre-commit will do check-code things.

## Known limitation
This package is only the sample code to show the concept. It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet. Any codes including the API definition, the library and the drivers are subject to change.

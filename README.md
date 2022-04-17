# td-shim
Confidential Containers Shim Firmware

## Feature Introduction

This is a Shim Firmware to support [Intel TDX](https://software.intel.com/content/www/us/en/develop/articles/intel-trust-domain-extensions.html).

The API specification is at [td-shim specification](doc/tdshim_spec.md).

The secure boot specification for td-shim is at [secure boot specification](doc/secure_boot.md)

The design is at [td-shim design](doc/design.md).

The threat model analysis is at [td-shim threat model](doc/threat_model.md).

## How to build

### Tools

1. Install [RUST](https://www.rust-lang.org/)

please use nightly-2022-04-07.

NOTE: We need install nightly version because we use cargo-xbuild.

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
set CC_x86_64_unknown_uefi=clang
set AR_x86_64_unknown_uefi=llvm-ar
```

### Secure boot support

Please follow [Secure Boot Guide](doc/secure_boot_guide.md)


### Build TdShim
```
cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx
cargo run -p td-shim-tools --bin td-shim-ld -- target/x86_64-unknown-uefi/release/ResetVector.bin target/x86_64-unknown-uefi/release/td-shim.efi -o target/x86_64-unknown-uefi/release/final.bin
```

### Build PE format payload
```
cargo xbuild -p td-payload --target x86_64-unknown-uefi --release --features=main,tdx
cargo run -p td-shim-tools --bin td-shim-ld --no-default-features --features=linker -- target/x86_64-unknown-uefi/release/ResetVector.bin target/x86_64-unknown-uefi/release/td-shim.efi -p target/x86_64-unknown-uefi/release/td-payload.efi -o target/x86_64-unknown-uefi/release/final-pe.bin
```

### Build Elf format payload
```
cargo xbuild -p td-payload --target devtools/rustc-targets/x86_64-unknown-none.json --release --features=main,tdx
cargo run -p td-shim-tools --bin td-shim-ld --no-default-features --features=linker -- target/x86_64-unknown-uefi/release/ResetVector.bin target/x86_64-unknown-uefi/release/td-shim.efi -p target/x86_64-unknown-none/release/td-payload -o target/x86_64-unknown-uefi/release/final-elf.bin
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

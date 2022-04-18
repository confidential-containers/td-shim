#!/bin/bash

export CC=clang
export AR=llvm-ar
export AS=nasm

if [[ ! $PWD =~ td-shim$ ]];then
    pushd ..
fi

final_pe() {
    echo final-pe
    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features
    cargo xbuild -p td-payload --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-uefi/release/td-payload.efi \
        -o target/x86_64-unknown-uefi/release/final-pe.bin
}

final_pe_boot_kernel() {
    echo "final-pe with boot-kernel support"
    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx,boot-kernel

    cargo run -p td-shim-tools --features=td-shim/default,td-shim/tdx,boot-kernel --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -o target/x86_64-unknown-uefi/release/final-pe-boot-kernel.bin
}

final_pe_test() {
    echo "final-pe with test td payload"
    cd tests
    cargo xbuild -p test-td-payload --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features
    cd ..

    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-uefi/release/test-td-payload.efi \
        -o target/x86_64-unknown-uefi/release/final-pe-test.bin

    cargo run -p td-shim-tools --features="enroller" --bin td-shim-enroll \
        target/x86_64-unknown-uefi/release/final-pe-test.bin \
        -f F10E684E-3ABD-20E4-5932-8F973C355E57 tests/test-td-payload/src/test.json \
        -o target/x86_64-unknown-uefi/release/final-pe-test.bin
}

final_elf() {
    echo final-elf
    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features
    cargo xbuild -p td-payload --target devtools/rustc-targets/x86_64-unknown-none.json --release --features=main,tdx --no-default-features
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-none/release/td-payload \
        -o target/x86_64-unknown-uefi/release/final-elf.bin 
}

case "${1:-}" in
    elf) final_elf ;;
    pe) final_pe ;;
    pe_boot_kernel) final_pe_boot_kernel ;;
    pe_test) final_pe_test;;
    *) final_pe && final_pe_boot_kernel && final_elf && final_pe_test;;
esac

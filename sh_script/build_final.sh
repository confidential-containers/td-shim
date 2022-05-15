#!/bin/bash

export CC=clang
export AR=llvm-ar
export AS=nasm

config_num=5

if [[ ! $PWD =~ td-shim$ ]];then
    pushd ..
fi

final_boot_kernel() {
    echo "Build final binary with boot-kernel support"
    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx,boot-kernel

    cargo run -p td-reproducible-tool -- -n td-shim --target x86_64-unknown-uefi

    cargo run -p td-shim-tools --features=td-shim/default,td-shim/tdx,boot-kernel --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -o target/x86_64-unknown-uefi/release/final-boot-kernel.bin
}

final_pe() {
    echo final-pe
    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features
    cargo xbuild -p td-payload --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features

    cargo run -p td-reproducible-tool -- -n td-shim --target x86_64-unknown-uefi
    cargo run -p td-reproducible-tool -- -n td-payload --target x86_64-unknown-uefi

    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-uefi/release/td-payload.efi \
        -o target/x86_64-unknown-uefi/release/final-pe.bin
}

final_pe_test() {
    echo "Build final binary with PE format test td payload"
    pushd tests
    cargo xbuild -p test-td-payload --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features
    popd

    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features

    cargo run -p td-reproducible-tool -- -n td-shim --target x86_64-unknown-uefi
    cargo run -p td-reproducible-tool -- -n test-td-payload --target x86_64-unknown-uefi

    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-uefi/release/test-td-payload.efi \
        -o target/x86_64-unknown-uefi/release/final-pe-test.bin
    
    for ((i=1; i<=${config_num}; i++))
    do
        cargo run -p td-shim-tools --features="enroller" --bin td-shim-enroll \
        target/x86_64-unknown-uefi/release/final-pe-test.bin \
        -f F10E684E-3ABD-20E4-5932-8F973C355E57 tests/test-td-payload/config/test_config_${i}.json \
        -o target/x86_64-unknown-uefi/release/final-pe-test${i}.bin
    done 
}

final_elf() {
    echo final-elf
    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features
    cargo xbuild -p td-payload --target devtools/rustc-targets/x86_64-unknown-none.json --release --features=main,tdx --no-default-features

    cargo run -p td-reproducible-tool -- -n td-shim --target x86_64-unknown-uefi
    cargo run -p td-reproducible-tool -- -n td-payload --target x86_64-unknown-none

    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-none/release/td-payload \
        -o target/x86_64-unknown-uefi/release/final-elf.bin 
}

final_elf_test() {
    echo "Build final binary with ELF format test td payload"
    pushd tests
    cargo xbuild -p test-td-payload --target ../devtools/rustc-targets/x86_64-unknown-none.json --release --features=main,tdx --no-default-features
    popd

    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features

    cargo run -p td-reproducible-tool -- -n td-shim --target x86_64-unknown-uefi
    cargo run -p td-reproducible-tool -- -n test-td-payload --target x86_64-unknown-none

    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-none/release/test-td-payload \
        -o target/x86_64-unknown-uefi/release/final-elf-test.bin

    for ((i=1; i<=${config_num}; i++))
    do
        cargo run -p td-shim-tools --features="enroller" --bin td-shim-enroll \
        target/x86_64-unknown-uefi/release/final-elf-test.bin \
        -f F10E684E-3ABD-20E4-5932-8F973C355E57 tests/test-td-payload/config/test_config_${i}.json \
        -o target/x86_64-unknown-uefi/release/final-elf-test${i}.bin
    done 
}

final_pe_sb_test() {
    echo "Build final binaries with PE format td payload for secure boot test"
    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx,secure-boot --no-default-features
    cargo xbuild -p td-payload --target x86_64-unknown-uefi --release --features=main,tdx --no-default-features

    cargo run -p td-reproducible-tool -- -n td-shim --target x86_64-unknown-uefi
    cargo run -p td-reproducible-tool -- -n td-payload --target x86_64-unknown-uefi

    cargo run -p td-shim-tools --bin td-shim-sign-payload -- -A ECDSA_NIST_P384_SHA384 data/sample-keys/ecdsa-p384-private.pk8 target/x86_64-unknown-uefi/release/td-payload.efi 1 1

    echo "Build final binary with unsigned td payload"
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-uefi/release/td-payload.efi \
        -o target/x86_64-unknown-uefi/release/final-pe-unsigned.bin
    
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/x86_64-unknown-uefi/release/final-pe-unsigned.bin \
        -H SHA384 \
        -k data/sample-keys/ecdsa-p384-public.der \
        -o target/x86_64-unknown-uefi/release/final-pe-sb-unsigned.bin

    echo "Build final binary with signed td payload and enroll uncorrect public key in CFV"
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-uefi/release/td-payload-signed \
        -o target/x86_64-unknown-uefi/release/final-pe-signed.bin
    
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/x86_64-unknown-uefi/release/final-pe-signed.bin \
        -H SHA384 \
        -k data/sample-keys/rsa-3072-public.der \
        -o target/x86_64-unknown-uefi/release/final-pe-sb-mismatch-pubkey.bin

    echo "Build final binary with signed td payload and enroll correct public key in CFV"
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/x86_64-unknown-uefi/release/final-pe-signed.bin \
        -H SHA384 \
        -k data/sample-keys/ecdsa-p384-public.der \
        -o target/x86_64-unknown-uefi/release/final-pe-sb-normal.bin
}

final_elf_sb_test() {
    echo "Build final binaries with ELF format td payload for secure boot test"
    cargo xbuild -p td-shim --target x86_64-unknown-uefi --release --features=main,tdx,secure-boot --no-default-features
    cargo xbuild -p td-payload --target devtools/rustc-targets/x86_64-unknown-none.json --release --features=main,tdx --no-default-features

    cargo run -p td-reproducible-tool -- -n td-shim --target x86_64-unknown-uefi
    cargo run -p td-reproducible-tool -- -n td-payload --target x86_64-unknown-none

    cargo run -p td-shim-tools --bin td-shim-sign-payload -- -A ECDSA_NIST_P384_SHA384 data/sample-keys/ecdsa-p384-private.pk8 target/x86_64-unknown-none/release/td-payload 1 1 

    echo "Build final binary with unsigned td payload"
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-none/release/td-payload \
        -o target/x86_64-unknown-uefi/release/final-elf-unsigned.bin
    
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/x86_64-unknown-uefi/release/final-elf-unsigned.bin \
        -H SHA384 \
        -k data/sample-keys/ecdsa-p384-public.der \
        -o target/x86_64-unknown-uefi/release/final-elf-sb-unsigned.bin

    echo "Build final binary with signed td payload and enroll uncorrect public key in CFV"
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-uefi/release/ResetVector.bin \
        target/x86_64-unknown-uefi/release/td-shim.efi \
        -p target/x86_64-unknown-none/release/td-payload-signed \
        -o target/x86_64-unknown-uefi/release/final-elf-signed.bin
    
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/x86_64-unknown-uefi/release/final-elf-signed.bin \
        -H SHA384 \
        -k data/sample-keys/rsa-3072-public.der \
        -o target/x86_64-unknown-uefi/release/final-elf-sb-mismatch-pubkey.bin

    echo "Build final binary with signed td payload and enroll correct public key in CFV"
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/x86_64-unknown-uefi/release/final-elf-signed.bin \
        -H SHA384 \
        -k data/sample-keys/ecdsa-p384-public.der \
        -o target/x86_64-unknown-uefi/release/final-elf-sb-normal.bin
}

case "${1:-}" in
    boot_kernel) final_boot_kernel ;;
    pe) final_pe ;;
    elf) final_elf ;;
    pe_test) final_pe_test ;;
    elf_test) final_elf_test ;;
    pe_sb_test) final_pe_sb_test ;;
    elf_sb_test) final_elf_sb_test ;;
    *) final_boot_kernel && final_pe && final_elf && final_pe_test && final_elf_test && final_pe_sb_test && final_elf_sb_test;; 
esac

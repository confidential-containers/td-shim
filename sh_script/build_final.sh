#!/bin/bash

export CC_x86_64_unknown_none=clang
export AR_x86_64_unknown_none=llvm-ar
export CC=clang
export AR=llvm-ar
export AS=nasm

config_num=5

if [[ ! $PWD =~ td-shim$ ]];then
    pushd ..
fi

final_boot_kernel() {
    echo "Build final binary with boot-kernel support"

    cargo image --release -o target/release/final-boot-kernel.bin
}

final_elf() {
    echo final-elf
    cargo --example-payload -o target/release/final-elf.bin 
}

final_elf_test() {
    echo "Build final binary with ELF format test td payload"
    pushd tests
    cargo build -p test-td-payload --target x86_64-unknown-none --release --features=main,tdx --no-default-features
    popd

    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n test-td-payload --target x86_64-unknown-none

    for ((i=1; i<=${config_num}; i++))
    do
        cargo image --release -t executable \
            -p target/x86_64-unknown-none/release/test-td-payload \
            --enroll-file F10E684E-3ABD-20E4-5932-8F973C355E57,tests/test-td-payload/config/test_config_${i}.json \
            -o target/release/final-elf-test${i}.bin
    done 
}

final_elf_sb_test() {
    echo "Build final binaries with ELF format td payload for secure boot test"
    cargo build -p td-payload --target x86_64-unknown-none --release --bin example --features=tdx,start,cet-shstk,stack-guard
    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n example --target x86_64-unknown-none

    cargo run -p td-shim-tools --bin td-shim-sign-payload -- -A ECDSA_NIST_P384_SHA384 data/sample-keys/ecdsa-p384-private.pk8 target/x86_64-unknown-none/release/example 1 1 

    echo "Build final binary with unsigned td payload"
    cargo image --release -t executable --features secure-boot \
        -p target/x86_64-unknown-none/release/example \
        -H SHA384 \
        --enroll-key data/sample-keys/ecdsa-p384-public.der \
        -o target/release/final-elf-sb-unsigned.bin

    echo "Build final binary with signed td payload and enroll uncorrect public key in CFV"
    cargo image --release -t executable --features secure-boot \
        -p target/x86_64-unknown-none/release/td-payload-signed \
        -H SHA384 \
        --enroll-key data/sample-keys/rsa-3072-public.der \
        -o target/release/final-elf-sb-mismatch-pubkey.bin

    echo "Build final binary with signed td payload and enroll correct public key in CFV"
    cargo image --release -t executable --features secure-boot \
        -p target/x86_64-unknown-none/release/td-payload-signed \
        -H SHA384 \
        --enroll-key data/sample-keys/ecdsa-p384-public.der \
        -o target/release/final-elf-sb-normal.bin
}

final_igvm_test() {
    echo "Build final binaries with IGVM format image"
    cargo run -p td-layout-config --bin td-layout-config \
        devtools/td-layout-config/config_image.json -t image \
        --fw_top 0x40000000 -o td-layout/src/build_time.rs
    cargo build -p td-shim --target x86_64-unknown-none --release \
        --features=main,tdx
    cargo run -p td-shim-tools --bin td-shim-ld --features=linker -- \
        target/x86_64-unknown-none/release/ResetVector.bin \
        target/x86_64-unknown-none/release/td-shim \
        -o target/release/final.igvm --image-format igvm
}

./sh_script/preparation.sh

case "${1:-}" in
    boot_kernel) final_boot_kernel ;;
    pe) final_pe ;;
    elf) final_elf ;;
    elf_test) final_elf_test ;;
    elf_sb_test) final_elf_sb_test ;;
    igvm_test) final_igvm_test ;;
    *) final_boot_kernel && final_elf && final_elf_test && final_elf_sb_test;; 
esac

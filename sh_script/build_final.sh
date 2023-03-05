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
    cargo xbuild -p td-shim --target x86_64-unknown-none --release --features=main,tdx,boot-kernel

    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n td-shim --target x86_64-unknown-none

    cargo run -p td-shim-tools --features=td-shim/default,td-shim/tdx,boot-kernel --bin td-shim-ld -- \
        target/x86_64-unknown-none/release/ResetVector.bin \
        target/x86_64-unknown-none/release/td-shim \
        -o target/release/final-boot-kernel.bin
}

final_elf() {
    echo final-elf
    cargo xbuild -p td-shim --target x86_64-unknown-none --release --features=main,tdx --no-default-features
    cargo xbuild -p td-payload --target x86_64-unknown-none --release --bin example --features=tdx,start,cet-shstk,stack-guard

    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n td-shim --target x86_64-unknown-none
    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n example --target x86_64-unknown-none

    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-none/release/ResetVector.bin \
        target/x86_64-unknown-none/release/td-shim \
        -p target/x86_64-unknown-none/release/example \
        -o target/release/final-elf.bin 
}

final_elf_test() {
    echo "Build final binary with ELF format test td payload"
    pushd tests
    cargo xbuild -p test-td-payload --target x86_64-unknown-none --release --features=main,tdx --no-default-features
    popd

    cargo xbuild -p td-shim --target x86_64-unknown-none --release --features=main,tdx --no-default-features

    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n td-shim --target x86_64-unknown-none
    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n test-td-payload --target x86_64-unknown-none

    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-none/release/ResetVector.bin \
        target/x86_64-unknown-none/release/td-shim \
        -p target/x86_64-unknown-none/release/test-td-payload \
        -o target/release/final-elf-test.bin

    for ((i=1; i<=${config_num}; i++))
    do
        cargo run -p td-shim-tools --features="enroller" --bin td-shim-enroll \
        target/release/final-elf-test.bin \
        -f F10E684E-3ABD-20E4-5932-8F973C355E57 tests/test-td-payload/config/test_config_${i}.json \
        -o target/release/final-elf-test${i}.bin
    done 
}

final_elf_sb_test() {
    echo "Build final binaries with ELF format td payload for secure boot test"
    cargo xbuild -p td-shim --target x86_64-unknown-none --release --features=main,tdx,secure-boot --no-default-features
    cargo xbuild -p td-payload --target x86_64-unknown-none --release --bin example --features=tdx,start,cet-shstk,stack-guard

    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n td-shim --target x86_64-unknown-none
    cargo run -p td-shim-tools --bin td-shim-strip-info -- -n example --target x86_64-unknown-none

    cargo run -p td-shim-tools --bin td-shim-sign-payload -- -A ECDSA_NIST_P384_SHA384 data/sample-keys/ecdsa-p384-private.pk8 target/x86_64-unknown-none/release/example 1 1 

    echo "Build final binary with unsigned td payload"
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-none/release/ResetVector.bin \
        target/x86_64-unknown-none/release/td-shim \
        -p target/x86_64-unknown-none/release/example \
        -o target/release/final-elf-unsigned.bin
    
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/release/final-elf-unsigned.bin \
        -H SHA384 \
        -k data/sample-keys/ecdsa-p384-public.der \
        -o target/release/final-elf-sb-unsigned.bin

    echo "Build final binary with signed td payload and enroll uncorrect public key in CFV"
    cargo run -p td-shim-tools --features="linker" --no-default-features --bin td-shim-ld -- \
        target/x86_64-unknown-none/release/ResetVector.bin \
        target/x86_64-unknown-none/release/td-shim \
        -p target/x86_64-unknown-none/release/td-payload-signed \
        -o target/release/final-elf-signed.bin
    
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/release/final-elf-signed.bin \
        -H SHA384 \
        -k data/sample-keys/rsa-3072-public.der \
        -o target/release/final-elf-sb-mismatch-pubkey.bin

    echo "Build final binary with signed td payload and enroll correct public key in CFV"
    cargo run -p td-shim-tools --bin td-shim-enroll -- \
        target/release/final-elf-signed.bin \
        -H SHA384 \
        -k data/sample-keys/ecdsa-p384-public.der \
        -o target/release/final-elf-sb-normal.bin
}

./sh_script/preparation.sh

case "${1:-}" in
    boot_kernel) final_boot_kernel ;;
    pe) final_pe ;;
    elf) final_elf ;;
    elf_test) final_elf_test ;;
    elf_sb_test) final_elf_sb_test ;;
    *) final_boot_kernel && final_pe && final_elf && final_elf_test && final_elf_sb_test;; 
esac

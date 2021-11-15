#!/bin/bash

if [[ ! $PWD =~ rust-td$ ]];then
    pushd ..
fi

git clean -f

export RUSTFLAGS="-Zinstrument-coverage"
export LLVM_PROFILE_FILE="your_name-%p-%m.profraw"

cd ./pe-loader
cargo test
cd ..

cd ./elf-loader
cargo test
cd ..

cargo test

grcov . --binary-path ./target/debug/ -s . -t html --branch --ignore-not-existing -o ./target/debug/coverage/

grcov . --binary-path ./target/debug/ -s . -t lcov --branch --ignore-not-existing -o ./lcov.infoba

unset RUSTFLAGS
unset LLVM_PROFILE_FILE

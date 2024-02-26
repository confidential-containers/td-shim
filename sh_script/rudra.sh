#!/bin/bash

if [[ ! $PWD =~ td-shim$ ]]; then
    pushd ..
fi

type rudra

if [[ $? != 0 ]]; then
    echo -e "\033[31m Please install rudra \033[0m"
    exit 1
fi

rudra_rust_version=nightly-2021-08-20

if [[ ! $(cat rust-toolchain) =~ $rudra_rust_version ]]; then
    echo -e "\033[31m Now rudra version supports $rudra_rust_version, please refer to https://github.com/sslab-gatech/Rudra or doc/static_analyzer.md \033[0m"
    exit 1
fi
paths=(
    "td-exception"
    "td-layout"
    "td-loader"
    "td-logger"
    "td-paging"
    "td-payload"
    "td-shim"
    "td-shim-interface/src"
    "td-shim-tools"
    "tdx-tdcall"
)

for i in ${paths[@]}; do
    pushd $PWD/$i

    case "$i" in
    td-shim) cargo rudra --features main,tdx ;;
    *) cargo rudra ;;
    esac

    popd
done

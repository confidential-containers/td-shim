#!/bin/bash

if [[ ! $PWD =~ rust-td$ ]];then
    pushd ..
fi

type rudra

if [[ $? != 0 ]]; then
    echo -e "\033[31m Please install rudra \033[0m"
    exit
fi

origin=`cat rust-toolchain`

flag=false
if [[ ! $origin =~ "nightly-2021-08-20" ]];then
    flag=true
    echo "nightly-2021-08-20" > rust-toolchain
    echo $origin
fi
paths=(
    "elf-loader"
    "pe-loader"
    "r-uefi-pi"
    "rust-paging"
    "rust-td-layout"
    "rust-td-payload"
    "rust-td-tool"
    "rust-tdshim"
    "tdx-exception"
    "tdx-logger"
    "tdx-tdcall"
    "uefi-pi"
)

for i in ${paths[@]};do
    echo $PWD/$i
    pushd $PWD/$i
    cargo rudra
    popd
done

if [ $flag == true ];then
    echo $origin > rust-toolchain
fi

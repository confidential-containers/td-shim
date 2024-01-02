#!/bin/bash

TOOLCHAIN_VER=$1
TRY_TIMES=5
echo ${TOOLCHAIN_VER}

while [ ${TRY_TIMES} -gt 0 ]
do
    exist=`rustup toolchain list | grep ${TOOLCHAIN_VER} | wc -l`
    if [[ ${exist} == 0 ]]
    then
        rustup toolchain install ${TOOLCHAIN_VER} --component rust-src
    else
        rustup component add rust-src
        echo "Toolchain ${TOOLCHAIN_VER} is installed."
        break
    fi
    sleep 30
    let "TRY_TIMES--"
done

if [[ ${TRY_TIMES} == 0 ]]
then
    echo "Install toolchian ${TOOLCHAIN_VER} failed."
    exit 1
fi
#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

script_path=$(dirname "$0")
temp_dir=$(mktemp -d)
nohup_logfile="${temp_dir}/nohup.log"

guest_image="/home/env/guest_img/td-guest.raw"
kernel="/home/env/kernel_img/vmlinuz"
cloud_hypervisor_tdx_path="/home/env/cloud-hypervisor/target/release/cloud-hypervisor"
qemu_tdx_path="/usr/libexec/qemu-kvm"

firmware=""
type="pe"

# Test Configuration Info
cpus=1
memory=2G

trap cleanup exit

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -f <TD Shim Firmware file path> required.
  -i <Guest image file path> by default is td-guest-centos8.4.qcow2.
  -k <Kernel binary file path> by default is bzImage.
  -t [pe|elf] firmware type, by default it is "pe".
  -c <CPU number> by default is 1.
  -m <Memory size> by defalt is 2G.
  -h Show help info
EOM
    exit 0
}

proccess_args() {
    while getopts ":i:k:f:t:c:m:h" option; do
        case "${option}" in
            i) guest_image=${OPTARG};;
            K) kernel=${OPTARG};;
            f) firmware=${OPTARG};;
            t) type=${OPTARG};;
            c) cpus=${OPTARG};;
            m) memory=${OPTARG};;
            h) usage;;
        esac
    done

    if [[ -z ${firmware} ]]; then
        die "Please input correct TD Shim Image path"
    fi

    [ -e ${firmware} ] || die "TD Shim Image path: ${firmware} is not exists"
    [ -e ${guest_image} ] || die "TDX Guest Image path: ${guest_image} is not exists"
    [ -e ${kernel} ] || die "TDX Guest Kernel Image path: ${kernel} is not exists"

    if [[ -n ${type} ]]; then
        case "${type}" in
            pe|elf) echo "";;
            *) die "Unspported type: ${type}";;
        esac
    fi

    echo "========================================="
    echo "TD Shim Image     : ${firmware}"
    echo "Guest Image       : ${guest_image}"
    echo "Kernel binary     : ${kernel}"
    echo "Type              : ${type}"
    echo "CPUs              : ${cpus}"
    echo "Memmory Size      : ${memory}"
    echo "========================================="
}

setup() {
    echo "========================================="
    echo "              Setup ENV                  "
    echo "========================================="
    [ -e "/home/env" ] || mkdir -p "/home/env"

    [ -e ${cloud_hypervisor_tdx_path} ] || install_cloudhypervisor_tdx
    [ -e ${cloud_hypervisor_tdx_path} ] || die "TDX Cloud Hypervisor path: ${cloud_hypervisor_tdx_path} is not exists"

    [ -e ${qemu_tdx_path} ] ||install_qemu_tdx
    [ -e ${qemu_tdx_path} ] || die "TDX QEMU path: ${qemu_tdx_path} is not exists"
}

cleanup() {
    sudo rm -rf ${tmp_dir}
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

check_result()  {
    time=0
    result=1
    while ((${time}<=$3))
    do
        sleep 1
        if [[ `grep -c "$2" "$1"` -ne 0 ]]
        then
            result=0
            break
        fi
        let "time++"
    done
    return ${result}
}

install_cloudhypervisor_tdx() {
    echo "-- Install Cloud Hypervisor"
    cd "/home/env"
    git clone https://github.com/cloud-hypervisor/cloud-hypervisor.git && cd cloud-hypervisor
    # Build TDX supported Cloud Hypervisor
    cargo build --release --features "fwdebug,tdx"
    cd ${script_path}
}

install_qemu_tdx() {
    echo "-- Install QEMU"
    dnf update qemu --allowerasing
}

launch_td_os() {
    echo "-- launch td os"
    local time_out=60
    local key_str1="login:"
    local key_str2="Guest initialized"

    nohup ${cloud_hypervisor_tdx_path} -v \
                                       --tdx firmware=${firmware} \
                                       --memory size=${memory} \
                                       --cpus boot=${cpus} \
                                       --kernel ${kernel} \
                                       --disk path=${guest_image} \
                                       --cmdline "root=/dev/vda1 console=hvc0 rw" > ${nohup_logfile} 2>&1 &

    check_result ${nohup_logfile} "${key_str1}" ${time_out}

    if [[ $? -eq 0 ]]
    then
        ps aux | grep ${cloud_hypervisor_tdx_path} | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
        echo "-- launch td os: Pass"
    else
        ps aux | grep ${cloud_hypervisor_tdx_path} | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
        cat ${nohup_logfile} && echo "-- launch td os: Fail" && exit 1
    fi
}

launch_td_test_payload() {
    echo "-- launch td test payload"
    local time_out=10
    local key_str="0 failed"

    nohup ${qemu_tdx_path} -accel kvm \
        -name process=rust-td,debug-threads=on \
        -smp ${cpus},sockets=${cpus} \
        -object tdx-guest,id=tdx,debug=on \
        -machine q35,kvm-type=tdx,pic=no,kernel_irqchip=split,confidential-guest-support=tdx \
        -no-hpet \
        -cpu host,pmu=off,-kvm-steal-time \
        -device loader,file=${firmware},id=fd0 \
        -m ${memory} -nographic -vga none \
        -chardev stdio,id=mux,mux=on,signal=off \
        -device virtio-serial,romfile= \
        -device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
        -d int -no-reboot > ${nohup_logfile} 2>&1 &
    
    check_result ${nohup_logfile} "${key_str}" ${time_out}

    if [[ $? -eq 0 ]]
    then
        ps aux | grep ${qemu_tdx_path} | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
        cat ${nohup_logfile} && echo "-- launch td payload: Pass"
    else
        ps aux | grep ${qemu_tdx_path} | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
        cat ${nohup_logfile} && echo "-- launch td payload: Fail" && exit 1
    fi
}

test_secure_boot() {
    echo "-- secure boot test"
    local time_out=10
    if [[ ${firmware} == *normal* ]]
    then
        local key_str="Starting td-payload hob"
    elif [[ ${firmware} == *mismatch-pubkey* ]]
    then
        local key_str="Verification fails: InvalidPublicKey"
    elif [[ ${firmware} == *unsigned* ]]
    then
        local key_str="Secure Boot: Cannot read verify header from payload binary"
    else
        die "The firmware name ${firmware} is not suitable for secure boot test"
    fi  
    
    nohup ${qemu_tdx_path} -accel kvm \
        -name process=rust-td,debug-threads=on \
        -smp ${cpus},sockets=${cpus} \
        -object tdx-guest,id=tdx,debug=on \
        -machine q35,kvm-type=tdx,pic=no,kernel_irqchip=split,confidential-guest-support=tdx \
        -no-hpet \
        -cpu host,pmu=off,-kvm-steal-time \
        -device loader,file=${firmware},id=fd0 \
        -m ${memory} -nographic -vga none \
        -chardev stdio,id=mux,mux=on,signal=off \
        -device virtio-serial,romfile= \
        -device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
        -d int -no-reboot > ${nohup_logfile} 2>&1 &
    
    check_result ${nohup_logfile} "${key_str}" ${time_out}

    if [[ $? -eq 0 ]]
    then
        ps aux | grep ${qemu_tdx_path} | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
        echo "-- secure boot test: Pass"
    else
        ps aux | grep ${qemu_tdx_path} | grep -v grep | awk -F ' ' '{print $2}' | xargs kill -9
        cat ${nohup_logfile} && echo "-- secure boot test: Fail" && exit 1
    fi
}

run_test() {
    echo "========================================="
    echo "               Run Test                  "
    echo "========================================="
    if [[ ${firmware} == *final-boot-kernel.bin* ]]
    then
        launch_td_os
    fi

    if [[ ${firmware} == *final-${type}-test* ]]
    then
        launch_td_test_payload
    fi

    if [[ ${firmware} == *final-${type}-sb* ]]
    then
        test_secure_boot
    fi  
}

main() {
    setup
    run_test
    cleanup
}

proccess_args $@
main
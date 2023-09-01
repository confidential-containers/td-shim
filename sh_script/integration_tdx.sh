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
qemu_tdx_path="/usr/local/bin/qemu-system-x86_64"

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
  -p <Cloud Hypervisor/Qemu path>.
  -i <Guest image file path> by default is td-guest.raw.
  -k <Kernel binary file path> by default is vmlinuz.
  -t [pe|elf] firmware type, by default it is "pe".
  -c <CPU number> by default is 1.
  -m <Memory size> by defalt is 2G.
  -h Show help info
EOM
    exit 0
}

proccess_args() {
    while getopts ":i:p:k:f:t:c:m:h" option; do
        case "${option}" in
            i) guest_image=${OPTARG};;
            p) cloud_hypervisor_tdx_path=${OPTARG}
               qemu_tdx_path=${OPTARG};;
            k) kernel=${OPTARG};;
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

    if [[ ${firmware} == *final-boot-kernel.bin* ]]
    then
        [ -e ${guest_image} ] || die "TDX Guest Image path: ${guest_image} is not exists"
        [ -e ${kernel} ] || die "TDX Guest Kernel Image path: ${kernel} is not exists"
        [ -e ${cloud_hypervisor_tdx_path} ] || die "TDX Cloud Hypervisor path: ${cloud_hypervisor_tdx_path} is not exists"
    else
        [ -e ${qemu_tdx_path} ] || die "TDX QEMU path: ${qemu_tdx_path} is not exists"
    fi
    
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

launch_td_os() {
    echo "-- launch td os"
    local time_out=120
    local key_str1="login:"
    local key_str2="Guest initialized"

    nohup ${cloud_hypervisor_tdx_path} -v \
                                       --platform tdx=on \
                                       --firmware ${firmware} \
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
    local time_out=120
    local key_str="0 failed"

    nohup ${qemu_tdx_path} -accel kvm \
        -name process=rust-td,debug-threads=on \
        -smp ${cpus},sockets=${cpus} \
        -object tdx-guest,id=tdx,debug=on \
        -object memory-backend-memfd-private,id=ram1,size=${memory} \
        -machine q35,memory-backend=ram1,kernel_irqchip=split,confidential-guest-support=tdx \
        -no-hpet \
        -cpu host,pmu=off,-kvm-steal-time \
        -bios ${firmware} \
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
    local time_out=120
    local key_str="Starting td-payload hob"
    
    nohup ${qemu_tdx_path} -accel kvm \
        -name process=rust-td,debug-threads=on \
        -smp ${cpus},sockets=${cpus} \
        -object tdx-guest,id=tdx,debug=on \
        -object memory-backend-memfd-private,id=ram1,size=${memory} \
        -machine q35,memory-backend=ram1,kernel_irqchip=split,confidential-guest-support=tdx \
        -no-hpet \
        -cpu host,pmu=off,-kvm-steal-time \
        -bios ${firmware} \
        -m ${memory} -nographic -vga none \
        -chardev stdio,id=mux,mux=on,signal=off \
        -device virtio-serial,romfile= \
        -device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
        -d int -no-reboot > ${nohup_logfile} 2>&1 &
    
    check_result ${nohup_logfile} "${key_str}" ${time_out}

    if [[ $? -eq 0 && ${firmware} == *normal* ]] ||
        [[ $? -ne 0 && ${firmware} == *mismatch-pubkey* ]] ||
        [[ $? -ne 0 && ${firmware} == *unsigned* ]]
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
    run_test
    cleanup
}

proccess_args $@
main
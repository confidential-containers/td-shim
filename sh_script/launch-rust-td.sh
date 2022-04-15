#!/bin/bash

now=$(date +"%m%d_%H%M")
LOGFILE=stdout.${now}.log

QEMU=/home/oem/tdvf-install/usr/libexec/qemu-kvm
BIOS=/home/oem/final.bin

$QEMU \
  -no-reboot -name debug-threads=on -enable-kvm -smp 1,sockets=1 -object tdx-guest,id=tdx,debug=on \
  -machine q35,accel=kvm,kvm-type=tdx,kernel_irqchip=split,confidential-guest-support=tdx -no-hpet \
  -cpu host,host-phys-bits,+invtsc \
  -device loader,file=$BIOS,id=fd0 \
  -m 2G -nographic -vga none | tee -a ${LOGFILE}

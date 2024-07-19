#!/bin/bash

# Default values
QEMU_PATH="/usr/libexec/qemu-kvm"
BIOS_IMAGE="final.bin"
CPUS=1
MEM="1G"

# Function to display usage
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -p <qemu_path>    Specify the QEMU executable path. Default is /usr/libexec/qemu-kvm."
    echo "  -c <cpus>         Number of CPUs. Default is 1."
    echo "  -m <memory>       Memory size. Default is 1G."
    echo "  -b <bios_image>   Path to the BIOS image file. Default is final.bin."
    echo "  -h                Display this help message and exit."
    exit 1
}

# Parse command line options
while getopts ":p:c:m:b:h" opt; do
    case $opt in
        p)
            QEMU_PATH="$OPTARG"
            ;;
        c)
            CPUS="$OPTARG"
            ;;
        m)
            MEM="$OPTARG"
            ;;
        b)
            BIOS_IMAGE="$OPTARG"
            ;;
        h)
            usage
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            usage
            ;;
    esac
done

# Timestamp for logfile
now=$(date +"%m%d_%H%M")
LOGFILE=stdout.${now}.log

# Check QEMU version for memory backend options
QEMU_VERSION=$(${QEMU_PATH} --version | grep -oP 'version \K[^\s]+')
if [ "$(printf '%s\n' "8.0.0" "${QEMU_VERSION}" | sort -V | head -n1)" == "8.0.0" ]; then
    MEMORY_BACKEND="-object memory-backend-ram,id=ram1,size=${MEM},private=on"
else
    MEMORY_BACKEND="-object memory-backend-memfd-private,id=ram1,size=${MEM}"
fi

# Construct the QEMU command
QEMU_CMD="${QEMU_PATH} -accel kvm \
        -name process=rust-td,debug-threads=on \
        -smp ${CPUS} \
        -object tdx-guest,id=tdx,debug=on \
        -machine q35,memory-backend=ram1,kernel_irqchip=split,confidential-guest-support=tdx \
        -no-hpet \
        -cpu host,pmu=off,-kvm-steal-time \
        -bios ${BIOS_IMAGE} \
        -m ${MEM} -nographic -vga none \
        -chardev stdio,id=mux,mux=on,signal=off \
        -device virtio-serial,romfile= \
        -device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
        -d int -no-reboot ${MEMORY_BACKEND}"

# Execute the QEMU command and redirect output to logfile
$QEMU_CMD 2>&1 | tee "${LOGFILE}"

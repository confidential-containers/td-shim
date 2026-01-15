#!/usr/bin/env python3
# Copyright (c) 2026 Alibaba Cloud
#
# SPDX-License-Identifier: Apache-2.0
#
# A Python implementation to calculate td-payload reference value with QEMU Kernel Direct Boot patch

import argparse
import hashlib
import sys
from pathlib import Path

# Refer to https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#signature-image-only,
# file offset specified at offset 0x3c,
# size of PE signature is 4: "PE\0\0"
IMAGE_PE_OFFSET = 0x003c
PE_SIGNATURE_SIZE = 4
IMGAE_BEGIN_ADDR = 0x0000

# Refer to https://www.kernel.org/doc/html/latest/arch/x86/boot.html#details-of-header-fields
# Protocol version addr: 0x206, size: 2
IMAGE_PROTOCOL_ADDR = 0x0206


def get_image_regions(buf):
    """Get image regions for hashing."""
    # Region 1~3 regions are known.
    number_of_region_entry = 3
    regions_base = []
    regions_size = []

    # Refer to https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#coff-file-header-object-and-image,
    # After the signature of an image file is COFF File Header, size is 20 bytes.
    # NumberOfSections       Offset: 2    Size: 2
    size_of_coff_file_header = 20

    coff_file_header_offset = (
        (buf[IMAGE_PE_OFFSET + 3] << 24)
        | (buf[IMAGE_PE_OFFSET + 2] << 16)
        | (buf[IMAGE_PE_OFFSET + 1] << 8)
        | buf[IMAGE_PE_OFFSET]
    ) + PE_SIGNATURE_SIZE

    number_of_pecoff_entry = (
        (buf[coff_file_header_offset + 3] << 8)
        | buf[coff_file_header_offset + 2]
    )
    number_of_region_entry += number_of_pecoff_entry

    # SizeOfOptionalHeader   Offset: 16    Size: 2
    size_of_optional_header = (
        (buf[coff_file_header_offset + 17] << 8)
        | buf[coff_file_header_offset + 16]
    )

    optional_header_addr = coff_file_header_offset + size_of_coff_file_header

    # Refer to https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-standard-fields-image-only
    # Only support PE32+
    # SizeOfHeaders   Offset: 60      Size: 4
    # CheckSum        Offset: 64      Size: 4
    # Cert table      Offset: 144     Size: 8

    optional_size_of_headers_offset = 0x003c
    optional_checksum_offset = 0x0040
    optional_cert_table_offset = 0x0090

    size_of_headers = (
        (buf[optional_header_addr + optional_size_of_headers_offset + 3] << 24)
        | (buf[optional_header_addr + optional_size_of_headers_offset + 2] << 16)
        | (buf[optional_header_addr + optional_size_of_headers_offset + 1] << 8)
        | buf[optional_header_addr + optional_size_of_headers_offset]
    )

    # Region 1: from file begin to CheckSum
    regions_base.append(IMGAE_BEGIN_ADDR)
    regions_size.append(
        optional_header_addr + optional_checksum_offset - IMGAE_BEGIN_ADDR
    )

    # Region 2: from CheckSum end to certificate table entry
    regions_base.append(optional_header_addr + optional_checksum_offset + 4)
    regions_size.append(optional_cert_table_offset -
                        (optional_checksum_offset + 4))

    # Region 3: from cert table end to Header end
    regions_base.append(optional_header_addr + optional_cert_table_offset + 8)
    regions_size.append(
        size_of_headers - (optional_header_addr +
                           optional_cert_table_offset + 8)
    )

    # Refer to https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
    # Size Of each Section is 40 bytes
    # SizeOfRawData       Offset: 16      Size:4
    # PointerToRawData    Offset: 20      Size:4
    p = coff_file_header_offset + size_of_coff_file_header + size_of_optional_header
    for _i in range(number_of_pecoff_entry):
        p += 16
        size = (
            (buf[p + 3] << 24)
            | (buf[p + 2] << 16)
            | (buf[p + 1] << 8)
            | buf[p]
        )
        p += 4
        base = (
            (buf[p + 3] << 24)
            | (buf[p + 2] << 16)
            | (buf[p + 1] << 8)
            | buf[p]
        )
        regions_base.append(base)
        regions_size.append(size)
        p += 20

    return number_of_region_entry, regions_base, regions_size


def qemu(path):
    """Process kernel file with QEMU patch."""
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    buf = bytearray(path.read_bytes())
    protocol = (buf[IMAGE_PROTOCOL_ADDR + 1] << 8) | buf[IMAGE_PROTOCOL_ADDR]
    if protocol < 0x206:
        raise ValueError("Protocol version should be 2.06+")

    hasher = hashlib.sha384()
    number_of_region_entry, regions_base, regions_size = get_image_regions(buf)

    for index in range(number_of_region_entry):
        region_data = buf[regions_base[index]: regions_base[index] + regions_size[index]]
        hasher.update(region_data)

    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Calculate td-payload reference value with QEMU Kernel Direct Boot patch"
    )
    parser.add_argument(
        "-k",
        "--kernel",
        required=True,
        help="path to vmlinuz kernel",
    )

    args = parser.parse_args()

    try:
        result = qemu(args.kernel)
        print(result)
    except Exception as e:
        print(f"[ERROR]: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

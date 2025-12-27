#!/usr/bin/env python3
# Copyright (c) 2025 Alibaba Cloud
#
# SPDX-License-Identifier: Apache-2.0

"""
Python implementation of td-shim-tee-info-hash tool.
This tool calculates MRTD (Measurement Register TD) value from the shim binary image.
"""

import argparse
import logging
import os
import struct
import sys
from hashlib import sha384
from typing import BinaryIO, List

# Constants
SHA384_DIGEST_SIZE = 0x30
TDVF_DESCRIPTOR_OFFSET = 0x20
MRTD_EXTENSION_BUFFER_SIZE = 0x80
TDH_MR_EXTEND_GRANULARITY = 0x100
PAGE_SIZE = 0x1000
MEM_PAGE_ADD_ASCII_SIZE = 0xC
MEM_PAGE_ADD_GPA_OFFSET = 0x10
MEM_PAGE_ADD_GPA_SIZE = 0x8
MR_EXTEND_ASCII_SIZE = 0x9
MR_EXTEND_GPA_OFFSET = 0x10
MR_EXTEND_GPA_SIZE = 0x8
OVMF_TABLE_FOOTER_GUID_OFFSET = 0x30

# TDX Metadata constants
TDX_METADATA_SIGNATURE = 0x46564454
TDX_METADATA_ATTRIBUTES_EXTEND_MEM_PAGE_ADD = 0x2
TDX_METADATA_ATTRIBUTES_EXTENDMR = 0x00000001
TDX_METADATA_SECTION_TYPE_TD_INFO = 7
TDX_METADATA_SECTION_TYPE_MAX = 9

# GUID size
GUID_SIZE = 16


def parse_guid_from_bytes(guid_bytes: bytes) -> tuple:
    """
    Parse GUID from bytes according to GUID format:
    - First 4 bytes: f0 (little-endian u32)
    - Next 2 bytes: f1 (little-endian u16)
    - Next 2 bytes: f2 (little-endian u16)
    - Last 8 bytes: f3 (big-endian, direct copy)
    """
    if len(guid_bytes) < GUID_SIZE:
        raise ValueError(f"Invalid GUID size: {len(guid_bytes)} < {GUID_SIZE}")

    f0 = struct.unpack("<I", guid_bytes[0:4])[0]  # little-endian u32
    f1 = struct.unpack("<H", guid_bytes[4:6])[0]  # little-endian u16
    f2 = struct.unpack("<H", guid_bytes[6:8])[0]  # little-endian u16
    f3 = guid_bytes[8:16]  # big-endian, direct copy

    return (f0, f1, f2, f3)


def guid_to_bytes(f0: int, f1: int, f2: int, f3: bytes) -> bytes:
    """
    Convert GUID fields to bytes according to GUID format.
    """
    result = bytearray()
    result.extend(struct.pack("<I", f0))  # little-endian u32
    result.extend(struct.pack("<H", f1))  # little-endian u16
    result.extend(struct.pack("<H", f2))  # little-endian u16
    result.extend(f3)  # big-endian, direct copy
    return bytes(result)


def compare_guid(guid_bytes: bytes, expected_guid_bytes: bytes) -> bool:
    """
    Compare two GUIDs by parsing them according to GUID format.
    """
    try:
        parsed1 = parse_guid_from_bytes(guid_bytes)
        parsed2 = parse_guid_from_bytes(expected_guid_bytes)
        return parsed1 == parsed2
    except (ValueError, struct.error):
        return False


# OVMF Table Footer GUID: 96b582de-1fb2-45f7-baea-a366c55a082d
# Format: f0=0x96b582de, f1=0x1fb2, f2=0x45f7, f3=[0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d]
# Bytes: f0 (little-endian) + f1 (little-endian) + f2 (little-endian) + f3 (direct)
OVMF_TABLE_FOOTER_GUID = guid_to_bytes(
    0x96b582de, 0x1fb2, 0x45f7,
    bytes([0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d])
)

# OVMF Table TDX Metadata GUID: e47a6535-984a-4798-865e-4685a7bf8ec2
# Format: f0=0xe47a6535, f1=0x984a, f2=0x4798, f3=[0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2]
OVMF_TABLE_TDX_METADATA_GUID = guid_to_bytes(
    0xe47a6535, 0x984a, 0x4798,
    bytes([0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2])
)

# TDX Metadata GUID: E9EAF9F3-168E-44D5-A8EB-7F4D8738F6AE
# Format: f0=0xE9EAF9F3, f1=0x168E, f2=0x44D5, f3=[0xA8, 0xEB, 0x7F, 0x4D, 0x87, 0x38, 0xF6, 0xAE]
TDX_METADATA_GUID = guid_to_bytes(
    0xE9EAF9F3, 0x168E, 0x44D5,
    bytes([0xA8, 0xEB, 0x7F, 0x4D, 0x87, 0x38, 0xF6, 0xAE])
)


class TdxMetadataDescriptor:
    """TDX Metadata Descriptor structure."""

    STRUCT_FORMAT = "<IIII"  # signature, length, version, number_of_section_entry
    SIZE = 16

    def __init__(self, signature: int, length: int, version: int, number_of_section_entry: int):
        self.signature = signature
        self.length = length
        self.version = version
        self.number_of_section_entry = number_of_section_entry

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TdxMetadataDescriptor':
        """Parse from binary data."""
        if len(data) < cls.SIZE:
            raise ValueError(f"Invalid data size: {len(data)} < {cls.SIZE}")
        values = struct.unpack(cls.STRUCT_FORMAT, data[:cls.SIZE])
        return cls(*values)

    def is_valid(self) -> bool:
        """Check if descriptor is valid."""
        if self.signature != TDX_METADATA_SIGNATURE:
            return False
        if self.version != 1:
            return False
        if self.number_of_section_entry == 0:
            return False
        if self.length < 16:
            return False
        if (self.length - 16) % 32 != 0:
            return False
        if (self.length - 16) // 32 != self.number_of_section_entry:
            return False
        return True


class TdxMetadataSection:
    """TDX Metadata Section structure."""

    # data_offset, raw_data_size, memory_address, memory_data_size, type, attributes
    STRUCT_FORMAT = "<IIQQII"
    SIZE = 32

    def __init__(self, data_offset: int, raw_data_size: int, memory_address: int,
                 memory_data_size: int, section_type: int, attributes: int):
        self.data_offset = data_offset
        self.raw_data_size = raw_data_size
        self.memory_address = memory_address
        self.memory_data_size = memory_data_size
        self.type = section_type
        self.attributes = attributes

    @classmethod
    def from_bytes(cls, data: bytes) -> 'TdxMetadataSection':
        """Parse from binary data."""
        if len(data) < cls.SIZE:
            raise ValueError(f"Invalid data size: {len(data)} < {cls.SIZE}")
        values = struct.unpack(cls.STRUCT_FORMAT, data[:cls.SIZE])
        return cls(values[0], values[1], values[2], values[3], values[4], values[5])


def build_mrtd(image_file: BinaryIO, image_size: int) -> bytes:
    """Build MRTD (Measurement Register TD) from the image file."""
    metadata_off = 0

    # Try to find OVMF table footer GUID
    image_file.seek(image_size - OVMF_TABLE_FOOTER_GUID_OFFSET)
    footer_guid_buf = image_file.read(GUID_SIZE)
    if compare_guid(footer_guid_buf, OVMF_TABLE_FOOTER_GUID):
        # OVMF format
        image_file.seek(image_size - OVMF_TABLE_FOOTER_GUID_OFFSET - 2)
        table_len = struct.unpack("<H", image_file.read(2))[0] - GUID_SIZE - 2
        ovmf_table_offset = image_size - OVMF_TABLE_FOOTER_GUID_OFFSET - 2

        count = 0
        while count < table_len:
            image_file.seek(ovmf_table_offset - GUID_SIZE)
            guid_buf = image_file.read(GUID_SIZE)

            image_file.seek(ovmf_table_offset - GUID_SIZE - 2)
            entry_len = struct.unpack("<H", image_file.read(2))[0]

            if compare_guid(guid_buf, OVMF_TABLE_TDX_METADATA_GUID):
                image_file.seek(ovmf_table_offset - GUID_SIZE - 2 - 4)
                metadata_offset_value = struct.unpack(
                    "<I", image_file.read(4))[0]
                metadata_off = image_size - metadata_offset_value - GUID_SIZE
                break

            ovmf_table_offset -= entry_len
            count += entry_len
    else:
        # TDVF format
        image_file.seek(image_size - TDVF_DESCRIPTOR_OFFSET)
        metadata_off = struct.unpack("<I", image_file.read(4))[0] - GUID_SIZE

    # Read metadata descriptor
    image_file.seek(metadata_off)
    guid_buf = image_file.read(GUID_SIZE)
    if not compare_guid(guid_buf, TDX_METADATA_GUID):
        raise ValueError("Invalid TDX Metadata GUID")

    desc_data = image_file.read(TdxMetadataDescriptor.SIZE)
    descriptor = TdxMetadataDescriptor.from_bytes(desc_data)

    if not descriptor.is_valid():
        raise ValueError("Invalid TDX Metadata Descriptor")

    # Read full metadata
    image_file.seek(metadata_off + GUID_SIZE)
    metadata_buf = image_file.read(descriptor.length)

    # Parse sections
    desc_offset = TdxMetadataDescriptor.SIZE
    sha384hasher = sha384()
    buffer128 = bytearray(MRTD_EXTENSION_BUFFER_SIZE)
    buffer3_128 = [bytearray(MRTD_EXTENSION_BUFFER_SIZE) for _ in range(3)]

    for _ in range(descriptor.number_of_section_entry):
        sec_data = metadata_buf[desc_offset:desc_offset +
                                TdxMetadataSection.SIZE]
        sec = TdxMetadataSection.from_bytes(sec_data)
        desc_offset += TdxMetadataSection.SIZE

        # Sanity checks
        if sec.memory_address % PAGE_SIZE != 0:
            raise ValueError("Memory address must be 4K aligned!")

        if (sec.type != TDX_METADATA_SECTION_TYPE_TD_INFO and
            (sec.memory_address != 0 or sec.memory_data_size != 0) and
                sec.memory_data_size < sec.raw_data_size):
            raise ValueError(
                "Memory data size must exceed or equal the raw data size!")

        if sec.memory_data_size % PAGE_SIZE != 0:
            raise ValueError("Memory data size must be 4K aligned!")

        if sec.type >= TDX_METADATA_SECTION_TYPE_MAX:
            raise ValueError("Invalid type value!")

        nr_pages = sec.memory_data_size // PAGE_SIZE

        # Process pages one by one: PAGE.ADD then MR.EXTEND for each page
        for iter in range(nr_pages):
            if sec.attributes & TDX_METADATA_ATTRIBUTES_EXTEND_MEM_PAGE_ADD == 0:
                fill_buffer128_with_mem_page_add(
                    buffer128, sec.memory_address + iter * PAGE_SIZE
                )
                sha384hasher.update(buffer128)

            if sec.attributes & TDX_METADATA_ATTRIBUTES_EXTENDMR != 0:
                granularity = TDH_MR_EXTEND_GRANULARITY
                iteration = PAGE_SIZE // granularity
                for chunk_iter in range(iteration):
                    fill_buffer3_128_with_mr_extend(
                        buffer3_128,
                        sec.memory_address + iter * PAGE_SIZE + chunk_iter * granularity,
                        image_file,
                        sec.data_offset + iter * PAGE_SIZE + chunk_iter * granularity,
                    )
                    sha384hasher.update(buffer3_128[0])
                    sha384hasher.update(buffer3_128[1])
                    sha384hasher.update(buffer3_128[2])

    return sha384hasher.digest()


def fill_buffer128_with_mem_page_add(buf: bytearray, gpa: int):
    """Fill buffer with MEM.PAGE.ADD data."""
    buf[:] = bytearray(MRTD_EXTENSION_BUFFER_SIZE)
    buf[0:MEM_PAGE_ADD_ASCII_SIZE] = b"MEM.PAGE.ADD"
    buf[MEM_PAGE_ADD_GPA_OFFSET:MEM_PAGE_ADD_GPA_OFFSET + MEM_PAGE_ADD_GPA_SIZE] = \
        struct.pack("<Q", gpa)


def fill_buffer3_128_with_mr_extend(
    buf: List[bytearray], gpa: int, file: BinaryIO, data_offset: int
):
    """Fill buffer with MR.EXTEND data."""
    for b in buf:
        b[:] = bytearray(MRTD_EXTENSION_BUFFER_SIZE)

    buf[0][0:MR_EXTEND_ASCII_SIZE] = b"MR.EXTEND"
    buf[0][MR_EXTEND_GPA_OFFSET:MR_EXTEND_GPA_OFFSET + MR_EXTEND_GPA_SIZE] = \
        struct.pack("<Q", gpa)

    file.seek(data_offset)
    data1 = file.read(MRTD_EXTENSION_BUFFER_SIZE)
    data2 = file.read(MRTD_EXTENSION_BUFFER_SIZE)

    if len(data1) < MRTD_EXTENSION_BUFFER_SIZE:
        raise IOError(
            f"Failed to read enough data for buffer[1]: got {len(data1)}, expected {MRTD_EXTENSION_BUFFER_SIZE}")
    if len(data2) < MRTD_EXTENSION_BUFFER_SIZE:
        raise IOError(
            f"Failed to read enough data for buffer[2]: got {len(data2)}, expected {MRTD_EXTENSION_BUFFER_SIZE}")

    buf[1][:] = data1
    buf[2][:] = data2


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Calculate MRTD (Measurement Register TD) value from the shim binary image"
    )
    parser.add_argument(
        "-i", "--image",
        required=True,
        help="shim binary file"
    )
    parser.add_argument(
        "-l", "--log-level",
        default="info",
        choices=["off", "error", "warn", "info", "debug", "trace"],
        help="logging level [default: info]"
    )

    args = parser.parse_args()

    # Setup logging
    log_level_map = {
        "off": logging.CRITICAL + 1,
        "error": logging.ERROR,
        "warn": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
        "trace": logging.DEBUG,  # Python doesn't have trace, use debug
    }
    logging.basicConfig(
        level=log_level_map.get(args.log_level, logging.INFO),
        format='%(levelname)s: %(message)s'
    )

    # Build MRTD
    logging.info(f"Reading image from {args.image}")
    with open(args.image, 'rb') as image_file:
        image_size = os.path.getsize(args.image)
        mrtd = build_mrtd(image_file, image_size)

    # Output MRTD as hexadecimal string
    print(mrtd.hex())

    return 0


if __name__ == "__main__":
    sys.exit(main())

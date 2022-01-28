// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

/*
    Image Layout:
                  Binary                       Address
            0x00000000 -> +--------------+ <-  0xFF000000
                          |     VAR      |
            0x00040000 -> +--------------+ <-  0xFF040000
                          |  TD_MAILBOX  |
            0x00041000 -> +--------------+ <-  0xFF041000
                          |    TD_HOB    |
            0x00044000 -> +--------------+ <-  0xFF044000
                          |    (Guard)   |
                          |  TEMP_STACK  |
            0x00064000 -> +--------------+ <-  0xFF064000
                          |   TEMP_RAM   |
            0x00084000 -> +--------------+ <-  0xFF084000
           (0x00C2C000)   | Rust Payload |
                          |     (pad)    |
                          |   metadata   |
            0x00CB0000 -> +--------------+ <-  0xFFCB0000
           (0x00348000)   |   Rust IPL   |
                          |     (pad)    |
            0x00FF8000 -> +--------------+ <-  0xFFFF8000
           (0x00008000)   | Reset Vector |
            0x01000000 -> +--------------+ <- 0x100000000 (4G)
*/

// Image
pub const TD_SHIM_CONFIG_OFFSET: u32 = 0x0;
pub const TD_SHIM_CONFIG_SIZE: u32 = 0x40000;
pub const TD_SHIM_MAILBOX_OFFSET: u32 = 0x40000; // TD_SHIM_CONFIG_OFFSET + TD_SHIM_CONFIG_SIZE
pub const TD_SHIM_MAILBOX_SIZE: u32 = 0x1000;
pub const TD_SHIM_HOB_OFFSET: u32 = 0x41000; // TD_SHIM_MAILBOX_OFFSET + TD_SHIM_MAILBOX_SIZE
pub const TD_SHIM_HOB_SIZE: u32 = 0x2000;
pub const TD_SHIM_TEMP_STACK_GUARD_SIZE: u32 = 0x1000;
pub const TD_SHIM_TEMP_STACK_OFFSET: u32 = 0x44000; // TD_SHIM_HOB_OFFSET + TD_SHIM_HOB_SIZE + TD_SHIM_TEMP_STACK_GUARD_SIZE
pub const TD_SHIM_TEMP_STACK_SIZE: u32 = 0x20000;
pub const TD_SHIM_TEMP_HEAP_OFFSET: u32 = 0x64000; // TD_SHIM_TEMP_STACK_OFFSET + TD_SHIM_TEMP_STACK_SIZE
pub const TD_SHIM_TEMP_HEAP_SIZE: u32 = 0x20000;

pub const TD_SHIM_PAYLOAD_OFFSET: u32 = 0x84000; // TD_SHIM_TEMP_HEAP_OFFSET + TD_SHIM_TEMP_HEAP_SIZE
pub const TD_SHIM_PAYLOAD_SIZE: u32 = 0xC2C000;
pub const TD_SHIM_IPL_OFFSET: u32 = 0xCB0000; // TD_SHIM_PAYLOAD_OFFSET + TD_SHIM_PAYLOAD_SIZE
pub const TD_SHIM_METADATA_OFFSET: u32 = 0xCAFF30; // TD_SHIM_IPL_OFFSET - size_of::<TdxMetadata>() + size_of::<TdxMetadataGuid>()
pub const TD_SHIM_IPL_SIZE: u32 = 0x348000;
pub const TD_SHIM_RESET_VECTOR_OFFSET: u32 = 0xFF8000; // TD_SHIM_IPL_OFFSET + TD_SHIM_IPL_SIZE
pub const TD_SHIM_RESET_VECTOR_SIZE: u32 = 0x8000;
pub const TD_SHIM_FIRMWARE_SIZE: u32 = 0x1000000; // TD_SHIM_RESET_VECTOR_OFFSET + TD_SHIM_RESET_VECTOR_SIZE

// Image loaded
pub const TD_SHIM_FIRMWARE_BASE: u32 = 0xFF000000; // 0xFFFFFFFF - TD_SHIM_FIRMWARE_SIZE + 1
pub const TD_SHIM_CONFIG_BASE: u32 = 0xFF000000; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_CONFIG_OFFSET
pub const TD_SHIM_MAILBOX_BASE: u32 = 0xFF040000; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_MAILBOX_OFFSET
pub const TD_SHIM_HOB_BASE: u32 = 0xFF041000; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_HOB_OFFSET
pub const TD_SHIM_TEMP_STACK_BASE: u32 = 0xFF044000; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_TEMP_STACK_OFFSET
pub const TD_SHIM_TEMP_HEAP_BASE: u32 = 0xFF064000; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_TEMP_HEAP_OFFSET
pub const TD_SHIM_PAYLOAD_BASE: u32 = 0xFF084000; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_PAYLOAD_OFFSET
pub const TD_SHIM_IPL_BASE: u32 = 0xFFCB0000; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_IPL_OFFSET
pub const TD_SHIM_RESET_VECTOR_BASE: u32 = 0xFFFF8000; // TD_SHIM_FIRMWARE_BASE + TD_SHIM_RESET_VECTOR_OFFSET
pub const TD_SHIM_RESET_SEC_CORE_ENTRY_POINT_ADDR: u32 = 0xFFFFFFD4; // 0xFFFFFFFF - 0x20 - 12 + 1
pub const TD_SHIM_RESET_SEC_CORE_BASE_ADDR: u32 = 0xFFFFFFD8; // 0xFFFFFFFF - 0x20 - 8 + 1
pub const TD_SHIM_RESET_SEC_CORE_SIZE_ADDR: u32 = 0xFFFFFFDC; // 0xFFFFFFFF - 0x20 - 4 + 1

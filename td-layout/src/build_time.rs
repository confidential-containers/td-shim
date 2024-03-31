// Copyright (c) 2021 - 2024  Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

// Auto-generated by `td-layout-config`, do not edit manually.

/*
Image Layout
+----------------------------------------+ <- 0x0
|                PAYLOAD                 |   (0xC2D000) 12.18 MB
+----------------------------------------+ <- 0xC2D000
|                 CONFIG                 |   (0x40000) 256 kB
+----------------------------------------+ <- 0xC6D000
|                MAILBOX                 |   (0x1000) 4 kB
+----------------------------------------+ <- 0xC6E000
|               TEMP_STACK               |   (0x20000) 128 kB
+----------------------------------------+ <- 0xC8E000
|               TEMP_HEAP                |   (0x20000) 128 kB
+----------------------------------------+ <- 0xCAE000
|                  FREE                  |   (0x0) 0 B
+----------------------------------------+ <- 0xCAE000
|                METADATA                |   (0x1000) 4 kB
+----------------------------------------+ <- 0xCAF000
|                  IPL                   |   (0x349000) 3.29 MB
+----------------------------------------+ <- 0xFF8000
|              RESET_VECTOR              |   (0x8000) 32 kB
+----------------------------------------+ <- 0x1000000
Image size: 0x1000000 (16 MB)
*/

// Image configuration
pub const TD_SHIM_IMAGE_SIZE: u32 = 0x1000000;
pub const TD_SHIM_PAYLOAD_OFFSET: u32 = 0x0;
pub const TD_SHIM_CONFIG_OFFSET: u32 = 0xC2D000;
pub const TD_SHIM_MAILBOX_OFFSET: u32 = 0xC6D000;
pub const TD_SHIM_TEMP_STACK_OFFSET: u32 = 0xC6E000;
pub const TD_SHIM_TEMP_HEAP_OFFSET: u32 = 0xC8E000;
pub const TD_SHIM_FREE_OFFSET: u32 = 0xCAE000;
pub const TD_SHIM_METADATA_OFFSET: u32 = 0xCAE000;
pub const TD_SHIM_IPL_OFFSET: u32 = 0xCAF000;
pub const TD_SHIM_RESET_VECTOR_OFFSET: u32 = 0xFF8000;

// Size of regions
pub const TD_SHIM_PAYLOAD_SIZE: u32 = 0xC2D000;
pub const TD_SHIM_CONFIG_SIZE: u32 = 0x40000;
pub const TD_SHIM_MAILBOX_SIZE: u32 = 0x1000;
pub const TD_SHIM_TEMP_STACK_SIZE: u32 = 0x20000;
pub const TD_SHIM_TEMP_HEAP_SIZE: u32 = 0x20000;
pub const TD_SHIM_FREE_SIZE: u32 = 0x0;
pub const TD_SHIM_METADATA_SIZE: u32 = 0x1000;
pub const TD_SHIM_IPL_SIZE: u32 = 0x349000;
pub const TD_SHIM_RESET_VECTOR_SIZE: u32 = 0x8000;

// ROM configuration
pub const TD_SHIM_FIRMWARE_BASE: u32 = 0xFFC2D000;
pub const TD_SHIM_FIRMWARE_SIZE: u32 = 0x3D3000;
pub const TD_SHIM_CONFIG_BASE: u32 = 0xFFC2D000;
pub const TD_SHIM_MAILBOX_BASE: u32 = 0xFFC6D000;
pub const TD_SHIM_TEMP_STACK_BASE: u32 = 0xFFC6E000;
pub const TD_SHIM_TEMP_HEAP_BASE: u32 = 0xFFC8E000;
pub const TD_SHIM_FREE_BASE: u32 = 0xFFCAE000;
pub const TD_SHIM_METADATA_BASE: u32 = 0xFFCAE000;
pub const TD_SHIM_IPL_BASE: u32 = 0xFFCAF000;
pub const TD_SHIM_RESET_VECTOR_BASE: u32 = 0xFFFF8000;

// TD_SHIM_SEC_INFO_OFFSET equals to firmware size - metadata pointer offset -
// OVMF GUID table size - SEC Core information size.
pub const TD_SHIM_SEC_CORE_INFO_OFFSET: u32 = 0xFFFFAC;
pub const TD_SHIM_SEC_CORE_INFO_BASE: u32 = 0xFFFFFFAC;

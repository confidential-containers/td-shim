// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

use scroll::{Pread, Pwrite};
use uefi_pi::pi;

pub mod acpi;
pub mod tcg;
#[cfg(feature = "main")]
pub mod td;

pub const TD_HOB_ACPI_TABLE_GUID: [u8; 16] = [
    0x70, 0x58, 0x0c, 0x6a, 0xed, 0xd4, 0xf4, 0x44, 0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d,
];

pub const TD_HOB_KERNEL_INFO_GUID: [u8; 16] = [
    0x12, 0xa4, 0x6f, 0xb9, 0x1f, 0x46, 0xe3, 0x4b, 0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0,
];

#[repr(C)]
#[derive(Copy, Clone, Debug, Pwrite, Pread)]
pub struct HobTemplate {
    pub handoff_info_table: pi::hob::HandoffInfoTable,
    pub firmware_volume: pi::hob::FirmwareVolume,
    pub cpu: pi::hob::Cpu,
    pub payload: pi::hob::MemoryAllocation,
    pub page_table: pi::hob::MemoryAllocation,
    pub stack: pi::hob::MemoryAllocation,
    pub memory_above_1m: pi::hob::ResourceDescription,
    pub memory_blow_1m: pi::hob::ResourceDescription,
    pub end_off_hob: pi::hob::Header,
}

#[repr(C)]
#[derive(Default, Clone, Copy, Pread, Pwrite)]
pub struct PayloadInfo {
    pub image_type: u32,
    pub entry_point: u64,
}

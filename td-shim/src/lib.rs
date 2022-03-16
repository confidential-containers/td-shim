// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

use scroll::{Pread, Pwrite};

use td_uefi_pi::pi;

pub mod acpi;
pub mod event_log;
pub mod fv;
pub mod reset_vector;
pub mod secure_boot;

pub const TD_ACPI_TABLE_HOB_GUID: [u8; 16] = [
    0x70, 0x58, 0x0c, 0x6a, 0xed, 0xd4, 0xf4, 0x44, 0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d,
];

pub const TD_KERNEL_INFO_HOB_GUID: [u8; 16] = [
    0x12, 0xa4, 0x6f, 0xb9, 0x1f, 0x46, 0xe3, 0x4b, 0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0,
];

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TdKernelInfoHobType {
    ///  Payload Binary is a PE/COFF or ELF executable image as payload.
    ///
    /// Entrypoint can be found by parsing the image header. This type image does not follow
    /// Linux boot protocol. A payload HOB is used to pass data from TdShim to payload.
    ExecutablePayload = 0,

    /// Payload Binary is bzImage, follow Linux boot protocol.
    ///
    /// The first 512 bytes are boot_param. (zero page). The entrypoint is start address of loaded
    /// 64bit Linux kernel plus 0x200
    BzImage,

    /// Payload Binary is VMM loaded vmLinux, follow Linux boot protocol.
    ///
    /// The entrypoint is defined at HOB_PAYLOAD_INFO_TABLE.Entrypoint.
    RawVmLinux,

    /// Unknown Image type
    UnknownImage = u32::MAX,
}

impl From<&TdKernelInfoHobType> for u32 {
    fn from(v: &TdKernelInfoHobType) -> Self {
        *v as u32
    }
}

impl From<u32> for TdKernelInfoHobType {
    fn from(v: u32) -> Self {
        match v {
            0 => TdKernelInfoHobType::ExecutablePayload,
            1 => TdKernelInfoHobType::BzImage,
            2 => TdKernelInfoHobType::RawVmLinux,
            _ => TdKernelInfoHobType::UnknownImage,
        }
    }
}

#[derive(Pwrite)]
pub struct ConfigurationTable {
    pub guid: event_log::Guid,
    pub table: u64, // should be usize, usize can't be derived by pwrite, but tdx only support 64bit
}

#[derive(Pwrite)]
pub struct TdxHandoffTablePointers {
    pub table_descripion_size: u8,
    pub table_description: [u8; 8],
    pub number_of_tables: u64,
    pub table_entry: [ConfigurationTable; 1],
}

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

/// Write three bytes from an integer value into the buffer.
pub fn write_u24(data: u32, buf: &mut [u8]) {
    assert!(data < 0xffffff);
    buf[0] = (data & 0xFF) as u8;
    buf[1] = ((data >> 8) & 0xFF) as u8;
    buf[2] = ((data >> 16) & 0xFF) as u8;
}

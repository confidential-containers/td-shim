// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

use scroll::{Pread, Pwrite};

pub mod acpi;
pub mod metadata;
pub mod td_uefi_pi;

use td_uefi_pi::pi::{self, guid};

// This GUID is used for ACPI GUID Extension HOB
// Please refer to:
// https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md#acpi-guid-extension-hob
pub const TD_ACPI_TABLE_HOB_GUID: guid::Guid = guid::Guid::from_fields(
    0x6a0c5870,
    0xd4ed,
    0x44f4,
    [0xa1, 0x35, 0xdd, 0x23, 0x8b, 0x6f, 0xc, 0x8d],
);

// This GUID is used for TD Payload Info GUID Extension HOB
// Please refer to:
// https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md#td-payload-info-guid-extension-hob
pub const TD_PAYLOAD_INFO_HOB_GUID: guid::Guid = guid::Guid::from_fields(
    0xb96fa412,
    0x461f,
    0x4be3,
    [0x8c, 0xd, 0xad, 0x80, 0x5a, 0x49, 0x7a, 0xc0],
);

// This GUID is used for E820 Memory Map GUID Extension HOB
// Please refer to:
// https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md#e820-memory-map-guid-extension-hob
pub const TD_E820_TABLE_HOB_GUID: pi::guid::Guid = pi::guid::Guid::from_fields(
    0x8f8072ea,
    0x3486,
    0x4b47,
    [0x86, 0xa7, 0x23, 0x53, 0xb8, 0x8a, 0x87, 0x73],
);

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TdPayloadInfoHobType {
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

impl From<&TdPayloadInfoHobType> for u32 {
    fn from(v: &TdPayloadInfoHobType) -> Self {
        *v as u32
    }
}

impl From<u32> for TdPayloadInfoHobType {
    fn from(v: u32) -> Self {
        match v {
            0 => TdPayloadInfoHobType::ExecutablePayload,
            1 => TdPayloadInfoHobType::BzImage,
            2 => TdPayloadInfoHobType::RawVmLinux,
            _ => TdPayloadInfoHobType::UnknownImage,
        }
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy, Pread, Pwrite)]
pub struct PayloadInfo {
    pub image_type: u32,
    pub reserved: u32,
    pub entry_point: u64,
}

/// Write three bytes from an integer value into the buffer.
pub fn write_u24(data: u32, buf: &mut [u8; 3]) {
    assert!(data <= 0xffffff);
    buf[0] = (data & 0xFF) as u8;
    buf[1] = ((data >> 8) & 0xFF) as u8;
    buf[2] = ((data >> 16) & 0xFF) as u8;
}

// To protect against speculative attacks, place the LFENCE instruction after the range
// check and branch, but before any code that consumes the checked value.
pub fn speculation_barrier() {
    unsafe { core::arch::asm!("lfence") }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tdpayload_info_hob_type() {
        assert_eq!(
            TdPayloadInfoHobType::from(0),
            TdPayloadInfoHobType::ExecutablePayload
        );
        assert_eq!(TdPayloadInfoHobType::from(1), TdPayloadInfoHobType::BzImage);
        assert_eq!(
            TdPayloadInfoHobType::from(2),
            TdPayloadInfoHobType::RawVmLinux
        );
        assert_eq!(
            TdPayloadInfoHobType::from(3),
            TdPayloadInfoHobType::UnknownImage
        );
    }

    #[test]
    fn test_write_u24() {
        let mut buf: [u8; 3] = [0; 3];
        write_u24(0xffffff, &mut buf);
    }
}

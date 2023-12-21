// Copyright (c) 2022 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

pub mod log;

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub const SHA384_DIGEST_SIZE: usize = 48;
pub const TPML_ALG_SHA384: u16 = 0xc;
pub const TPML_DIGEST_VALUES_PACKED_SIZE: usize = 54;
pub const PCR_DIGEST_NUM: usize = 1;

pub const EV_NO_ACTION: u32 = 0x0000_0003;
pub const EV_SEPARATOR: u32 = 0x0000_0004;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000_000A;
pub const EV_EFI_EVENT_BASE: u32 = 0x8000_0000;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = EV_EFI_EVENT_BASE + 0xA;
pub const EV_EFI_HANDOFF_TABLES2: u32 = EV_EFI_EVENT_BASE + 0xB;

const VENDOR_INFO_SIZE: usize = 7;
const VENDOR_INFO: &[u8; VENDOR_INFO_SIZE] = b"td-shim";

/// TCG_EfiSpecIdEvent is the first event in the event log
/// It is used to determine the version and format of the events in the log, identify
/// the number and size of the recorded digests
///
/// Defined in TCG PC Client Platform Firmware Profile Specification:
/// 'Table 20 TCG_EfiSpecIdEvent'
#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct TcgEfiSpecIdevent {
    pub signature: [u8; 16],
    pub platform_class: u32,
    pub spec_version_minor: u8,
    pub spec_version_major: u8,
    pub spec_errata: u8,
    pub uintn_size: u8,
    pub number_of_algorithms: u32,
    pub digest_sizes: [TcgEfiSpecIdEventAlgorithmSize; 1],
    pub vendor_info_size: u8,
    // Fix the vendor info size to VENDOR_INFO_SIZE
    pub vendor_info: [u8; VENDOR_INFO_SIZE],
}

impl TcgEfiSpecIdevent {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

impl Default for TcgEfiSpecIdevent {
    fn default() -> Self {
        Self {
            signature: *b"Spec ID Event03\0",
            platform_class: 0,
            spec_version_minor: 0,
            spec_version_major: 0x2,
            spec_errata: 105,
            uintn_size: 0x2,
            number_of_algorithms: 1,
            digest_sizes: [TcgEfiSpecIdEventAlgorithmSize {
                algorithm_id: TPML_ALG_SHA384,
                digest_size: SHA384_DIGEST_SIZE as u16,
            }],
            vendor_info_size: VENDOR_INFO_SIZE as u8,
            vendor_info: *VENDOR_INFO,
        }
    }
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct TcgEfiSpecIdEventAlgorithmSize {
    algorithm_id: u16,
    digest_size: u16,
}

/// Used to record the payload binary information into event log.
///
/// Defined in TCG PC Client Platform Firmware Profile Specification section
/// 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
pub struct UefiPlatformFirmwareBlob2 {
    data: Vec<u8>,
}

impl UefiPlatformFirmwareBlob2 {
    pub fn new(blob_desc: &[u8], blob_base: u64, blob_length: u64) -> Option<Self> {
        if blob_desc.len() > u8::MAX as usize {
            return None;
        }

        // UINT8 BlobDescriptionSize
        let mut data = vec![blob_desc.len() as u8];

        // UINT8 BlobDescriptionSize
        data.extend_from_slice(blob_desc);

        // UEFI_PHYSICAL_ADDRESS BlobBase
        data.extend_from_slice(&u64::to_le_bytes(blob_base));
        // U64 BlobLength
        data.extend_from_slice(&u64::to_le_bytes(blob_length));

        Some(Self { data })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }
}

#[repr(C, packed)]
#[derive(Default, FromBytes, AsBytes, FromZeroes)]
pub struct CcEventHeader {
    pub mr_index: u32,
    pub event_type: u32,
    pub digest: TpmlDigestValues,
    pub event_size: u32,
}

impl core::fmt::Display for CcEventHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mr_index = self.mr_index;
        let event_type = self.event_type;
        let event_size = self.event_size;

        write!(
            f,
            "CC Event:
                MrIndex  - 0x{:x}
                EventType - 0x{:x}
                Digest -
                    {:}
                EventSize - 0x{:x}",
            mr_index, event_type, self.digest, event_size,
        )
    }
}

#[repr(C, packed)]
#[derive(Default, FromBytes, AsBytes, FromZeroes)]
pub struct TpmlDigestValues {
    pub count: u32,
    pub digests: [TpmtHa; PCR_DIGEST_NUM],
}

impl core::fmt::Display for TpmlDigestValues {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (idx, digest) in self.digests.iter().enumerate() {
            let hash_alg = digest.hash_alg;
            let sha384 = digest.digest.sha384;
            write!(
                f,
                "({}) HashAlgo: 0x{:x}, Digest: {:x?}",
                idx, hash_alg, sha384
            )?;
        }
        Ok(())
    }
}

#[repr(C, packed)]
#[derive(Default, FromBytes, AsBytes, FromZeroes)]
pub struct TpmtHa {
    pub hash_alg: u16,
    pub digest: TpmuHa,
}

#[repr(C, packed)]
#[derive(FromBytes, AsBytes, FromZeroes)]
pub struct TpmuHa {
    pub sha384: [u8; SHA384_DIGEST_SIZE],
}

impl Default for TpmuHa {
    fn default() -> Self {
        TpmuHa {
            sha384: [0; SHA384_DIGEST_SIZE],
        }
    }
}

#[repr(C, packed)]
#[derive(Default, FromBytes, AsBytes, FromZeroes)]
pub struct TcgPcrEventHeader {
    pub mr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 20],
    pub event_size: u32,
}

impl core::fmt::Display for TcgPcrEventHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mr_index = self.mr_index;
        let event_type = self.event_type;
        let digest = self.digest;
        let event_size = self.event_size;
        write!(
            f,
            "PCR Event:
                MrIndex  - {}
                EventType - 0x{:x}
                Digest - {:x?}
                EventSize - 0x{:x}",
            mr_index, event_type, digest, event_size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_size() {
        assert_eq!(size_of::<TpmuHa>(), SHA384_DIGEST_SIZE);
        assert_eq!(size_of::<TpmtHa>(), SHA384_DIGEST_SIZE + 2);
        assert_eq!(size_of::<TpmlDigestValues>(), 54);
        assert_eq!(size_of::<CcEventHeader>(), 66);
        assert_eq!(size_of::<TcgEfiSpecIdevent>(), 40);
    }

    #[test]
    fn test_uefi_platform_firmware_blob2() {
        // Descriptor size should be less than 255
        let desc = [0u8; 256];
        let blob2 = UefiPlatformFirmwareBlob2::new(&desc, 0x0, 0x1000);
        assert!(blob2.is_none());

        let blob2 = UefiPlatformFirmwareBlob2::new(b"td_payload\0", 0x0, 0x1000).unwrap();
        assert_eq!(blob2.as_bytes().len(), 28);
    }

    #[test]
    fn test_tpml_digest_value() {
        let value = TpmlDigestValues {
            count: 0,
            digests: Default::default(),
        };
        let mut buf = [0u8; size_of::<TpmlDigestValues>()];
        buf.copy_from_slice(value.as_bytes());
    }

    #[test]
    fn test_cc_event_header() {
        let hdr = CcEventHeader {
            mr_index: 0,
            event_type: 0,
            digest: TpmlDigestValues {
                count: 0,
                digests: Default::default(),
            },
            event_size: 0,
        };
        let mut buf = [0u8; size_of::<CcEventHeader>()];
        buf.copy_from_slice(hdr.as_bytes());
    }

    #[test]
    fn test_tcgefispec_id_event() {
        let event = TcgEfiSpecIdevent::new();

        let bytes = event.as_bytes();
        assert_eq!(bytes.len(), size_of::<TcgEfiSpecIdevent>());
    }
}

// Copyright (c) 2020 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::{mem::size_of, ptr::slice_from_raw_parts};
use scroll::{ctx, Endian, Pread, Pwrite};
use zerocopy::{AsBytes, FromBytes};

use crate::acpi::{calculate_checksum, GenericSdtHeader};

pub const SHA384_DIGEST_SIZE: usize = 48;
pub const TPML_ALG_SHA384: u16 = 0xc;
pub const TPML_DIGEST_VALUES_PACKED_SIZE: usize = 54;
pub const PCR_DIGEST_NUM: usize = 1;
pub const CC_EVENT_HEADER_SIZE: usize = 66;
pub const CCEL_CC_TYPE_TDX: u8 = 2;

pub const EV_NO_ACTION: u32 = 0x00000003;
pub const EV_SEPARATOR: u32 = 0x00000004;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000000A;
pub const EV_EFI_EVENT_BASE: u32 = 0x80000000;
pub const EV_EFI_PLATFORM_FIRMWARE_BLOB2: u32 = EV_EFI_EVENT_BASE + 0xA;
pub const EV_EFI_HANDOFF_TABLES2: u32 = EV_EFI_EVENT_BASE + 0xB;

pub const PLATFORM_CONFIG_HOB: &[u8] = b"td_hob\0";
pub const PLATFORM_CONFIG_PAYLOAD_PARAMETER: &[u8] = b"td_payload_info\0";
pub const PLATFORM_CONFIG_SECURE_POLICY_DB: &[u8] = b"secure_policy_db";
pub const PLATFORM_CONFIG_SECURE_AUTHORITY: &[u8] = b"secure_authority";
pub const PLATFORM_CONFIG_SVN: &[u8] = b"td_payload_svn\0";
pub const PLATFORM_FIRMWARE_BLOB2_PAYLOAD: &[u8] = b"td_payload\0";

const VENDOR_INFO_SIZE: usize = 7;
const VENDOR_INFO: &[u8; VENDOR_INFO_SIZE] = b"td_shim";

/// TCG_EfiSpecIdEvent is the first event in the event log
/// It is used to determine the version and format of the events in the log, identify
/// the number and size of the recorded digests
///
/// Defined in TCG PC Client Platform Firmware Profile Specification:
/// 'Table 20 TCG_EfiSpecIdEvent'
#[repr(C)]
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

#[repr(C)]
pub struct TcgEfiSpecIdEventAlgorithmSize {
    algorithm_id: u16,
    digest_size: u16,
}

impl TcgEfiSpecIdevent {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
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

/// Used to record configuration information into event log
///
/// Defined in td-shim spec 'Table 3.5-4 TD_SHIM_PLATFORM_CONFIG_INFO'
#[repr(C)]
#[derive(Debug, Default)]
pub struct TdShimPlatformConfigInfoHeader {
    pub descriptor: [u8; 16],
    pub info_length: u32,
}

impl TdShimPlatformConfigInfoHeader {
    pub fn new(descriptor: &[u8], info_length: u32) -> Option<Self> {
        if descriptor.len() > 16 {
            return None;
        }

        let mut header = Self {
            info_length,
            ..Default::default()
        };

        header.descriptor[..descriptor.len()].copy_from_slice(descriptor);
        Some(header)
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { &*slice_from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
}

/// Used to record the payload binary information into event log.
///
/// Defined in TCG PC Client Platform Firmware Profile Specification section
/// 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
pub struct UefiPlatformFirmwareBlob2 {
    data: Vec<u8>,
}

impl UefiPlatformFirmwareBlob2 {
    pub fn new(desciptor: &[u8], base: u64, length: u64) -> Option<Self> {
        if desciptor.len() > u8::MAX as usize {
            return None;
        }

        // UINT8 BlobDescriptionSize
        let mut data = vec![desciptor.len() as u8];

        // UINT8 BlobDescriptionSize
        data.extend_from_slice(desciptor);

        // UEFI_PHYSICAL_ADDRESS BlobBase
        data.extend_from_slice(&u64::to_le_bytes(base));
        // U64 BlobLength
        data.extend_from_slice(&u64::to_le_bytes(length));

        Some(Self { data })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }
}

#[repr(C)]
#[derive(Default, Debug, Pread, Pwrite, AsBytes, FromBytes)]
pub struct Guid {
    pub data1: u32,
    pub data2: u32,
    pub data3: u32,
    pub data4: u32,
}

pub const TD_LOG_EFI_HANDOFF_TABLE_GUID: Guid = Guid {
    data1: 0xf706dd8f,
    data2: 0x11e9eebe,
    data3: 0xa7e41499,
    data4: 0x51e6daa0,
};

#[repr(C)]
#[derive(Default, Debug, Pread, Pwrite)]
pub struct TdHandoffTable {
    pub guid: Guid,
    pub table: u64, // should be usize, usize can't be derived by pwrite, but tdx only support 64bit
}

#[repr(C)]
#[derive(Default, Debug, Pwrite)]
pub struct TdHandoffTablePointers {
    pub table_descripion_size: u8,
    pub table_description: [u8; 8],
    pub number_of_tables: u64,
    pub table_entry: [TdHandoffTable; 1],
}

#[repr(C)]
#[derive(Debug)]
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

impl<'a> ctx::TryFromCtx<'a, Endian> for TpmuHa {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], _endian: Endian) -> Result<(Self, usize), Self::Error> {
        let mut sha384: [u8; SHA384_DIGEST_SIZE] = [0; SHA384_DIGEST_SIZE];
        sha384.copy_from_slice(&src[0..SHA384_DIGEST_SIZE]);
        Ok((TpmuHa { sha384 }, sha384.len()))
    }
}

impl ctx::TryIntoCtx<Endian> for &TpmuHa {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], _endian: Endian) -> Result<usize, Self::Error> {
        if this.len() < SHA384_DIGEST_SIZE {
            return Err(scroll::Error::BadOffset(SHA384_DIGEST_SIZE));
        }

        this[0..SHA384_DIGEST_SIZE].copy_from_slice(&self.sha384);
        Ok(SHA384_DIGEST_SIZE)
    }
}

#[repr(C)]
#[derive(Default, Debug, Pread, Pwrite)]
pub struct TpmtHa {
    pub hash_alg: u16,
    pub digest: TpmuHa,
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct TpmlDigestValues {
    pub count: u32,
    pub digests: [TpmtHa; PCR_DIGEST_NUM],
}

impl<'a> ctx::TryFromCtx<'a, Endian> for TpmlDigestValues {
    type Error = scroll::Error;

    fn try_from_ctx(src: &'a [u8], endian: Endian) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;
        let count = src.gread_with::<u32>(offset, endian)?;
        let mut digests: [TpmtHa; PCR_DIGEST_NUM] = [TpmtHa::default(); PCR_DIGEST_NUM];
        src.gread_inout_with(offset, &mut digests, endian)?;

        Ok((TpmlDigestValues { count, digests }, *offset))
    }
}

impl ctx::TryIntoCtx<Endian> for &TpmlDigestValues {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], endian: Endian) -> Result<usize, Self::Error> {
        let type_size = TPML_DIGEST_VALUES_PACKED_SIZE;
        if this.len() < type_size {
            return Err(scroll::Error::BadOffset(type_size));
        }

        let offset = &mut 0;
        this.gwrite_with::<u32>(self.count, offset, endian)?;
        for index in 0..PCR_DIGEST_NUM {
            this.gwrite_with::<&TpmtHa>(&self.digests[index], offset, endian)?;
        }

        Ok(*offset)
    }
}

#[repr(C)]
#[derive(Default, Debug, Pread, Pwrite)]
pub struct CcEventHeader {
    pub mr_index: u32,
    pub event_type: u32,
    pub digest: TpmlDigestValues,
    pub event_size: u32,
}

#[repr(C)]
#[derive(Default, Debug, Pread, Pwrite)]
pub struct TcgPcrEventHeader {
    pub mr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 20],
    pub event_size: u32,
}

#[repr(C, packed)]
#[derive(Default, AsBytes, FromBytes)]
pub struct Ccel {
    pub header: GenericSdtHeader,
    pub cc_type: u8,
    pub cc_subtype: u8,
    pub reserved: u16,
    pub laml: u64,
    pub lasa: u64,
}

impl Ccel {
    pub fn new(cc_type: u8, cc_subtype: u8, laml: u64, lasa: u64) -> Ccel {
        let mut ccel = Ccel {
            header: GenericSdtHeader::new(b"CCEL", size_of::<Ccel>() as u32, 1),
            cc_type,
            cc_subtype,
            reserved: 0,
            laml,
            lasa,
        };
        ccel.checksum();
        ccel
    }

    pub fn checksum(&mut self) {
        self.header.checksum = 0;
        self.header
            .set_checksum(calculate_checksum(self.as_bytes()));
    }
}

pub struct CcEventDumper<'a> {
    area: &'a mut [u8],
    size: usize,
}

impl<'a> CcEventDumper<'a> {
    pub fn new(cc_event_mem: &'static mut [u8], size: usize) -> Self {
        CcEventDumper {
            area: cc_event_mem,
            size,
        }
    }

    pub fn dump_event_log(&self) {
        let mut offset = 0;

        if let Some(pcr_header) = self.read_pcr_event_header(offset) {
            Self::dump_pcr_event(&pcr_header);
            offset = offset
                .saturating_add(size_of::<TcgPcrEventHeader>() + pcr_header.event_size as usize);
        } else {
            log::info!("PCR event header not found\n");
            return;
        };

        if self.size < size_of::<TcgPcrEventHeader>() + CC_EVENT_HEADER_SIZE {
            log::info!("No event header in event log\n");
            return;
        }

        while offset <= self.size - CC_EVENT_HEADER_SIZE as usize {
            if let Some(cc_event_header) = self.read_cc_event_header(offset) {
                offset += CC_EVENT_HEADER_SIZE;
                let cc_event_size = cc_event_header.event_size as usize;
                if cc_event_size + offset <= self.area.len() {
                    let cc_event_data = &self.area[offset..offset + cc_event_size];
                    Self::dump_event(&cc_event_header, cc_event_data);
                }
                offset = offset.saturating_add(cc_event_size);
            } else {
                break;
            }
        }
    }

    fn dump_pcr_event(pcr_event_header: &TcgPcrEventHeader) {
        log::info!("PCR Event:\n");
        log::info!("    MrIndex  - {}\n", pcr_event_header.mr_index);
        log::info!("    EventType - 0x{:x}\n", pcr_event_header.event_type);
        log::info!("    Digest - {:x?}\n", pcr_event_header.digest);
        log::info!("    EventSize - 0x{:x}\n", pcr_event_header.event_size);
    }

    fn dump_event(cc_event_header: &CcEventHeader, _td_event_data: &[u8]) {
        let mr_index = cc_event_header.mr_index;
        let event_type = cc_event_header.event_type;
        let event_size = cc_event_header.event_size;

        log::info!("CC Event:\n");
        log::info!("    MrIndex  - {}\n", mr_index);
        log::info!("    EventType - 0x{:x}\n", event_type);

        for i in 0..cc_event_header.digest.count {
            let hash_alg = cc_event_header.digest.digests[i as usize].hash_alg;
            log::info!("      HashAlgo : 0x{:x}\n", hash_alg);
            log::info!(
                "      Digest({}): {:x?}\n",
                i,
                cc_event_header.digest.digests[i as usize].digest
            );
        }

        log::info!("    EventSize - 0x{:x}\n", event_size);
        log::info!("\n");
    }

    fn read_pcr_event_header(&self, offset: usize) -> Option<TcgPcrEventHeader> {
        if let Ok(v) = self.area.pread::<TcgPcrEventHeader>(offset) {
            Some(v)
        } else {
            None
        }
    }

    fn read_cc_event_header(&self, offset: usize) -> Option<CcEventHeader> {
        if let Ok(v) = self.area.pread::<CcEventHeader>(offset) {
            Some(v)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_size() {
        assert_eq!(size_of::<TpmuHa>(), SHA384_DIGEST_SIZE);
        assert_eq!(size_of::<TpmtHa>(), SHA384_DIGEST_SIZE + 2);
        assert_eq!(size_of::<Ccel>(), 56);
        assert_eq!(size_of::<TdShimPlatformConfigInfoHeader>(), 20);
        assert_eq!(size_of::<TcgEfiSpecIdevent>(), 40);
    }

    #[test]
    fn test_uefi_platform_firmware_blob2() {
        // Descriptor size should be less than 255
        let desc = [0u8; 256];
        let blob2 = UefiPlatformFirmwareBlob2::new(&desc, 0x0, 0x1000);
        assert!(blob2.is_none());

        let blob2 =
            UefiPlatformFirmwareBlob2::new(PLATFORM_FIRMWARE_BLOB2_PAYLOAD, 0x0, 0x1000).unwrap();
        assert_eq!(blob2.as_bytes().len(), 28);
    }

    #[test]
    fn test_tpml_digest_value() {
        let value = TpmlDigestValues {
            count: 0,
            digests: Default::default(),
        };
        let mut buf = [0u8; TPML_DIGEST_VALUES_PACKED_SIZE];

        buf.pwrite(&value, 0).unwrap();
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
        let mut buf = [0u8; CC_EVENT_HEADER_SIZE];
        buf.pwrite(&hdr, 0).unwrap();
    }

    #[test]
    fn test_dump_event_log() {
        const DIGEST_COUNT_OFFSET: usize = size_of::<TcgPcrEventHeader>() + size_of::<u32>() * 2;
        let mut buf =
            Vec::with_capacity(size_of::<TcgPcrEventHeader>() + size_of::<CcEventHeader>());
        buf.fill(0);
        let eventlog = unsafe {
            core::slice::from_raw_parts_mut(
                buf.as_ptr() as *const u8 as *mut u8,
                size_of::<TcgPcrEventHeader>() + size_of::<CcEventHeader>(),
            )
        };
        // Correct count to 1
        eventlog[DIGEST_COUNT_OFFSET] = 0x1;
        let dumper = CcEventDumper::new(
            eventlog,
            size_of::<TcgPcrEventHeader>() + size_of::<CcEventHeader>(),
        );
        dumper.dump_event_log();
    }

    #[test]
    fn test_tdshim_platform_configinfo_header() {
        // descriptor length < 16
        let descriptor: [u8; 15] = [0; 15];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_some());

        // descriptor length = 16
        let descriptor: [u8; 16] = [0; 16];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_some());
        assert_eq!(
            TdShimPlatformConfigInfoHeader::new(&descriptor, 0)
                .unwrap()
                .as_bytes(),
            [0; 20]
        );

        // descriptor length > 16
        let descriptor: [u8; 17] = [0; 17];
        assert!(TdShimPlatformConfigInfoHeader::new(&descriptor, 0).is_none());
    }

    #[test]
    fn test_tcgefispec_id_event() {
        let event = TcgEfiSpecIdevent::new();

        let bytes = event.as_bytes();
        assert_eq!(bytes.len(), size_of::<TcgEfiSpecIdevent>());
    }

    #[test]
    fn test_ccel() {
        let ccel = Ccel::new(CCEL_CC_TYPE_TDX, 0, 0x100, 0);

        assert_eq!(&ccel.header.signature, b"CCEL");
        assert_eq!(ccel.header.checksum, 45);
    }
}

// Copyright (c) 2020 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use core::mem::size_of;

use scroll::{ctx, Endian, Pread, Pwrite};
use zerocopy::{AsBytes, FromBytes};

use crate::acpi::{calculate_checksum, GenericSdtHeader};

pub const SHA384_DIGEST_SIZE: usize = 48;
pub const TPML_ALG_SHA384: u16 = 0xc;
pub const TPML_DIGEST_VALUES_PACKED_SIZE: usize = 54;
pub const PCR_DIGEST_NUM: usize = 1;
pub const CC_EVENT_HEADER_SIZE: usize = 66;
pub const CCEL_CC_TYPE_TDX: u8 = 2;

pub const EV_EFI_EVENT_BASE: u32 = 0x80000000;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = EV_EFI_EVENT_BASE + 0x0000000A;
pub const EV_EFI_HANDOFF_TABLES2: u32 = EV_EFI_EVENT_BASE + 0xB;

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

        while offset < self.size as usize {
            if let Some(cc_event_header) = self.read_header(offset) {
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

    fn read_header(&self, offset: usize) -> Option<CcEventHeader> {
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
        //assert_eq!(size_of::<TcgPcrEvent2Header>(), PCR_EVENT_HEADER_SIZE);
        assert_eq!(size_of::<Tdel>(), 56);
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
    fn test_tcg_pcr_event2_header() {
        let hdr = TcgPcrEvent2Header {
            pcr_index: 0,
            event_type: 0,
            digest: TpmlDigestValues {
                count: 0,
                digests: Default::default(),
            },
            event_size: 0,
        };
        let mut buf = [0u8; PCR_EVENT_HEADER_SIZE];
        buf.pwrite(&hdr, 0).unwrap();
    }
}

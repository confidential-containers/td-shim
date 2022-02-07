// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{convert::TryInto, mem::size_of};

use ring::digest;
use scroll::{ctx, Endian, Pread, Pwrite};
use zerocopy::{AsBytes, FromBytes};

use crate::acpi::{calculate_checksum, GenericSdtHeader};

const SHA384_DIGEST_SIZE: usize = 48;
const TPM_ALG_SHA384: u16 = 0xc;
// sizeof::<TpmtHa>() * PCR_DIGEST_NUM + sizeof::<u32>()
const TPML_DIGEST_VALUES_PACKED_SIZE: usize = 54;
const PCR_DIGEST_NUM: usize = 1;
const PCR_EVENT_HEADER_SIZE: usize = 66;

#[derive(Debug)]
struct TpmuHa {
    sha384: [u8; SHA384_DIGEST_SIZE],
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

    fn try_from_ctx(src: &'a [u8], endian: Endian) -> Result<(Self, usize), Self::Error> {
        let mut sha384: [u8; SHA384_DIGEST_SIZE] = [0; SHA384_DIGEST_SIZE];
        sha384.copy_from_slice(&src[0..SHA384_DIGEST_SIZE]);
        Ok((TpmuHa { sha384 }, sha384.len()))
    }
}

impl ctx::TryIntoCtx<Endian> for &TpmuHa {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], endian: Endian) -> Result<usize, Self::Error> {
        if this.len() < SHA384_DIGEST_SIZE {
            return Err(scroll::Error::BadOffset(SHA384_DIGEST_SIZE));
        }

        this[0..SHA384_DIGEST_SIZE].copy_from_slice(&self.sha384);
        Ok(SHA384_DIGEST_SIZE)
    }
}

#[repr(C)]
#[derive(Default, Pread, Pwrite)]
struct TpmtHa {
    hash_alg: u16,
    digest: TpmuHa,
}

struct TpmlDigestValues {
    count: u32,
    digests: [TpmtHa; PCR_DIGEST_NUM],
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
        this.gwrite_with::<u32>(self.count, offset, endian);
        for index in 0..PCR_DIGEST_NUM {
            this.gwrite_with::<&TpmtHa>(&self.digests[index], offset, endian)?;
        }

        Ok(*offset)
    }
}

#[repr(C)]
#[derive(Pread, Pwrite)]
struct TcgPcrEvent2Header {
    pcr_index: u32,
    event_type: u32,
    digest: TpmlDigestValues,
    event_size: u32,
}

#[repr(C, packed)]
#[derive(Default, AsBytes, FromBytes)]
pub struct Tdel {
    header: GenericSdtHeader,
    reserved: u32,
    laml: u64,
    lasa: u64,
}

impl Tdel {
    pub fn new(laml: u64, lasa: u64) -> Tdel {
        let mut tdel = Tdel {
            header: GenericSdtHeader::new(b"TDEL", size_of::<Tdel>() as u32, 1),
            laml,
            lasa,
            ..Default::default()
        };
        tdel.checksum();
        tdel
    }

    pub fn checksum(&mut self) {
        self.header.checksum = 0;
        self.header.checksum(calculate_checksum(self.as_bytes()));
    }
}

pub struct TdEventLog {
    area: &'static mut [u8],
    format: i32,
    lasa: u64,
    laml: usize,
    size: usize,
    last: u64,
    started: bool,
    truncated: bool,
}

impl TdEventLog {
    pub fn create_tdel(&self) -> Tdel {
        Tdel::new(self.laml as u64, self.lasa as u64)
    }

    pub fn new(td_event_mem: &'static mut [u8]) -> TdEventLog {
        let laml = td_event_mem.len();

        TdEventLog {
            area: td_event_mem,
            format: 0x02,
            lasa: 0,
            laml,
            size: 0,
            last: 0,
            started: false,
            truncated: false,
        }
    }

    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<,,
    pub fn create_event_log(
        &mut self,
        pcr_index: u32,
        event_type: u32,
        event_data: &[u8],
        hash_data: &[u8],
    ) {
        log::info!("calc td_hob digest ...\n");

        let event_data_size = event_data.len();
        let hash_value = digest::digest(&digest::SHA384, hash_data);
        let hash_value = hash_value.as_ref();
        assert_eq!(hash_value.len(), SHA384_DIGEST_SIZE);
        // Safe to unwrap() because we have checked the size.
        let hash384_value: [u8; SHA384_DIGEST_SIZE] = hash_value.try_into().unwrap();

        crate::td::extend_rtmr(&hash384_value, pcr_index);

        let event2_header = TcgPcrEvent2Header {
            pcr_index,
            event_type,
            digest: TpmlDigestValues {
                count: 1,
                digests: [TpmtHa {
                    hash_alg: TPM_ALG_SHA384,
                    digest: TpmuHa {
                        sha384: hash384_value,
                    },
                }],
            },
            event_size: event_data_size as u32,
        };
        let new_log_size = PCR_EVENT_HEADER_SIZE + event2_header.event_size as usize;
        if self.size + new_log_size > self.laml {
            return;
        }

        self.write_header(&event2_header, self.size);
        self.write_data(event_data, self.size + PCR_EVENT_HEADER_SIZE);

        self.last = self.lasa + self.size as u64;
        self.size += new_log_size;
    }

    #[allow(unused)]
    pub fn dump_event_log(&self) {
        let mut offset = 0;

        while offset < self.size as usize {
            if let Some(td_event_header) = self.read_header(offset) {
                offset += PCR_EVENT_HEADER_SIZE;
                let td_event_size = td_event_header.event_size as usize;
                if td_event_size + offset <= self.area.len() {
                    let td_event_data = &self.area[offset..offset + td_event_size];
                    dump_event(&td_event_header, td_event_data);
                }
                offset.saturating_add(td_event_size);
            } else {
                break;
            }
        }
    }

    fn read_header(&self, offset: usize) -> Option<TcgPcrEvent2Header> {
        if let Ok(v) = self.area.pread::<TcgPcrEvent2Header>(offset) {
            Some(v)
        } else {
            None
        }
    }

    fn write_header(&mut self, header: &TcgPcrEvent2Header, offset: usize) {
        let _ = self.area.pwrite(header, offset);
    }

    fn write_data(&mut self, data: &[u8], offset: usize) {
        self.area[offset..offset + data.len()].copy_from_slice(data);
    }
}

fn dump_event(td_event_header: &TcgPcrEvent2Header, td_event_data: &[u8]) {
    let pcr_index = td_event_header.pcr_index;
    let event_type = td_event_header.event_type;
    let event_size = td_event_header.event_size;

    log::info!("TD Event:\n");
    log::info!("    PcrIndex  - {}\n", pcr_index);
    log::info!("    EventType - 0x{:x}\n", event_type);

    for i in 0..td_event_header.digest.count {
        let hash_alg = td_event_header.digest.digests[i as usize].hash_alg;
        log::info!("      HashAlgo : 0x{:x}\n", hash_alg);
        log::info!(
            "      Digest({}): {:x?}\n",
            i,
            td_event_header.digest.digests[i as usize].digest
        );
    }

    log::info!("    EventSize - 0x{:x}\n", event_size);
    log::info!("\n");
}
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::slice_from_raw_parts_mut;

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

    #[test]
    fn test_create_event_log() {
        let mut buf = [0u8; 128];
        let slice = unsafe { &mut *slice_from_raw_parts_mut(buf.as_mut_ptr(), buf.len()) };
        let mut logger = TdEventLog::new(slice);
        let tdel = logger.create_tdel();
        assert_eq!(tdel.laml as u64, 128);
        assert_eq!(tdel.lasa as u64, 0);

        logger.create_event_log(1, 2, &[0u8], &[08u8]);
    }
}

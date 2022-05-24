// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;
use scroll::{Pread, Pwrite};
use td_shim::event_log::{
    CcEventHeader, Ccel, TpmlDigestValues, TpmtHa, TpmuHa, CCEL_CC_TYPE_TDX, CC_EVENT_HEADER_SIZE,
    SHA384_DIGEST_SIZE, TPML_ALG_SHA384,
};

#[allow(unused)]
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

    pub fn create_ccel(&self) -> Ccel {
        Ccel::new(
            CCEL_CC_TYPE_TDX,
            0,
            self.laml as u64,
            self.area.as_ptr() as u64,
        )
    }

    pub fn create_event_log(
        &mut self,
        mr_index: u32,
        event_type: u32,
        event_data: &[u8],
        hash_data: &[u8],
    ) {
        let event_data_size = event_data.len();
        let hash_value = ring::digest::digest(&ring::digest::SHA384, hash_data);
        let hash_value = hash_value.as_ref();
        assert_eq!(hash_value.len(), SHA384_DIGEST_SIZE);
        // Safe to unwrap() because we have checked the size.
        let hash384_value: [u8; SHA384_DIGEST_SIZE] = hash_value.try_into().unwrap();

        crate::td::extend_rtmr(&hash384_value, mr_index);

        let event2_header = CcEventHeader {
            mr_index,
            event_type,
            digest: TpmlDigestValues {
                count: 1,
                digests: [TpmtHa {
                    hash_alg: TPML_ALG_SHA384,
                    digest: TpmuHa {
                        sha384: hash384_value,
                    },
                }],
            },
            event_size: event_data_size as u32,
        };
        let new_log_size = CC_EVENT_HEADER_SIZE + event2_header.event_size as usize;
        if self.size + new_log_size > self.laml {
            return;
        }

        self.write_header(&event2_header, self.size);
        self.write_data(event_data, self.size + CC_EVENT_HEADER_SIZE);

        self.last = self.lasa + self.size as u64;
        self.size += new_log_size;
    }

    fn write_header(&mut self, header: &CcEventHeader, offset: usize) {
        let _ = self.area.pwrite(header, offset);
    }

    fn write_data(&mut self, data: &[u8], offset: usize) {
        self.area[offset..offset + data.len()].copy_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_event_log() {
        let mut buf = [0u8; 128];
        let slice =
            unsafe { &mut *core::ptr::slice_from_raw_parts_mut(buf.as_mut_ptr(), buf.len()) };
        let mut logger = TdEventLog::new(slice);
        let ccel = logger.create_ccel();
        assert_eq!(ccel.laml as u64, 128);
        assert_eq!(ccel.lasa as u64, 0);

        logger.create_event_log(1, 2, &[0u8], &[08u8]);
    }
}

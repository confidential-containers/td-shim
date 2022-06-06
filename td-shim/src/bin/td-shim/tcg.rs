// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::convert::TryInto;
use core::mem::size_of;
use scroll::{Pread, Pwrite};
use td_shim::event_log::{
    CcEventHeader, Ccel, TcgEfiSpecIdevent, TdShimPlatformConfigInfoHeader, TpmlDigestValues,
    TpmtHa, TpmuHa, CCEL_CC_TYPE_TDX, CC_EVENT_HEADER_SIZE, EV_NO_ACTION, EV_PLATFORM_CONFIG_FLAGS,
    EV_SEPARATOR, SHA384_DIGEST_SIZE, TPML_ALG_SHA384,
};

#[derive(Debug)]
pub enum TdEventLogError {
    OutOfResource,
    InvalidParameter,
}

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
    ) -> Result<(), TdEventLogError> {
        let sha384 = Self::calculate_digest_and_extend(hash_data, mr_index);
        let event_size = event_data.len();

        self.log_event(mr_index, event_type, event_data, &sha384)
    }

    pub fn create_event_log_platform_config(
        &mut self,
        mr_index: u32,
        descriptor: &[u8],
        info: &[u8],
    ) -> Result<(), TdEventLogError> {
        let sha384 = Self::calculate_digest_and_extend(info, mr_index);
        let event_size = info.len() + size_of::<TdShimPlatformConfigInfoHeader>();

        // Write the event header into event log memory and update the 'size' and 'last'
        let event_offset = self
            .log_header(
                mr_index,
                EV_PLATFORM_CONFIG_FLAGS,
                &sha384,
                event_size as u32,
            )
            .ok_or(TdEventLogError::OutOfResource)?;

        // Write the platform config info header into event log
        let config = TdShimPlatformConfigInfoHeader::new(descriptor, info.len() as u32)
            .ok_or(TdEventLogError::InvalidParameter)?;
        self.write_data(config.as_bytes(), event_offset + CC_EVENT_HEADER_SIZE);

        // Fill the config info data into event log
        self.write_data(
            info,
            event_offset + CC_EVENT_HEADER_SIZE + size_of::<TdShimPlatformConfigInfoHeader>(),
        );

        self.update_offset(event_size + CC_EVENT_HEADER_SIZE);

        Ok(())
    }

    pub fn create_seperator(&mut self) -> Result<(), TdEventLogError> {
        let separator = u32::to_le_bytes(0);

        // Measure 0x0000_0000 into RTMR[0] and RTMR[1]
        let _ = Self::calculate_digest_and_extend(&separator, 1);
        let sha384 = Self::calculate_digest_and_extend(&separator, 2);

        self.log_event(1, EV_SEPARATOR, &separator, &sha384)?;
        self.log_event(2, EV_SEPARATOR, &separator, &sha384)
    }

    fn calculate_digest_and_extend(hash_data: &[u8], mr_index: u32) -> [u8; SHA384_DIGEST_SIZE] {
        let hash_value = ring::digest::digest(&ring::digest::SHA384, hash_data);
        let hash_value = hash_value.as_ref();
        assert_eq!(hash_value.len(), SHA384_DIGEST_SIZE);
        // Safe to unwrap() because we have checked the size.
        let hash384_value: [u8; SHA384_DIGEST_SIZE] = hash_value.try_into().unwrap();

        // Extend the digest to the RTMR
        crate::td::extend_rtmr(&hash384_value, mr_index);

        hash384_value
    }

    fn log_event(
        &mut self,
        mr_index: u32,
        event_type: u32,
        event_data: &[u8],
        sha384: &[u8; 48],
    ) -> Result<(), TdEventLogError> {
        // Write the event header into event log memory and update the 'size' and 'last'
        let event_offset = self
            .log_header(mr_index, event_type, &sha384, event_data.len() as u32)
            .ok_or(TdEventLogError::OutOfResource)?;

        // Fill the event data into event log
        self.write_data(event_data, event_offset + CC_EVENT_HEADER_SIZE);

        self.update_offset(CC_EVENT_HEADER_SIZE + event_data.len());

        Ok(())
    }

    fn log_header(
        &mut self,
        mr_index: u32,
        event_type: u32,
        digest: &[u8; SHA384_DIGEST_SIZE],
        event_size: u32,
    ) -> Option<usize> {
        if self.size + event_size as usize + CC_EVENT_HEADER_SIZE > self.laml {
            return None;
        }

        let event2_header = CcEventHeader {
            mr_index,
            event_type,
            digest: TpmlDigestValues {
                count: 1,
                digests: [TpmtHa {
                    hash_alg: TPML_ALG_SHA384,
                    digest: TpmuHa { sha384: *digest },
                }],
            },
            event_size,
        };

        let _ = self.area.pwrite(event2_header, self.size);

        Some(self.size)
    }

    fn write_data(&mut self, data: &[u8], offset: usize) {
        self.area[offset..offset + data.len()].copy_from_slice(data);
    }

    fn update_offset(&mut self, new_log_size: usize) {
        self.last = self.lasa + self.size as u64;
        self.size += new_log_size;
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

// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use alloc::boxed::Box;
use core::mem::size_of;

type Result<T> = core::result::Result<T, CcEventLogError>;

#[derive(Debug)]
pub enum CcEventLogError {
    InvalidParameter,
    OutOfResource,
    InvalidMrIndex(u32),
    ExtendMr,
}

#[allow(unused)]
pub struct CcEventLogWriter<'a> {
    area: &'a mut [u8],
    offset: usize,
    last: usize,
    extender: Box<dyn Fn(&[u8; SHA384_DIGEST_SIZE], u32) -> Result<()>>,
}

impl<'a> CcEventLogWriter<'a> {
    pub fn new(
        area: &mut [u8],
        extender: Box<dyn Fn(&[u8; SHA384_DIGEST_SIZE], u32) -> Result<()>>,
    ) -> Result<CcEventLogWriter> {
        let mut cc_event_log = CcEventLogWriter {
            area,
            offset: 0,
            last: 0,
            extender,
        };

        // Create the TCG_EfiSpecIDEvent as the first event
        let first = TcgEfiSpecIdevent::default();
        cc_event_log.log_pcr_event(0, EV_NO_ACTION, first.as_bytes())?;

        Ok(cc_event_log)
    }

    pub fn create_event_log(
        &mut self,
        mr_index: u32,
        event_type: u32,
        event_data: &[&[u8]],
        hash_data: &[u8],
    ) -> Result<()> {
        let sha384 = self.calculate_digest_and_extend(hash_data, mr_index)?;

        self.log_cc_event(mr_index, event_type, event_data, &sha384)
    }

    pub fn create_seperator(&mut self) -> Result<()> {
        let separator = u32::to_le_bytes(0);

        // Measure 0x0000_0000 into RTMR[0] and RTMR[1]
        let _ = self.calculate_digest_and_extend(&separator, 1)?;
        let sha384 = self.calculate_digest_and_extend(&separator, 2)?;

        self.log_cc_event(1, EV_SEPARATOR, &[&separator], &sha384)?;
        self.log_cc_event(2, EV_SEPARATOR, &[&separator], &sha384)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.area[..self.offset]
    }

    fn log_pcr_event(
        &mut self,
        mr_index: u32,
        event_type: u32,
        event_data: &[u8],
    ) -> Result<usize> {
        let event_size = size_of::<TcgPcrEventHeader>()
            .checked_add(event_data.len())
            .ok_or(CcEventLogError::InvalidParameter)?;

        if self
            .offset
            .checked_add(event_size)
            .ok_or(CcEventLogError::InvalidParameter)?
            > self.area.len()
        {
            return Err(CcEventLogError::OutOfResource);
        }

        let pcr_header = TcgPcrEventHeader {
            mr_index,
            event_type,
            digest: [0u8; 20],
            event_size: event_data.len() as u32,
        };

        let data_offset = self.offset + size_of::<TcgPcrEventHeader>();
        self.area[self.offset..data_offset].copy_from_slice(pcr_header.as_bytes());
        self.write_data(event_data, data_offset);
        self.update_offset(size_of::<TcgPcrEventHeader>() + event_data.len());

        Ok(self.offset)
    }

    fn log_cc_event(
        &mut self,
        mr_index: u32,
        event_type: u32,
        event_data: &[&[u8]],
        sha384: &[u8; 48],
    ) -> Result<()> {
        let event_data_size: usize = event_data.iter().map(|&data| data.len()).sum();
        let event_size = size_of::<CcEventHeader>()
            .checked_add(event_data_size)
            .ok_or(CcEventLogError::InvalidParameter)?;

        if self
            .offset
            .checked_add(event_size)
            .ok_or(CcEventLogError::InvalidParameter)?
            > self.area.len()
        {
            return Err(CcEventLogError::OutOfResource);
        }

        // Write the event header into event log memory and update the 'size' and 'last'
        let event_offset = self
            .log_cc_event_header(mr_index, event_type, sha384, event_data_size as u32)
            .ok_or(CcEventLogError::OutOfResource)?;

        let mut data_offset = size_of::<CcEventHeader>();
        // Fill the event data into event log
        for &data in event_data {
            self.write_data(
                data,
                event_offset
                    .checked_add(data_offset)
                    .ok_or(CcEventLogError::OutOfResource)?,
            );
            data_offset += data.len()
        }

        self.update_offset(event_size);

        Ok(())
    }

    fn log_cc_event_header(
        &mut self,
        mr_index: u32,
        event_type: u32,
        digest: &[u8; SHA384_DIGEST_SIZE],
        event_size: u32,
    ) -> Option<usize> {
        let event_header = CcEventHeader {
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

        self.area[self.offset..self.offset + size_of::<CcEventHeader>()]
            .copy_from_slice(event_header.as_bytes());

        Some(self.offset)
    }

    fn write_data(&mut self, data: &[u8], offset: usize) {
        self.area[offset..offset + data.len()].copy_from_slice(data);
    }

    fn update_offset(&mut self, new_log_size: usize) {
        self.last = self.offset;
        self.offset += new_log_size;
    }

    fn calculate_digest_and_extend(
        &self,
        hash_data: &[u8],
        mr_index: u32,
    ) -> Result<[u8; SHA384_DIGEST_SIZE]> {
        let mut digest_sha384 = [0u8; SHA384_DIGEST_SIZE];

        Self::hash_sha384(hash_data, &mut digest_sha384);

        // Extend the digest to the RTMR
        (self.extender)(&digest_sha384, mr_index)?;

        Ok(digest_sha384)
    }

    #[cfg(feature = "ring")]
    fn hash_sha384(hash_data: &[u8], digest_sha384: &mut [u8; SHA384_DIGEST_SIZE]) {
        let digest = ring::digest::digest(&ring::digest::SHA384, hash_data);
        let digest = digest.as_ref();
        assert_eq!(digest.len(), SHA384_DIGEST_SIZE);

        digest_sha384.clone_from_slice(digest);
    }

    #[cfg(all(not(feature = "ring"), feature = "sha2"))]
    fn hash_sha384(hash_data: &[u8], digest_sha384: &mut [u8; SHA384_DIGEST_SIZE]) {
        use sha2::{Digest, Sha384};

        let mut digest = Sha384::new();
        digest.update(hash_data);
        let digest = digest.finalize();
        assert_eq!(digest.as_slice().len(), SHA384_DIGEST_SIZE);

        digest_sha384.clone_from_slice(digest.as_slice());
    }
}

#[derive(Clone, Copy)]
pub struct CcEvents<'a> {
    pub bytes: &'a [u8],
}

type EventData<'a> = &'a [u8];

impl<'a> Iterator for CcEvents<'a> {
    type Item = (CcEventHeader, EventData<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() < size_of::<CcEventHeader>() {
            return None;
        }

        let event_header = CcEventHeader::read_from(&self.bytes[..size_of::<CcEventHeader>()])?;
        if event_header.event_size == 0 {
            return None;
        }

        let end_of_event = size_of::<CcEventHeader>() + event_header.event_size as usize;
        if end_of_event < self.bytes.len() {
            let event_data = &self.bytes[size_of::<CcEventHeader>()..end_of_event];
            self.bytes = &self.bytes[end_of_event..];
            Some((event_header, event_data))
        } else {
            None
        }
    }
}

pub struct CcEventLogReader<'a> {
    pub pcr_event_header: TcgPcrEventHeader,
    pub specific_id_event: TcgEfiSpecIdevent,
    pub cc_events: CcEvents<'a>,
}

impl<'a> CcEventLogReader<'a> {
    pub fn new(bytes: &[u8]) -> Option<CcEventLogReader> {
        let specific_id_event_size =
            size_of::<TcgPcrEventHeader>() + size_of::<TcgEfiSpecIdevent>();
        if bytes.len() < specific_id_event_size {
            return None;
        }

        // TCG_EfiSpecIDEvent should be the first event
        let pcr_event_header =
            TcgPcrEventHeader::read_from(&bytes[..size_of::<TcgPcrEventHeader>()])?;
        let specific_id_event = TcgEfiSpecIdevent::read_from(
            &bytes[size_of::<TcgPcrEventHeader>()..specific_id_event_size],
        )?;
        let cc_event_log = CcEventLogReader {
            cc_events: CcEvents {
                bytes: &bytes[specific_id_event_size..],
            },
            pcr_event_header,
            specific_id_event,
        };

        Some(cc_event_log)
    }

    pub fn query(&self, key: &[u8]) -> Option<CcEventHeader> {
        for (header, data) in self.cc_events {
            if data.len() < key.len() {
                return None;
            }
            if &data[..key.len()] == key {
                return Some(header);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use alloc::{boxed::Box, vec};

    use crate::{
        log::CcEventLogReader, CcEventHeader, TcgEfiSpecIdevent, TcgPcrEventHeader, EV_SEPARATOR,
        SHA384_DIGEST_SIZE,
    };

    use super::{CcEventLogWriter, Result};

    fn extender(_digest: &[u8; SHA384_DIGEST_SIZE], _mr_index: u32) -> Result<()> {
        // Do nothing
        Ok(())
    }

    #[test]
    fn test_cc_eventlog_writter_new() {
        let mut event_log =
            vec![0u8; size_of::<TcgPcrEventHeader>() + size_of::<TcgEfiSpecIdevent>()];
        let _ = CcEventLogWriter::new(&mut event_log, Box::new(extender)).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_cc_eventlog_writter_new_with_small_buf() {
        let mut event_log =
            vec![0u8; size_of::<TcgPcrEventHeader>() + size_of::<TcgEfiSpecIdevent>() - 1];
        let _ = CcEventLogWriter::new(&mut event_log, Box::new(extender)).unwrap();
    }

    #[test]
    fn test_cc_eventlog_writter() {
        let mut event_log = vec![0u8; 0x1000];

        let mut writter = CcEventLogWriter::new(&mut event_log, Box::new(extender)).unwrap();
        let first_event_size = size_of::<TcgPcrEventHeader>() + size_of::<TcgEfiSpecIdevent>();
        assert_eq!(writter.as_slice().len(), first_event_size);

        writter
            .create_event_log(2, 3, &[b"event1:", b"012"], &[0, 1, 2])
            .unwrap();
        let second_event_size = size_of::<CcEventHeader>() + 10;
        assert_eq!(
            writter.as_slice().len(),
            first_event_size + second_event_size
        );

        writter.create_seperator().unwrap();
        let seperator_size = (size_of::<CcEventHeader>() + size_of::<u32>()) * 2;
        assert_eq!(
            writter.as_slice().len(),
            first_event_size + second_event_size + seperator_size
        );

        assert_eq!(
            &event_log[first_event_size..first_event_size + second_event_size],
            &[
                0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0xc, 0x0, 0x4f, 0x89,
                0x58, 0x54, 0xc1, 0xa4, 0xfc, 0x5a, 0xa2, 0xe0, 0x45, 0x6e, 0xaf, 0x8d, 0xe, 0xca,
                0xa7, 0xc, 0x19, 0x6b, 0xd9, 0x1, 0x15, 0x38, 0x61, 0xd7, 0x6b, 0x8f, 0xa3, 0xcd,
                0x95, 0xce, 0xea, 0x29, 0xea, 0xb6, 0xa2, 0x79, 0xf8, 0xb0, 0x84, 0x37, 0x70, 0x3c,
                0xe0, 0xb4, 0xb9, 0x1a, 0xa, 0x0, 0x0, 0x0, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x31,
                0x3a, 0x30, 0x31, 0x32
            ]
        );
    }

    #[test]
    fn test_eventlog_reader_new() {
        let mut event_log =
            vec![0u8; size_of::<TcgPcrEventHeader>() + size_of::<TcgEfiSpecIdevent>()];
        let reader = CcEventLogReader::new(&mut event_log).unwrap();
        assert_eq!(reader.cc_events.bytes.len(), 0)
    }

    #[test]
    #[should_panic]
    fn test_eventlog_reader_new_with_small_buf() {
        let mut event_log =
            vec![0u8; size_of::<TcgPcrEventHeader>() + size_of::<TcgEfiSpecIdevent>() - 1];
        let _ = CcEventLogReader::new(&mut event_log).unwrap();
    }

    #[test]
    fn test_cc_events_iterator() {
        let mut event_log = vec![0u8; 0x1000];

        let mut writter = CcEventLogWriter::new(&mut event_log, Box::new(extender)).unwrap();

        writter
            .create_event_log(2, 3, &[b"event1:", b"012"], &[0, 1, 2])
            .unwrap();

        writter.create_seperator().unwrap();

        let reader = CcEventLogReader::new(&mut event_log).unwrap();

        for (idx, (event_header, event_data)) in reader.cc_events.enumerate() {
            let event_type = event_header.event_type;
            if idx == 0 {
                assert_eq!(event_type, 3);
                assert_eq!(event_data, b"event1:012");
            } else if idx == 1 {
                assert_eq!(event_type, EV_SEPARATOR);
                assert_eq!(event_data, &[0u8; 4]);
            }
        }
    }

    #[test]
    fn test_cc_event_log_reader_query() {
        let mut event_log = vec![0u8; 0x1000];

        let mut writter = CcEventLogWriter::new(&mut event_log, Box::new(extender)).unwrap();

        writter
            .create_event_log(2, 3, &[b"event1:", b"012"], &[0, 1, 2])
            .unwrap();

        writter.create_seperator().unwrap();

        let reader = CcEventLogReader::new(&mut event_log).unwrap();

        assert!(reader.query(b"event1:012").is_some());
    }
}

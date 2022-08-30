// Copyright (c) 2020 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use cc_measurement::{
    log::{CcEventLogError, CcEventLogWriter},
    UefiPlatformFirmwareBlob2, EV_EFI_PLATFORM_FIRMWARE_BLOB2, EV_PLATFORM_CONFIG_FLAGS,
};
use core::{mem::size_of, ptr::slice_from_raw_parts};

pub const CCEL_CC_TYPE_TDX: u8 = 2;

pub const PLATFORM_CONFIG_HOB: &[u8] = b"td_hob\0";
pub const PLATFORM_CONFIG_PAYLOAD_PARAMETER: &[u8] = b"td_payload_info\0";
pub const PLATFORM_CONFIG_SECURE_POLICY_DB: &[u8] = b"secure_policy_db";
pub const PLATFORM_CONFIG_SECURE_AUTHORITY: &[u8] = b"secure_authority";
pub const PLATFORM_CONFIG_SVN: &[u8] = b"td_payload_svn\0";
pub const PLATFORM_FIRMWARE_BLOB2_PAYLOAD: &[u8] = b"td_payload\0";

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

pub fn create_event_log_platform_config(
    event_log: &mut CcEventLogWriter,
    mr_index: u32,
    descriptor: &[u8],
    data: &[u8],
) -> Result<(), CcEventLogError> {
    // Write the `TdShimPlatformConfigInfoHeader + data` into event log
    let config_header = TdShimPlatformConfigInfoHeader::new(descriptor, data.len() as u32)
        .ok_or(CcEventLogError::InvalidParameter)?;

    event_log.create_event_log(
        mr_index,
        EV_PLATFORM_CONFIG_FLAGS,
        &[config_header.as_bytes(), data],
        data,
    )?;

    Ok(())
}

pub fn log_hob_list(hob_list: &[u8], cc_event_log: &mut CcEventLogWriter) {
    create_event_log_platform_config(cc_event_log, 1, PLATFORM_CONFIG_HOB, hob_list)
        .expect("Failed to log HOB list to the td event log");
}

pub fn log_payload_binary(payload: &[u8], cc_event_log: &mut CcEventLogWriter) {
    let blob2 = UefiPlatformFirmwareBlob2::new(
        PLATFORM_FIRMWARE_BLOB2_PAYLOAD,
        payload.as_ptr() as u64,
        payload.len() as u64,
    )
    .expect("Invalid payload binary information or descriptor");

    cc_event_log
        .create_event_log(
            2,
            EV_EFI_PLATFORM_FIRMWARE_BLOB2,
            &[blob2.as_bytes()],
            payload,
        )
        .expect("Failed to log HOB list to the td event log");
}

pub fn log_payload_parameter(payload_parameter: &[u8], cc_event_log: &mut CcEventLogWriter) {
    create_event_log_platform_config(
        cc_event_log,
        2,
        PLATFORM_CONFIG_PAYLOAD_PARAMETER,
        payload_parameter,
    )
    .expect("Failed to log HOB list to the td event log");
}

#[cfg(test)]
mod test {
    use super::TdShimPlatformConfigInfoHeader;
    use core::mem::size_of;

    #[test]
    fn test_struct_size() {
        assert_eq!(size_of::<TdShimPlatformConfigInfoHeader>(), 20);
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
}

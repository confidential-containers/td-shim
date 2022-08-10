// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::build_time::{
    TD_SHIM_CONFIG_BASE, TD_SHIM_CONFIG_SIZE, TD_SHIM_MAILBOX_BASE, TD_SHIM_MAILBOX_SIZE,
    TD_SHIM_PAYLOAD_BASE, TD_SHIM_PAYLOAD_SIZE,
};
use crate::runtime::{
    TD_HOB_BASE, TD_HOB_SIZE, TD_PAYLOAD_ACPI_SIZE, TD_PAYLOAD_BASE, TD_PAYLOAD_EVENT_LOG_SIZE,
    TD_PAYLOAD_MAILBOX_SIZE, TD_PAYLOAD_SIZE, TD_PAYLOAD_UNACCEPTED_MEMORY_BITMAP_SIZE,
};

/// Type of build time and runtime memory regions.
pub enum SliceType {
    /// The `VAR` regions in image file
    Config,
    /// The `TD_HOB` region in image file
    TdHob,
    /// The `Payload and Metadata` region in image file
    ShimPayload,
    /// The `TD_MAILBOX` region in image file
    MailBox,
    /// The `PAYLOAD` region in runtime memory layout
    Payload,
    /// The `TD_HOB` region in runtime memory layout
    PayloadHob,
    /// The 'Mailbox' region in runtime memory layout
    RelocatedMailbox,
    /// The `TD_EVENT_LOG` region in runtime memory layout
    EventLog,
    /// The `ACPI` region in runtime memory layout
    Acpi,
    /// The 'UNACCEPTED_BITMAP' region in runtime memory layout
    UnacceptedMemoryBitmap,
}

/// Get an immutable reference to a region.
///
/// These regions are read-only, so it's safe to return multiple immutable references.
pub fn get_mem_slice<'a>(t: SliceType) -> &'a [u8] {
    unsafe {
        match t {
            SliceType::Config => core::slice::from_raw_parts(
                TD_SHIM_CONFIG_BASE as *const u8,
                TD_SHIM_CONFIG_SIZE as usize,
            ),
            SliceType::ShimPayload => core::slice::from_raw_parts(
                TD_SHIM_PAYLOAD_BASE as *const u8,
                TD_SHIM_PAYLOAD_SIZE as usize,
            ),
            SliceType::TdHob => {
                core::slice::from_raw_parts(TD_HOB_BASE as *const u8, TD_HOB_SIZE as usize)
            }
            SliceType::Payload => {
                core::slice::from_raw_parts(TD_PAYLOAD_BASE as *const u8, TD_PAYLOAD_SIZE as usize)
            }
            _ => panic!("get_mem_slice: not support"),
        }
    }
}

/// Get mutable reference to a fixed memory region.
///
/// # Safety
///
/// This function may break rust ownership model potentially. So caller must take the responsibility
/// to ensure ownership and concurrent access to the underlying data.
pub unsafe fn get_mem_slice_mut<'a>(t: SliceType) -> &'a mut [u8] {
    match t {
        SliceType::TdHob => panic!("get_mem_slice_mut: read only"),
        SliceType::ShimPayload => panic!("get_mem_slice_mut: read only"),
        SliceType::Payload => core::slice::from_raw_parts_mut(
            TD_PAYLOAD_BASE as *const u8 as *mut u8,
            TD_PAYLOAD_SIZE as usize,
        ),
        SliceType::MailBox => core::slice::from_raw_parts_mut(
            TD_SHIM_MAILBOX_BASE as *const u8 as *mut u8,
            TD_SHIM_MAILBOX_SIZE as usize,
        ),
        _ => panic!("get_mem_slice_mut: not support"),
    }
}

/// Get mutable reference to a dynamic memory region.
///
/// # Safety
///
/// This function may break rust ownership model potentially. So caller must take the responsibility
/// to ensure ownership and concurrent access to the underlying data.
pub unsafe fn get_dynamic_mem_slice_mut<'a>(t: SliceType, base_address: usize) -> &'a mut [u8] {
    match t {
        SliceType::EventLog => core::slice::from_raw_parts_mut(
            base_address as *const u8 as *mut u8,
            TD_PAYLOAD_EVENT_LOG_SIZE as usize,
        ),
        SliceType::RelocatedMailbox => core::slice::from_raw_parts_mut(
            base_address as *const u8 as *mut u8,
            TD_PAYLOAD_MAILBOX_SIZE as usize,
        ),
        SliceType::Acpi | SliceType::PayloadHob => core::slice::from_raw_parts_mut(
            base_address as *const u8 as *mut u8,
            TD_PAYLOAD_ACPI_SIZE as usize,
        ),
        SliceType::UnacceptedMemoryBitmap => core::slice::from_raw_parts_mut(
            base_address as *const u8 as *mut u8,
            TD_PAYLOAD_UNACCEPTED_MEMORY_BITMAP_SIZE as usize,
        ),

        _ => panic!("get_dynamic_mem_slice_mut: not support"),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    const TEST_BASE_ADDRESS: usize = 0xF000_0000;

    #[test]
    fn test_get_mem_slice_with_type_config() {
        let config = get_mem_slice(SliceType::Config);
        assert_eq!(config.len(), TD_SHIM_CONFIG_SIZE as usize);
    }

    #[test]
    fn test_get_mem_slice_with_type_tdhob() {
        let hob_list = get_mem_slice(SliceType::TdHob);
        assert_eq!(hob_list.len(), TD_HOB_SIZE as usize);
    }

    #[test]
    fn test_get_mem_slice_with_type_shimpayload() {
        let payload = get_mem_slice(SliceType::ShimPayload);
        assert_eq!(payload.len(), TD_SHIM_PAYLOAD_SIZE as usize);
    }

    #[test]
    fn test_get_mem_slice_with_type_payload() {
        let payload = get_mem_slice(SliceType::Payload);
        assert_eq!(payload.len(), TD_PAYLOAD_SIZE as usize);
    }

    #[test]
    #[should_panic(expected = "get_mem_slice: not support")]
    fn test_get_mem_slice_with_type_payloadhob() {
        get_mem_slice(SliceType::PayloadHob);
    }

    #[test]
    #[should_panic(expected = "get_mem_slice: not support")]
    fn test_get_mem_slice_with_type_mailbox() {
        get_mem_slice(SliceType::MailBox);
    }

    #[test]
    #[should_panic(expected = "get_mem_slice: not support")]
    fn test_get_mem_slice_with_type_eventlog() {
        get_mem_slice(SliceType::EventLog);
    }

    #[test]
    #[should_panic(expected = "get_mem_slice: not support")]
    fn test_get_mem_slice_with_type_acpi() {
        get_mem_slice(SliceType::Acpi);
    }

    #[test]
    fn test_get_mem_slice_mut_with_type_payload() {
        let payload = unsafe { get_mem_slice_mut(SliceType::Payload) };
        assert_eq!(payload.len(), TD_PAYLOAD_SIZE as usize);
    }

    #[test]
    fn test_get_mem_slice_mut_with_type_mailbox() {
        let mailbox = unsafe { get_mem_slice_mut(SliceType::MailBox) };
        assert_eq!(mailbox.len(), TD_SHIM_MAILBOX_SIZE as usize);
    }

    #[test]
    #[should_panic(expected = "get_mem_slice_mut: read only")]
    fn test_get_mem_slice_mut_with_type_tdhob() {
        unsafe {
            get_mem_slice_mut(SliceType::TdHob);
        }
    }

    #[test]
    #[should_panic(expected = "get_mem_slice_mut: read only")]
    fn test_get_mem_slice_mut_with_type_shimpayload() {
        unsafe {
            get_mem_slice_mut(SliceType::ShimPayload);
        }
    }

    #[test]
    #[should_panic(expected = "get_mem_slice_mut: not support")]
    fn test_get_mem_slice_mut_with_type_config() {
        unsafe {
            get_mem_slice_mut(SliceType::Config);
        }
    }

    #[test]
    #[should_panic(expected = "get_mem_slice_mut: not support")]
    fn test_get_mem_slice_mut_with_type_payloadhob() {
        unsafe {
            get_mem_slice_mut(SliceType::PayloadHob);
        }
    }

    #[test]
    #[should_panic(expected = "get_mem_slice_mut: not support")]
    fn test_get_mem_slice_mut_with_type_eventlog() {
        unsafe {
            get_mem_slice_mut(SliceType::EventLog);
        }
    }

    #[test]
    #[should_panic(expected = "get_mem_slice_mut: not support")]
    fn test_get_mem_slice_mut_with_type_acpi() {
        unsafe {
            get_mem_slice_mut(SliceType::Acpi);
        }
    }

    #[test]
    fn test_get_dynamic_mem_slice_mut_with_type_eventlog() {
        let eventlog = unsafe { get_dynamic_mem_slice_mut(SliceType::EventLog, TEST_BASE_ADDRESS) };
        assert_eq!(eventlog.len(), TD_PAYLOAD_EVENT_LOG_SIZE as usize);
    }

    #[test]
    fn test_get_dynamic_mem_slice_mut_with_type_relocatemailbox() {
        let relocatemailbox =
            unsafe { get_dynamic_mem_slice_mut(SliceType::RelocatedMailbox, TEST_BASE_ADDRESS) };
        assert_eq!(relocatemailbox.len(), TD_PAYLOAD_MAILBOX_SIZE as usize);
    }

    #[test]
    fn test_get_dynamic_mem_slice_mut_with_type_acpi() {
        let acpi = unsafe { get_dynamic_mem_slice_mut(SliceType::Acpi, TEST_BASE_ADDRESS) };
        assert_eq!(acpi.len(), TD_PAYLOAD_ACPI_SIZE as usize);
    }

    #[test]
    fn test_get_dynamic_mem_slice_mut_with_type_unacceptedmemorybitmap() {
        let unacceptedmemorybitmap = unsafe {
            get_dynamic_mem_slice_mut(SliceType::UnacceptedMemoryBitmap, TEST_BASE_ADDRESS)
        };
        assert_eq!(
            unacceptedmemorybitmap.len(),
            TD_PAYLOAD_UNACCEPTED_MEMORY_BITMAP_SIZE as usize
        );
    }

    #[test]
    #[should_panic(expected = "get_dynamic_mem_slice_mut: not support")]
    fn test_get_dynamic_mem_slice_mut_with_type_config() {
        unsafe {
            get_dynamic_mem_slice_mut(SliceType::Config, TEST_BASE_ADDRESS);
        }
    }

    #[test]
    #[should_panic(expected = "get_dynamic_mem_slice_mut: not support")]
    fn test_get_dynamic_mem_slice_mut_with_type_tdhob() {
        unsafe {
            get_dynamic_mem_slice_mut(SliceType::TdHob, TEST_BASE_ADDRESS);
        }
    }

    #[test]
    #[should_panic(expected = "get_dynamic_mem_slice_mut: not support")]
    fn test_get_dynamic_mem_slice_mut_with_type_shimpayload() {
        unsafe {
            get_dynamic_mem_slice_mut(SliceType::ShimPayload, TEST_BASE_ADDRESS);
        }
    }

    #[test]
    #[should_panic(expected = "get_dynamic_mem_slice_mut: not support")]
    fn test_get_dynamic_mem_slice_mut_with_type_mailbox() {
        unsafe {
            get_dynamic_mem_slice_mut(SliceType::MailBox, TEST_BASE_ADDRESS);
        }
    }

    #[test]
    #[should_panic(expected = "get_dynamic_mem_slice_mut: not support")]
    fn test_get_dynamic_mem_slice_mut_with_type_payload() {
        unsafe {
            get_dynamic_mem_slice_mut(SliceType::Payload, TEST_BASE_ADDRESS);
        }
    }
}

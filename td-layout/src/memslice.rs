// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::build_time::{
    TD_SHIM_CONFIG_BASE, TD_SHIM_CONFIG_SIZE, TD_SHIM_HOB_BASE, TD_SHIM_HOB_SIZE,
    TD_SHIM_MAILBOX_BASE, TD_SHIM_MAILBOX_SIZE, TD_SHIM_PAYLOAD_BASE, TD_SHIM_PAYLOAD_SIZE,
};
use crate::runtime::{
    TD_PAYLOAD_ACPI_SIZE, TD_PAYLOAD_BASE, TD_PAYLOAD_EVENT_LOG_SIZE, TD_PAYLOAD_HOB_SIZE,
    TD_PAYLOAD_MAILBOX_SIZE, TD_PAYLOAD_SIZE,
};

/// Type of build time and runtime memory regions.
pub enum SliceType {
    /// The `VAR` regions in image file
    Config,
    /// The `TD_HOB` region in image file
    ShimHob,
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
            SliceType::ShimHob => core::slice::from_raw_parts(
                TD_SHIM_HOB_BASE as *const u8,
                TD_SHIM_HOB_SIZE as usize,
            ),
            SliceType::ShimPayload => core::slice::from_raw_parts(
                TD_SHIM_PAYLOAD_BASE as *const u8,
                TD_SHIM_PAYLOAD_SIZE as usize,
            ),
            SliceType::Payload => {
                core::slice::from_raw_parts(TD_PAYLOAD_BASE as *const u8, TD_PAYLOAD_SIZE)
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
        SliceType::ShimHob => panic!("get_mem_slice_mut: read only"),
        SliceType::ShimPayload => panic!("get_mem_slice_mut: read only"),
        SliceType::Payload => core::slice::from_raw_parts_mut(
            TD_PAYLOAD_BASE as *const u8 as *mut u8,
            TD_PAYLOAD_SIZE,
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
        SliceType::PayloadHob => core::slice::from_raw_parts_mut(
            base_address as *const u8 as *mut u8,
            TD_PAYLOAD_HOB_SIZE as usize,
        ),
        SliceType::EventLog => core::slice::from_raw_parts_mut(
            base_address as *const u8 as *mut u8,
            TD_PAYLOAD_EVENT_LOG_SIZE as usize,
        ),
        SliceType::RelocatedMailbox => core::slice::from_raw_parts_mut(
            base_address as *const u8 as *mut u8,
            TD_PAYLOAD_MAILBOX_SIZE as usize,
        ),
        SliceType::Acpi => core::slice::from_raw_parts_mut(
            base_address as *const u8 as *mut u8,
            TD_PAYLOAD_ACPI_SIZE as usize,
        ),

        _ => panic!("get_dynamic_mem_slice_mut: not support"),
    }
}

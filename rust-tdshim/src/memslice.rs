// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use td_layout::build_time::*;
use td_layout::runtime::*;

#[allow(dead_code)]
pub enum SliceType {
    Config,
    ShimHob,
    ShimPayload,
    MailBox,
    Payload,
    PayloadHob,
    EventLog,
    Acpi,
}
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
            _ => {
                panic!("not support")
            }
        }
    }
}

pub fn get_mem_slice_mut<'a>(t: SliceType) -> &'a mut [u8] {
    unsafe {
        match t {
            SliceType::ShimHob => {
                panic!("read only")
            }
            SliceType::ShimPayload => {
                panic!("read only")
            }
            SliceType::Payload => core::slice::from_raw_parts_mut(
                TD_PAYLOAD_BASE as *const u8 as *mut u8,
                TD_PAYLOAD_SIZE,
            ),
            SliceType::MailBox => core::slice::from_raw_parts_mut(
                TD_SHIM_MAILBOX_BASE as *const u8 as *mut u8,
                TD_SHIM_MAILBOX_SIZE as usize,
            ),
            _ => {
                panic!("not support")
            }
        }
    }
}

pub fn get_dynamic_mem_slice_mut<'a>(t: SliceType, base_address: usize) -> &'a mut [u8] {
    unsafe {
        match t {
            SliceType::PayloadHob => core::slice::from_raw_parts_mut(
                base_address as *const u8 as *mut u8,
                TD_PAYLOAD_HOB_SIZE as usize,
            ),
            SliceType::EventLog => core::slice::from_raw_parts_mut(
                base_address as *const u8 as *mut u8,
                TD_PAYLOAD_EVENT_LOG_SIZE as usize,
            ),
            SliceType::Acpi => core::slice::from_raw_parts_mut(
                base_address as *const u8 as *mut u8,
                TD_PAYLOAD_EVENT_LOG_SIZE as usize,
            ),
            _ => {
                panic!("not support")
            }
        }
    }
}

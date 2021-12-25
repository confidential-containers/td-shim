// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use rust_td_layout::build_time::*;
use rust_td_layout::runtime::*;

pub enum SliceType {
    ShimHob,
    ShimPayload,
    Payload,
    PayloadHob,
    EventLog,
}
pub fn get_mem_slice<'a>(t: SliceType) -> &'a [u8] {
    unsafe {
        match t {
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
            _ => {
                panic!("not support")
            }
        }
    }
}

// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub fn get_shared_page_mask() -> u64 {
    0
}

pub fn accept_memory_resource_range(_cpu_num: u32, _address: u64, _size: u64) {}

pub fn get_num_vcpus() -> u32 {
    1
}

pub fn extend_rtmr(_data: &[u8], _pcr_index: u32) {}

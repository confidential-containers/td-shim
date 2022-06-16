// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use tdx_tdcall::tdx;

extern "win64" {
    fn asm_read_msr64(index: u32) -> u64;
    fn asm_write_msr64(index: u32, value: u64) -> u64;
}

const EXTENDED_FUNCTION_INFO: u32 = 0x80000000;
const EXTENDED_PROCESSOR_INFO: u32 = 0x80000001;

const SHA384_DIGEST_SIZE: usize = 48;

pub fn get_shared_page_mask() -> u64 {
    tdx::td_shared_mask().expect("Unable to get GPAW")
}

pub fn accept_memory_resource_range(address: u64, size: u64) {
    let cpu_num = get_num_vcpus();
    super::tdx_mailbox::accept_memory_resource_range(cpu_num, address, size)
}

pub fn relocate_mailbox(address: u32) {
    super::tdx_mailbox::relocate_mailbox(address).expect("Unable to relocate mailbox");
}

pub fn get_num_vcpus() -> u32 {
    let td_info = tdx::tdcall_get_td_info().expect("Fail to get TDINFO");

    log::info!("gpaw - {:?}\n", td_info.gpaw);
    log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);

    td_info.num_vcpus
}

pub fn extend_rtmr(data: &[u8; SHA384_DIGEST_SIZE], mr_index: u32) {
    let digest = tdx::TdxDigest { data: *data };

    let rtmr_index = match mr_index {
        0 => {
            log::info!("MrIndex 0 should be extended vith RDMR\n");
            0xFF
        }
        1 | 2 | 3 | 4 => mr_index - 1,
        _ => {
            log::info!("invalid mr_index 0x{:x}\n", mr_index);
            0xFF
        }
    };

    if rtmr_index > 3 {
        return;
    }

    tdx::tdcall_extend_rtmr(&digest, rtmr_index);
}

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
    tdx_tdcall::tdx::td_shared_page_mask()
}

pub fn accept_memory_resource_range(mut cpu_num: u32, address: u64, size: u64) {
    super::tdx_mailbox::accept_memory_resource_range(cpu_num, address, size)
}

pub fn get_num_vcpus() -> u32 {
    let mut td_info = tdx::TdInfoReturnData {
        gpaw: 0,
        attributes: 0,
        max_vcpus: 0,
        num_vcpus: 0,
        rsvd: [0; 3],
    };

    tdx::tdcall_get_td_info(&mut td_info);
    log::info!("gpaw - {:?}\n", td_info.gpaw);
    log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);

    td_info.num_vcpus
}

pub fn extend_rtmr(data: &[u8; SHA384_DIGEST_SIZE], pcr_index: u32) {
    let digest = tdx::TdxDigest { data: *data };

    log::info!("extend_rtmr ...\n");
    let mr_index = match pcr_index {
        0 => {
            log::info!("PCR[0] should be extended vith RDMR\n");
            0xFF
        }
        1 | 7 => 0,
        2..=6 => 1,
        8..=15 => 2,
        _ => {
            log::info!("invalid pcr_index 0x{:x}\n", pcr_index);
            0xFF
        }
    };
    if mr_index >= 3 {
        return;
    }

    tdx::tdcall_extend_rtmr(&digest, mr_index);
}

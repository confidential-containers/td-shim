// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use cc_measurement::log::CcEventLogError;
use td_exception::idt::DescriptorTablePointer;
use tdx_tdcall::tdx;

pub use super::tdx_mailbox::ap_set_payload;

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

pub fn relocate_mailbox(new_mailbox: &mut [u8]) {
    super::tdx_mailbox::relocate_mailbox(new_mailbox).expect("Unable to relocate mailbox");
}

pub fn relocate_ap_page_table(page_table_base: u64) {
    super::tdx_mailbox::relocate_page_table(get_num_vcpus(), page_table_base);
}

pub fn set_idt(idt_ptr: &DescriptorTablePointer) {
    super::tdx_mailbox::set_idt(get_num_vcpus(), idt_ptr);
}

pub fn get_num_vcpus() -> u32 {
    let td_info = tdx::tdcall_get_td_info().expect("Fail to get TDINFO");

    log::info!("gpaw - {:?}\n", td_info.gpaw);
    log::info!("num_vcpus - {:?}\n", td_info.num_vcpus);

    td_info.num_vcpus
}

pub fn extend_rtmr(data: &[u8; SHA384_DIGEST_SIZE], mr_index: u32) -> Result<(), CcEventLogError> {
    let digest = tdx::TdxDigest { data: *data };

    let rtmr_index = match mr_index {
        1 | 2 | 3 | 4 => mr_index - 1,
        e => return Err(CcEventLogError::InvalidMrIndex(e)),
    };

    tdx::tdcall_extend_rtmr(&digest, rtmr_index).map_err(|_| CcEventLogError::ExtendMr)
}

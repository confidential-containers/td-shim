// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern "win64" {
    fn asm_read_msr64(index: u32) -> u64;
    fn asm_write_msr64(index: u32, value: u64) -> u64;
}

const EXTENDED_FUNCTION_INFO: u32 = 0x80000000;
const EXTENDED_PROCESSOR_INFO: u32 = 0x80000001;

fn is_execute_disable_bit_available() -> bool {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(EXTENDED_FUNCTION_INFO) };

    if cpuid.eax >= EXTENDED_PROCESSOR_INFO {
        let cpuid = unsafe { core::arch::x86_64::__cpuid(EXTENDED_PROCESSOR_INFO) };
        if (cpuid.edx & 0x00100000) != 0 {
            // Bit 20: Execute Disable Bit available.
            return true;
        }
    }

    false
}

//  Enable Execute Disable Bit.
fn enable_execute_disable_bit() {
    let mut msr: u64;

    unsafe { msr = asm_read_msr64(0xC0000080) };
    msr |= 0x800;
    unsafe { asm_write_msr64(0xC0000080, msr) };
}

/// Enable the execute disable.
pub fn enable_execution_disable_bit() {
    // For now EFER cannot be set in TDX, but the NX is enabled by default.
    if false && is_execute_disable_bit_available() {
        enable_execute_disable_bit();
    }
}

pub fn get_shared_page_mask() -> u64 {
    tdx_tdcall::tdx::td_shared_page_mask()
}

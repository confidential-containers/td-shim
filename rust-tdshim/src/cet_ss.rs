// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::registers::control::Cr4;

const CPUID_EXTEND_FEATURES: u32 = 0x7;
const CPUID_CET_SS_BIT: u32 = 1 << 7;
const CPUID_CET_IBT: u32 = 1 << 20;
const CPUID_CET_XSS_U: u32 = 1 << 11;
const CPUID_CET_XSS_S: u32 = 1 << 12;

const MSR_IA32_S_CET: u32 = 0x6A2;
const MSR_IA32_PL0_SSP: u32 = 0x6A4;
const MSR_IA32_INTERRUPT_SSP_TABLE_ADDR: u32 = 0x6A8;
const MSR_IA32_XSS: u32 = 0xDA0;

const EXCEPTION_PAGE_SIZE: u64 = 0x1000;
const GUARD_PAGE_SIZE: u64 = 0x1000;

const CR4_CET_ENABLE_BIT: u64 = 1 << 23;

#[derive(Default)]
struct Isst {
    entries: [u64; 8],
}

lazy_static! {
    static ref INTERRUPT_SSP_TABLE: Mutex<Isst> = Mutex::new(Isst::default());
}

extern "win64" {
    fn asm_read_msr64(index: u32) -> u64;
    fn asm_write_msr64(index: u32, value: u64) -> u64;
}

fn is_cet_available() -> (bool, bool) {
    let mut cet_supported: bool = false;
    let mut cet_xss_supported: bool = false;

    //EAX = 7, ECX = 0: extend features.
    let cpuid = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };

    log::info!("cpuid 7,0 {:x}\n", cpuid.ecx);
    if cpuid.ecx & CPUID_CET_SS_BIT != 0 {
        cet_supported = true;

        let cpuid = unsafe { core::arch::x86_64::__cpuid_count(0x0D, 1) };
        if cpuid.ecx & CPUID_CET_XSS_S != 0 {
            cet_xss_supported = true;
        }
    }

    (cet_supported, cet_xss_supported)
}

fn disable_cet() {
    unsafe {
        Cr4::write_raw(Cr4::read_raw() & !CR4_CET_ENABLE_BIT);
    }
}

fn enable_cet() {
    unsafe {
        Cr4::write_raw(Cr4::read_raw() | CR4_CET_ENABLE_BIT);
    }
}

#[allow(unused)]
pub fn enable_cet_ss(shadow_stack_addr: u64, shadow_stack_size: u64) {
    let (cet_supported, cet_xss_supported) = is_cet_available();

    log::info!("CET support: {}\n", cet_supported);

    if !cet_supported {
        return;
    }

    unsafe {
        asm_write_msr64(MSR_IA32_S_CET, 1);
    }

    //
    // +------------------------------------------------------------- +
    // | Exception Page -- Token | Guard Page | Shadow Stack -- Token |
    // +------------------------------------------------------------- +
    //

    // Init SS Token
    let pl0_ssp: u64 = shadow_stack_addr + shadow_stack_size - 8;
    unsafe {
        *(pl0_ssp as *mut u64) = pl0_ssp;
    }

    enable_cet();

    // Init Exception Page token and interrupt ssp table
    let ist = &mut INTERRUPT_SSP_TABLE.lock();
    let token = shadow_stack_addr + EXCEPTION_PAGE_SIZE - 8;
    unsafe {
        *(token as *mut u64) = token;
    }
    ist.entries[1] = token;

    if cet_xss_supported {
        unsafe { asm_write_msr64(MSR_IA32_XSS, asm_read_msr64(MSR_IA32_XSS) | 1 << 12) };
    }

    unsafe {
        asm_write_msr64(MSR_IA32_PL0_SSP, pl0_ssp);
        asm_write_msr64(
            MSR_IA32_INTERRUPT_SSP_TABLE_ADDR,
            ist.entries.as_ptr() as u64,
        );
    }
}

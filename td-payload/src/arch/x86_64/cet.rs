// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::arch::asm;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::registers::model_specific::Msr;

use crate::arch::paging;

use super::paging::{disable_wp, enable_wp};

const CPUID_EXTEND_FEATURES: u32 = 0x7;
const CPUID_CET_SHSTK: u32 = 1 << 7;
const CPUID_CET_IBT: u32 = 1 << 20;
const MSR_IA32_S_CET: u32 = 0x6A2;
const MSR_IA32_PL0_SSP: u32 = 0x6A4;

const MSR_CET_SHSTK: u64 = 1;
const MSR_CET_IBT: u64 = 1 << 2;

lazy_static! {
    static ref ISST: Mutex<InterruptShadowStackTable> =
        Mutex::new(InterruptShadowStackTable::default());
}

// Interrupt Shadow Stack Table.
// Ref: Section 6.14.5 Interrupt Stack Table, Intel SDM Vol.3
#[derive(Default)]
struct InterruptShadowStackTable {
    #[allow(unused)]
    entries: [u64; 8],
}

pub fn init_cet_shstk(shadow_stack_addr: u64, shadow_stack_size: usize) -> bool {
    if !is_shstk_available() {
        return false;
    }

    disable_cet();

    paging::set_wp(shadow_stack_addr, shadow_stack_size);

    let mut msr_cet = Msr::new(MSR_IA32_S_CET);
    unsafe { msr_cet.write(msr_cet.read() | MSR_CET_SHSTK) };

    disable_wp();

    // Init SS Token
    let pl0_ssp = shadow_stack_addr + shadow_stack_size as u64 - 8;
    unsafe { *(pl0_ssp as *mut u64) = pl0_ssp };

    let mut msr_ssp = Msr::new(MSR_IA32_PL0_SSP);
    unsafe { msr_ssp.write(pl0_ssp) };

    #[cfg(feature = "stack-guard")]
    enable_cet_shstk_guard_page(shadow_stack_addr);

    enable_wp();

    true
}

/// Enable the CET shadow stack
/// # Safety
///
/// This function must be called inside a function that will never return,
/// otherwise Control Protection Exception will be triggered.
#[inline(always)]
pub unsafe fn enable_cet_shstk() {
    enable_cet();
    asm!("setssbsy");
}

pub fn enable_cet_ibt() -> bool {
    if !is_ibt_available() {
        return false;
    }

    disable_cet();
    let mut msr_cet = Msr::new(MSR_IA32_S_CET);
    unsafe { msr_cet.write(msr_cet.read() | MSR_CET_IBT) };
    enable_cet();

    true
}

fn is_shstk_available() -> bool {
    let cpuid = unsafe { core::arch::x86_64::__cpuid_count(CPUID_EXTEND_FEATURES, 0) };
    cpuid.ecx & CPUID_CET_SHSTK != 0
}

fn is_ibt_available() -> bool {
    let cpuid = unsafe { core::arch::x86_64::__cpuid_count(CPUID_EXTEND_FEATURES, 0) };
    cpuid.ecx & CPUID_CET_IBT != 0
}

/// Enable the CET by setting the bit 23 of CR4
#[inline(always)]
fn enable_cet() {
    unsafe {
        asm!(
            "push rax",
            "mov rax, cr4",
            "bts eax, 23",
            "mov cr4, rax",
            "pop rax"
        );
    }
}

/// Enable the CET by setting the bit 23 of CR4
#[inline]
fn disable_cet() {
    unsafe {
        asm!(
            "push rax",
            "mov rax, cr4",
            "btr eax, 23",
            "mov cr4, rax",
            "pop rax"
        );
    }
}

//
// +------------------------------------------------------------- +
// | Exception Page -- Token | Guard Page | Shadow Stack -- Token |
// +------------------------------------------------------------- +
//
#[cfg(feature = "stack-guard")]
fn enable_cet_shstk_guard_page(shadow_stack_addr: u64) {
    use crate::arch::guard_page::set_guard_page;

    const EXCEPTION_PAGE_SIZE: u64 = 0x1000;
    const MSR_IA32_INTERRUPT_SSP_TABLE_ADDR: u32 = 0x6A8;

    // To support this stack-switching mechanism with shadow stacks enabled,
    // the processor provides an MSR, IA32_INTERRUPT_SSP_TABLE, to program
    // the linear address of a table of seven shadow stack pointers that are
    // selected using the IST index from the gate descriptor.
    let isst = &mut ISST.lock();
    let token = shadow_stack_addr + EXCEPTION_PAGE_SIZE - 8;
    unsafe { *(token as *mut u64) = token };

    isst.entries[1] = token;

    let mut msr_ssp_table =
        x86_64::registers::model_specific::Msr::new(MSR_IA32_INTERRUPT_SSP_TABLE_ADDR);
    unsafe { msr_ssp_table.write(isst.entries.as_ptr() as u64) };

    let guard_page = shadow_stack_addr + EXCEPTION_PAGE_SIZE;
    set_guard_page(guard_page);
}

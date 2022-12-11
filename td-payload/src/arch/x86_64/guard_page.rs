// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::mm::SIZE_4K;

use super::{gdt::tss_set_ist, idt::idt_set_ist, paging::set_not_present};

pub fn set_guard_page(base: u64) {
    set_not_present(base, SIZE_4K);
}

/// Set the known good stack to the Interrupt Stack Table. System will switch
/// to the exception stack automatically when `Page Fault`exception occurs.
///
/// # Safety
/// The GDT/IDT and TSS must have been initialized when calling this function.
pub unsafe fn set_exception_stack(good_stack_top: u64, idt_index: u8, ist_index: u8) {
    tss_set_ist(ist_index - 1, good_stack_top);
    idt_set_ist(idt_index, ist_index);
}

// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{
    acpi::init_acpi_tables,
    arch::{gdt, idt},
    hob::{self, get_hob},
    mm::{
        dma::init_dma, get_usable, heap::init_heap, init_ram, layout::RuntimeLayout,
        page_table::init_pt_frame_allocator,
    },
};

#[cfg(any(feature = "cet-ibt", feature = "cet-shstk"))]
use super::cet;

use super::{apic::enable_apic_interrupt, paging};
#[cfg(feature = "stack-guard")]
use super::{
    guard_page,
    idt::{PAGE_FAULT_EXCEPTION, PAGE_FAULT_IST},
};

pub fn pre_init(hob: u64, layout: &RuntimeLayout) {
    let hob = hob::init(hob).expect("Invalid payload HOB");
    let memory_map = init_ram(hob).expect("Failed to parse E820 table from payload HOB");

    let page_table = get_usable(layout.page_table_size).expect("Failed to allocate page table");
    init_pt_frame_allocator(page_table, layout.page_table_size);

    paging::setup_paging(memory_map).expect("Failed to setup paging");

    let heap = get_usable(layout.heap_size).expect("Failed to allocate heap");
    init_heap(heap, layout.heap_size);

    let dma = get_usable(layout.dma_size).expect("Failed to allocate dma");
    init_dma(dma, layout.dma_size);

    // Init Global Descriptor Table and Task State Segment
    gdt::init_gdt();

    // Setup global IDT and exception handlers
    // Safety: GDT has been setup
    unsafe { idt::init_idt() };

    enable_apic_interrupt();
}

pub fn init(layout: &RuntimeLayout, next: unsafe extern "C" fn()) -> ! {
    init_acpi_tables(get_hob().expect("HOB is not intialized"))
        .expect("Fail to initialize ACPI tables");

    let stack = get_usable(layout.stack_size).expect("Failed to allocate stack");

    #[cfg(feature = "stack-guard")]
    {
        const EXCEPTION_STACK_SIZE: usize = 0x1000;

        let good_stack_top = stack + EXCEPTION_STACK_SIZE as u64;
        guard_page::set_guard_page(good_stack_top);
        unsafe {
            guard_page::set_exception_stack(good_stack_top, PAGE_FAULT_EXCEPTION, PAGE_FAULT_IST);
        }
    }

    #[cfg(feature = "cet-shstk")]
    {
        let shadow_stack =
            get_usable(layout.shadow_stack_size).expect("Failed to allocate shadow stack");
        cet::init_cet_shstk(shadow_stack, layout.shadow_stack_size);
    }

    #[cfg(feature = "cet-ibt")]
    cet::init_cet_ibt();

    // Safety: `init` will never return
    #[cfg(any(feature = "cet-ibt", feature = "cet-shstk"))]
    unsafe {
        cet::enable_cet();
    }

    jump_to_next(stack + layout.stack_size as u64, next as *const fn() as u64);
}

fn jump_to_next(stack_top: u64, next: u64) -> ! {
    unsafe {
        core::arch::asm!("mov rsp, {}; call {}", in(reg) stack_top, in(reg) next);
    }

    panic!("Unreachable");
}

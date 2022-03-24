// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]
#![feature(global_asm)]
#![feature(asm)]
#![feature(alloc_error_handler)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(unused_imports)]

use core::ffi::c_void;
use core::mem::size_of;
use core::panic::PanicInfo;

use r_efi::efi;
use scroll::{Pread, Pwrite};
use zerocopy::{AsBytes, ByteSlice, FromBytes};

use td_layout::build_time::{self, *};
use td_layout::memslice;
use td_layout::runtime::{self, *};
use td_layout::RuntimeMemoryLayout;
use td_shim::acpi::GenericSdtHeader;
use td_shim::event_log::{
    self, TdHandoffTable, TdHandoffTablePointers, EV_EFI_HANDOFF_TABLES2, EV_PLATFORM_CONFIG_FLAGS,
    TD_LOG_EFI_HANDOFF_TABLE_GUID,
};
use td_shim::{
    HobTemplate, PayloadInfo, TdKernelInfoHobType, TD_ACPI_TABLE_HOB_GUID, TD_KERNEL_INFO_HOB_GUID,
};
use td_uefi_pi::{fv, hob, pi};

use crate::tcg::TdEventLog;

mod acpi;
mod asm;
mod heap;
mod linux;
mod td;

extern "win64" {
    fn switch_stack_call(entry_point: usize, stack_top: usize, P1: usize, P2: usize);
}

#[cfg(not(test))]
#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &PanicInfo) -> ! {
    log::info!("panic ... {:?}\n", _info);
    panic!("deadloop");
}

#[cfg(not(test))]
#[alloc_error_handler]
#[allow(clippy::empty_loop)]
fn alloc_error(_info: core::alloc::Layout) -> ! {
    log::info!("alloc_error ... {:?}\n", _info);
    panic!("deadloop");
}

/// Main entry point of the td-shim, and the bootstrap code should jump here.
///
/// The bootstrap should prepare the context to satisfy `_start()`'s expectation:
/// - the memory is in 1:1 identity mapping mode with paging enabled
/// - the stack is ready for use
///
/// # Arguments
/// - `boot_fv`: pointer to the boot firmware volume
/// - `top_of_start`: top address of the stack
/// - `init_vp`: [31:0] TDINITVP - Untrusted Configuration
/// - `info`: [6:0] CPU supported GPA width, [7:7] 5 level page table support, [23:16] VCPUID,
///           [32:24] VCPU_Index
#[cfg(not(test))]
#[no_mangle]
#[export_name = "efi_main"]
pub extern "win64" fn _start(
    boot_fv: *const c_void,
    top_of_stack: *const c_void,
    init_vp: *const c_void,
    info: usize,
) -> ! {
    // The bootstrap code has setup the stack, but only the stack is available now...
    let _ = td_logger::init();
    log::info!("Starting RUST Based TdShim boot_fv - {:p}, Top of stack - {:p}, init_vp - {:p}, info - 0x{:x} \n",
               boot_fv, top_of_stack, init_vp, info);
    td_exception::setup_exception_handlers();
    log::info!("setup_exception_handlers done\n");

    // First initialize the heap allocator so that we have a normal rust world to live in...
    heap::init();

    panic!("Linux kernel should not return here!!!");
}

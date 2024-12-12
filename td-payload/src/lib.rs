// Copyright (c) 2022 Intel Corporation
// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use console::CONSOLE;
use core::fmt::{Arguments, Write};

extern crate alloc;

pub mod acpi;
pub mod arch;
pub mod console;
pub mod hob;
pub mod mm;

/// The entry point of Payload
///
/// For the x86_64-unknown-uefi target, the entry point name is 'efi_main'
/// For the x86_64-unknown-none target, the entry point name is '_start'
#[no_mangle]
#[cfg(all(not(test), feature = "start"))]
#[cfg_attr(target_os = "uefi", export_name = "efi_main")]
pub extern "C" fn _start(hob: u64, _payload: u64) -> ! {
    use mm::layout::RuntimeLayout;
    extern "C" {
        fn main();
    }

    let layout = RuntimeLayout::default();

    arch::init::pre_init(hob, &layout, false);
    arch::init::init(&layout, main);
}

pub fn console(args: Arguments) {
    CONSOLE
        .lock()
        .write_fmt(args)
        .expect("Failed to write console");
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::console(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[derive(Debug)]
pub enum Error {
    ParseHob,
    GetMemoryMap,
    GetAcpiTable,
    SetupMemoryLayout,
    SetupPageTable,
}

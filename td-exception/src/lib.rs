// Copyright (c) 2020-2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![feature(asm)]
#![feature(naked_functions)]
#![feature(global_asm)]

pub mod asm;
pub mod idt;

pub(crate) mod interrupt;

/// Initialize exception/interrupt handlers.
pub fn setup_exception_handlers() {
    unsafe { idt::init() };
}

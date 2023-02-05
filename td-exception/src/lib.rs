// Copyright (c) 2020-2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![feature(naked_functions)]

pub mod asm;
pub mod idt;
pub mod interrupt;

/// Initialize exception/interrupt handlers.
pub fn setup_exception_handlers() {
    unsafe { idt::init() };
}

#[cfg(feature = "integration-test")]
lazy_static::lazy_static! {
    pub static ref DIVIDED_BY_ZERO_EVENT_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
}

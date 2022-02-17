// Copyright (c) 2020-2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! X86 exception and interrupt manager.
//!
//! The `td-exception` crate manages x86 exceptions and interrupts for td-shim, which implements:
//! - interrupt/exception handlers
//! - IDT(interrupt descriptor table) manager

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

#[cfg(feature = "integration-test")]
lazy_static::lazy_static! {
    pub static ref DIVIDED_BY_ZERO_EVENT_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
}

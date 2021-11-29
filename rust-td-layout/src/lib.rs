// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]
#![forbid(unsafe_code)]

//! Define file (build-time) and runtime layout for shim binary.
//!
//! Note:
//! `repr(C)` should be used to control the exact data structure layout.
//! - `repr(rust)`: By default, composite structures have an alignment equal to the maximum of their
//!   fields' alignments. Rust will consequently insert padding where necessary to ensure that all
//!   fields are properly aligned and that the overall type's size is a multiple of its alignment.
//!   And fields may be reordered, not following the literal order of fields.
//! - `repr(C)` is the most important repr. It has fairly simple intent: do what C does. The order,
//!   size, and alignment of fields is exactly what you would expect from C or C++. Any type you
//!   expect to pass through an FFI boundary should have repr(C), as C is the lingua-franca of the
//!   programming world. This is also necessary to soundly do more elaborate tricks with data layout
//!   such as reinterpreting values as a different type.

use core::fmt;

pub mod build_time;
pub mod mailbox;
pub mod metadata;
pub mod runtime;

#[derive(Default)]
pub struct RuntimeMemoryLayout {
    pub runtime_page_table_base: u64,
    pub runtime_payload_param_base: u64,
    pub runtime_payload_base: u64,

    pub runtime_event_log_base: u64,
    pub runtime_acpi_base: u64,
    pub runtime_hob_base: u64,
    pub runtime_shadow_stack_base: u64,
    pub runtime_stack_base: u64,
    pub runtime_heap_base: u64,
    pub runtime_dma_base: u64,

    pub runtime_stack_top: u64,
    pub runtime_shadow_stack_top: u64,

    pub runtime_memory_bottom: u64,
}

impl RuntimeMemoryLayout {
    pub fn new(memory_top: u64) -> Self {
        use crate::runtime::*;
        let current_base = memory_top;

        let current_base = current_base - TD_PAYLOAD_EVENT_LOG_SIZE as u64;
        let runtime_event_log_base = current_base;

        let current_base = current_base - TD_PAYLOAD_ACPI_SIZE as u64;
        let runtime_acpi_base = current_base;

        let current_base = current_base - TD_PAYLOAD_HOB_SIZE as u64;
        let runtime_hob_base = current_base;

        let runtime_shadow_stack_top = current_base;
        let current_base = current_base - TD_PAYLOAD_SHADOW_STACK_SIZE as u64;
        let runtime_shadow_stack_base = current_base;

        let runtime_stack_top = current_base;
        let current_base = current_base - TD_PAYLOAD_STACK_SIZE as u64;
        let runtime_stack_base = current_base;

        let current_base = current_base - TD_PAYLOAD_HEAP_SIZE as u64;
        let runtime_heap_base = current_base;

        let current_base = current_base - TD_PAYLOAD_DMA_SIZE as u64;
        let runtime_dma_base = current_base;

        let runtime_memory_bottom = current_base;

        let runtime_page_table_base = TD_PAYLOAD_PAGE_TABLE_BASE as u64;
        let runtime_payload_param_base = TD_PAYLOAD_PARAM_BASE as u64;
        let runtime_payload_base = TD_PAYLOAD_BASE as u64;

        RuntimeMemoryLayout {
            runtime_page_table_base,
            runtime_payload_param_base,
            runtime_payload_base,
            runtime_event_log_base,
            runtime_hob_base,
            runtime_acpi_base,
            runtime_shadow_stack_base,
            runtime_shadow_stack_top,
            runtime_stack_base,
            runtime_stack_top,
            runtime_heap_base,
            runtime_dma_base,
            runtime_memory_bottom,
        }
    }
}

impl fmt::Debug for RuntimeMemoryLayout {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RuntimeMemoryLayout")
            .field(
                "runtime_page_table_base",
                &format_args!("0x{:x}", self.runtime_page_table_base),
            )
            .field(
                "runtime_payload_base",
                &format_args!("0x{:x}", self.runtime_payload_base),
            )
            .field(
                "runtime_event_log_base",
                &format_args!("0x{:x}", self.runtime_event_log_base),
            )
            .field(
                "runtime_hob_base",
                &format_args!("0x{:x}", self.runtime_hob_base),
            )
            .field(
                "runtime_stack_base",
                &format_args!("0x{:x}", self.runtime_stack_base),
            )
            .field(
                "runtime_stack_top",
                &format_args!("0x{:x}", self.runtime_stack_top),
            )
            .field(
                "runtime_heap_base",
                &format_args!("0x{:x}", self.runtime_heap_base),
            )
            .field(
                "runtime_dma_base",
                &format_args!("0x{:x}", self.runtime_dma_base),
            )
            .finish()
    }
}

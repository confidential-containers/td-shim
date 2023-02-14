// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

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
pub mod memslice;
pub mod runtime;

use runtime::*;

// Minimal memory size to build the runtime layout.
#[cfg(feature = "boot-kernel")]
pub const MIN_MEMORY_SIZE: u64 = (ACPI_SIZE
    + UNACCEPTED_MEMORY_BITMAP_SIZE
    + PAYLOAD_PAGE_TABLE_SIZE
    + EVENT_LOG_SIZE
    + PAYLOAD_MAILBOX_SIZE) as u64;

#[cfg(not(feature = "boot-kernel"))]
pub const MIN_MEMORY_SIZE: u64 =
    (ACPI_SIZE + PAYLOAD_SIZE + PAYLOAD_PAGE_TABLE_SIZE + EVENT_LOG_SIZE + PAYLOAD_MAILBOX_SIZE)
        as u64;

pub const TD_PAYLOAD_PARTIAL_ACCEPT_MEMORY_SIZE: u32 = 0x10000000;

#[derive(Default)]
pub struct RuntimeMemoryLayout {
    pub runtime_event_log_base: u64,
    pub runtime_page_table_base: u64,
    pub runtime_acpi_base: u64,
    pub runtime_mailbox_base: u64,
    pub runtime_unaccepted_bitmap_base: u64,
    pub runtime_payload_base: u64,
    pub runtime_memory_bottom: u64,
    pub runtime_memory_top: u64,
}

impl RuntimeMemoryLayout {
    pub fn new(memory_top: u64) -> Self {
        // Align the base with 4KiB
        let mut current_base = memory_top & !0xfff;

        if current_base < MIN_MEMORY_SIZE {
            panic!("memory_top 0x{:x} is too small", memory_top);
        }

        current_base -= EVENT_LOG_SIZE as u64;
        let runtime_event_log_base = current_base;

        current_base -= PAYLOAD_MAILBOX_SIZE as u64;
        let runtime_mailbox_base = current_base;

        current_base -= PAYLOAD_PAGE_TABLE_SIZE as u64;
        let runtime_page_table_base = current_base;

        // Payload memory does not need to be reserved for booting Linux Kernel
        #[cfg(not(feature = "boot-kernel"))]
        {
            current_base -= PAYLOAD_SIZE as u64;
        }
        let runtime_payload_base = current_base;

        current_base -= ACPI_SIZE as u64;
        let runtime_acpi_base = current_base;

        #[cfg(feature = "boot-kernel")]
        {
            current_base -= UNACCEPTED_MEMORY_BITMAP_BASE as u64;
        }
        let runtime_unaccepted_bitmap_base = current_base;

        RuntimeMemoryLayout {
            runtime_event_log_base,
            runtime_mailbox_base,
            runtime_page_table_base,
            runtime_acpi_base,
            runtime_unaccepted_bitmap_base,
            runtime_payload_base,
            runtime_memory_bottom: current_base,
            runtime_memory_top: memory_top,
        }
    }
}

impl fmt::Debug for RuntimeMemoryLayout {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RuntimeMemoryLayout")
            .field(
                "runtime_mailbox_base",
                &format_args!("0x{:x}", self.runtime_mailbox_base),
            )
            .field(
                "runtime_event_log_base",
                &format_args!("0x{:x}", self.runtime_event_log_base),
            )
            .field(
                "runtime_page_table_base",
                &format_args!("0x{:x}", self.runtime_page_table_base),
            )
            .field(
                "runtime_acpi_base",
                &format_args!("0x{:x}", self.runtime_acpi_base),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_invalid_memory_top() {
        RuntimeMemoryLayout::new(MIN_MEMORY_SIZE as u64 - 0x100000);
    }

    #[test]
    fn test_runtime_memory_layout_new() {
        let layout = RuntimeMemoryLayout::new(MIN_MEMORY_SIZE + 0x100);

        assert_eq!(
            layout.runtime_mailbox_base,
            MIN_MEMORY_SIZE as u64 - (EVENT_LOG_SIZE + PAYLOAD_MAILBOX_SIZE) as u64,
        );

        assert_eq!(
            layout.runtime_event_log_base,
            MIN_MEMORY_SIZE as u64 - EVENT_LOG_SIZE as u64,
        );
    }

    #[test]
    #[cfg(feature = "boot-kernel")]
    fn test_runtime_memory_layout_boot_kernel() {
        assert_eq!(MIN_MEMORY_SIZE, 0x262000);

        let layout = RuntimeMemoryLayout::new(MIN_MEMORY_SIZE + 0x1000);

        assert_eq!(layout.runtime_memory_bottom, 0x1000);
    }

    #[test]
    #[cfg(not(feature = "boot-kernel"))]
    fn test_runtime_memory_layout_boot_payload() {
        assert_eq!(MIN_MEMORY_SIZE, 0x2222000);

        let layout = RuntimeMemoryLayout::new(MIN_MEMORY_SIZE + 0x1000);

        assert_eq!(layout.runtime_memory_bottom, 0x1000);
    }

    #[test]
    fn test_runtime_memory_layout_default() {
        let _ = RuntimeMemoryLayout::default();
    }
}

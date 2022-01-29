// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use td_layout::{build_time, runtime, RuntimeMemoryLayout};

const MAX_E820_ENTRY: usize = 128;

#[derive(Clone, Copy)]
pub enum E820Type {
    Memory = 1,
    Reserved = 2,
    Acpi = 3,
    Nvs = 4,
    Unusable = 5,
    Disabled = 6,
    Pmem = 7,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub r#type: u32,
}

impl E820Entry {
    pub fn new(addr: u64, size: u64, r#type: E820Type) -> Self {
        E820Entry {
            addr,
            size,
            r#type: r#type as u32,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct E820Table {
    entries: [E820Entry; MAX_E820_ENTRY],
    size: usize,
}

impl Default for E820Table {
    fn default() -> Self {
        Self {
            entries: [E820Entry::default(); MAX_E820_ENTRY],
            size: 0,
        }
    }
}

impl E820Table {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_range(&mut self, r#type: E820Type, start: u64, length: u64) {
        if self.size == MAX_E820_ENTRY {
            return;
        }
        if self.size > 0 {
            let end_entry = &mut self.entries[self.size - 1];
            let exist_end = end_entry.addr + end_entry.size;
            if start == exist_end + 1 && r#type as u32 == end_entry.r#type {
                end_entry.size += length;
                return;
            }
        }
        self.entries[self.size] = E820Entry::new(start, length, r#type);
        self.size += 1;
    }
    pub fn as_slice(&'_ self) -> &'_ [E820Entry] {
        &self.entries
    }
}

//TBD: Remove these
pub fn create_e820_entries(runtime_memory: &RuntimeMemoryLayout) -> E820Table {
    let mut table = E820Table::new();
    table.add_range(E820Type::Memory, 0, runtime_memory.runtime_acpi_base as u64);
    table.add_range(
        E820Type::Acpi,
        runtime_memory.runtime_acpi_base,
        runtime::TD_PAYLOAD_ACPI_SIZE as u64,
    );
    table.add_range(
        E820Type::Nvs,
        runtime_memory.runtime_event_log_base,
        runtime::TD_PAYLOAD_EVENT_LOG_SIZE as u64,
    );
    table.add_range(
        E820Type::Nvs,
        build_time::TD_SHIM_MAILBOX_BASE as u64,
        build_time::TD_SHIM_MAILBOX_SIZE as u64,
    );
    table
}

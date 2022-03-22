// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use td_layout::{build_time, runtime, RuntimeMemoryLayout};

// Linux BootParam supports 128 e820 entries, so...
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
            if start == exist_end && r#type as u32 == end_entry.r#type {
                end_entry.size += length;
                return;
            }
        }
        self.entries[self.size] = E820Entry::new(start, length, r#type);
        self.size += 1;
    }

    pub fn as_slice(&self) -> &[E820Entry] {
        &self.entries
    }
}

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
        runtime_memory.runtime_mailbox_base,
        runtime::TD_PAYLOAD_MAILBOX_SIZE as u64,
    );
    // TODO: above memory above 4G? Should those memory be reported as `Memory`?

    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn test_e820_entry_size() {
        assert_eq!(size_of::<E820Entry>(), 20);
        assert_eq!(
            size_of::<[E820Entry; MAX_E820_ENTRY]>(),
            20 * MAX_E820_ENTRY
        );
    }

    #[test]
    fn test_e820_table() {
        let mut table = E820Table::new();
        assert_eq!(table.size as usize, 0);
        table.add_range(E820Type::Memory, 0x0, 0x1000);
        assert_eq!(table.size as usize, 1);
        table.add_range(E820Type::Memory, 0x1000, 0x1000);
        assert_eq!(table.size as usize, 1);
        assert_eq!(table.entries[0].size as u64, 0x2000);
        table.add_range(E820Type::Acpi, 0x2000, 0x1000);
        assert_eq!(table.size as usize, 2);

        for idx in 0..MAX_E820_ENTRY {
            table.add_range(E820Type::Memory, idx as u64 * 0x2000, 0x1000);
        }
        assert_eq!(table.size as usize, MAX_E820_ENTRY);
    }
}

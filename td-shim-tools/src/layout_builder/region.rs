// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{fmt, fmt::Display};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct MemoryRegion {
    base: usize,
    length: usize,
    name: String,
}

impl MemoryRegion {
    pub fn new(base: usize, length: usize, name: String) -> Self {
        MemoryRegion {
            base: base,
            length: length,
            name: name,
        }
    }
}

pub struct MemoryRegions {
    memory_region_list: Vec<MemoryRegion>,
    base: usize,
    offset: usize,
}

impl MemoryRegions {
    pub fn new(base: usize) -> Self {
        Self {
            memory_region_list: Vec::new(),
            base: base,
            offset: base,
        }
    }
    pub fn create_region<T: ToString>(mut self, name: T, length: usize) -> Self {
        let memory_region = MemoryRegion::new(self.offset, length, name.to_string());
        self.memory_region_list.push(memory_region);
        // self.memory_regions.insert(name, memory_region.clone());
        self.offset = self.offset.checked_add(length).expect("length too large");
        self
    }

    pub fn get_total_length(&self) -> usize {
        self.offset - self.base
    }

    pub fn get_regions(&self) -> &Vec<MemoryRegion> {
        &self.memory_region_list
    }

    pub fn get_base(&self) -> usize {
        self.base
    }

    #[allow(unused)]
    pub fn get_memory_region(&self, name: &'static str) -> Option<&MemoryRegion> {
        self.memory_region_list
            .iter()
            .find(|v| -> bool { v.name == name })
    }
}

impl Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.

        write!(
            f,
            "[mem 0x{:016x}-0x{:016x}] {}",
            self.base,
            self.length + self.base,
            self.name
        )
    }
}

impl Display for MemoryRegions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for v in self.memory_region_list.iter() {
            writeln!(f, "{}", v)?;
        }
        write!(f, "Total length: 0x{:x}", self.get_total_length())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic() {
        let regions = MemoryRegions::new(0x0)
            .create_region("LEGACY", 0x10_0000)
            .create_region("RESERVED_2", 0x70_0000)
            .create_region("TD_HOB", 0x10_0000)
            .create_region("KERNEL_PARAM", 0x1000)
            .create_region("KERNEL", 0x200_0000)
            .create_region("RESERVED", 0x200_0000)
            .create_region("UNACCEPTED", 0x4_0000)
            .create_region("ACPI", 0x10_0000)
            .create_region("STACK", 0x10000)
            .create_region("PAYLOAD", 0x200_0000)
            .create_region("PAGE_TABLE", 0x2_0000)
            .create_region("MAILBOX", 0x2000)
            .create_region("TD_EVENT_LOG", 0x10_0000);
    }
}

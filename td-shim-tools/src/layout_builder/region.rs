// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{fmt, fmt::Display};
use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Serialize, Deserialize, Clone)]
pub struct LayoutEntry {
    name: String,
    region: Range<usize>,
    entry_type: String,
    tolm: bool,
}

impl LayoutEntry {
    pub fn new(name: String, region: Range<usize>, entry_type: String, tolm: bool) -> Self {
        Self {
            name,
            region,
            entry_type,
            tolm,
        }
    }
}

impl Display for LayoutEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.

        write!(
            f,
            "[mem 0x{:016x}-0x{:016x}] {}",
            self.region.start, self.region.end, self.name
        )
    }
}

pub struct LayoutConfig {
    list: Vec<LayoutEntry>,
    free: usize,
    base: usize,
    top: usize,
    low_offset: usize,
    high_offset: usize,
}

impl LayoutConfig {
    pub fn new(base: usize, top: usize) -> Self {
        Self {
            list: vec![LayoutEntry::new(
                "Free".to_string(),
                base..top,
                "Memory".to_string(),
                false,
            )],
            free: 0,
            base,
            top,
            low_offset: base,
            high_offset: top,
        }
    }

    pub fn reserve_low<T: ToString>(&mut self, name: T, length: usize, entry_type: T) {
        self.list.insert(
            self.free,
            LayoutEntry::new(
                name.to_string(),
                self.low_offset..self.low_offset + length,
                entry_type.to_string().to_ascii_uppercase(),
                false,
            ),
        );

        self.low_offset = self
            .low_offset
            .checked_add(length)
            .expect("Invalid region length.");
        self.free += 1;

        let free = self.list.get_mut(self.free).unwrap();
        free.region = self.low_offset..self.high_offset;
    }

    pub fn reserve_high<T: ToString>(&mut self, name: T, length: usize, entry_type: T) {
        self.high_offset = self
            .high_offset
            .checked_sub(length)
            .expect("Invalid region length.");

        self.list.insert(
            self.free + 1,
            LayoutEntry::new(
                name.to_string().to_ascii_uppercase(),
                self.high_offset..self.high_offset + length,
                entry_type.to_string(),
                true,
            ),
        );

        let free = self.list.get_mut(self.free).unwrap();
        free.region = self.low_offset..self.high_offset;
    }

    pub fn get_total_length(&self) -> usize {
        self.top - self.base
    }

    pub fn get_total_usage(&self) -> usize {
        self.top - self.base - (self.high_offset - self.low_offset)
    }

    pub fn get_regions(&self) -> &[LayoutEntry] {
        self.list.as_slice()
    }

    pub fn get_base(&self) -> usize {
        self.base
    }

    #[allow(unused)]
    pub fn get_layout_region(&self, name: &'static str) -> Option<&LayoutEntry> {
        self.list.iter().find(|v| -> bool { v.name == name })
    }
}

impl Display for LayoutConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for v in self.list.iter() {
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
        let mut regions = LayoutConfig::new(0x0, 0x8000_0000);
        regions.reserve_low("IPL", 0x80_0000, "Memory");
        regions.reserve_low("TD_HOB", 0x10_0000, "Memory");
        regions.reserve_low("LAZY_ACCEPT_BITMAP", 0x4_0000, "Memory");
        regions.reserve_low("TD_PAYLOAD_PARAM", 0x1000, "Memory");
        regions.reserve_low("TD_PAYLOAD", 0x200_0000, "Memory");
        regions.reserve_high("ACPI", 0x10_0000, "Acpi");
        regions.reserve_high("PAYLOAD", 0x200_0000, "Reserved");
        regions.reserve_high("PAGE_TABLE", 0x2_0000, "Reserved");
        regions.reserve_high("STACK", 0x10000, "Reserved");
        regions.reserve_high("MAILBOX", 0x2000, "Nvs");
        regions.reserve_high("TD_EVENT_LOG", 0x10_0000, "Nvs");
    }
}

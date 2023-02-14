// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{fmt, fmt::Display};
use serde::{Deserialize, Serialize};
use std::ops::Range;

pub(crate) const ENTRY_TYPE_FILTER: &str = "FilterType";

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
    base: usize,
    top: usize,
    free_index: usize,
}

impl LayoutConfig {
    pub fn new(base: usize, top: usize) -> Self {
        Self {
            list: vec![LayoutEntry::new(
                "Free".to_string(),
                base..top,
                ENTRY_TYPE_FILTER.to_string(),
                false,
            )],
            free_index: 0,
            base,
            top,
        }
    }

    pub fn reserve_low<T: ToString>(&mut self, name: T, length: usize, entry_type: T) {
        let new_free_base = self
            .free_base()
            .checked_add(length)
            .expect("Invalid region length.");
        let free_top = self.list[self.free_index].region.end;

        self.list.insert(
            self.free_index,
            LayoutEntry::new(
                name.to_string().to_ascii_uppercase(),
                self.free_base()..self.free_base() + length,
                entry_type.to_string(),
                false,
            ),
        );
        self.free_index += 1;

        self.list[self.free_index].region = new_free_base..free_top;
    }

    pub fn reserve_high<T: ToString>(&mut self, name: T, length: usize, entry_type: T) {
        let new_free_top = self
            .free_top()
            .checked_sub(length)
            .expect("Invalid region length.");

        self.list.insert(
            self.free_index + 1,
            LayoutEntry::new(
                name.to_string().to_ascii_uppercase(),
                new_free_top..new_free_top + length,
                entry_type.to_string(),
                true,
            ),
        );

        self.list[self.free_index].region = self.free_base()..new_free_top;
    }

    pub fn get_total_usage(&self) -> usize {
        self.top - self.base - (self.free_top() - self.free_base())
    }

    pub fn get_regions(&self) -> &[LayoutEntry] {
        self.list.as_slice()
    }

    pub fn get_base(&self) -> usize {
        self.base
    }

    pub fn get_top(&self) -> usize {
        self.top
    }

    fn free_base(&self) -> usize {
        self.list[self.free_index].region.start
    }

    fn free_top(&self) -> usize {
        self.list[self.free_index].region.end
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
        writeln!(f, "Layout Base: 0x{:x}", self.get_base())?;
        writeln!(f, "Layout Top: 0x{:x}", self.get_top())
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

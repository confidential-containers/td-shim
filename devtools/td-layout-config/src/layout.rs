// Copyright (c) 2022, 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::{fmt, fmt::Display};
use inflector::cases::{pascalcase, screamingsnakecase};
use serde::{Deserialize, Serialize};
use std::ops::Range;

pub(crate) const ENTRY_TYPE_FILTER: &str = "FilterType";

#[derive(Serialize, Deserialize, Clone)]
pub struct LayoutEntry {
    name: String,
    name_screaming_snake_case: String,
    region: Range<usize>,
    entry_type: String,
    tolm: bool,
}

impl LayoutEntry {
    pub fn new(name: String, region: Range<usize>, entry_type: String, tolm: bool) -> Self {
        let name = pascalcase::to_pascal_case(&name);
        let name_screaming_snake_case = screamingsnakecase::to_screaming_snake_case(&name);

        Self {
            name,
            name_screaming_snake_case,
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
}

impl LayoutConfig {
    pub fn new(base: usize, top: usize) -> Self {
        Self {
            list: vec![LayoutEntry::new(
                "FREE".to_string(),
                base..top,
                ENTRY_TYPE_FILTER.to_string(),
                false,
            )],
            base,
            top,
        }
    }

    pub fn reserve_low<T: ToString>(&mut self, name: T, length: usize, entry_type: T) {
        let free_index = self
            .find_free_region_for_low(length)
            .expect("No suitable free region found");

        let free_base = self.list[free_index].region.start;
        let new_free_base = free_base
            .checked_add(length)
            .expect("Invalid region length.");
        let free_top = self.list[free_index].region.end;

        self.list.insert(
            free_index,
            LayoutEntry::new(
                name.to_string(),
                free_base..free_base + length,
                entry_type.to_string(),
                false,
            ),
        );

        // Update the free region to start after the allocated region
        self.list[free_index + 1].region = new_free_base..free_top;
    }

    /// Reserve a region at the low end with a base aligned to `alignment`.
    pub fn reserve_low_aligned<T: ToString>(
        &mut self,
        name: T,
        length: usize,
        entry_type: T,
        alignment: usize,
    ) {
        let (free_index, aligned_base) = self
            .find_free_region_for_aligned(length, alignment)
            .expect("No suitable free region found for aligned allocation");

        let free_base = self.list[free_index].region.start;
        let new_free_base = aligned_base
            .checked_add(length)
            .expect("Invalid region length.");
        let free_top = self.list[free_index].region.end;

        let mut insert_index = free_index;

        // If there's a gap due to alignment, keep it as free space
        if aligned_base > free_base {
            // Update current free region to cover the gap
            self.list[free_index].region = free_base..aligned_base;
            insert_index += 1;
        }

        self.list.insert(
            insert_index,
            LayoutEntry::new(
                name.to_string(),
                aligned_base..aligned_base + length,
                entry_type.to_string(),
                false,
            ),
        );

        // Create or update the remaining free region after the allocation
        if new_free_base < free_top {
            self.list.insert(
                insert_index + 1,
                LayoutEntry::new(
                    "FREE".to_string(),
                    new_free_base..free_top,
                    ENTRY_TYPE_FILTER.to_string(),
                    false,
                ),
            );
        }

        // If we didn't create a gap, we need to remove the original free region
        if aligned_base == free_base {
            self.list.remove(insert_index + 1);
        }
    }

    pub fn reserve_high<T: ToString>(&mut self, name: T, length: usize, entry_type: T) {
        // Find the last free region that can accommodate the allocation
        let free_index = self
            .list
            .iter()
            .enumerate()
            .rev()
            .find_map(|(i, entry)| {
                if self.is_free_region(entry) && entry.region.len() >= length {
                    Some(i)
                } else {
                    None
                }
            })
            .expect("No suitable free region found");

        let free_base = self.list[free_index].region.start;
        let free_top = self.list[free_index].region.end;
        let new_free_top = free_top
            .checked_sub(length)
            .expect("Invalid region length.");

        self.list.insert(
            free_index + 1,
            LayoutEntry::new(
                name.to_string(),
                new_free_top..new_free_top + length,
                entry_type.to_string(),
                true,
            ),
        );

        self.list[free_index].region = free_base..new_free_top;
    }

    pub fn get_total_usage(&self) -> usize {
        let total_free: usize = self
            .list
            .iter()
            .filter(|entry| self.is_free_region(entry))
            .map(|entry| entry.region.len())
            .sum();
        self.top - self.base - total_free
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

    fn is_free_region(&self, entry: &LayoutEntry) -> bool {
        entry.entry_type == ENTRY_TYPE_FILTER
    }

    fn find_free_region_for_low(&self, required_size: usize) -> Option<usize> {
        self.list.iter().enumerate().find_map(|(i, entry)| {
            if self.is_free_region(entry) && entry.region.len() >= required_size {
                Some(i)
            } else {
                None
            }
        })
    }

    fn find_free_region_for_aligned(
        &self,
        length: usize,
        alignment: usize,
    ) -> Option<(usize, usize)> {
        for (i, entry) in self.list.iter().enumerate() {
            if !self.is_free_region(entry) {
                continue;
            }

            let free_base = entry.region.start;
            let aligned_base = if alignment == 0 {
                free_base
            } else {
                (free_base + alignment - 1) & !(alignment - 1)
            };

            let required_end = aligned_base.checked_add(length);
            if let Some(end) = required_end {
                if end <= entry.region.end {
                    return Some((i, aligned_base));
                }
            }
        }
        None
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

    #[test]
    fn test_aligned_allocation() {
        let mut regions = LayoutConfig::new(0x0, 0x10000);

        // Reserve some low memory first
        regions.reserve_low("LOW1", 0x100, "Memory");

        // Reserve aligned memory with 0x1000 alignment
        // This should create a gap
        regions.reserve_low_aligned("ALIGNED", 0x500, "Memory", 0x1000);

        // Verify we have multiple free regions
        let free_count = regions
            .list
            .iter()
            .filter(|entry| regions.is_free_region(entry))
            .count();

        assert!(
            free_count > 1,
            "Should have multiple free regions after aligned allocation"
        );

        // Verify the aligned region starts at 0x1000
        let aligned_region = regions.get_layout_region("Aligned");
        assert!(aligned_region.is_some());
        assert_eq!(aligned_region.unwrap().region.start, 0x1000);
    }
}

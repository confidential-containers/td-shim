// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::vec::Vec;
use td_shim::e820::{E820Entry, E820Type};

// Linux BootParam supports 128 e820 entries, so...
const MAX_E820_ENTRY: usize = 128;

#[derive(Debug)]
pub struct E820Table {
    entries: Vec<E820Entry>,
}

#[derive(Debug)]
pub enum E820Error {
    RangeAlreadyExists,
    RangeNotExists,
    TooManyEntries,
}

impl Default for E820Table {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl E820Table {
    pub fn new() -> Self {
        Self::default()
    }

    // Add a new range to the table
    pub fn add_range(
        &mut self,
        r#type: E820Type,
        start: u64,
        length: u64,
    ) -> Result<(), E820Error> {
        let mut pos = self.entries.len();
        for (i, e) in self.entries.iter().enumerate() {
            if start >= e.addr && start < e.addr + e.size {
                return Err(E820Error::RangeAlreadyExists);
            }
            if start + length <= e.addr {
                pos = i;
                break;
            }
        }
        if self.entries.len() == MAX_E820_ENTRY && !self.able_to_merge(pos, r#type, start, length) {
            return Err(E820Error::TooManyEntries);
        }
        self.entries
            .insert(pos, E820Entry::new(start, length, r#type));
        self.merge();
        Ok(())
    }

    // Convert an existing range to another type
    pub fn convert_range(
        &mut self,
        r#type: E820Type,
        start: u64,
        length: u64,
    ) -> Result<(), E820Error> {
        let entry_num = self.entries.len();
        let mut idx = 0;
        loop {
            if idx == entry_num {
                break;
            }
            let entry_end = self.entries[idx].addr + self.entries[idx].size;
            if start >= self.entries[idx].addr && start < entry_end {
                // Return error if the length exceeds the range of current entry
                if length > entry_end - start {
                    return Err(E820Error::RangeNotExists);
                }
                // If range covers the whole entry, update the type,
                // otherwise insert a new entry.
                if self.entries[idx].size == length {
                    self.entries[idx].r#type = r#type as u32;
                    self.merge();
                    return Ok(());
                }

                if self.entries[idx].addr == start {
                    // if the entry num of e820 table has reached the maximum, and
                    // the new entry cannot be merged with an exits one, then return
                    // an error.
                    if entry_num == MAX_E820_ENTRY
                        && !self.able_to_merge(idx, r#type, start, length)
                    {
                        return Err(E820Error::TooManyEntries);
                    }
                    self.entries[idx].size -= length;
                    self.entries[idx].addr = start + length;
                    self.entries
                        .insert(idx, E820Entry::new(start, length, r#type))
                } else if self.entries[idx].addr + self.entries[idx].size == start + length {
                    // check if the new entry can be merged with the right one
                    if entry_num == MAX_E820_ENTRY
                        && !self.able_to_merge(idx, r#type, start, length)
                    {
                        return Err(E820Error::TooManyEntries);
                    }
                    self.entries[idx].size -= length;
                    self.entries
                        .insert(idx + 1, E820Entry::new(start, length, r#type))
                } else {
                    self.entries[idx].size = start - self.entries[idx].addr;
                    self.entries
                        .insert(idx + 1, E820Entry::new(start, length, r#type));
                    self.entries.insert(
                        idx + 2,
                        E820Entry::new(
                            start + length,
                            entry_end - (start + length),
                            self.entries[idx].r#type.into(),
                        ),
                    );
                }
                self.merge();
                return Ok(());
            }
            idx += 1;
        }
        return Err(E820Error::RangeNotExists);
    }

    // Check if the new entry can be merged with the its neighbour
    // if exists
    fn able_to_merge(&self, pos: usize, r#type: E820Type, start: u64, length: u64) -> bool {
        if (pos > 0
            && self.entries[pos - 1].r#type == r#type as u32
            && self.entries[pos - 1].addr + self.entries[pos - 1].size == start)
            || (pos + 1 < self.entries.len()
                && self.entries[pos + 1].r#type == r#type as u32
                && self.entries[pos + 1].addr == start + length)
        {
            true
        } else {
            false
        }
    }

    fn merge(&mut self) {
        let mut entry_num = self.entries.len();
        let mut idx = 0;
        loop {
            if idx == entry_num - 1 {
                break;
            }
            let entry_end = self.entries[idx].addr + self.entries[idx].size;
            if entry_end == self.entries[idx + 1].addr
                && self.entries[idx].r#type == self.entries[idx + 1].r#type
            {
                self.entries[idx].size += self.entries[idx + 1].size;
                self.entries.remove(idx + 1);
                entry_num -= 1;
                continue;
            }
            idx += 1;
        }
    }

    pub fn as_slice(&self) -> &[E820Entry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e820_table_add_range() {
        let mut table = E820Table::new();
        table.add_range(E820Type::Memory, 0x0, 0x1000).unwrap();
        table.add_range(E820Type::Memory, 0x2000, 0x1000).unwrap();
        assert_eq!(table.as_slice().len(), 2);
        table.add_range(E820Type::Memory, 0x1000, 0x1000).unwrap();
        assert_eq!(table.as_slice().len(), 1);
    }

    #[test]
    fn test_e820_table_convert_range() {
        let mut table = E820Table::new();
        table.add_range(E820Type::Memory, 0x0, 0x1000).unwrap();
        table.add_range(E820Type::Memory, 0x2000, 0x1000).unwrap();
        table.add_range(E820Type::Acpi, 0x1000, 0x1000).unwrap();
        assert_eq!(table.as_slice().len(), 3);
        table
            .convert_range(E820Type::Memory, 0x1400, 0x800)
            .unwrap();
        assert_eq!(table.as_slice().len(), 5);

        table.convert_range(E820Type::Acpi, 0x1400, 0x800).unwrap();
        table
            .convert_range(E820Type::Memory, 0x1000, 0x800)
            .unwrap();
        assert_eq!(table.as_slice().len(), 3);

        table.convert_range(E820Type::Acpi, 0x1000, 0x800).unwrap();
        table
            .convert_range(E820Type::Memory, 0x1800, 0x800)
            .unwrap();
        assert_eq!(table.as_slice().len(), 3);

        let mut table = E820Table::new();
        let result = table.convert_range(E820Type::Memory, 0x0, 0x1000);
        assert!(result.is_err());
        table.add_range(E820Type::Memory, 0x2000, 0x1000).unwrap();
        table.add_range(E820Type::Memory, 0x0, 0x1000).unwrap();
        assert_eq!(table.as_slice().len(), 2);
        let result = table.convert_range(E820Type::Memory, 0x800, 0x2000);
        assert!(result.is_err());
    }
}

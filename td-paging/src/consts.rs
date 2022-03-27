// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

/// Guest physical to virtual address mapping offset. 0 means identity mapping.
pub const PHYS_VIRT_OFFSET: usize = 0;
/// Page size.
pub const PAGE_SIZE: usize = 0x1000;
/// The memory size reserved for page table pages.
pub const PAGE_TABLE_SIZE: usize = 0x800000;

/// Default PTE(page table entry) size.
pub const PAGE_SIZE_DEFAULT: usize = 0x4000_0000;
/// Minimal PTE(page table entry) size.
pub const PAGE_SIZE_4K: usize = 0x1000;

#[cfg(test)]
mod tests {
    use super::*;
    use td_layout::runtime;

    #[test]
    fn test_constants() {
        // Ensure the runtime layout has reserved enough space for page table pages.
        assert!(
            PAGE_TABLE_SIZE as u64
                <= runtime::TD_PAYLOAD_PARAM_BASE - runtime::TD_PAYLOAD_PAGE_TABLE_BASE
        );
    }
}

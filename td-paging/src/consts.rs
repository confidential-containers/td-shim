// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

/// Guest physical to virtual address mapping offset. 0 means identity mapping.
pub const PHYS_VIRT_OFFSET: usize = 0;
/// Page size.
pub const PAGE_SIZE: usize = 0x1000;

/// Default PTE(page table entry) size.
pub const PAGE_SIZE_DEFAULT: usize = 0x4000_0000;
/// Minimal PTE(page table entry) size.
pub const PAGE_SIZE_4K: usize = 0x1000;

// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub const DEFAULT_HEAP_SIZE: usize = 0x1000000;
pub const DEFAULT_STACK_SIZE: usize = 0x800000;
pub const DEFAULT_PAGE_TABLE_SIZE: usize = 0x800000;
#[cfg(not(feature = "coverage"))]
pub const DEFAULT_DMA_SIZE: usize = 0x100000;
#[cfg(feature = "coverage")]
pub const DEFAULT_DMA_SIZE: usize = 0x300000;
#[cfg(feature = "cet-shstk")]
pub const DEFAULT_SHADOW_STACK_SIZE: usize = 0x10000;

#[derive(Debug)]
pub struct RuntimeLayout {
    pub heap_size: usize,
    pub stack_size: usize,
    pub page_table_size: usize,
    pub dma_size: usize,
    #[cfg(feature = "cet-shstk")]
    pub shadow_stack_size: usize,
}

impl Default for RuntimeLayout {
    fn default() -> Self {
        Self {
            heap_size: DEFAULT_HEAP_SIZE,
            stack_size: DEFAULT_STACK_SIZE,
            page_table_size: DEFAULT_PAGE_TABLE_SIZE,
            dma_size: DEFAULT_DMA_SIZE,
            #[cfg(feature = "cet-shstk")]
            shadow_stack_size: DEFAULT_SHADOW_STACK_SIZE,
        }
    }
}

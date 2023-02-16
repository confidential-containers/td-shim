// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_std]

//! Define file (build-time) and runtime layout for shim binary.
//!
//! Note:
//! `repr(C)` should be used to control the exact data structure layout.
//! - `repr(rust)`: By default, composite structures have an alignment equal to the maximum of their
//!   fields' alignments. Rust will consequently insert padding where necessary to ensure that all
//!   fields are properly aligned and that the overall type's size is a multiple of its alignment.
//!   And fields may be reordered, not following the literal order of fields.
//! - `repr(C)` is the most important repr. It has fairly simple intent: do what C does. The order,
//!   size, and alignment of fields is exactly what you would expect from C or C++. Any type you
//!   expect to pass through an FFI boundary should have repr(C), as C is the lingua-franca of the
//!   programming world. This is also necessary to soundly do more elaborate tricks with data layout
//!   such as reinterpreting values as a different type.

use memslice::SliceType;

pub mod build_time;
pub mod mailbox;
pub mod memslice;
pub mod runtime;

pub const TD_PAYLOAD_PARTIAL_ACCEPT_MEMORY_SIZE: u32 = 0x10000000;

const MAX_RUNTIME_LAYOUT_REGION: usize = 32;

pub type LayoutConfig = (&'static str, usize, &'static str);

#[derive(Clone, Copy, Debug)]
pub struct LayoutRegion {
    pub name: &'static str,
    pub base_address: usize,
    pub size: usize,
    pub r#type: &'static str,
}

impl Default for LayoutRegion {
    fn default() -> Self {
        Self {
            name: "Unknown",
            base_address: 0,
            size: 0,
            r#type: "Unknown",
        }
    }
}

pub struct RuntimeMemoryLayout {
    regions: [LayoutRegion; MAX_RUNTIME_LAYOUT_REGION],
    used_num: usize,
}

impl RuntimeMemoryLayout {
    pub fn new(tolm: usize, config: &[LayoutConfig]) -> Option<Self> {
        let total_size = config.iter().map(|item| item.1).sum();
        if config.len() > MAX_RUNTIME_LAYOUT_REGION || tolm < total_size {
            return None;
        }

        let mut regions = [LayoutRegion::default(); MAX_RUNTIME_LAYOUT_REGION];
        let mut used_num = 0;
        let mut bottom = 0;
        let mut top = tolm;
        for (idx, item) in config.iter().enumerate() {
            regions[idx].name = item.0;
            regions[idx].size = item.1;
            regions[idx].r#type = item.2;

            if regions[idx].r#type == "Memory" {
                regions[idx].base_address = bottom;
                bottom += regions[idx].size;
            } else {
                regions[idx].base_address = top - regions[idx].size;
                top = regions[idx].base_address;
            }

            used_num += 1;
        }

        Some(Self { regions, used_num })
    }

    pub fn regions(&self) -> &[LayoutRegion] {
        &self.regions.as_slice()[..self.used_num]
    }

    pub fn get_region(&self, name: SliceType) -> Option<LayoutRegion> {
        self.regions
            .iter()
            .find(|item| item.name == name.as_str())
            .map(|region| *region)
    }

    pub unsafe fn get_mem_slice(&self, name: SliceType) -> Option<&'static [u8]> {
        let region = self.get_region(name)?;
        unsafe {
            Some(core::slice::from_raw_parts(
                region.base_address as *const u8,
                region.size,
            ))
        }
    }

    pub unsafe fn get_mem_slice_mut(&self, name: SliceType) -> Option<&'static mut [u8]> {
        let region = self.get_region(name)?;
        unsafe {
            Some(core::slice::from_raw_parts_mut(
                region.base_address as *mut u8,
                region.size,
            ))
        }
    }
}

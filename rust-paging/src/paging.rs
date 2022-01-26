// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::cmp::min;
use log::{info, trace};
use x86_64::{
    structures::paging::PageTableFlags as Flags,
    structures::paging::{
        mapper::MappedFrame, mapper::TranslateResult, Mapper, OffsetPageTable, Page, PageSize,
        PhysFrame, Size1GiB, Size2MiB, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

use super::frame::{BMFrameAllocator, FRAME_ALLOCATOR};
use rust_td_layout::runtime::TD_PAYLOAD_PAGE_TABLE_BASE;

const ALIGN_4K_BITS: u64 = 12;
const ALIGN_4K: u64 = 1 << ALIGN_4K_BITS;
const ALIGN_2M_BITS: u64 = 21;
const ALIGN_2M: u64 = 1 << ALIGN_2M_BITS;
const ALIGN_1G_BITS: u64 = 30;
const ALIGN_1G: u64 = 1 << ALIGN_1G_BITS;

/// Create page table entries to map `[va, va + sz)` to `[pa, ps + sz)` with page size `ps` and
/// page attribute `flags`.
///
/// # Panic
/// - `pa + sz` wraps around.
/// - `va + sz` wraps around.
/// - `pa`, `va` or `sz` is not page aligned.
pub fn create_mapping_with_flags(
    pt: &mut OffsetPageTable,
    mut pa: PhysAddr,
    mut va: VirtAddr,
    ps: u64,
    mut sz: u64,
    flags: Flags,
) {
    let allocator: &mut BMFrameAllocator = &mut FRAME_ALLOCATOR.lock();

    while sz > 0 {
        let addr_align = min(
            ps.trailing_zeros(),
            min(pa.as_u64().trailing_zeros(), va.as_u64().trailing_zeros()),
        ) as u64;
        let mapped_size = if addr_align >= ALIGN_1G_BITS && sz >= ALIGN_1G {
            trace!(
                "1GB {} {:016x} /{:016x} {:016x}\n",
                addr_align,
                sz,
                pa.as_u64(),
                va.as_u64()
            );
            type S = Size1GiB;
            let page: Page<S> = Page::containing_address(va);
            let frame: PhysFrame<S> = PhysFrame::containing_address(pa);
            unsafe {
                pt.map_to(page, frame, flags, allocator)
                    .expect("map_to failed")
                    .flush();
            }
            S::SIZE
        } else if addr_align >= ALIGN_2M_BITS && sz >= ALIGN_2M {
            trace!(
                "2MB {} {:016x} /{:016x} {:016x}\n",
                addr_align,
                sz,
                pa.as_u64(),
                va.as_u64()
            );
            type S = Size2MiB;
            let page: Page<S> = Page::containing_address(va);
            let frame: PhysFrame<S> = PhysFrame::containing_address(pa);
            unsafe {
                pt.map_to(page, frame, flags, allocator)
                    .expect("map_to failed")
                    .flush();
            }
            S::SIZE
        } else {
            trace!(
                "4KB {} {:016x} /{:016x} {:016x}\n",
                addr_align,
                sz,
                pa.as_u64(),
                va.as_u64()
            );
            type S = Size4KiB;
            let page: Page<S> = Page::containing_address(va);
            let frame: PhysFrame<S> = PhysFrame::containing_address(pa);
            unsafe {
                pt.map_to(page, frame, flags, allocator)
                    .expect("map_to failed")
                    .flush();
            }
            S::SIZE
        };

        sz -= mapped_size;
        pa += mapped_size;
        va += mapped_size;
    }
}

/// Create page table entries to map `[va, va + sz)` to `[pa, ps + sz)` with page size `ps` and
/// mark pages as `PRESENT | WRITABLE`.
///
/// Note: the caller must ensure `pa + sz` and `va + sz` doesn't wrap around.
pub fn create_mapping(pt: &mut OffsetPageTable, pa: PhysAddr, va: VirtAddr, ps: u64, sz: u64) {
    let flags = Flags::PRESENT | Flags::WRITABLE;

    create_mapping_with_flags(pt, pa, va, ps, sz, flags)
}

/// Write physical address of level 4 page table page to `CR3`.
pub fn cr3_write() {
    unsafe {
        x86::controlregs::cr3_write(TD_PAYLOAD_PAGE_TABLE_BASE);
    }
    log::info!("Cr3 - {:x}\n", unsafe { x86::controlregs::cr3() });
}

/// Modify page flags for all 4K PTEs for virtual address range [va, va + sz), stops at the first
/// whole.
pub fn set_page_flags(pt: &mut OffsetPageTable, mut va: VirtAddr, mut size: i64, flag: Flags) {
    let mut page_size: u64;

    while size > 0 {
        if let TranslateResult::Mapped { frame, .. } = pt.translate(va) {
            match frame {
                MappedFrame::Size4KiB(..) => {
                    type S = Size4KiB;
                    page_size = S::SIZE;
                    let page: Page<S> = Page::containing_address(va);
                    unsafe {
                        pt.update_flags(page, flag).unwrap().flush();
                    }
                }
                MappedFrame::Size2MiB(..) => {
                    type S = Size2MiB;
                    page_size = S::SIZE;
                }
                MappedFrame::Size1GiB(..) => {
                    type S = Size1GiB;
                    page_size = S::SIZE;
                }
            }
        } else {
            break;
        }
        size -= page_size as i64;
        va += page_size;
    }
}

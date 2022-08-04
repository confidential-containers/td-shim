// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::cmp::min;
use log::{info, trace};
use x86_64::{
    structures::paging::{mapper::MapToError, PageTableFlags as Flags},
    structures::paging::{
        mapper::MappedFrame, mapper::TranslateResult, Mapper, OffsetPageTable, Page, PageSize,
        PhysFrame, Size1GiB, Size2MiB, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

use super::frame::{BMFrameAllocator, FRAME_ALLOCATOR};
use crate::{Error, Result};

const ALIGN_4K_BITS: u64 = 12;
const ALIGN_4K: u64 = 1 << ALIGN_4K_BITS;
const ALIGN_2M_BITS: u64 = 21;
const ALIGN_2M: u64 = 1 << ALIGN_2M_BITS;
const ALIGN_1G_BITS: u64 = 30;
const ALIGN_1G: u64 = 1 << ALIGN_1G_BITS;

/// Write physical address of level 4 page table page to `CR3`.
pub fn cr3_write(addr: u64) {
    unsafe {
        x86::controlregs::cr3_write(addr);
    }
    info!("Cr3 - {:x}\n", unsafe { x86::controlregs::cr3() });
}

// Map a frame of size S from physical address
// to virtual address
fn map_page<'a, S: PageSize>(
    pt: &mut OffsetPageTable<'a>,
    pa: PhysAddr,
    va: VirtAddr,
    flags: Flags,
    allocator: &mut BMFrameAllocator,
) -> Result<()>
where
    OffsetPageTable<'a>: Mapper<S>,
{
    let page: Page<S> = Page::containing_address(va);
    let frame: PhysFrame<S> = PhysFrame::containing_address(pa);
    trace!(
        "Mapping {:016x} to {:016x} with granularity: {:x}\n",
        pa.as_u64(),
        va.as_u64(),
        S::SIZE,
    );
    unsafe {
        match pt.map_to(page, frame, flags, allocator) {
            Ok(mapper) => mapper.flush(),
            Err(e) => match e {
                MapToError::PageAlreadyMapped(_) => {}
                _ => return Err(Error::MappingError(pa.as_u64(), S::SIZE)),
            },
        }
    }

    Ok(())
}

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
) -> Result<()> {
    let allocator: &mut BMFrameAllocator = &mut FRAME_ALLOCATOR.lock();

    if pa.as_u64().checked_add(sz).is_none()
        || va.as_u64().checked_add(sz).is_none()
        || pa.as_u64() & (ALIGN_4K - 1) != 0
        || va.as_u64() & (ALIGN_4K - 1) != 0
        || sz & (ALIGN_4K - 1) != 0
        || ps.count_ones() != 1
        || ps < ALIGN_4K as u64
    {
        return Err(Error::InvalidArguments);
    }

    while sz > 0 {
        let addr_align = min(
            ps.trailing_zeros(),
            min(pa.as_u64().trailing_zeros(), va.as_u64().trailing_zeros()),
        ) as u64;
        let mapped_size = if addr_align >= ALIGN_1G_BITS && sz >= ALIGN_1G {
            map_page::<Size1GiB>(pt, pa, va, flags, allocator)?;
            Size1GiB::SIZE
        } else if addr_align >= ALIGN_2M_BITS && sz >= ALIGN_2M {
            map_page::<Size2MiB>(pt, pa, va, flags, allocator)?;
            Size2MiB::SIZE
        } else {
            map_page::<Size4KiB>(pt, pa, va, flags, allocator)?;
            Size4KiB::SIZE
        };

        sz -= mapped_size;
        pa += mapped_size;
        va += mapped_size;
    }

    Ok(())
}

/// Create page table entries to map `[va, va + sz)` to `[pa, ps + sz)` with page size `ps` and
/// mark pages as `PRESENT | WRITABLE`.
///
/// Note: the caller must ensure `pa + sz` and `va + sz` doesn't wrap around.
pub fn create_mapping(
    pt: &mut OffsetPageTable,
    pa: PhysAddr,
    va: VirtAddr,
    ps: u64,
    sz: u64,
) -> Result<()> {
    let flags = Flags::PRESENT | Flags::WRITABLE;

    create_mapping_with_flags(pt, pa, va, ps, sz, flags)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frame, init, PAGE_SIZE_4K, PHYS_VIRT_OFFSET};
    use x86_64::structures::paging::PageTable;

    const TD_PAYLOAD_PAGE_TABLE_BASE: u64 = 0x800000;
    const PAGE_TABLE_SIZE: usize = 0x800000;

    fn create_pt(base: u64, offset: u64) -> OffsetPageTable<'static> {
        let pt = unsafe {
            OffsetPageTable::new(&mut *(base as *mut PageTable), VirtAddr::new(offset as u64))
        };
        frame::FRAME_ALLOCATOR.lock().reserve(base);

        pt
    }

    #[test]
    #[should_panic]
    fn test_invalid_pa_sz() {
        init(TD_PAYLOAD_PAGE_TABLE_BASE, PAGE_TABLE_SIZE).unwrap();
        let mut pt = create_pt(TD_PAYLOAD_PAGE_TABLE_BASE, PHYS_VIRT_OFFSET as u64);
        assert!(create_mapping(
            &mut pt,
            PhysAddr::new(0x1000000),
            VirtAddr::new(0),
            PAGE_SIZE_4K as u64,
            u64::MAX,
        )
        .is_ok())
    }

    #[test]
    #[should_panic]
    fn test_invalid_va_sz() {
        init(TD_PAYLOAD_PAGE_TABLE_BASE, PAGE_TABLE_SIZE).unwrap();
        let mut pt = create_pt(TD_PAYLOAD_PAGE_TABLE_BASE, PHYS_VIRT_OFFSET as u64);
        assert!(create_mapping(
            &mut pt,
            PhysAddr::new(0x0),
            VirtAddr::new(0x1000000),
            PAGE_SIZE_4K as u64,
            u64::MAX,
        )
        .is_ok());
    }
}

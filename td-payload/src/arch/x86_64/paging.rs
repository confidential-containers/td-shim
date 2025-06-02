// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ops::{Index, IndexMut};

use paging::PageTableFlags as Flags;
use td_layout::build_time;
use td_paging::cr3_write;
use td_shim::e820::E820Entry;
use x86_64::{
    registers::control::{Cr0, Cr0Flags, Cr3},
    structures::paging::{
        self,
        mapper::{MappedFrame, TranslateResult},
        FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageSize, PageTable,
        PageTableIndex, PhysFrame, Size1GiB, Size2MiB, Size4KiB, Translate,
    },
    PhysAddr, VirtAddr,
};

use crate::{
    mm::page_table::{alloc_pt_frame, free_pt_frame},
    Error,
};

struct FrameAlloc;

unsafe impl FrameAllocator<Size4KiB> for FrameAlloc {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let addr = unsafe { alloc_pt_frame()? };
        Some(PhysFrame::containing_address(
            PhysAddr::try_new(addr as u64).ok()?,
        ))
    }
}

impl FrameDeallocator<Size4KiB> for FrameAlloc {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        free_pt_frame(frame.start_address().as_u64() as usize)
    }
}

// Create 1:1 mapping for physical and virtual memory
pub fn setup_paging(memory_map: &[E820Entry]) -> Result<(), Error> {
    let pml4 = unsafe { alloc_pt_frame().ok_or(Error::SetupPageTable)? };

    // Create an offset page table instance to manage the paging
    let mut pt = unsafe { OffsetPageTable::new(&mut *(pml4 as *mut PageTable), VirtAddr::new(0)) };

    for entry in memory_map {
        if entry.size == 0 {
            break;
        }

        identity_map(&mut pt, entry.addr, entry.size)?;
    }
    identity_map(
        &mut pt,
        build_time::TD_SHIM_FIRMWARE_BASE as u64,
        build_time::TD_SHIM_FIRMWARE_SIZE as u64,
    )?;

    cr3_write(pml4 as u64);
    Ok(())
}

pub fn identity_map(pt: &mut OffsetPageTable, address: u64, size: u64) -> Result<(), Error> {
    let mut frame_allocator = FrameAlloc {};

    if address.checked_add(size).is_none()
        || address % Size4KiB::SIZE != 0
        || size % Size4KiB::SIZE != 0
    {
        return Err(Error::SetupPageTable);
    }

    let nframes = size / Size4KiB::SIZE;

    for frame in 0..nframes {
        let addr = address + frame * Size4KiB::SIZE;
        identity_map_page::<Size4KiB>(
            pt,
            addr,
            Flags::PRESENT | Flags::WRITABLE,
            &mut frame_allocator,
        )
        .map_err(|_| Error::SetupPageTable)?;
    }

    Ok(())
}

fn identity_map_page<'a, S: PageSize>(
    pt: &mut OffsetPageTable<'a>,
    address: u64,
    flags: Flags,
    frame_allocator: &mut FrameAlloc,
) -> Result<(), Error>
where
    OffsetPageTable<'a>: Mapper<S>,
{
    let frame: PhysFrame<S> = PhysFrame::containing_address(PhysAddr::new(address));

    unsafe {
        pt.identity_map(frame, flags, frame_allocator)
            .map(|mapper| mapper.flush())
            .map_err(|_| Error::SetupPageTable)
    }
}

pub fn set_nx(address: u64, size: usize) {
    let mut pt = offset_pt();
    let flags = Flags::PRESENT | Flags::WRITABLE | Flags::NO_EXECUTE;

    set_page_flags(&mut pt, address, size, flags);
}

pub fn set_wp(address: u64, size: usize) {
    let mut pt = offset_pt();
    let flags = Flags::PRESENT;

    set_page_flags(&mut pt, address, size, flags);
    enable_wp();
}

pub fn set_not_present(address: u64, size: usize) {
    let mut pt = offset_pt();
    let flags: Flags = Flags::empty();

    set_page_flags(&mut pt, address, size, flags);
}

#[cfg(feature = "tdx")]
pub fn set_shared_bit(address: u64, size: usize) {
    let mut pt = offset_pt();
    map_shared(&mut pt, address, size, true);
}

#[cfg(feature = "tdx")]
pub fn clear_shared_bit(address: u64, size: usize) {
    let mut pt = offset_pt();
    map_shared(&mut pt, address, size, false);
}

pub fn enable_wp() {
    unsafe {
        let cr0 = Cr0::read();
        if (cr0 & Cr0Flags::WRITE_PROTECT).bits() != 0 {
            return;
        }

        Cr0::write(cr0 | Cr0Flags::WRITE_PROTECT);
    }
}

pub fn disable_wp() {
    unsafe {
        let cr0 = Cr0::read();
        if (cr0 & Cr0Flags::WRITE_PROTECT).bits() == 0 {
            return;
        }

        Cr0::write(Cr0::read() & !Cr0Flags::WRITE_PROTECT);
    }
}

fn offset_pt() -> OffsetPageTable<'static> {
    let cr3 = Cr3::read().0.start_address().as_u64();
    let pt = unsafe { OffsetPageTable::new(&mut *(cr3 as *mut PageTable), VirtAddr::new(0)) };

    pt
}

pub(crate) fn set_page_flags(pt: &mut OffsetPageTable, va: u64, size: usize, flag: Flags) {
    let end = va + size as u64;
    let mut va = VirtAddr::new(va);

    while va.as_u64() < end {
        if let TranslateResult::Mapped { frame, .. } = pt.translate(va) {
            unsafe {
                match frame {
                    MappedFrame::Size4KiB(..) => {
                        pt.update_flags(Page::<Size4KiB>::containing_address(va), flag)
                            .unwrap()
                            .flush();
                    }
                    MappedFrame::Size2MiB(..) => {
                        pt.update_flags(Page::<Size2MiB>::containing_address(va), flag)
                            .unwrap()
                            .flush();
                    }
                    MappedFrame::Size1GiB(..) => {
                        pt.update_flags(Page::<Size1GiB>::containing_address(va), flag)
                            .unwrap()
                            .flush();
                    }
                }
            }
            va = VirtAddr::new(va.as_u64().checked_add(frame.size()).unwrap())
        } else {
            break;
        }
    }
}

#[cfg(feature = "tdx")]
fn map_shared(pt: &mut OffsetPageTable, va: u64, size: usize, shared: bool) {
    let end = va + size as u64;
    let mut va = VirtAddr::new(va);

    while va.as_u64() < end {
        if let TranslateResult::Mapped { frame, .. } = pt.translate(va) {
            pt_set_shared_bit(pt, &Page::containing_address(va), shared);
            va = VirtAddr::new(va.as_u64().checked_add(frame.size()).unwrap())
        } else {
            break;
        }
    }
}

#[cfg(feature = "tdx")]
fn pt_set_shared_bit(pt: &mut OffsetPageTable, page: &Page, shared: bool) {
    let p4 = pt.level_4_table();
    let p3 = unsafe { &mut *(p4.index(page.p4_index()).addr().as_u64() as *mut PageTable) };

    if page.size() == Size1GiB::SIZE {
        pt_entry_set_shared_bit(p3, page.p3_index(), shared);
    }

    let p2 = unsafe { &mut *(p3.index(page.p3_index()).addr().as_u64() as *mut PageTable) };
    if page.size() == Size2MiB::SIZE {
        pt_entry_set_shared_bit(p2, page.p2_index(), shared);
    }

    let p1 = unsafe { &mut *(p2.index(page.p2_index()).addr().as_u64() as *mut PageTable) };
    if page.size() == Size4KiB::SIZE {
        pt_entry_set_shared_bit(p1, page.p1_index(), shared);
    }
}

#[cfg(feature = "tdx")]
fn pt_entry_set_shared_bit(page_table: &mut PageTable, index: PageTableIndex, shared: bool) {
    let entry = page_table.index(index);
    let shared_bit = tdx_tdcall::tdx::td_shared_mask().expect("Failed to get shared bit of GPA");

    let addr = if shared {
        entry.addr().as_u64() | shared_bit
    } else {
        entry.addr().as_u64() & !shared_bit
    };
    let flags = entry.flags();

    page_table
        .index_mut(index)
        .set_addr(PhysAddr::new(addr), flags);
}

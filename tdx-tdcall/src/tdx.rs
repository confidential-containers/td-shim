// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::result::Result;
use core::sync::atomic::{fence, Ordering};
use lazy_static::lazy_static;

extern "win64" {
    pub fn td_call(Leaf: u64, P1: u64, P2: u64, P3: u64, Results: u64) -> u64;
    pub fn td_vm_call(
        Leaf: u64,
        P1: u64,
        P2: u64,
        P3: u64,
        P4: u64,
        Val: *mut core::ffi::c_void,
    ) -> u64;
}

// const TDCALL_TDVMCALL: u64 = 0;
const TDCALL_TDINFO: u64 = 1;
const TDCALL_TDEXTENDRTMR: u64 = 2;
const TDCALL_TDGETVEINFO: u64 = 3;
// const TDCALL_TDSETCPUIDVE: u64 = 5;
const TDCALL_TDACCEPTPAGE: u64 = 6;

const TDVMCALL_MAPGPA: u64 = 0x10001;
// const TDVMCALL_CPUID: u64 = 0x0000a;
const TDVMCALL_HALT: u64 = 0x0000c;
const TDVMCALL_IO: u64 = 0x0001e;
// const TDVMCALL_RDMSR: u64 = 0x0001f;
// const TDVMCALL_WRMSR: u64 = 0x00020;
const TDVMCALL_MMIO: u64 = 0x00030;

const IO_READ: u64 = 0;
const IO_WRITE: u64 = 1;

pub const TDX_EXIT_REASON_SUCCESS: u64 = 0;
const TDX_EXIT_REASON_PAGE_ALREADY_ACCEPTED: u64 = 0x00000B0A00000000;
const TDX_EXIT_REASON_PAGE_SIZE_MISMATCH: u64 = 0xC0000B0B00000000;

pub const EXIT_REASON_CPUID: u32 = 10;
pub const EXIT_REASON_HLT: u32 = 12;
pub const EXIT_REASON_IO_INSTRUCTION: u32 = 30;
pub const EXIT_REASON_MSR_READ: u32 = 31;
pub const EXIT_REASON_MSR_WRITE: u32 = 32;
pub const EXIT_REASON_EPT_VIOLATION: u32 = 48;
pub const EXIT_REASON_VMCALL: u32 = 18;
pub const EXIT_REASON_MWAIT_INSTRUCTION: u32 = 36;
pub const EXIT_REASON_MONITOR_INSTRUCTION: u32 = 39;
pub const EXIT_REASON_WBINVD: u32 = 54;
pub const EXIT_REASON_RDPMC: u32 = 15;

const TDVMCALL_STATUS_SUCCESS: u64 = 0;

lazy_static! {
    static ref SHARED_MASK: u64 = td_shared_page_mask();
}

#[repr(align(64))]
pub struct TdxDigest {
    pub data: [u8; 48],
}

#[repr(C)]
pub struct TdCallGenericReturnData {
    pub data: [u64; 6],
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct TdInfoReturnData {
    pub gpaw: u64,
    pub attributes: u64,
    pub max_vcpus: u32,
    pub num_vcpus: u32,
    pub rsvd: [u64; 3],
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct TdVeInfoReturnData {
    pub exit_reason: u32,
    pub rsvd: u32,
    pub exit_qualification: u64,
    pub guest_la: u64,
    pub guest_pa: u64,
    pub exit_instruction_length: u32,
    pub exit_instruction_info: u32,
    pub rsvd1: u64,
}

#[derive(PartialEq)]
pub enum TdCallError {
    TdxExitReasonPageAlreadyAccepted,
    TdxExitReasonPageSizeMismatch,
    TdxExitReasonOperandInvalid,
    TdxExitReasonOperandBusy,
}

pub fn tdvmcall_halt() {
    unsafe { td_vm_call(TDVMCALL_HALT, 0, 0, 0, 0, core::ptr::null_mut()) };
}

pub fn tdvmcall_io_read_8(port: u16) -> u8 {
    let mut val: u64 = 0;
    let ret = unsafe {
        td_vm_call(
            TDVMCALL_IO,
            core::mem::size_of::<u8>() as u64,
            IO_READ,
            port as u64,
            0,
            &mut val as *mut u64 as *mut core::ffi::c_void,
        )
    };
    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
    val as u8
}

pub fn tdvmcall_io_read_32(port: u16) -> u32 {
    let mut val: u64 = 0;
    let ret = unsafe {
        td_vm_call(
            TDVMCALL_IO,
            core::mem::size_of::<u32>() as u64,
            IO_READ,
            port as u64,
            0,
            &mut val as *mut u64 as *mut core::ffi::c_void,
        )
    };
    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
    val as u32
}

pub fn tdvmcall_io_write_8(port: u16, byte: u8) {
    let ret = unsafe {
        td_vm_call(
            TDVMCALL_IO,
            core::mem::size_of::<u8>() as u64,
            IO_WRITE,
            port as u64,
            byte as u64,
            core::ptr::null_mut(),
        )
    };
    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

pub fn tdvmcall_io_write_32(port: u16, byte: u32) {
    let ret = unsafe {
        td_vm_call(
            TDVMCALL_IO,
            core::mem::size_of::<u32>() as u64,
            IO_WRITE,
            port as u64,
            byte as u64,
            core::ptr::null_mut(),
        )
    };
    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

pub fn tdcall_get_td_info(td_info: &mut TdInfoReturnData) {
    let buffer: u64 = td_info as *mut TdInfoReturnData as *mut core::ffi::c_void as usize as u64;
    log::info!("td_info data addr: 0x{:x}\n", buffer);

    let ret = unsafe { td_call(TDCALL_TDINFO, 0, 0, 0, buffer) };
    if ret != TDX_EXIT_REASON_SUCCESS {
        tdvmcall_halt();
    }
}

pub fn tdcall_extend_rtmr(digest: &TdxDigest, mr_index: u32) {
    let buffer: u64 = &digest.data as *const u8 as *const core::ffi::c_void as usize as u64;
    log::info!("rtmr data addr: 0x{:x}\n", buffer);

    let ret = unsafe { td_call(TDCALL_TDEXTENDRTMR, buffer, mr_index as u64, 0, 0) };
    if ret != TDX_EXIT_REASON_SUCCESS {
        tdvmcall_halt();
    }
}

pub fn tdcall_get_ve_info(ve_info: &mut TdVeInfoReturnData) {
    let buffer: u64 = ve_info as *mut TdVeInfoReturnData as *mut core::ffi::c_void as usize as u64;

    let ret = unsafe { td_call(TDCALL_TDGETVEINFO, 0, 0, 0, buffer) };
    if ret != TDX_EXIT_REASON_SUCCESS {
        tdvmcall_halt();
    }
}

pub fn tdcall_accept_page(address: u64) -> Result<(), TdCallError> {
    let ret = unsafe { td_call(TDCALL_TDACCEPTPAGE, address, 0, 0, 0) };
    if ret != TDX_EXIT_REASON_SUCCESS {
        if (ret & !0xffu64) == TDX_EXIT_REASON_PAGE_ALREADY_ACCEPTED {
            return Err(TdCallError::TdxExitReasonPageAlreadyAccepted);
        } else if (ret & !0xffu64) == TDX_EXIT_REASON_PAGE_SIZE_MISMATCH {
            return Err(TdCallError::TdxExitReasonPageSizeMismatch);
        } else {
            tdvmcall_halt();
        }
    }
    Ok(())
}

pub fn tdvmcall_mmio_write<T: Sized>(address: *const T, value: T) {
    let address = address as u64 | *SHARED_MASK;
    fence(Ordering::SeqCst);
    let ret = unsafe {
        let val = *(&value as *const T as *const u64);
        td_vm_call(
            TDVMCALL_MMIO,
            core::mem::size_of::<T>() as u64,
            IO_WRITE,
            address,
            val,
            core::ptr::null_mut(),
        )
    };
    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

pub fn tdvmcall_mmio_read<T: Clone + Copy + Sized>(address: usize) -> T {
    let mut val = 0u64;
    let address = address as u64 | *SHARED_MASK;
    fence(Ordering::SeqCst);
    let ret = unsafe {
        td_vm_call(
            TDVMCALL_MMIO,
            core::mem::size_of::<T>() as u64,
            IO_READ,
            address,
            0,
            &mut val as *mut u64 as *mut core::ffi::c_void,
        )
    };
    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
    unsafe { *(&val as *const u64 as *const T) }
}

pub fn td_shared_page_mask() -> u64 {
    let mut td_info = TdInfoReturnData::default();
    tdcall_get_td_info(&mut td_info);
    let gpaw = (td_info.gpaw & 0x3f) as u8;
    assert!((gpaw == 48 || gpaw == 52));
    1u64 << (gpaw - 1)
}

pub fn tdvmcall_mapgpa(paddress: u64, length: usize) {
    let paddr = paddress | *SHARED_MASK;
    let ret = unsafe {
        td_vm_call(
            TDVMCALL_MAPGPA,
            paddr,
            length as u64,
            0,
            0,
            core::ptr::null_mut(),
        )
    };
    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
    log::info!(
        "tdvmcall mapgpa - paddr: {:x}, length: {:x}\n",
        paddr,
        length
    );
}

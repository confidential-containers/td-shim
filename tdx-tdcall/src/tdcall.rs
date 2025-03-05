// Copyright (c) 2020-2022, 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Implemention of a subset of TDCALL functions defined in
//! Intel TDX Module v1.0 and v1.5 Spec.
//!
//! The TDCALL instruction causes a VM exit to the Intel TDX Module. It is used to call
//! guest-side Intel TDX functions, either local or a TD exit to the host VMM.

use core::result::Result;
use crate::*;

pub const PAGE_SIZE_4K: u64 = 0x1000;
pub const PAGE_SIZE_2M: u64 = 0x200000;
pub const TARGET_TD_UUID_NUM: usize = 4;

// Guest-Side (TDCALL) interface functions leaf numbers
pub const TDCALL_TDINFO: u64 = 1;
pub const TDCALL_TDEXTENDRTMR: u64 = 2;
pub const TDCALL_TDGETVEINFO: u64 = 3;
pub const TDCALL_TDREPORT: u64 = 4;
pub const TDCALL_TDACCEPTPAGE: u64 = 6;
pub const TDCALL_VM_RD: u64 = 7;
pub const TDCALL_VM_WR: u64 = 8;
pub const TDCALL_VP_RD: u64 = 9;
pub const TDCALL_VP_WR: u64 = 10;
pub const TDCALL_SYS_RD: u64 = 11;
pub const TDCALL_SERVTD_RD: u64 = 18;
pub const TDCALL_SERVTD_WR: u64 = 20;
pub const TDCALL_MEM_PAGE_ATTR_WR: u64 = 24;
pub const TDCALL_VP_ENTER: u64 = 25;
pub const TDCALL_VP_INVEPT: u64 = 26;
pub const TDCALL_VP_INVVPID: u64 = 27;

// TDCALL completion status code
pub const TDCALL_STATUS_SUCCESS: u64 = 0;

// leaf-specific completion status code
pub const TDCALL_STATUS_PAGE_ALREADY_ACCEPTED: u64 = 0x00000B0A00000000;
pub const TDCALL_STATUS_PAGE_SIZE_MISMATCH: u64 = 0xC0000B0B00000001;

/// SHA384 digest value extended to RTMR
/// Both alignment and size are 64 bytes.
#[repr(C, align(64))]
pub struct TdxDigest {
    pub data: [u8; 48],
}

/// Guest TD execution evironment returned from TDG.VP.INFO leaf
#[repr(C)]
#[derive(Debug, Default)]
pub struct TdInfo {
    pub gpaw: u64,
    pub attributes: u64,
    pub max_vcpus: u32,
    pub num_vcpus: u32,
    pub vcpu_index: u32,
    pub rsvd: [u32; 5],
}

/// Virtualization exception information returned from TDG.VP.VEINFO.GET leaf
#[repr(C)]
#[derive(Debug, Default)]
pub struct TdVeInfo {
    pub exit_reason: u32,
    pub rsvd: u32,
    pub exit_qualification: u64,
    pub guest_la: u64,
    pub guest_pa: u64,
    pub exit_instruction_length: u32,
    pub exit_instruction_info: u32,
    pub rsvd1: u64,
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct ServtdRWResult {
    pub content: u64,
    pub uuid: [u64; 4],
}

// Wrapper for use of asm_td_call, this function takes a mutable reference of a
// TdVmcallArgs structure to ensure the input is valid
//
// ## TDCALL ABI
// Defined in TDX Module 1.0 Spec section 'TDCALL Instruction (Common)'
//
// ### Input Operands:
//  * RAX - Leaf and version numbers.
//  * Other - Used by leaf functions as input values.
//
// ### Output Operands:
//  * RAX - Instruction return code.
//  * Other - Used by leaf functions as output values.
//
pub fn td_call(args: &mut TdcallArgs) -> u64 {
    unsafe { asm::asm_td_call(args as *mut TdcallArgs as *mut c_void) }
}

// Used to pass the values of input/output register when performing TDCALL
// instruction
#[repr(C)]
#[derive(Default)]
pub struct TdcallArgs {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
}

/// TDCALL instruction return error code
///
/// Refer to Intel TDX Module 1.0 Specifiction section 'TDCALL Instruction (Common)'
#[derive(Debug, PartialEq)]
pub enum TdCallError {
    // Invalid parameters
    TdxExitInvalidParameters,

    // The operand is busy (e.g., it is locked in Exclusive mode)
    TdxExitReasonOperandBusy(u32),

    // Operand is invalid (e.g., illegal leaf number)
    TdxExitReasonOperandInvalid(u32),

    // Error code defined by individual leaf function
    LeafSpecific(u64),
}

// TDCALL Completion Status Codes (Returned in RAX) Definition
impl From<u64> for TdCallError {
    fn from(val: u64) -> Self {
        match val >> 32 {
            0x8000_0200 => Self::TdxExitReasonOperandBusy(val as u32),
            0xC000_0100 => Self::TdxExitReasonOperandInvalid(val as u32),
            _ => Self::LeafSpecific(val),
        }
    }
}

/// Get guest TD execution environment information
///
/// Details can be found in TDX Module ABI spec section 'TDG.VP.INFO Leaf'
pub fn get_td_info() -> Result<TdInfo, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_TDINFO,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    let td_info = TdInfo {
        gpaw: args.rcx & 0x3f,
        attributes: args.rdx,
        max_vcpus: (args.r8 >> 32) as u32,
        num_vcpus: args.r8 as u32,
        vcpu_index: args.r9 as u32,
        ..Default::default()
    };

    Ok(td_info)
}

/// Extend a TDCS.RTMR measurement register
///
/// Details can be found in TDX Module ABI spec section 'TDG.VP.INFO Leaf'
pub fn extend_rtmr(digest: &TdxDigest, mr_index: u32) -> Result<(), TdCallError> {
    let buffer: u64 = core::ptr::addr_of!(digest.data) as u64;

    let mut args = TdcallArgs {
        rax: TDCALL_TDEXTENDRTMR,
        rcx: buffer,
        rdx: mr_index as u64,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Get virtualization exception information for the recent #VE
///
/// Details can be found in TDX Module ABI spec section 'TDG.VP.VEINFO.GET Leaf'
pub fn get_ve_info() -> Result<TdVeInfo, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_TDGETVEINFO,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    let ve_info = TdVeInfo {
        exit_reason: args.rcx as u32,
        exit_qualification: args.rdx,
        guest_la: args.r8,
        guest_pa: args.r9,
        exit_instruction_length: args.r10 as u32,
        exit_instruction_info: (args.r10 >> 32) as u32,
        ..Default::default()
    };

    Ok(ve_info)
}

/// Accept a pending private page, and initialize the page to zeros using the TD ephemeral
/// private key
///
/// Details can be found in TDX Module ABI spec section 'TDG.MEM.PAGE.Accept Leaf'
pub fn accept_page(address: u64) -> Result<(), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_TDACCEPTPAGE,
        rcx: address,
        ..Default::default()
    };

    const MAX_RETRIES_ACCEPT_PAGE: usize = 5;
    let mut retry_counter = 0;
    let mut ret = 0;

    while retry_counter < MAX_RETRIES_ACCEPT_PAGE {
        ret = td_call(&mut args);

        if ret == TDCALL_STATUS_SUCCESS {
            return Ok(());
        } else {
            match TdCallError::from(ret) {
                TdCallError::TdxExitReasonOperandBusy(_) => retry_counter += 1,
                e => return Err(e),
            }
        }
    }

    Err(ret.into())
}

/// Accept a range of private pages and initialize the pages to zeros using the TD ephemeral
/// private key.
///
/// This function is a wrapper to `accept_page()`.
pub fn td_accept_pages(address: u64, pages: u64, page_size: u64) {
    for i in 0..pages {
        let accept_addr = address + i * page_size;
        let accept_level = if page_size == PAGE_SIZE_2M { 1 } else { 0 };
        match accept_page(accept_addr | accept_level) {
            Ok(()) => {}
            Err(e) => {
                if let TdCallError::LeafSpecific(error_code) = e {
                    if error_code == TDCALL_STATUS_PAGE_SIZE_MISMATCH {
                        if page_size == PAGE_SIZE_2M {
                            td_accept_pages(accept_addr, 512, PAGE_SIZE_4K);
                            continue;
                        }
                    } else if error_code == TDCALL_STATUS_PAGE_ALREADY_ACCEPTED {
                        continue;
                    }
                }
                panic!(
                    "Accept Page Error: 0x{:x}, page_size: {}, err {:x?}\n",
                    accept_addr, page_size, e
                );
            }
        }
    }
}

/// Accept a range of either 4K normal pages or 2M huge pages. This is basically a wrapper over
/// td_accept_pages and initializes the pages to zero using the TD ephemeral private key.
pub fn td_accept_memory(address: u64, len: u64) {
    let mut start = address;
    let end = address + len;

    while start < end {
        let remaining = end - start;

        // Try larger accepts first to keep 1G/2M Secure EPT entries
        // where possible and speeds up process by cutting number of
        // tdcalls (if successful).
        if remaining >= PAGE_SIZE_2M && (start & (PAGE_SIZE_2M - 1)) == 0 {
            let npages = remaining >> 21;
            td_accept_pages(start, npages, PAGE_SIZE_2M);
            start += npages << 21;
        } else if remaining >= PAGE_SIZE_4K && (start & (PAGE_SIZE_4K - 1)) == 0 {
            let mut npages = remaining >> 12;
            // Try to consume in 4K chunks until 2M aligned.
            if remaining >= PAGE_SIZE_2M {
                npages = (PAGE_SIZE_2M - (start & (PAGE_SIZE_2M - 1))) >> 12;
            }
            td_accept_pages(start, npages, PAGE_SIZE_4K);
            start += npages << 12;
        } else {
            panic!("Accept Memory Error: 0x{:x}, length: {}\n", address, len);
        }
    }
}

/// Get the guest physical address (GPA) width via TDG.VP.INFO
/// The GPA width can be used to determine the shared-bit of GPA
pub fn td_shared_mask() -> Option<u64> {
    let td_info = get_td_info().ok()?;
    let gpaw = (td_info.gpaw & 0x3f) as u8;

    // Detail can be found in TDX Module v1.5 ABI spec section 'TDVPS(excluding TD VMCS)'.
    if gpaw == 48 || gpaw == 52 {
        Some(1u64 << (gpaw - 1))
    } else {
        None
    }
}

/// Used by a service TD to read a metadata field (control structure field) of
/// a target TD.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.SERVTD.RD Leaf'.
pub fn servtd_rd(
    binding_handle: u64,
    field_identifier: u64,
    target_td_uuid: &[u64],
) -> Result<ServtdRWResult, TdCallError> {
    if target_td_uuid.len() != TARGET_TD_UUID_NUM {
        return Err(TdCallError::TdxExitInvalidParameters);
    }

    let mut args = TdcallArgs {
        rax: TDCALL_SERVTD_RD,
        rcx: binding_handle,
        rdx: field_identifier,
        r10: target_td_uuid[0],
        r11: target_td_uuid[1],
        r12: target_td_uuid[2],
        r13: target_td_uuid[3],
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    let sertd_rw_result = ServtdRWResult {
        content: args.r8,
        uuid: [args.r10, args.r11, args.r12, args.r13],
    };

    Ok(sertd_rw_result)
}

/// Used by a service TD to write a metadata field (control structure field) of
/// a target TD.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.SERVTD.RD Leaf'.
pub fn servtd_wr(
    binding_handle: u64,
    field_identifier: u64,
    data: u64,
    target_td_uuid: &[u64],
) -> Result<ServtdRWResult, TdCallError> {
    if target_td_uuid.len() != TARGET_TD_UUID_NUM {
        return Err(TdCallError::TdxExitInvalidParameters);
    }

    let mut args = TdcallArgs {
        rax: TDCALL_SERVTD_WR,
        rcx: binding_handle,
        rdx: field_identifier,
        r8: data,
        r9: u64::MAX,
        r10: target_td_uuid[0],
        r11: target_td_uuid[1],
        r12: target_td_uuid[2],
        r13: target_td_uuid[3],
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    let result = ServtdRWResult {
        content: args.r8,
        uuid: [args.r10, args.r11, args.r12, args.r13],
    };

    Ok(result)
}

/// Used to read a TDX Module global-scope metadata field.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.SYS.RD Leaf'.
pub fn sys_rd(field_identifier: u64) -> core::result::Result<(u64, u64), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_SYS_RD,
        rdx: field_identifier,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok((args.rdx, args.r8))
}

/// Read a VCPU-scope metadata field (control structure field) of a TD.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.VP.RD Leaf'.
pub fn vp_read(field: u64) -> Result<(u64, u64), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_RD,
        rdx: field,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok((args.rdx, args.r8))
}

/// Write a VCPU-scope metadata field (control structure field) of a TD.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.VP.WR Leaf'.
pub fn vp_write(field: u64, value: u64, mask: u64) -> Result<u64, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_WR,
        rdx: field,
        r8: value,
        r9: mask,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(args.r8)
}

/// Invalidate mappings in the translation lookaside buffers (TLBs) and paging-structure caches
/// for a specified L2 VM and a specified list of 4KB page linear addresses.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.VP.INVVPID Leaf'.
pub fn vp_invvpid(flags: u64, gla: u64) -> Result<u64, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_INVVPID,
        rcx: flags,
        rdx: gla,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(args.rdx)
}

/// Invalidate cached EPT translations for selected L2 VM.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.VP.INVEPT Leaf'.
pub fn vp_invept(vm_flags: u64) -> Result<(), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_INVEPT,
        rcx: vm_flags,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Enter L2 VCPU operation.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.VP.ENTER Leaf'.
pub fn vp_enter(vm_flags: u64, gpa: u64) -> TdcallArgs {
    let mut args = TdcallArgs {
        rax: TDCALL_VP_ENTER,
        rcx: vm_flags,
        rdx: gpa,
        ..Default::default()
    };

    td_call(&mut args);

    args
}

/// Read a TD-scope metadata field (control structure field) of a TD.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.VM.RD Leaf'.
pub fn vm_read(field: u64, version: u8) -> Result<(u64, u64), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VM_RD | (version as u64) << 16,
        rdx: field,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok((args.rdx, args.r8))
}

/// Write a TD-scope metadata field (control structure field) of a TD.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.VM.WR Leaf'.
pub fn vm_write(field: u64, value: u64, mask: u64) -> Result<u64, TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_VM_WR,
        rdx: field,
        r8: value,
        r9: mask,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(args.r8)
}

/// Write the attributes of a private page.  Create or remove L2 page aliases as required.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.MEM.PAGE.ATTR.WR Leaf'.
pub fn mem_page_attr_wr(
    gpa_mapping: u64,
    gpa_attr: u64,
    attr_flags: u64,
) -> Result<(u64, u64), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_MEM_PAGE_ATTR_WR,
        rcx: gpa_mapping,
        rdx: gpa_attr,
        r8: attr_flags,
        ..Default::default()
    };

    const MAX_RETRIES_ATTR_WR: usize = 5;
    let mut retry_counter = 0;
    let mut ret = 0;

    while retry_counter < MAX_RETRIES_ATTR_WR {
        ret = td_call(&mut args);

        if ret == TDCALL_STATUS_SUCCESS {
            return Ok((args.rcx, args.rdx));
        } else {
            match TdCallError::from(ret) {
                TdCallError::TdxExitReasonOperandBusy(_) => retry_counter += 1,
                e => return Err(e),
            }
        }
    }

    Err(ret.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn test_struct_size_alignment() {
        assert_eq!(align_of::<TdxDigest>(), 64);
        assert_eq!(size_of::<TdxDigest>(), 64);
        assert_eq!(size_of::<TdInfo>(), 48);
        assert_eq!(size_of::<TdVeInfo>(), 48);
    }

    #[test]
    fn test_servtd_rd() {
        let uuid: [u64; 3] = [0; 3];
        let ret = servtd_rd(0x0, 0x0, &uuid);

        assert!(ret.is_err());
    }

    #[test]
    fn test_servtd_wr() {
        let uuid: [u64; 3] = [0; 3];
        let ret = servtd_wr(0x0, 0x0, 0x0, &uuid);

        assert!(ret.is_err());
    }
}

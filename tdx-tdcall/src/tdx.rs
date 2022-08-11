// Copyright (c) 2020-2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Implemention of a subset of TDCALL functions defined in Intel TDX Module v1.0 and v1.5
//! Spec and TDVMCALL sub-functions defined in TDX GHCI Spec.
//!
//! The TDCALL instruction causes a VM exit to the Intel TDX Module. It is used to call
//! guest-side Intel TDX functions, either local or a TD exit to the host VMM.
//!
//! TDVMCALL (TDG.VP.VMCALL) is a leaf function 0 for TDCALL. It helps invoke services from
//! the host VMM.

use core::result::Result;
use core::sync::atomic::{fence, Ordering};
use lazy_static::lazy_static;

use crate::*;

const IO_READ: u64 = 0;
const IO_WRITE: u64 = 1;
const TARGET_TD_UUID_NUM: usize = 4;

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
    pub rsvd: [u64; 3],
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

/// Emulated CPUID values returned from TDG.VP.VMCALL<Instruction.CPUID>
#[repr(C)]
#[derive(Debug, Default)]
pub struct CpuIdInfo {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct ServtdRWResult {
    pub content: u64,
    pub uuid: [u64; 4],
}

lazy_static! {
    static ref SHARED_MASK: u64 = td_shared_mask().expect("Fail to get the shared mask of TD");
}

/// Used to help perform HLT operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.HLT>'
pub fn tdvmcall_halt() {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_HALT,
        ..Default::default()
    };

    let _ = td_vmcall(&mut args);
}

/// Request the VMM perform single byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_read_8(port: u16) -> u8 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u8>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    args.r11 as u8
}

/// Request the VMM perform 2-bytes byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_read_16(port: u16) -> u16 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u16>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    args.r11 as u16
}

/// Request the VMM perform 4-bytes byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_read_32(port: u16) -> u32 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u32>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    args.r11 as u32
}

/// Request the VMM perform single byte IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_write_8(port: u16, byte: u8) {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u8>() as u64,
        r13: IO_WRITE,
        r14: port as u64,
        r15: byte as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Request the VMM perform 2-bytes IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_write_16(port: u16, byte: u16) {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u16>() as u64,
        r13: IO_WRITE,
        r14: port as u64,
        r15: byte as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Request the VMM perform 4-bytes IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn tdvmcall_io_write_32(port: u16, byte: u32) {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u32>() as u64,
        r13: IO_WRITE,
        r14: port as u64,
        r15: byte as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Used to help request the VMM perform emulated-MMIO-write operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<#VE.RequestMMIO>'
pub fn tdvmcall_mmio_write<T: Sized>(address: *const T, value: T) {
    let address = address as u64 | *SHARED_MASK;
    fence(Ordering::SeqCst);
    let val = unsafe { *(&value as *const T as *const u64) };

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_MMIO,
        r12: core::mem::size_of::<T>() as u64,
        r13: IO_WRITE,
        r14: address,
        r15: val,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Used to help request the VMM perform emulated-MMIO-read operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<#VE.RequestMMIO>'
pub fn tdvmcall_mmio_read<T: Clone + Copy + Sized>(address: usize) -> T {
    let address = address as u64 | *SHARED_MASK;
    fence(Ordering::SeqCst);

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_MMIO,
        r12: core::mem::size_of::<T>() as u64,
        r13: IO_READ,
        r14: address,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    unsafe { *(&args.r11 as *const u64 as *const T) }
}

/// Used to request the host VMM to map a GPA range as a private or shared memory mappings.
/// It can be used to convert page mappings from private to shared or vice versa
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<MapGPA>'
pub fn tdvmcall_mapgpa(shared: bool, paddr: u64, length: usize) -> Result<(), TdVmcallError> {
    let share_bit = *SHARED_MASK;
    let paddr = if shared {
        paddr | share_bit
    } else {
        paddr & (!share_bit)
    };

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_MAPGPA,
        r12: paddr,
        r13: length as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    log::trace!(
        "tdvmcall mapgpa - paddr: {:x}, length: {:x}\n",
        paddr,
        length
    );

    Ok(())
}

/// Used to help perform RDMSR operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.RDMSR>'
pub fn tdvmcall_rdmsr(index: u32) -> u64 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_RDMSR,
        r12: index as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    args.r11
}

/// Used to help perform WRMSR operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.WRMSR>'
pub fn tdvmcall_wrmsr(index: u32, value: u64) {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_WRMSR,
        r12: index as u64,
        r13: value,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }
}

/// Used to enable the TD-guest to request the VMM to emulate the CPUID operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.WRMSR>'
pub fn tdvmcall_cpuid(eax: u32, ecx: u32) -> CpuIdInfo {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_CPUID,
        r12: eax as u64,
        r13: ecx as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        tdvmcall_halt();
    }

    CpuIdInfo {
        eax: args.r12 as u32,
        ebx: args.r13 as u32,
        ecx: args.r14 as u32,
        edx: args.r15 as u32,
    }
}

/// Used to request the host VMM specify which interrupt vector to use as an event-notify
/// vector.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<SetupEventNotifyInterrupt>'
pub fn tdvmcall_setup_event_notify(vector: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_SETUPEVENTNOTIFY,
        r12: vector as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Used to invoke a request to generate a TD-Quote signing by a TD-Quoting Enclave
/// operating in the host environment.
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<GetQuote>'
///
/// * buffer: a piece of 4KB-aligned shared memory
pub fn tdvmcall_get_quote(buffer: &mut [u8]) -> Result<(), TdVmcallError> {
    let addr = buffer.as_mut_ptr() as u64;

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_GETQUOTE,
        r12: addr,
        r13: buffer.len() as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// TDG.VP.VMCALL<Service> defines an interface for the command/response that
/// may have long latency.
/// Details can be found in TDX GHCI v1.5 spec section 'TDG.VP.VMCALL<Service>'
///
/// * command: a piece of 4KB-aligned shared memory as input
/// * response: a piece of 4KB-aligned shared memory as ouput
/// * interrupt: event notification interrupt vector, valid values [32-255]
/// * wait_time: Maximum wait time for the command and response
pub fn tdvmcall_service(
    command: &[u8],
    response: &mut [u8],
    interrupt: u64,
    wait_time: u64,
) -> Result<(), TdVmcallError> {
    let command = command.as_ptr() as u64;
    let response = response.as_mut_ptr() as u64;

    // Ensure the address is aligned to 4K bytes
    if (command & 0xfff) != 0 || (response & 0xfff) != 0 {
        return Err(TdVmcallError::VmcallAlignError);
    }

    // Ensure that the interrupt vector is in a valid range
    if (1..32).contains(&interrupt) {
        return Err(TdVmcallError::VmcallOperandInvalid);
    }

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_SERVICE,
        r12: command,
        r13: response,
        r14: interrupt,
        r15: wait_time,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Get guest TD execution environment information
///
/// Details can be found in TDX Module ABI spec section 'TDG.VP.INFO Leaf'
pub fn tdcall_get_td_info() -> Result<TdInfo, TdCallError> {
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
        ..Default::default()
    };

    Ok(td_info)
}

/// Extend a TDCS.RTMR measurement register
///
/// Details can be found in TDX Module ABI spec section 'TDG.VP.INFO Leaf'
pub fn tdcall_extend_rtmr(digest: &TdxDigest, mr_index: u32) -> Result<(), TdCallError> {
    let buffer: u64 = &digest.data as *const u8 as u64;

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
pub fn tdcall_get_ve_info() -> Result<TdVeInfo, TdCallError> {
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
pub fn tdcall_accept_page(address: u64) -> Result<(), TdCallError> {
    let mut args = TdcallArgs {
        rax: TDCALL_TDACCEPTPAGE,
        rcx: address,
        ..Default::default()
    };

    let ret = td_call(&mut args);

    if ret != TDCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Get the guest physical address (GPA) width via TDG.VP.INFO
/// The GPA width can be used to determine the shared-bit of GPA
pub fn td_shared_mask() -> Option<u64> {
    let td_info = tdcall_get_td_info().ok()?;
    let gpaw = (td_info.gpaw & 0x3f) as u8;

    Some(1u64 << (gpaw - 1))
}

/// Used by a service TD to read a metadata field (control structure field) of
/// a target TD.
///
/// Details can be found in TDX Module v1.5 ABI spec section 'TDG.SERVTD.RD Leaf'.
pub fn tdcall_servtd_rd(
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
pub fn tdcall_servtd_wr(
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
    fn test_tdcall_servtd_rd() {
        let uuid: [u64; 3] = [0; 3];
        let ret = tdcall_servtd_rd(0x0, 0x0, &uuid);

        assert!(ret.is_err());
    }

    #[test]
    fn test_tdcall_servtd_wr() {
        let uuid: [u64; 3] = [0; 3];
        let ret = tdcall_servtd_wr(0x0, 0x0, 0x0, &uuid);

        assert!(ret.is_err());
    }
}

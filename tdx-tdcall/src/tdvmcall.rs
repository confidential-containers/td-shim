// Copyright (c) 2020-2022, 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Implemention of a subset of TDVMCALL sub-functions defined in TDX GHCI Spec.
//!
//! TDVMCALL (TDG.VP.VMCALL) is a leaf function 0 for TDCALL. It helps invoke services from
//! the host VMM.

use core::result::Result;
use x86_64::registers::rflags::{self, RFlags};
use core::sync::atomic::{fence, Ordering};
use lazy_static::lazy_static;
use crate::*;

lazy_static! {
    static ref SHARED_MASK: u64 = td_shared_mask().expect("Fail to get the shared mask of TD");
}

// GTDG.VP.VMCALL leaf sub-function numbers
const TDVMCALL_CPUID: u64 = 0x0000a;
const TDVMCALL_HALT: u64 = 0x0000c;
const TDVMCALL_IO: u64 = 0x0001e;
const TDVMCALL_RDMSR: u64 = 0x0001f;
const TDVMCALL_WRMSR: u64 = 0x00020;
const TDVMCALL_MMIO: u64 = 0x00030;
const TDVMCALL_MAPGPA: u64 = 0x10001;
const TDVMCALL_GETQUOTE: u64 = 0x10002;
const TDVMCALL_SETUPEVENTNOTIFY: u64 = 0x10004;
const TDVMCALL_SERVICE: u64 = 0x10005;

// TDVMCALL completion status code
const TDVMCALL_STATUS_SUCCESS: u64 = 0;
const TDVMCALL_STATUS_RETRY: u64 = 1;

// Used to pass the values of input/output register when performing TDVMCALL
// instruction
#[repr(C)]
#[derive(Default)]
pub struct TdVmcallArgs {
    // Input: Always 0 for  (standard VMCALL)
    // Output: Sub-function
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
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

/// TDVMCALL sub-function return error code
///
/// Refer to Guest-Host-Communication-Interface(GHCI) for Intel TDX
/// table 'TDCALL[TDG.VP.VMCALL]- Sub-function Completion-Status Codes'
#[derive(Debug, PartialEq)]
pub enum TdVmcallError {
    // TDCALL[TDG.VP.VMCALL] sub-function invocation must be retried
    VmcallRetry,

    // Invalid operand to TDG.VP.VMCALL sub-function
    VmcallOperandInvalid,

    // GPA already mapped
    VmcallGpaInuse,

    // Operand (address) alignment error
    VmcallAlignError,

    Other,
}

impl From<u64> for TdVmcallError {
    fn from(val: u64) -> Self {
        match val {
            0x1 => TdVmcallError::VmcallRetry,
            0x8000_0000_0000_0000 => TdVmcallError::VmcallOperandInvalid,
            0x8000_0000_0000_0001 => TdVmcallError::VmcallGpaInuse,
            0x8000_0000_0000_0002 => TdVmcallError::VmcallAlignError,
            _ => TdVmcallError::Other,
        }
    }
}

// A public wrapper for use of asm_td_vmcall, this function takes a mutable reference of a
// TdcallArgs structure to ensure the input is valid
//
// ## TDVMCALL ABI
// Defined in GHCI Spec section 'TDCALL [TDG.VP.VMCALL] leaf'
//
// ### Input Operands:
// * RAX - TDCALL instruction leaf number (0 - TDG.VP.VMCALL)
// * RCX - A bitmap that controls which part of guest TD GPR is exposed to VMM.
// * R10 - Set to 0 indicates leaf-function used in R11 is defined in standard GHCI Spec.
// * R11 - TDG.VP.VMCALL sub-function is R10 is zero
// * RBX, RBP, RDI, RSI, R8-R10, R12-R15 - Used to pass values to VMM in sub-functions.
//
// ### Output Operands:
// * RAX - TDCALL instruction return code, always return Success(0).
// * R10 - TDG.VP.VMCALL sub-function return value
// * R11 - Correspond to each TDG.VP.VMCALL.
// * R8-R9, R12-R15, RBX, RBP, RDI, RSI - Correspond to each TDG.VP.VMCALL sub-function.
//
pub fn td_vmcall(args: &mut TdVmcallArgs) -> u64 {
    unsafe { asm::asm_td_vmcall(args as *mut TdVmcallArgs as *mut c_void, 0) }
}

/// Used to help perform HLT operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.HLT>'
pub fn halt() {
    let interrupt_blocked = !rflags::read().contains(RFlags::INTERRUPT_FLAG);

    let mut args = TdVmcallArgs {
        r11: TDVMCALL_HALT,
        r12: interrupt_blocked as u64,
        ..Default::default()
    };

    let _ = td_vmcall(&mut args);
}

/// Executing `hlt` instruction will cause a #VE to emulate the instruction. Safe halt operation
/// `sti;hlt` which typically used for idle is not working in this case since `hlt` instruction
/// must be the instruction next to `sti`. To use safe halt, `sti` must be executed just before
/// `tdcall` instruction.
pub fn sti_halt() {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_HALT,
        ..Default::default()
    };

    // Set the `do_sti` flag to execute `sti` before `tdcall` instruction
    // Result is always `TDG.VP.VMCALL_SUCCESS`
    let _ = td_vmcall_ex(&mut args, true);
}

const IO_READ: u64 = 0;
const IO_WRITE: u64 = 1;

/// Request the VMM perform single byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn io_read_8(port: u16) -> u8 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u8>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        halt();
    }

    (args.r11 & 0xff) as u8
}

/// Request the VMM perform 2-bytes byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn io_read_16(port: u16) -> u16 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u16>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        halt();
    }

    (args.r11 & 0xffff) as u16
}

/// Request the VMM perform 4-bytes byte IO read operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn io_read_32(port: u16) -> u32 {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_IO,
        r12: core::mem::size_of::<u32>() as u64,
        r13: IO_READ,
        r14: port as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        halt();
    }

    (args.r11 & 0xffff_ffff) as u32
}

/// Request the VMM perform single byte IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn io_write_8(port: u16, byte: u8) {
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
        halt();
    }
}

/// Request the VMM perform 2-bytes IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn io_write_16(port: u16, byte: u16) {
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
        halt();
    }
}

/// Request the VMM perform 4-bytes IO write operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.IO>'
pub fn io_write_32(port: u16, byte: u32) {
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
        halt();
    }
}

/// Used to help request the VMM perform emulated-MMIO-write operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<#VE.RequestMMIO>'
pub fn mmio_write<T: Sized>(address: *const T, value: T) {
    let address = address as u64 | *SHARED_MASK;
    fence(Ordering::SeqCst);
    let val = unsafe { *(core::ptr::addr_of!(value) as *const u64) };

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
        halt();
    }
}

/// Used to help request the VMM perform emulated-MMIO-read operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<#VE.RequestMMIO>'
pub fn mmio_read<T: Clone + Copy + Sized>(address: usize) -> T {
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
        halt();
    }

    unsafe { *(core::ptr::addr_of!(args.r11) as *const T) }
}

/// Used to request the host VMM to map a GPA range as a private or shared memory mappings.
/// It can be used to convert page mappings from private to shared or vice versa
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<MapGPA>'
pub fn mapgpa(shared: bool, paddr: u64, length: usize) -> Result<(), TdVmcallError> {
    let share_bit = *SHARED_MASK;
    let mut map_start = if shared {
        paddr | share_bit
    } else {
        paddr & (!share_bit)
    };
    let map_end = map_start
        .checked_add(length as u64)
        .ok_or(TdVmcallError::Other)?;

    const MAX_RETRIES_PER_PAGE: usize = 3;
    let mut retry_counter = 0;

    while retry_counter < MAX_RETRIES_PER_PAGE {
        log::trace!(
            "tdvmcall mapgpa - start: {:x}, length: {:x}\n",
            map_start,
            map_end - map_start,
        );
        let mut args = TdVmcallArgs {
            r11: TDVMCALL_MAPGPA,
            r12: map_start,
            r13: map_end - map_start,
            ..Default::default()
        };

        let ret = td_vmcall(&mut args);
        if ret == TDVMCALL_STATUS_SUCCESS {
            return Ok(());
        } else if ret != TDVMCALL_STATUS_RETRY {
            return Err(ret.into());
        }

        let retry_addr = args.r11;
        if retry_addr < map_start || retry_addr >= map_end {
            return Err(TdVmcallError::Other);
        }

        // Increase the retry count for the current page
        if retry_addr == map_start {
            retry_counter += 1;
            continue;
        }

        // Failed in a new address, update the `map_start` and reset counter
        map_start = retry_addr;
        retry_counter = 0;
    }

    Err(TdVmcallError::Other)
}

/// Used to help perform RDMSR operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.RDMSR>'
pub fn rdmsr(index: u32) -> Result<u64, TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_RDMSR,
        r12: index as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(args.r11)
}

/// Used to help perform WRMSR operation.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.WRMSR>'
pub fn wrmsr(index: u32, value: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_WRMSR,
        r12: index as u64,
        r13: value,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        return Err(ret.into());
    }

    Ok(())
}

/// Used to enable the TD-guest to request the VMM to emulate the CPUID operation
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<Instruction.WRMSR>'
pub fn cpuid(eax: u32, ecx: u32) -> CpuIdInfo {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_CPUID,
        r12: eax as u64,
        r13: ecx as u64,
        ..Default::default()
    };

    let ret = td_vmcall(&mut args);

    if ret != TDVMCALL_STATUS_SUCCESS {
        halt();
    }

    CpuIdInfo {
        eax: (args.r12 & 0xffff_ffff) as u32,
        ebx: (args.r13 & 0xffff_ffff) as u32,
        ecx: (args.r14 & 0xffff_ffff) as u32,
        edx: (args.r15 & 0xffff_ffff) as u32,
    }
}

/// Used to request the host VMM specify which interrupt vector to use as an event-notify
/// vector.
///
/// Details can be found in TDX GHCI spec section 'TDG.VP.VMCALL<SetupEventNotifyInterrupt>'
pub fn setup_event_notify(vector: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TDVMCALL_SETUPEVENTNOTIFY,
        r12: vector,
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
pub fn get_quote(buffer: &mut [u8]) -> Result<(), TdVmcallError> {
    let addr = buffer.as_mut_ptr() as u64 | *SHARED_MASK;

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
pub fn service(
    command: &[u8],
    response: &mut [u8],
    interrupt: u64,
    wait_time: u64,
) -> Result<(), TdVmcallError> {
    let command = command.as_ptr() as u64 | *SHARED_MASK;
    let response = response.as_mut_ptr() as u64 | *SHARED_MASK;

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

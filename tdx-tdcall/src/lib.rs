// Copyright (c) 2020-2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Guest-Side (TDCALL) Interface Helper Functions
//!
//! This crate implements the helper functions for the TDCALL interface functions defined in
//! Intel TDX Module specifiction and the TDVMCALL sub-functions defined in Intel TDX
//! Guest-Hypervisor Communication Interface specification. It also provides the constants
//! and data structures that are defined in the specifications.
//!
//! Please refer to following links for detail:
//! [Intel TDX Module v1.0 Spec](https://www.intel.com/content/dam/develop/external/us/en/documents/tdx-module-1.0-public-spec-v0.931.pdf)
//! [Intel TDX Module v1.5 Spec](https://www.intel.com/content/dam/develop/external/us/en/documents/intel-tdx-module-1.5-abi-spec-348551001.pdf)
//! [Intel TDX Guest-Hypervisor Communication Interface Spec](https://cdrdv2.intel.com/v1/dl/getContent/726790)
//! [Intel TDX Guest-Hypervisor Communication Interface Spec v1.5](https://cdrdv2.intel.com/v1/dl/getContent/726792)
//!
//! A subset of TDCALL interface functions is defined in crate::tdx, and the TDG.MR.REPORT
//! leaf function and TDREPORT_STRUCT related definitions are defined in crate::tdreport
//! separately.

#![no_std]

use core::ffi::c_void;

#[cfg(feature = "use_tdx_emulation")]
pub const USE_TDX_EMULATION: bool = true;
#[cfg(not(feature = "use_tdx_emulation"))]
pub const USE_TDX_EMULATION: bool = false;

#[cfg(not(feature = "no-tdaccept"))]
pub const TDACCEPT_SUPPORT: bool = true;
#[cfg(feature = "no-tdaccept")]
pub const TDACCEPT_SUPPORT: bool = false;

pub mod asm;
pub mod tdreport;
pub mod tdx;

// Guest-Side (TDCALL) interface functions leaf numbers
const TDCALL_TDINFO: u64 = 1;
const TDCALL_TDEXTENDRTMR: u64 = 2;
const TDCALL_TDGETVEINFO: u64 = 3;
const TDCALL_TDREPORT: u64 = 4;
#[cfg(not(feature = "no-tdaccept"))]
const TDCALL_TDACCEPTPAGE: u64 = 6;
const TDCALL_VM_RD: u64 = 7;
const TDCALL_VM_WR: u64 = 8;
const TDCALL_VP_RD: u64 = 9;
const TDCALL_VP_WR: u64 = 10;
const TDCALL_SYS_RD: u64 = 11;
const TDCALL_SERVTD_RD: u64 = 18;
const TDCALL_SERVTD_WR: u64 = 20;
const TDCALL_VERIFYREPORT: u64 = 22;
const TDCALL_MEM_PAGE_ATTR_WR: u64 = 24;
const TDCALL_VP_ENTER: u64 = 25;
const TDCALL_VP_INVEPT: u64 = 26;
const TDCALL_VP_INVVPID: u64 = 27;
#[cfg(feature = "tdg_dbg")]
const TDCALL_TDG_DEBUG: u64 = 254;

// TDCALL completion status code
const TDCALL_STATUS_SUCCESS: u64 = 0;

// leaf-specific completion status code
pub const TDCALL_STATUS_PAGE_ALREADY_ACCEPTED: u64 = 0x00000B0A00000000;
pub const TDCALL_STATUS_PAGE_SIZE_MISMATCH: u64 = 0xC0000B0B00000001;

cfg_if::cfg_if! {
    if #[cfg(not(feature = "no-tdvmcall"))] {
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
        const TDVMCALL_MIGTD: u64 = 0x10006;

        // TDVMCALL completion status code
        const TDVMCALL_STATUS_SUCCESS: u64 = 0;
        const TDVMCALL_STATUS_RETRY: u64 = 1;

        // TDVMCALL<MigTD> leaf function numbers
        const TDVMCALL_MIGTD_WAITFORREQUEST: u16 = 1;
        const TDVMCALL_MIGTD_REPORTSTATUS: u16 = 2;
        const TDVMCALL_MIGTD_SEND: u16= 3;
        const TDVMCALL_MIGTD_RECEIVE: u16 = 4;
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
#[cfg(not(feature = "no-tdvmcall"))]
pub fn td_vmcall(args: &mut TdVmcallArgs) -> u64 {
    unsafe { asm::asm_td_vmcall(args as *mut TdVmcallArgs as *mut c_void, 0) }
}

// An extended public wrapper for use of asm_td_vmcall.
//
// `do_sti` is a flag used to determine whether to execute `sti` instruction before `tdcall`
#[cfg(not(feature = "no-tdvmcall"))]
pub fn td_vmcall_ex(args: &mut TdVmcallArgs, do_sti: bool) -> u64 {
    unsafe { asm::asm_td_vmcall(args as *mut TdVmcallArgs as *mut c_void, do_sti as u64) }
}

// An extended public wrapper for use of asm_td_vmcall_ex.
//
// `do_sti` is a flag used to determine whether to execute `sti` instruction before `tdcall`
#[cfg(not(feature = "no-tdvmcall"))]
pub fn td_vmcall_ex2(args: &mut TdVmcallArgsEx, do_sti: bool) -> u64 {
    unsafe { asm::asm_td_vmcall_ex(args as *mut TdVmcallArgsEx as *mut c_void, do_sti as u64) }
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

// Used to pass the values of input/output register when performing TDVMCALL
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

// Used to pass the values of input/output register when performing TDVMCALL
// instruction
#[cfg(not(feature = "no-tdvmcall"))]
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

// Used to pass the values of input/output register when performing TDVMCALL
// instruction
#[cfg(not(feature = "no-tdvmcall"))]
#[repr(C)]
#[derive(Default)]
pub struct TdVmcallArgsEx {
    // Input: Always 0 for  (standard VMCALL)
    // Output: Sub-function
    pub rdx: u64,
    pub rbx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
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

/// TDVMCALL sub-function return error code
///
/// Refer to Guest-Host-Communication-Interface(GHCI) for Intel TDX
/// table 'TDCALL[TDG.VP.VMCALL]- Sub-function Completion-Status Codes'
#[cfg(not(feature = "no-tdvmcall"))]
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

#[cfg(not(feature = "no-tdvmcall"))]
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

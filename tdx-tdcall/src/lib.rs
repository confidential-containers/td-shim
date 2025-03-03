// Copyright (c) 2020-2022 Intel Corporation
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

pub mod asm;
pub mod tdreport;
pub mod tdx;
#[cfg(feature = "tdvmcall")]
pub mod tdvmcall;

// Guest-Side (TDCALL) interface functions leaf numbers
const TDCALL_TDINFO: u64 = 1;
const TDCALL_TDEXTENDRTMR: u64 = 2;
const TDCALL_TDGETVEINFO: u64 = 3;
const TDCALL_TDREPORT: u64 = 4;
const TDCALL_TDACCEPTPAGE: u64 = 6;
const TDCALL_VM_RD: u64 = 7;
const TDCALL_VM_WR: u64 = 8;
const TDCALL_VP_RD: u64 = 9;
const TDCALL_VP_WR: u64 = 10;
const TDCALL_SYS_RD: u64 = 11;
const TDCALL_SERVTD_RD: u64 = 18;
const TDCALL_SERVTD_WR: u64 = 20;
const TDCALL_MEM_PAGE_ATTR_WR: u64 = 24;
const TDCALL_VP_ENTER: u64 = 25;
const TDCALL_VP_INVEPT: u64 = 26;
const TDCALL_VP_INVVPID: u64 = 27;

// TDCALL completion status code
const TDCALL_STATUS_SUCCESS: u64 = 0;

// leaf-specific completion status code
pub const TDCALL_STATUS_PAGE_ALREADY_ACCEPTED: u64 = 0x00000B0A00000000;
pub const TDCALL_STATUS_PAGE_SIZE_MISMATCH: u64 = 0xC0000B0B00000001;


// An extended public wrapper for use of asm_td_vmcall.
//
// `do_sti` is a flag used to determine whether to execute `sti` instruction before `tdcall`
pub fn td_vmcall_ex(args: &mut TdVmcallArgs, do_sti: bool) -> u64 {
    unsafe { asm::asm_td_vmcall(args as *mut TdVmcallArgs as *mut c_void, do_sti as u64) }
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
